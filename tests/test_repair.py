from __future__ import annotations

import dataclasses

import pytest

from app.api.upload import save_upload
from app.core.llm.prompts import REPAIR_PROMPT_VERSION
from app.core.parser.code_parser import parse_code
from app.core.repair.patcher import (
    build_diff,
    generate_patch,
    strip_line_number_prefixes,
    syntax_check,
)
from app.core.repair.verifier import llm_verify, rescan_clean
from app.db import repository
from app.errors import LLMError
from app.services.repair_service import RepairService
from conftest import FakeLLM, read_sample

VULNERABLE = read_sample("code/sql_injection/vuln_01.py").decode("utf-8")
PATCHED = VULNERABLE.replace(
    '    cursor.execute(f"SELECT id, name FROM users WHERE name = \'{name}\'")',
    '    cursor.execute("SELECT id, name FROM users WHERE name = ?", (name,))',
)


def test_strip_line_number_prefixes_threshold():
    prefixed = "1 | line one\n2 | line two\n3 | line three\nplain line\n"
    assert strip_line_number_prefixes(prefixed) == "line one\nline two\nline three\nplain line\n"
    minority = "1 | line one\nplain line\nanother plain\n"
    assert strip_line_number_prefixes(minority) == minority


def test_syntax_check_and_diff():
    assert syntax_check("x = 1\n", "python") is True
    assert syntax_check("def broken(:\n", "python") is False
    assert syntax_check("<?php echo 1; ?>", "php") is None
    diff = build_diff("a\nb\n", "a\nc\n", "demo.py")
    assert "--- demo.py" in diff
    assert "+++ patched_demo.py" in diff
    assert "-b" in diff and "+c" in diff


def test_generate_patch_cleans_numbering_and_validates_schema():
    parsed = parse_code(VULNERABLE, "vuln.py")
    numbered = "\n".join(f"{index} | {line}" for index, line in enumerate(PATCHED.split("\n"), 1))
    client = FakeLLM(
        [
            {
                "patched_code": numbered,
                "explanation": "改为参数绑定",
                "changes": [{"line": 12, "before": "execute(f...)", "after": "execute(..., (name,))"}],
            }
        ]
    )
    result = generate_patch(client, {"vuln_type": "SQL_INJECTION"}, parsed, job_id="j1")
    assert "|" not in result.patched_code.split("SELECT")[0]
    assert "(name,)" in result.patched_code
    assert result.explanation == "改为参数绑定"
    assert client.calls[0]["job_id"] == "j1"
    assert client.calls[0]["prompt_version"] == REPAIR_PROMPT_VERSION

    bad_client = FakeLLM([{"explanation": "missing patched_code"}])
    with pytest.raises(LLMError) as exc:
        generate_patch(bad_client, {"vuln_type": "SQL_INJECTION"}, parsed)
    assert exc.value.code == "E_LLM_JSON"


def test_rescan_clean_detects_vulnerable_and_accepts_fix():
    assert rescan_clean(VULNERABLE, "vuln.py", "python", "SQL_INJECTION") is False
    assert rescan_clean(PATCHED, "vuln.py", "python", "SQL_INJECTION") is True
    # 规则候选带安全提示时视为已修复，避免重复告警。
    safe_php = read_sample("code/xss/safe_03.php").decode("utf-8")
    assert rescan_clean(safe_php, "safe.php", "php", "XSS") is True


def test_llm_verify_outcomes():
    finding = {"vuln_type": "SQL_INJECTION", "location": "app.py:12", "evidence": "x"}
    ok_client = FakeLLM([{"fixed": True, "residual_risk": "无", "notes": "已参数化"}])
    assert llm_verify(ok_client, finding, PATCHED, "python") == (True, "无")

    bad_client = FakeLLM([{"fixed": False, "residual_risk": "", "notes": "仍可拼接"}])
    assert llm_verify(bad_client, finding, VULNERABLE, "python") == (False, "仍可拼接")

    class FailingClient:
        def chat_json(self, *args, **kwargs):
            raise LLMError("E_LLM_TIMEOUT", "timeout", 504)

    fixed, residual = llm_verify(FailingClient(), finding, PATCHED, "python")
    assert fixed is None and "E_LLM_TIMEOUT" in residual

    invalid_client = FakeLLM([{"fixed": "not-a-boolean"}])
    with pytest.raises(LLMError) as exc:
        llm_verify(invalid_client, finding, PATCHED, "python")
    assert exc.value.code == "E_LLM_JSON"


def _seed_job_and_finding(
    settings,
    *,
    channel: str = "both",
    input_type: str = "code",
    filename: str = "vuln.py",
    content: bytes = VULNERABLE.encode("utf-8"),
):
    upload = save_upload(filename, content, "python" if input_type == "code" else "http")
    repository.create_job("j1", input_type, upload["file_id"], filename, "python", "test-model")
    source_line = VULNERABLE.split("\n")[11]
    repository.save_findings(
        "j1",
        [
            {
                "id": "v1",
                "vuln_type": "SQL_INJECTION",
                "severity": "HIGH",
                "confidence": 0.95,
                "location_type": "line",
                "location": "vuln.py:12",
                "line_start": 12,
                "line_end": 12,
                "rule_id": "SQLI-001",
                "cwe_id": "CWE-89",
                "evidence": source_line,
                "description": "SQL 拼接",
                "suggestion": "参数化查询",
                "source_channel": channel,
                "knowledge": [],
                "factors": {},
                "raw": {},
            }
        ],
    )
    return upload


def test_repair_service_creates_verified_patch(isolated_settings):
    _seed_job_and_finding(isolated_settings)
    client = FakeLLM([{"patched_code": PATCHED, "explanation": "参数化", "changes": []}])
    service = RepairService(settings=isolated_settings, client=client)
    result = service.create_repair("v1")
    assert result["syntax_ok"] is True
    assert result["rescan_clean"] is True
    assert result["llm_verified"] is None
    assert result["verified"] is True
    assert "人工复核" in result["notes"]

    detail = service.get_detail(result["repair_id"])
    assert "execute(\"SELECT" in detail["patched_code"]
    assert detail["diff"]
    path, download_name = service.get_download(result["repair_id"])
    assert path.is_file()
    assert download_name == "patched_vuln.py"
    assert path.parent == isolated_settings.patched_dir


def test_repair_service_rejects_rule_clue_http_and_disabled(isolated_settings):
    _seed_job_and_finding(isolated_settings, channel="rule")
    service = RepairService(settings=isolated_settings, client=FakeLLM([]))
    with pytest.raises(Exception) as exc:
        service.create_repair("v1")
    assert exc.value.code == "E_INPUT_FORMAT"

    repository.update_job("j1", status="DONE")
    repository.create_job("j2", "http", "f_missing", "request.http", "http", "test-model")
    repository.save_findings(
        "j2",
        [
            {
                "id": "v2",
                "vuln_type": "XSS",
                "severity": "MEDIUM",
                "source_channel": "both",
                "evidence": "x",
            }
        ],
    )
    with pytest.raises(Exception) as exc:
        service.create_repair("v2")
    assert exc.value.code == "E_INPUT_FORMAT"

    disabled = dataclasses.replace(isolated_settings, repair_enabled=False)
    disabled_service = RepairService(settings=disabled, client=FakeLLM([]))
    with pytest.raises(Exception) as exc:
        disabled_service.create_repair("v1")
    assert exc.value.code == "E_REPAIR_DISABLED"


def test_repair_service_rejects_oversized_file(isolated_settings):
    _seed_job_and_finding(isolated_settings)
    tiny = dataclasses.replace(isolated_settings, repair_max_file_kb=0)
    service = RepairService(settings=tiny, client=FakeLLM([]))
    with pytest.raises(Exception) as exc:
        service.create_repair("v1")
    assert exc.value.code == "E_REPAIR_TOO_LARGE"
