from __future__ import annotations

import json

from fastapi.testclient import TestClient

from app import config
from app.api import repairs as repairs_api
from app.api import scans as scans_api
from app.api.upload import save_upload
from app.core.parser.code_parser import parse_code
from app.db import repository
from app.main import app
from app.services.repair_service import RepairService
from app.services.scan_service import ScanService
from conftest import FakeLLM, read_sample

VULNERABLE = read_sample("code/sql_injection/vuln_01.py").decode("utf-8")
PATCHED = VULNERABLE.replace(
    '    cursor.execute(f"SELECT id, name FROM users WHERE name = \'{name}\'")',
    '    cursor.execute("SELECT id, name FROM users WHERE name = ?", (name,))',
)


def _client(isolated_settings):
    return TestClient(app)


def _sql_detection(parsed):
    return {
        "findings": [
            {
                "candidate_id": "C1",
                "vuln_type": "SQL_INJECTION",
                "cwe_id": "CWE-89",
                "line_start": 12,
                "line_end": 12,
                "evidence": parsed.line(12).strip(),
                "factors": {
                    "input_controllable": True,
                    "auth_required": False,
                    "sanitized": False,
                    "reason": "request.args 进入 f-string 拼接的 SQL",
                },
                "confidence": 0.9,
                "description": "用户输入拼接进 SQL 并执行",
                "suggestion": "使用参数化查询",
            }
        ],
        "suspicious_content": [],
    }


def _http_detection():
    return {
        "findings": [
            {
                "candidate_id": "C1",
                "vuln_type": "SQL_INJECTION",
                "location": "body.username",
                "evidence": "admin' OR '1'='1",
                "confidence": 0.9,
            }
        ],
        "suspicious_content": [],
    }


def _install_fake_scan(monkeypatch, response):
    def runner(job_id):
        ScanService(settings=config.settings, client=FakeLLM([response])).run(job_id)

    monkeypatch.setattr(scans_api, "run_scan_job", runner)


def _seed_finding(job_id="j_seed", channel="both"):
    content = VULNERABLE.encode("utf-8")
    upload = save_upload("vuln.py", content, "python")
    repository.create_job(job_id, "code", upload["file_id"], "vuln.py", "python", "test-model")
    repository.save_findings(
        job_id,
        [
            {
                "id": "v_seed",
                "vuln_type": "SQL_INJECTION",
                "severity": "HIGH",
                "confidence": 0.95,
                "location_type": "line",
                "location": "vuln.py:12",
                "line_start": 12,
                "line_end": 12,
                "rule_id": "SQLI-001",
                "cwe_id": "CWE-89",
                "evidence": VULNERABLE.split("\n")[11].strip(),
                "description": "SQL 注入",
                "suggestion": "参数化查询",
                "source_channel": channel,
                "knowledge": [],
                "factors": {},
                "raw": {},
            }
        ],
    )
    repository.update_job(job_id, status="DONE", stage="FINISHED")
    return upload


def test_upload_scan_findings_report_and_pages(isolated_settings, monkeypatch):
    with _client(isolated_settings) as client:
        upload_response = client.post(
            "/api/upload",
            files={
                "file": (
                    "vuln_01.py",
                    read_sample("code/sql_injection/vuln_01.py"),
                    "text/x-python",
                )
            },
        )
        assert upload_response.status_code == 200
        uploaded = upload_response.json()
        assert uploaded["language"] == "python"
        assert uploaded["file_id"].startswith("f_")

        parsed = parse_code(VULNERABLE, "vuln_01.py")
        _install_fake_scan(monkeypatch, _sql_detection(parsed))
        scan_response = client.post(
            "/api/scans", json={"input_type": "code", "file_id": uploaded["file_id"]}
        )
        assert scan_response.status_code == 200
        job_id = scan_response.json()["job_id"]

        job = client.get(f"/api/scans/{job_id}").json()
        assert job["status"] == "DONE"
        assert job["summary"]["HIGH"] == 1
        assert job["prompt_tokens"] == 120

        findings = client.get(f"/api/scans/{job_id}/findings").json()
        assert len(findings["findings"]) >= 1
        finding = findings["findings"][0]
        assert finding["source_channel"] == "both"
        assert finding["severity"] == "HIGH"
        assert finding["vuln_type_display"] == "SQL 注入"
        assert finding["knowledge"]

        scan_page = client.get(f"/scans/{job_id}")
        assert scan_page.status_code == 200
        assert "SQL 注入" in scan_page.text
        assert "双通道确认" in scan_page.text
        assert "生成修复" in scan_page.text

        report_json = client.get(f"/api/scans/{job_id}/report?format=json")
        assert report_json.status_code == 200
        assert "attachment" in report_json.headers["content-disposition"]
        report = json.loads(report_json.text)
        assert report["findings"][0]["id"] == finding["id"]
        assert "disclaimer" in report

        report_html = client.get(f"/api/scans/{job_id}/report")
        assert report_html.status_code == 200
        assert "人工复核" in report_html.text

        history = client.get("/api/scans").json()
        assert history["total"] == 1 and history["items"][0]["id"] == job_id
        assert client.get("/history").status_code == 200
        assert client.get("/").status_code == 200


def test_http_scan_flags_prompt_injection(isolated_settings, monkeypatch):
    raw = read_sample("injection/inj_param.txt").decode("utf-8")
    with _client(isolated_settings) as client:
        _install_fake_scan(monkeypatch, _http_detection())
        response = client.post("/api/scans", json={"input_type": "http", "raw_http": raw})
        assert response.status_code == 200
        job_id = response.json()["job_id"]

        findings = client.get(f"/api/scans/{job_id}/findings").json()
        assert findings["findings"][0]["location"] == "body.username"
        assert findings["suspicious_content"]
        assert findings["suspicious_content"][0]["origin"] == "header.x-audit"

        page = client.get(f"/scans/{job_id}")
        assert page.status_code == 200
        assert "检测到疑似提示注入内容" in page.text
        assert "body.username" in page.text


def test_upload_security_and_errors(isolated_settings):
    with _client(isolated_settings) as client:
        traversal = client.post(
            "/api/upload",
            files={"file": ("../../evil.py", b"print('x')\n", "text/x-python")},
        )
        assert traversal.status_code == 200
        assert traversal.json()["filename"] == "evil.py"
        stored = list(isolated_settings.uploads_dir.iterdir())
        assert len(stored) == 1
        assert stored[0].name.endswith(".py")
        assert "evil" not in stored[0].name

        bad_ext = client.post(
            "/api/upload", files={"file": ("shell.exe", b"MZ", "application/octet-stream")}
        )
        assert bad_ext.status_code == 400
        assert bad_ext.json()["error"]["code"] == "E_UPLOAD_TYPE"

        empty = client.post(
            "/api/upload", files={"file": ("empty.py", b"", "text/x-python")}
        )
        assert empty.status_code == 400
        assert empty.json()["error"]["code"] == "E_INPUT_FORMAT"

        binary = client.post(
            "/api/upload", files={"file": ("binary.py", b"a\x00b", "text/x-python")}
        )
        assert binary.status_code == 400
        assert binary.json()["error"]["code"] == "E_UPLOAD_TYPE"

        oversized = client.post(
            "/api/upload",
            files={"file": ("big.py", b"#" * (1024 * 1024 + 1), "text/x-python")},
        )
        assert oversized.status_code == 413
        assert oversized.json()["error"]["code"] == "E_UPLOAD_SIZE"

        missing = client.get("/api/scans/does-not-exist")
        assert missing.status_code == 404
        assert missing.json()["error"]["code"] == "E_NOT_FOUND"

        bad_payload = client.post("/api/scans", json={"input_type": "unknown"})
        assert bad_payload.status_code == 400
        assert bad_payload.json()["error"]["code"] == "E_INPUT_FORMAT"

        error_page = client.get("/scans/does-not-exist")
        assert error_page.status_code == 404
        assert "扫描任务不存在" in error_page.text
        assert "E_NOT_FOUND" in error_page.text


def test_security_headers(isolated_settings):
    with _client(isolated_settings) as client:
        index = client.get("/")
        assert index.headers["x-content-type-options"] == "nosniff"
        assert index.headers["x-frame-options"] == "DENY"
        assert "script-src 'self'" in index.headers["content-security-policy"]

        api = client.get("/api/scans")
        assert api.headers["cache-control"] == "no-store"
        assert "content-security-policy" in api.headers


def test_report_and_page_escape_untrusted_html(isolated_settings):
    _seed_finding("j_xss")
    repository.save_findings(
        "j_xss",
        [
            {
                "id": "v_xss",
                "vuln_type": "XSS",
                "severity": "MEDIUM",
                "confidence": 0.8,
                "location_type": "line",
                "location": "x.py:1",
                "line_start": 1,
                "line_end": 1,
                "rule_id": "XSS-001",
                "cwe_id": "CWE-79",
                "evidence": "<script>alert('injected')</script>",
                "description": '<img src=x onerror=alert(1)>',
                "suggestion": "输出编码",
                "source_channel": "both",
                "knowledge": [],
                "factors": {},
                "raw": {},
            }
        ],
    )
    with _client(isolated_settings) as client:
        page = client.get("/scans/j_xss")
        assert page.status_code == 200
        assert "<script>alert('injected')</script>" not in page.text
        assert "&lt;script&gt;" in page.text
        assert "<img src=x onerror=alert(1)>" not in page.text

        report = client.get("/api/scans/j_xss/report")
        assert report.status_code == 200
        assert "<script>alert('injected')</script>" not in report.text
        assert "&lt;script&gt;" in report.text


def test_repair_api_and_page(isolated_settings, monkeypatch):
    _seed_finding("j_repair")
    service = RepairService(
        settings=isolated_settings,
        client=FakeLLM([{"patched_code": PATCHED, "explanation": "参数化", "changes": []}]),
    )
    monkeypatch.setattr(repairs_api, "RepairService", lambda: service)
    with _client(isolated_settings) as client:
        response = client.post("/api/findings/v_seed/repair")
        assert response.status_code == 200
        repair = response.json()
        assert repair["syntax_ok"] is True
        assert repair["rescan_clean"] is True
        assert repair["verified"] is True

        detail = client.get(f"/api/repairs/{repair['repair_id']}")
        assert detail.status_code == 200
        assert detail.json()["finding"]["id"] == "v_seed"
        assert "(name,)" in detail.json()["patched_code"]
        download = client.get(f"/api/repairs/{repair['repair_id']}/download")
        assert download.status_code == 200
        assert "attachment" in download.headers["content-disposition"]
        assert b"(name,)" in download.content

        page = client.get(f"/repairs/{repair['repair_id']}")
        assert page.status_code == 200
        assert "修复后" in page.text

        missing = client.post("/api/findings/not-found/repair")
        assert missing.status_code == 404
