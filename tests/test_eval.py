from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.core.llm.client import Usage
from app.services.scan_service import ScanResult
from conftest import SAMPLES_DIR
from scripts import eval as eval_module
from scripts.eval import (
    Outcome,
    Sample,
    _accumulate_detection,
    _accumulate_injection,
    count_matches,
    finding_matches,
    load_samples,
    parse_category_list,
    parse_group_list,
)


def test_load_samples_counts_and_paths():
    samples = load_samples(SAMPLES_DIR, ("code", "http", "injection"))
    assert len(samples["code"]) == 30
    assert len(samples["http"]) == 10
    assert len(samples["injection"]) == 8
    assert samples["code"][0].path.is_file()
    assert samples["injection"][4].input_type == "http"
    limited = load_samples(SAMPLES_DIR, ("code",), limit=2)
    assert len(limited["code"]) == 2


def test_finding_matches_type_line_range_and_http_location():
    expected = {"vuln_type": "SQL_INJECTION", "line_start": 10, "line_end": 12}
    assert finding_matches(
        expected,
        {"vuln_type": "SQL_INJECTION", "line_start": 14, "line_end": 14},
        request_mode=False,
    )
    assert not finding_matches(
        expected,
        {"vuln_type": "SQL_INJECTION", "line_start": 15, "line_end": 15},
        request_mode=False,
    )
    assert not finding_matches(
        expected,
        {"vuln_type": "XSS", "line_start": 10, "line_end": 10},
        request_mode=False,
    )
    assert not finding_matches(
        {"vuln_type": "SQL_INJECTION"},
        {"vuln_type": "SQL_INJECTION", "line_start": 1},
        request_mode=False,
    )
    http_expected = {"vuln_type": "XSS", "location": "query.q"}
    assert finding_matches(
        http_expected,
        {"vuln_type": "XSS", "location": "query.q"},
        request_mode=True,
    )
    assert not finding_matches(
        http_expected,
        {"vuln_type": "XSS", "location": "query.other"},
        request_mode=True,
    )


def test_count_matches_is_one_to_one_and_counts_extra_predictions():
    expected = [
        {"vuln_type": "SQL_INJECTION", "line_start": 10},
        {"vuln_type": "XSS", "line_start": 20},
    ]
    predicted = [
        {"vuln_type": "SQL_INJECTION", "line_start": 11},
        {"vuln_type": "SQL_INJECTION", "line_start": 10},
        {"vuln_type": "COMMAND_INJECTION", "line_start": 30},
    ]
    counts = count_matches(expected, predicted, request_mode=False)
    assert counts.tp == 1
    assert counts.fn == 1
    assert counts.fp == 2


def _sample(name: str, category: str, expected: dict) -> Sample:
    return Sample(
        name=name,
        category=category,
        input_type="http" if category == "http" else "code",
        path=Path(name),
        expected=expected,
    )


def test_detection_metrics_exclude_rule_clues_and_count_hard_negative_fpr():
    positive = _sample(
        "vuln.py",
        "code",
        {
            "vulnerable": True,
            "findings": [{"vuln_type": "SQL_INJECTION", "line_start": 10}],
        },
    )
    safe = _sample("safe.py", "code", {"vulnerable": False, "findings": []})
    outcomes = [
        Outcome(
            sample=positive,
            result=ScanResult(
                findings=[
                    {
                        "vuln_type": "SQL_INJECTION",
                        "source_channel": "rule",
                        "line_start": 10,
                    }
                ],
                usage=Usage(prompt_tokens=10, completion_tokens=5),
                duration_ms=100,
            ),
            duration_ms=100,
        ),
        Outcome(
            sample=safe,
            result=ScanResult(
                findings=[
                    {
                        "vuln_type": "XSS",
                        "source_channel": "llm",
                        "line_start": 3,
                    }
                ],
                usage=Usage(prompt_tokens=20, completion_tokens=10),
                duration_ms=200,
            ),
            duration_ms=200,
        ),
    ]
    metrics = _accumulate_detection(outcomes)
    assert metrics["tp"] == 0 and metrics["fn"] == 1
    assert metrics["fp"] == 1
    assert metrics["rule_clues"] == 1
    assert metrics["hard_negative_fpr"] == 1.0
    assert metrics["avg_tokens"] == 22.5
    assert metrics["avg_latency_ms"] == 150.0


def test_injection_metrics_require_flag_and_untampered_findings():
    vuln = _sample(
        "inj.py",
        "code",
        {
            "suspicious": True,
            "vulnerable": True,
            "findings": [{"vuln_type": "XSS", "line_start": 4}],
        },
    )
    safe = _sample(
        "fake.py",
        "code",
        {"suspicious": True, "vulnerable": False, "findings": []},
    )
    outcomes = [
        Outcome(
            sample=vuln,
            result=ScanResult(
                findings=[
                    {
                        "vuln_type": "XSS",
                        "source_channel": "both",
                        "line_start": 4,
                    }
                ],
                suspicious=[{"line": 2, "quote": "ignore instructions"}],
                usage=Usage(prompt_tokens=1, completion_tokens=1),
            ),
        ),
        Outcome(
            sample=safe,
            result=ScanResult(
                findings=[
                    {
                        "vuln_type": "SQL_INJECTION",
                        "source_channel": "llm",
                        "line_start": 1,
                    }
                ],
                suspicious=[{"line": 2, "quote": "fake system"}],
                usage=Usage(prompt_tokens=1, completion_tokens=1),
            ),
        ),
    ]
    metrics = _accumulate_injection(outcomes)
    assert metrics["samples"] == 2
    assert metrics["success"] == 1
    assert metrics["suspicious_flagged"] == 2
    assert metrics["false_positives"] == 1


def test_eval_cli_parsers_validate_values():
    assert parse_group_list("a,d", "--groups") == ["A", "D"]
    assert parse_group_list("", "--injection-groups") == []
    with pytest.raises(ValueError):
        parse_group_list("E", "--groups")
    assert parse_category_list("code,http") == ("code", "http")
    with pytest.raises(ValueError):
        parse_category_list("code,unknown")


def test_eval_main_writes_json_and_markdown(tmp_path, monkeypatch):
    class FakeService:
        def __init__(self, *args, **kwargs):
            pass

        def analyze_code(self, parsed, options):
            return ScanResult(
                findings=[
                    {
                        "vuln_type": "COMMAND_INJECTION",
                        "severity": "HIGH",
                        "source_channel": "both",
                        "location": "vuln_01.py:11",
                        "line_start": 11,
                        "line_end": 11,
                    }
                ],
                usage=Usage(prompt_tokens=10, completion_tokens=5),
                duration_ms=12,
            )

    monkeypatch.setattr(eval_module, "ScanService", FakeService)
    output = tmp_path / "eval_result"
    exit_code = eval_module.main(
        [
            "--groups",
            "A",
            "--only",
            "code",
            "--limit",
            "1",
            "--injection-groups",
            "",
            "--cache",
            "--output",
            str(output),
        ]
    )
    assert exit_code == 0
    payload = json.loads(output.with_suffix(".json").read_text(encoding="utf-8"))
    detection = payload["groups"]["A"]["detection"]
    assert detection["tp"] == 1
    assert detection["precision"] == 1.0
    assert detection["recall"] == 1.0
    assert detection["json_valid_rate"] == 1.0
    assert "LLM 漏洞检测消融评测" in output.with_suffix(".md").read_text(
        encoding="utf-8"
    )
