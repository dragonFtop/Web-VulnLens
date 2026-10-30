from __future__ import annotations

import pytest

from app.core.extractor.candidates import Candidate, RequestCandidate
from app.core.llm.schemas import Factors, RawFinding
from app.core.llm.validate import ValidFinding
from app.services.postprocess import (
    compute_confidence,
    compute_severity,
    merge_results,
)


def _valid(
    vuln_type: str,
    *,
    line_start: int | None = 10,
    line_end: int | None = None,
    candidate_id: str | None = "C1",
    location: str | None = None,
    evidence: str = "cursor.execute(sql)",
    knowledge_ids: list[str] | None = None,
) -> ValidFinding:
    raw = RawFinding(
        candidate_id=candidate_id,
        vuln_type=vuln_type,
        line_start=line_start,
        line_end=line_end,
        location=location,
        evidence=evidence,
        factors=Factors(input_controllable=True, auth_required=False, sanitized=False),
        confidence=0.8,
        knowledge_ids=knowledge_ids or [],
    )
    return ValidFinding(
        raw=raw,
        evidence_verified=True,
        line_start=line_start,
        line_end=line_end or line_start,
        location=location or f"app.py:{line_start}",
        candidate_id=candidate_id,
    )


def _merge(valid, candidates, *, request_mode=False, use_candidates=True):
    return merge_results(
        valid_findings=valid,
        candidates=candidates,
        knowledge_by_candidate={"C1": [{"id": "KB-1", "title": "参数化查询"}]},
        knowledge_by_type={"XSS": [{"id": "KB-2", "title": "输出编码"}]},
        allowed_knowledge_ids={"KB-1", "KB-2"},
        filename="app.py",
        language="python",
        use_candidates=use_candidates,
        request_mode=request_mode,
    )


@pytest.mark.parametrize(
    ("vuln_type", "factors", "expected"),
    [
        ("SQL_INJECTION", {"input_controllable": True}, "HIGH"),
        ("SQL_INJECTION", {}, "MEDIUM"),
        ("XSS", {"input_controllable": None}, "MEDIUM"),
        ("XSS", {"input_controllable": None, "auth_required": True, "sanitized": True}, "LOW"),
        (
            "COMMAND_INJECTION",
            {"input_controllable": False, "auth_required": True, "sanitized": True},
            "LOW",
        ),
    ],
)
def test_compute_severity(vuln_type, factors, expected):
    assert compute_severity(vuln_type, factors) == expected


def test_compute_confidence_is_bounded():
    assert compute_confidence("both", True, None) == 0.95
    assert compute_confidence("both", True, 1.0) == 0.99
    assert compute_confidence("llm", False, None) == 0.60
    assert compute_confidence("rule", True, None) == 0.40
    assert compute_confidence("unknown", False, 0.0) == 0.30


def test_merge_confirmed_and_llm_findings():
    candidate = Candidate(
        id="C1",
        vuln_hint="SQL_INJECTION",
        language="python",
        rule_id="SQLI-001",
        line_start=10,
        line_end=10,
        evidence="cursor.execute(sql)",
    )
    valid = [
        _valid("SQL_INJECTION", line_start=10),
        _valid("XSS", line_start=20, candidate_id=None, evidence="render_template_string(x)"),
    ]
    results = _merge(valid, [candidate])
    confirmed = [item for item in results if item["source_channel"] != "rule"]
    assert [item["source_channel"] for item in confirmed] == ["both", "llm"]
    first = confirmed[0]
    assert first["severity"] == "HIGH"
    assert first["confidence"] == 0.98
    assert first["location"] == "app.py:10"
    assert first["cwe_id"] == "CWE-89"
    assert first["knowledge"][0]["id"] == "KB-1"
    assert confirmed[1]["cwe_id"] == "CWE-79"
    assert [item["id"] for item in confirmed[1]["knowledge"]] == ["KB-2"]


def test_merge_dedupes_and_keeps_rule_clue():
    candidate = Candidate(
        id="C1",
        vuln_hint="SQL_INJECTION",
        language="python",
        rule_id="SQLI-001",
        line_start=10,
        line_end=10,
        evidence="cursor.execute(sql)",
    )
    unmatched = Candidate(
        id="C2",
        vuln_hint="XSS",
        language="python",
        rule_id="XSS-001",
        line_start=30,
        line_end=30,
        evidence="Markup(value)",
        safe_patterns=["html.escape 转义"],
    )
    duplicate = _valid("SQL_INJECTION", line_start=11, candidate_id=None)
    duplicate.raw.confidence = 0.2
    results = _merge([_valid("SQL_INJECTION", line_start=10), duplicate], [candidate, unmatched])
    confirmed = [item for item in results if item["source_channel"] != "rule"]
    clues = [item for item in results if item["source_channel"] == "rule"]
    assert len(confirmed) == 1
    assert len(clues) == 1
    assert clues[0]["vuln_type"] == "XSS"
    assert clues[0]["line_start"] == 30
    assert "安全写法" in clues[0]["description"]
    assert clues[0]["raw"]["rule_only"] is True


def test_merge_respects_allowed_knowledge_ids():
    valid = [
        _valid(
            "XSS",
            line_start=20,
            candidate_id=None,
            evidence="return template",
            knowledge_ids=["KB-2", "KB-NOT-ALLOWED"],
        )
    ]
    results = _merge(valid, [], use_candidates=False)
    assert results[0]["source_channel"] == "llm"
    assert [item["id"] for item in results[0]["knowledge"]] == ["KB-2"]


def test_merge_request_mode_dedupe_and_rule_id():
    candidate = RequestCandidate(
        id="C1",
        vuln_hint="SQL_INJECTION",
        location="query",
        name="id",
        original_value="1%2527",
        variants=[{"label": "原始值", "value": "1%2527"}],
        decode_chain=["URL 解码"],
        matched_rules=["HTTP-SQLI-001"],
    )
    valid = [
        _valid(
            "SQL_INJECTION",
            line_start=None,
            candidate_id="C1",
            location="query.id",
            evidence="1'",
        )
    ]
    results = _merge(valid, [candidate], request_mode=True)
    confirmed = [item for item in results if item["source_channel"] != "rule"]
    assert len(confirmed) == 1
    assert confirmed[0]["rule_id"] == "HTTP-SQLI-001"
    assert confirmed[0]["location_type"] == "param"
    assert confirmed[0]["line_start"] is None
    assert confirmed[0]["knowledge"][0]["id"] == "KB-1"
