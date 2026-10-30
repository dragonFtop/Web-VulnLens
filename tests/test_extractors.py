from __future__ import annotations

import json

import pytest

from app.core.extractor.candidates import (
    Candidate,
    assign_candidate_ids,
    merge_contexts,
    sort_and_limit,
)
from app.core.extractor.rule_engine import (
    extract_candidates,
    extract_http_candidates,
)
from app.core.parser.code_parser import parse_code
from app.core.parser.http_parser import parse_http_request
from conftest import SAMPLES_DIR, read_sample


def _parse(relative: str):
    path_parts = relative.split("/")
    return parse_code(read_sample(relative), path_parts[-1])


def _candidate_types(candidates) -> set[tuple[str, int, int]]:
    return {(item.vuln_hint, item.line_start, item.line_end) for item in candidates}


@pytest.mark.parametrize(
    ("directory", "expected"),
    [
        ("sql_injection/vuln_01.py", {("SQL_INJECTION", 12, 12)}),
        ("sql_injection/vuln_05.py", {("SQL_INJECTION", 12, 12)}),
        ("xss/vuln_01.py", {("XSS", 9, 9)}),
        ("xss/vuln_02.py", {("XSS", 10, 10)}),
        ("command_injection/vuln_02.py", {("COMMAND_INJECTION", 11, 11)}),
        ("command_injection/vuln_03.py", {("COMMAND_INJECTION", 9, 9)}),
    ],
)
def test_python_ast_finds_examples(directory, expected):
    candidates, parse_error = extract_candidates(_parse(f"code/{directory}"))
    assert parse_error is None
    assert expected <= _candidate_types(candidates)


@pytest.mark.parametrize(
    ("relative", "expected"),
    [
        ("code/xss/vuln_03.php", {("XSS", 3, 3)}),
        ("code/xss/vuln_04.js", {("XSS", 6, 6)}),
        ("code/command_injection/vuln_04.php", {("COMMAND_INJECTION", 3, 3)}),
        ("code/command_injection/vuln_05.js", {("COMMAND_INJECTION", 7, 7)}),
    ],
)
def test_rule_engine_finds_php_js(relative, expected):
    candidates, parse_error = extract_candidates(_parse(relative))
    assert parse_error is None
    assert expected <= _candidate_types(candidates)


@pytest.mark.parametrize(
    "relative",
    [
        "code/sql_injection/safe_01.py",
        "code/sql_injection/safe_02.py",
        "code/sql_injection/safe_03.py",
        "code/sql_injection/safe_04.py",
        "code/xss/safe_01.py",
        "code/xss/safe_02.py",
        "code/xss/safe_04.js",
        "code/command_injection/safe_01.py",
        "code/command_injection/safe_02.py",
        "code/command_injection/safe_05.py",
    ],
)
def test_clean_hard_negatives_produce_no_candidates(relative):
    candidates, _error = extract_candidates(_parse(relative))
    assert candidates == []


def test_rule_based_hard_negatives_carry_safe_hints():
    for relative, label_fragment in (
        ("code/xss/safe_03.php", "htmlspecialchars"),
        ("code/xss/safe_05.js", "DOMPurify"),
        ("code/command_injection/safe_03.php", "escapeshellarg"),
        ("code/command_injection/safe_04.js", "execFile"),
    ):
        candidates, _error = extract_candidates(_parse(relative))
        assert candidates
        assert any(
            label_fragment.lower() in " ".join(candidate.safe_patterns).lower()
            for candidate in candidates
        )


def test_window_does_not_link_distant_php_source_and_sink():
    code = (
        "<?php\n"
        "$name = $_GET['name'];\n"
        + "\n".join(["// filler"] * 20)
        + "\necho $name;\n"
        "?>\n"
    )
    parsed = parse_code(code, "far.php")
    candidates, _error = extract_candidates(parsed)
    assert candidates == []


def test_python_syntax_error_falls_back_to_rules():
    code = (
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/x'\n"
        "def broken(:\n"
        "    value = request.args.get('v')\n"
        "    cursor.execute('SELECT * FROM t WHERE x = %s' % value)\n"
    )
    parsed = parse_code(code, "broken.py")
    candidates, parse_error = extract_candidates(parsed)
    assert parse_error
    assert any(candidate.vuln_hint == "SQL_INJECTION" for candidate in candidates)
    assert all("AST" in candidate.notes for candidate in candidates)


def test_http_sample_candidates_and_benign():
    expected = {
        "sqli_double_url.txt": ("SQL_INJECTION", "query.id"),
        "sqli_base64.txt": ("SQL_INJECTION", "query.filter"),
        "sqli_comment_bypass.txt": ("SQL_INJECTION", "query.id"),
        "xss_html_entity.txt": ("XSS", "query.q"),
        "xss_url_script.txt": ("XSS", "query.next"),
        "xss_base64.txt": ("XSS", "query.html"),
        "rce_url_semicolon.txt": ("COMMAND_INJECTION", "query.host"),
        "rce_base64.txt": ("COMMAND_INJECTION", "query.domain"),
        "rce_backtick.txt": ("COMMAND_INJECTION", "query.target"),
    }
    for filename, (vuln_type, location) in expected.items():
        request = parse_http_request(read_sample(f"http/{filename}"))
        candidates = extract_http_candidates(request)
        assert any(
            candidate.vuln_hint == vuln_type
            and f"{candidate.location}.{candidate.name}" == location
            for candidate in candidates
        ), filename

    benign = parse_http_request(read_sample("http/benign_search.txt"))
    assert extract_http_candidates(benign) == []


def test_candidate_ids_sort_and_context_merge():
    candidates = [
        Candidate("", "XSS", "python", "XSS-001", 30, 30, "b"),
        Candidate("", "SQL_INJECTION", "python", "SQLI-001", 10, 10, "a"),
        Candidate("", "XSS", "python", "XSS-001", 12, 12, "c"),
    ]
    limited, truncated = sort_and_limit(candidates, 2)
    assert truncated is True
    assert limited[0].vuln_hint == "SQL_INJECTION"
    assign_candidate_ids(limited)
    assert [item.id for item in limited] == ["C1", "C2"]

    lines = [f"line{i}" for i in range(1, 81)]
    context, was_truncated = merge_contexts(candidates, lines, max_chars=100000)
    assert was_truncated is False
    assert "line10" in context and "line30" in context
    assert "line50" not in context


def test_expected_json_annotations_are_self_consistent():
    root = SAMPLES_DIR
    for sub in ("sql_injection", "xss", "command_injection"):
        entries = json.loads(
            (root / "code" / sub / "expected.json").read_text(encoding="utf-8")
        )
        files = {entry["file"] for entry in entries}
        assert len(files) == 10
        positives = [entry for entry in entries if entry["vulnerable"]]
        assert len(positives) == 5
        for entry in positives:
            candidates, _ = extract_candidates(
                parse_code((root / "code" / sub / entry["file"]).read_bytes(), entry["file"])
            )
            for finding in entry["findings"]:
                assert any(
                    candidate.vuln_hint == finding["vuln_type"]
                    and candidate.line_start <= finding["line_end"] + 2
                    and finding["line_start"] <= candidate.line_end + 2
                    for candidate in candidates
                ), (sub, entry["file"], finding)
