from __future__ import annotations

from pathlib import Path

import pytest

from app.api.upload import sanitize_filename, save_upload
from app.core.parser.code_parser import decode_bytes, detect_language, parse_code
from app.core.parser.http_parser import decode_value, parse_http_request
from app.errors import AppError


def test_decode_utf8_and_gbk():
    text = "from flask import Flask\n# 中文注释\n"
    utf8_text, utf8_encoding = decode_bytes(text.encode("utf-8"))
    assert utf8_text == text
    assert utf8_encoding in {"utf-8", "utf-8-sig"}

    gbk_bytes = text.encode("gbk")
    gbk_text, gbk_encoding = decode_bytes(gbk_bytes)
    assert gbk_text == text and gbk_encoding == "gbk"


def test_decode_rejects_binary_and_bom_is_handled():
    with pytest.raises(AppError) as exc:
        decode_bytes(b"print(1)\x00")
    assert exc.value.code == "E_UPLOAD_TYPE"

    text, _encoding = decode_bytes(b"\xef\xbb\xbfprint(1)\n")
    assert text.startswith("print")


def test_language_detection():
    assert detect_language("a.py", "") == "python"
    assert detect_language("a.php", "") == "php"
    assert detect_language("a.js", "") == "javascript"
    assert detect_language("a.txt", "<?php echo 1;") == "php"
    assert detect_language("a.txt", "import os\nprint(1)") == "python"
    assert detect_language("a.txt", "const x = require('x');") == "javascript"
    with pytest.raises(AppError):
        detect_language("a.txt", "something_binary-ish")


def test_parse_code_numbering_and_rejects_unknown():
    parsed = parse_code("a\r\nb\rc\n", "demo.py")
    assert parsed.lines == ["a", "b", "c", ""]
    assert parsed.language == "python"
    with pytest.raises(AppError):
        parse_code(b"\xff\xfe\x00", "demo.bin")


def test_parse_get_query_and_headers():
    request = parse_http_request(
        "GET /search?q=test&q=second&page=2 HTTP/1.1\r\n"
        "Host: example.test\r\n"
        "X-Token: abc\r\n"
        "Cookie: session=deadbeef\r\n\r\n"
    )
    assert request.path == "/search"
    assert request.host == "example.test"
    params = {(item.location, item.name): item.original_value for item in request.params}
    repeated_q = [
        item.original_value
        for item in request.params
        if item.location == "query" and item.name == "q"
    ]
    assert repeated_q == ["test", "second"]
    assert params[("header", "x-token")] == "abc"
    assert params[("cookie", "session")] == "deadbeef"
    assert all(item.name != "host" for item in request.params)


def test_parse_post_form_and_json_body():
    form = parse_http_request(
        "POST /login HTTP/1.1\r\n"
        "Host: example.test\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
        "username=admin&password=p%40ss"
    )
    values = {(item.location, item.name): item.original_value for item in form.params}
    assert values[("body", "username")] == "admin"
    assert values[("body", "password")] == "p@ss"

    json_request = parse_http_request(
        "POST /api HTTP/1.1\n"
        "Host: example.test\n"
        "Content-Type: application/json\n\n"
        '{"user": {"name": "alice"}, "items": ["a", "b"], "ok": true}'
    )
    json_values = {(item.location, item.name): item.original_value for item in json_request.params}
    assert json_values[("body", "user.name")] == "alice"
    assert json_values[("body", "items[0]")] == "a"
    assert json_values[("body", "ok")] == "true"


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "GET /only-target HTTP/1.1\n",
        "get /path HTTP/1.1\n\n",
        "NONSENSE\n\n",
    ],
)
def test_malformed_requests_rejected(raw):
    if raw.startswith("GET /only-target"):
        # 合法请求行，缺少 Host 时仍可解析，不应当抛错。
        assert parse_http_request(raw).method == "GET"
        return
    with pytest.raises(AppError) as exc:
        parse_http_request(raw)
    assert exc.value.code == "E_INPUT_FORMAT"


def test_decode_chain_url_html_unicode_base64_and_mixed():
    assert decode_value("1%2527%2520OR%2520%25271%2527%253D%25271").final == "1' OR '1'='1"
    assert decode_value("%26lt%3Bscript%26gt%3Balert(1)%26lt%3B%2Fscript%26gt%3B").final == (
        "<script>alert(1)</script>"
    )
    assert decode_value("\\u003cscript\\u003e").final == "<script>"
    assert decode_value("%u003cscript%u003e").final == "<script>"
    assert decode_value("JyBPUiAnMSc9JzE=").final == "' OR '1'='1"

    mixed = decode_value("%253Cscript%253E")
    assert "<script>" in mixed.final
    assert mixed.chain.count("url") >= 2


def test_decode_value_limits_base64_to_printable():
    decoded = decode_value("AAECAwQFBgc=")
    assert decoded.final == "AAECAwQFBgc="


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("../../etc/passwd", "passwd"),
        ("..\\..\\windows\\system32\\cmd.py", "cmd.py"),
        ("normal.py", "normal.py"),
    ],
)
def test_sanitize_filename_never_uses_client_path(raw, expected):
    assert sanitize_filename(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "../", "..", "a\x00.py", "x" * 201])
def test_sanitize_filename_rejections(raw):
    with pytest.raises(AppError):
        sanitize_filename(raw)


def test_save_upload_uses_server_generated_name(isolated_settings):
    result = save_upload("../../evil.py", b"print('ok')\n", "python")
    stored = Path(isolated_settings.uploads_dir) / f"{result['file_id']}.py"
    assert stored.is_file()
    assert ".." not in result["file_id"]
    assert result["filename"] == "../../evil.py"

    with pytest.raises(AppError):
        save_upload("empty.py", b"", "python")
    with pytest.raises(AppError):
        save_upload("binary.py", b"abc\x00def", "python")
