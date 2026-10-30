from __future__ import annotations

import base64
import binascii
import html
import json
import re
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, unquote_plus, urlsplit

from app.errors import AppError

REQUEST_LINE_RE = re.compile(r"^([A-Z]+)\s+(\S+)\s+(HTTP/\d\.\d)$")
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$")
UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})|%u([0-9a-fA-F]{4})")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

SKIP_HEADER_PARAMS = {
    "host",
    "content-length",
    "content-type",
    "connection",
    "accept",
    "accept-encoding",
    "accept-language",
    "user-agent",
    "cache-control",
    "pragma",
    "cookie",
}

MAX_PARAM_VALUE = 4096


@dataclass
class HttpParam:
    location: str
    name: str
    original_value: str


@dataclass
class ParsedRequest:
    method: str
    target: str
    version: str
    path: str
    query: str
    headers: list[tuple[str, str]]
    body: str
    params: list[HttpParam]
    raw: str
    host: str = ""

    def header(self, name: str) -> str | None:
        lowered = name.lower()
        for key, value in self.headers:
            if key.lower() == lowered:
                return value
        return None

    def to_summary(self) -> dict:
        length = len(self.body.encode("utf-8", errors="replace"))
        return {
            "method": self.method,
            "target": self.target,
            "path": self.path,
            "version": self.version,
            "host": self.host,
            "content_type": self.header("content-type") or "",
            "body_bytes": length,
            "param_count": len(self.params),
        }


@dataclass
class DecodedValue:
    original: str
    variants: list[dict] = field(default_factory=list)
    chain: list[str] = field(default_factory=list)

    @property
    def final(self) -> str:
        return self.variants[-1]["value"] if self.variants else self.original


def _ensure_text(raw: bytes | str) -> str:
    if isinstance(raw, bytes):
        for encoding in ("utf-8-sig", "gbk", "latin-1"):
            try:
                return raw.decode(encoding)
            except UnicodeDecodeError:
                continue
        return raw.decode("latin-1", errors="replace")
    return raw


def _unicode_unescape(value: str) -> str:
    def replace(match: re.Match) -> str:
        hex_part = match.group(1) or match.group(2)
        try:
            return chr(int(hex_part, 16))
        except ValueError:
            return match.group(0)

    return UNICODE_ESCAPE_RE.sub(replace, value)


def _is_printable(text: str) -> bool:
    if not text:
        return False
    for char in text:
        if char.isprintable() or char in "\r\n\t":
            continue
        return False
    return True


def _try_base64(value: str) -> str | None:
    candidate = value.strip()
    if len(candidate) < 8 or len(candidate) > 4096:
        return None
    if not BASE64_RE.match(candidate):
        return None
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not _is_printable(text):
        return None
    return text


def decode_value(value: str) -> DecodedValue:
    initial = value[:MAX_PARAM_VALUE]
    result = DecodedValue(original=initial, variants=[{"label": "原始值", "value": initial}])
    current = initial
    for _ in range(2):
        changed = False
        steps = (
            ("url", "URL 解码", lambda v: unquote_plus(v)),
            ("html", "HTML 实体解码", lambda v: html.unescape(v)),
            ("unicode", "Unicode 转义解码", _unicode_unescape),
            ("base64", "Base64 解码", _try_base64),
        )
        for label, display, func in steps:
            nxt = func(current)
            if nxt is None or nxt == current:
                continue
            current = nxt[:MAX_PARAM_VALUE]
            result.variants.append({"label": display, "value": current})
            result.chain.append(label)
            changed = True
            if len(result.variants) >= 9:
                break
        if not changed or len(result.variants) >= 9:
            break
    return result


def _add_params(params: list[HttpParam], location: str, name: str, value: str) -> None:
    if len(params) >= 300:
        return
    safe_name = name[:128]
    params.append(HttpParam(location=location, name=safe_name, original_value=value[:MAX_PARAM_VALUE]))


def _flatten_json(value, prefix: str, params: list[HttpParam], depth: int = 0) -> None:
    if depth > 5 or len(params) >= 300:
        return
    if isinstance(value, dict):
        for key, child in value.items():
            _flatten_json(child, f"{prefix}.{key}" if prefix else str(key), params, depth + 1)
    elif isinstance(value, list):
        for index, child in enumerate(value[:30]):
            _flatten_json(child, f"{prefix}[{index}]", params, depth + 1)
    elif value is None:
        _add_params(params, "body", prefix or "body", "")
    elif isinstance(value, bool):
        _add_params(params, "body", prefix or "body", "true" if value else "false")
    elif isinstance(value, (int, float)):
        _add_params(params, "body", prefix or "body", str(value))
    else:
        _add_params(params, "body", prefix or "body", str(value))


def parse_http_request(raw: bytes | str) -> ParsedRequest:
    text = _ensure_text(raw)
    if not text.strip():
        raise AppError("E_INPUT_FORMAT", "请求内容为空", 400)
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    head, separator, body = normalized.partition("\n\n")
    if not separator:
        body = ""
    head_lines = head.split("\n")
    if not head_lines or not head_lines[0].strip():
        raise AppError("E_INPUT_FORMAT", "缺少 HTTP 请求行", 400)

    match = REQUEST_LINE_RE.match(head_lines[0].strip())
    if not match:
        raise AppError(
            "E_INPUT_FORMAT",
            "请求行无法解析，应为 METHOD TARGET HTTP/1.1",
            400,
        )
    method, target, version = match.groups()

    headers: list[tuple[str, str]] = []
    for line in head_lines[1:]:
        if not line.strip():
            continue
        key, sep, value = line.partition(":")
        key = key.strip()
        if not sep or not HEADER_NAME_RE.match(key):
            continue
        headers.append((key, value.strip()))

    split = urlsplit(target)
    path = split.path or "/"
    query = split.query
    params: list[HttpParam] = []

    if query:
        for name, values in parse_qs(query, keep_blank_values=True).items():
            for value in values:
                _add_params(params, "query", name, value)

    content_type = ""
    for key, value in headers:
        if key.lower() == "content-type":
            content_type = value.lower()
            break

    if body.strip():
        if "application/json" in content_type:
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                _add_params(params, "body", "raw", body)
            else:
                _flatten_json(payload, "", params)
        elif "application/x-www-form-urlencoded" in content_type:
            for name, values in parse_qs(body, keep_blank_values=True).items():
                for value in values:
                    _add_params(params, "body", name, value)
        else:
            _add_params(params, "body", "raw", body)

    cookie_header = None
    for key, value in headers:
        if key.lower() == "cookie":
            cookie_header = value
            break
    if cookie_header:
        jar = SimpleCookie()
        try:
            jar.load(cookie_header)
        except Exception:
            jar = SimpleCookie()
        for name, morsel in jar.items():
            _add_params(params, "cookie", name, morsel.value)

    for key, value in headers:
        if key.lower() in SKIP_HEADER_PARAMS:
            continue
        if value:
            _add_params(params, "header", key.lower(), value)

    host = ""
    for key, value in headers:
        if key.lower() == "host":
            host = value
            break

    return ParsedRequest(
        method=method,
        target=target,
        version=version,
        path=path,
        query=query,
        headers=headers,
        body=body,
        params=params,
        raw=normalized,
        host=host,
    )


def request_context_text(request: ParsedRequest, max_chars: int) -> str:
    summary = request.to_summary()
    lines = [
        f"{request.method} {request.target} {request.version}",
        f"Host: {request.host}" if request.host else "Host: (未提供)",
    ]
    for key, value in request.headers:
        if key.lower() in {"host"}:
            continue
        shown = value if len(value) <= 300 else value[:300] + "..."
        lines.append(f"{key}: {shown}")
    if request.body:
        body = request.body if len(request.body) <= 2000 else request.body[:2000] + "...(截断)"
        lines.append("")
        lines.append("[BODY]")
        lines.append(body)
    lines.append("")
    lines.append("[参数清单]")
    for param in request.params:
        value = param.original_value
        if len(value) > 300:
            value = value[:300] + "...(截断)"
        lines.append(f"- {param.location}.{param.name} = {value!r}")
    if not request.params:
        lines.append("(未解析到参数)")
    lines.append("")
    lines.append(f"[请求元数据] {json.dumps(summary, ensure_ascii=False)}")
    text = "\n".join(lines)
    if len(text) > max_chars:
        text = text[:max_chars] + "\n...(内容超长已截断)"
    return text
