from __future__ import annotations

from app.core.parser.http_parser import parse_http_request
from app.errors import AppError

CHANNEL_PRIORITY = {"both": 0, "llm": 1, "rule": 2}
MAX_HTTP_PARAMS = 80
MAX_VALUE_LEN = 400


def _clip(text: str, limit: int = MAX_VALUE_LEN) -> str:
    return text if len(text) <= limit else text[:limit] + "...(截断)"


def build_code_lines(
    text: str,
    findings: list[dict],
    suspicious: list[dict],
) -> list[dict]:
    if not text:
        return []
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    channels: dict[int, str] = {}
    finding_ids: dict[int, list[str]] = {}
    for finding in findings:
        if finding.get("location_type") != "line":
            continue
        start = finding.get("line_start")
        if not start:
            continue
        end = finding.get("line_end") or start
        try:
            start = int(start)
            end = int(end)
        except (TypeError, ValueError):
            continue
        start = max(1, start)
        end = min(len(lines), end)
        channel = finding.get("source_channel") or "rule"
        for number in range(start, end + 1):
            current = channels.get(number)
            if current is None or CHANNEL_PRIORITY.get(channel, 9) < CHANNEL_PRIORITY.get(
                current, 9
            ):
                channels[number] = channel
            finding_ids.setdefault(number, [])
            if finding["id"] not in finding_ids[number]:
                finding_ids[number].append(finding["id"])

    suspicious_lines = {
        int(item["line"]) for item in suspicious if item.get("line")
    }
    return [
        {
            "number": index + 1,
            "text": line,
            "channel": channels.get(index + 1),
            "finding_ids": finding_ids.get(index + 1, []),
            "suspicious": (index + 1) in suspicious_lines,
        }
        for index, line in enumerate(lines)
    ]


def build_raw_lines(text: str, suspicious: list[dict]) -> list[dict]:
    if not text:
        return []
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    suspicious_lines = {
        int(item["line"]) for item in suspicious if item.get("line")
    }
    return [
        {"number": index + 1, "text": line, "suspicious": (index + 1) in suspicious_lines}
        for index, line in enumerate(lines)
    ]


def build_http_view(text: str) -> dict | None:
    try:
        request = parse_http_request(text)
    except AppError:
        return None

    from app.core.parser.http_parser import decode_value

    params = []
    for param in request.params[:MAX_HTTP_PARAMS]:
        variants = []
        try:
            decoded = decode_value(param.original_value)
            variants = [
                {"label": item["label"], "value": _clip(item["value"])}
                for item in decoded.variants
            ]
        except Exception:  # noqa: BLE001
            variants = []
        params.append(
            {
                "location": param.location,
                "name": param.name,
                "original": _clip(param.original_value),
                "variants": variants,
                "changed": bool(variants and variants[-1]["value"] != param.original_value),
            }
        )
    return {
        "summary": request.to_summary(),
        "params": params,
        "total_params": len(request.params),
        "truncated": len(request.params) > MAX_HTTP_PARAMS,
    }


def build_diff_lines(diff: str) -> list[dict]:
    result = []
    for line in diff.split("\n"):
        if line.startswith("+++") or line.startswith("---"):
            kind = "meta"
        elif line.startswith("@@"):
            kind = "hunk"
        elif line.startswith("+"):
            kind = "add"
        elif line.startswith("-"):
            kind = "del"
        else:
            kind = "ctx"
        result.append({"text": line, "kind": kind})
    return result
