from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from pydantic import ValidationError

from app.core.extractor.candidates import Candidate, RequestCandidate
from app.core.llm.schemas import RawFinding, SuspiciousContent
from app.core.parser.code_parser import ParsedCode
from app.core.parser.http_parser import ParsedRequest, decode_value

CWE_ALIASES = {
    "SQL_INJECTION": {"CWE-89"},
    "XSS": {"CWE-79"},
    "COMMAND_INJECTION": {"CWE-78", "CWE-94"},
}
CANONICAL_CWE = {
    "SQL_INJECTION": "CWE-89",
    "XSS": "CWE-79",
    "COMMAND_INJECTION": "CWE-78",
}
LOCATION_LINE_RE = re.compile(r"(?:^|:)(\d{1,7})\s*$")
LINE_PREFIX_RE = re.compile(r"^\s*\d{1,7}\s*\|\s?")


@dataclass
class ValidFinding:
    raw: RawFinding
    evidence_verified: bool
    line_start: int | None
    line_end: int | None
    location: str
    candidate_id: str | None = None


@dataclass
class ValidationStats:
    raw_count: int = 0
    accepted: int = 0
    rejected: int = 0
    reasons: list[str] = field(default_factory=list)
    top_level_invalid: bool = False

    def reject(self, reason: str) -> None:
        self.rejected += 1
        if len(self.reasons) < 20:
            self.reasons.append(reason)


def _clean_line(text: str) -> str:
    return LINE_PREFIX_RE.sub("", text.strip()).strip()


def _truncate(text: str, limit: int = 4000) -> str:
    return text[:limit]


def _normalized_evidence_lines(evidence: str) -> list[str]:
    return [line for line in (_clean_line(part) for part in evidence.split("\n")) if line]


def _code_evidence_verified(
    evidence: str, line_start: int, line_end: int, parsed: ParsedCode
) -> bool:
    evidence_lines = _normalized_evidence_lines(evidence)
    if not evidence_lines:
        return False
    code_lines = {_clean_line(line) for line in parsed.lines}
    if any(line not in code_lines for line in evidence_lines):
        return False
    low = max(1, min(line_start, line_end) - 2)
    high = min(len(parsed.lines), max(line_start, line_end) + 2)
    nearby = {_clean_line(line) for line in parsed.lines[low - 1 : high]}
    return any(line in nearby for line in evidence_lines)


def _find_param(request: ParsedRequest, location: str | None):
    if not location:
        return None
    value = location.strip()
    for prefix in ("http.", "request."):
        if value.startswith(prefix):
            value = value[len(prefix):]
    for param in request.params:
        if f"{param.location}.{param.name}" == value:
            return param
    return None


def _param_values(param) -> list[str]:
    decoded = decode_value(param.original_value)
    values = [param.original_value]
    values.extend(item["value"] for item in decoded.variants)
    return list(dict.fromkeys(values))


def _evidence_in_values(evidence: str, values: list[str]) -> bool:
    evidence = evidence.strip()
    if not evidence:
        return False
    stripped = evidence.strip("'\" ")
    for value in values:
        if evidence in value or (stripped and stripped in value):
            return True
    return False


def _find_param_by_evidence(request: ParsedRequest, evidence: str):
    for param in request.params:
        if _evidence_in_values(evidence, _param_values(param)):
            return param
    return None


def _extract_line_from_location(location: str | None) -> int | None:
    if not location:
        return None
    match = LOCATION_LINE_RE.search(location)
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            return None
    return None


def validate_findings(
    data: dict,
    *,
    parsed: ParsedCode | None,
    request: ParsedRequest | None,
    candidates: list[Candidate] | list[RequestCandidate],
) -> tuple[list[ValidFinding], list[dict], ValidationStats]:
    stats = ValidationStats()
    raw_findings = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(raw_findings, list):
        stats.top_level_invalid = True
        return [], [], stats
    stats.raw_count = len(raw_findings)

    code_candidates = {
        candidate.id: candidate
        for candidate in candidates
        if isinstance(candidate, Candidate) and candidate.id
    }
    request_candidates = {
        candidate.id: candidate
        for candidate in candidates
        if isinstance(candidate, RequestCandidate) and candidate.id
    }

    valid: list[ValidFinding] = []
    for index, item in enumerate(raw_findings):
        if not isinstance(item, dict):
            stats.reject(f"第 {index + 1} 条 finding 不是对象")
            continue
        try:
            raw = RawFinding.model_validate(item)
        except ValidationError as exc:
            first = exc.errors()[0] if exc.errors() else {}
            stats.reject(f"第 {index + 1} 条字段非法：{first.get('msg', 'validation error')}")
            continue

        raw.evidence = _truncate(raw.evidence.strip(), 2000)
        raw.description = _truncate(raw.description)
        raw.suggestion = _truncate(raw.suggestion)
        try:
            raw.confidence = float(raw.confidence)
            if math.isnan(raw.confidence):
                raw.confidence = 0.5
        except (TypeError, ValueError):
            raw.confidence = 0.5
        raw.confidence = min(max(raw.confidence, 0.0), 1.0)

        allowed_cwe = CWE_ALIASES.get(raw.vuln_type, set())
        if not raw.cwe_id or raw.cwe_id not in allowed_cwe:
            raw.cwe_id = CANONICAL_CWE.get(raw.vuln_type, raw.cwe_id or "")

        candidate_id = raw.candidate_id if raw.candidate_id in (
            code_candidates if parsed is not None else request_candidates
        ) else None

        if parsed is not None:
            line_start = raw.line_start
            if line_start is None and candidate_id:
                line_start = code_candidates[candidate_id].line_start
            if line_start is None:
                line_start = _extract_line_from_location(raw.location)
            if line_start is None:
                stats.reject(f"第 {index + 1} 条缺少可用行号")
                continue
            line_end = raw.line_end if raw.line_end is not None else line_start
            try:
                line_start = int(line_start)
                line_end = int(line_end)
            except (TypeError, ValueError):
                stats.reject(f"第 {index + 1} 条行号非法")
                continue
            if not (1 <= line_start <= len(parsed.lines)) or not (
                1 <= line_end <= len(parsed.lines)
            ):
                stats.reject(f"第 {index + 1} 条行号越界")
                continue
            if line_end < line_start:
                line_end = line_start
            verified = _code_evidence_verified(raw.evidence, line_start, line_end, parsed)
            if not verified:
                stats.reject(f"第 {index + 1} 条证据无法在代码中逐字回验")
                continue
            location = raw.location or f"{parsed.filename}:{line_start}"
            valid.append(
                ValidFinding(
                    raw=raw,
                    evidence_verified=True,
                    line_start=line_start,
                    line_end=line_end,
                    location=location,
                    candidate_id=candidate_id,
                )
            )
        else:
            assert request is not None
            param = None
            if candidate_id and candidate_id in request_candidates:
                candidate = request_candidates[candidate_id]
                param = _find_param(request, f"{candidate.location}.{candidate.name}")
            if param is None:
                param = _find_param(request, raw.location)
            if param is None:
                param = _find_param_by_evidence(request, raw.evidence)
            if param is None:
                stats.reject(f"第 {index + 1} 条无法定位到请求参数")
                continue
            values = _param_values(param)
            if not _evidence_in_values(raw.evidence, values):
                stats.reject(f"第 {index + 1} 条证据无法在参数值中回验")
                continue
            location = raw.location or f"{param.location}.{param.name}"
            if _find_param(request, location) is None:
                location = f"{param.location}.{param.name}"
            raw.line_start = None
            raw.line_end = None
            valid.append(
                ValidFinding(
                    raw=raw,
                    evidence_verified=True,
                    line_start=None,
                    line_end=None,
                    location=location,
                    candidate_id=candidate_id,
                )
            )
        stats.accepted += 1

    suspicious: list[dict] = []
    raw_suspicious = data.get("suspicious_content", [])
    if isinstance(raw_suspicious, list):
        for item in raw_suspicious[:30]:
            if not isinstance(item, dict):
                continue
            try:
                entry = SuspiciousContent.model_validate(item)
            except ValidationError:
                continue
            quote = entry.quote.strip()
            if not quote:
                continue
            line = entry.line
            if line is not None and parsed is not None and not (1 <= int(line) <= len(parsed.lines)):
                line = None
            suspicious.append(
                {
                    "type": "PROMPT_INJECTION",
                    "line": int(line) if line is not None else None,
                    "quote": quote[:300],
                    "reason": (entry.reason or "模型标记的可疑内容")[:300],
                }
            )
    return valid, suspicious, stats
