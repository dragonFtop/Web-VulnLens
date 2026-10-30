from __future__ import annotations

from dataclasses import dataclass, field

from app.core.parser.code_parser import format_numbered

VULN_TYPES = ("SQL_INJECTION", "XSS", "COMMAND_INJECTION")
VULN_DISPLAY = {
    "SQL_INJECTION": "SQL 注入",
    "XSS": "XSS",
    "COMMAND_INJECTION": "命令执行",
}
CWE_BY_TYPE = {
    "SQL_INJECTION": "CWE-89",
    "XSS": "CWE-79",
    "COMMAND_INJECTION": "CWE-78",
}
SEVERITY_BASE = {"COMMAND_INJECTION": 3, "SQL_INJECTION": 3, "XSS": 2}
RISK_PRIORITY = {"COMMAND_INJECTION": 0, "SQL_INJECTION": 1, "XSS": 2}


@dataclass
class Candidate:
    id: str
    vuln_hint: str
    language: str
    rule_id: str
    line_start: int
    line_end: int
    evidence: str
    function_name: str | None = None
    safe_patterns: list[str] = field(default_factory=list)
    notes: str = ""
    function_line_start: int | None = None
    function_line_end: int | None = None

    def to_prompt_dict(self) -> dict:
        payload = {
            "candidate_id": self.id,
            "rule_id": self.rule_id,
            "vuln_hint": self.vuln_hint,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "function": self.function_name,
            "safe_patterns": self.safe_patterns,
            "notes": self.notes,
        }
        return payload


@dataclass
class RequestCandidate:
    id: str
    vuln_hint: str
    location: str
    name: str
    original_value: str
    variants: list[dict]
    decode_chain: list[str]
    matched_rules: list[str]
    notes: str = ""

    def to_prompt_dict(self) -> dict:
        return {
            "candidate_id": self.id,
            "vuln_hint": self.vuln_hint,
            "location": f"{self.location}.{self.name}",
            "original_value": self.original_value,
            "variants": self.variants,
            "decode_chain": self.decode_chain,
            "matched_rules": self.matched_rules,
            "notes": self.notes,
        }


def context_range(candidate: Candidate, total_lines: int) -> tuple[int, int]:
    if (
        candidate.function_line_start
        and candidate.function_line_end
        and candidate.function_line_end - candidate.function_line_start + 1 <= 120
    ):
        start = candidate.function_line_start
        end = candidate.function_line_end
    else:
        start = candidate.line_start - 15
        end = candidate.line_end + 15
    start = max(1, start)
    end = min(total_lines, end)
    if end - start + 1 > 60:
        center = candidate.line_start
        start = max(1, center - 30)
        end = min(total_lines, start + 59)
    return start, end


def merge_contexts(
    candidates: list[Candidate],
    lines: list[str],
    max_chars: int,
) -> tuple[str, bool]:
    ranges = [context_range(candidate, len(lines)) for candidate in candidates]
    ranges.sort()
    merged: list[list[int]] = []
    for start, end in ranges:
        if merged and start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])

    chunks: list[str] = []
    truncated = False
    for start, end in merged:
        chunk = format_numbered(lines, start, end)
        if chunks:
            chunk = f"... (省略) ...\n{chunk}"
        chunks.append(chunk)
        if sum(len(part) for part in chunks) > max_chars:
            truncated = True
            break
    text = "\n... (省略) ...\n".join(chunks)
    if len(text) > max_chars:
        text = text[:max_chars]
        truncated = True
    return text, truncated


def number_full_text(lines: list[str], max_chars: int) -> tuple[str, bool]:
    text = "\n".join(f"{i + 1} | {line}" for i, line in enumerate(lines))
    if len(text) > max_chars:
        return text[:max_chars], True
    return text, False


def sort_and_limit(candidates: list[Candidate], limit: int) -> tuple[list[Candidate], bool]:
    ordered = sorted(
        candidates,
        key=lambda c: (RISK_PRIORITY.get(c.vuln_hint, 9), c.line_start, c.rule_id),
    )
    return ordered[:limit], len(ordered) > limit


def assign_candidate_ids(candidates: list[Candidate]) -> None:
    for index, candidate in enumerate(candidates, start=1):
        candidate.id = f"C{index}"
