from __future__ import annotations

from app.core.extractor.candidates import (
    CWE_BY_TYPE,
    SEVERITY_BASE,
    VULN_DISPLAY,
    Candidate,
    RequestCandidate,
)
from app.core.llm.validate import ValidFinding

CHANNEL_BASE_CONFIDENCE = {"both": 0.90, "llm": 0.60, "rule": 0.35}
CHANNEL_RANK = {"both": 0, "llm": 1, "rule": 2}
SEVERITY_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

FALLBACK_SUGGESTIONS = {
    "SQL_INJECTION": "改用参数化查询（占位符 + 独立参数绑定），禁止将用户输入拼接到 SQL 文本。",
    "XSS": "根据输出上下文进行编码（HTML 转义、属性编码、JSON 编码），或使用白名单清洗富文本。",
    "COMMAND_INJECTION": "避免拼接 shell 命令；使用参数列表调用、固定白名单，并校验参数类型与取值。",
}


def compute_severity(vuln_type: str, factors: dict) -> str:
    score = SEVERITY_BASE.get(vuln_type, 2)
    controllable = factors.get("input_controllable")
    if controllable is True:
        score += 2
    elif controllable is None:
        score += 1
    if factors.get("auth_required") is True:
        score -= 1
    if factors.get("sanitized") is True:
        score -= 1
    if score >= 5:
        return "HIGH"
    if score >= 3:
        return "MEDIUM"
    return "LOW"


def compute_confidence(channel: str, evidence_verified: bool, llm_confidence: float | None) -> float:
    value = CHANNEL_BASE_CONFIDENCE.get(channel, 0.35)
    if evidence_verified:
        value += 0.05
    if llm_confidence is not None:
        value += max(-0.05, min(0.05, (llm_confidence - 0.5) * 0.1))
    return round(min(max(value, 0.30), 0.99), 2)


def _ranges_close(start_a: int, end_a: int, start_b: int, end_b: int) -> bool:
    if start_a <= end_b and start_b <= end_a:
        return True
    return min(abs(start_a - start_b), abs(start_a - end_b)) <= 2


def _match_candidate(
    finding: ValidFinding, candidates: list[Candidate]
) -> Candidate | None:
    raw = finding.raw
    by_id = {candidate.id: candidate for candidate in candidates}
    if finding.candidate_id and finding.candidate_id in by_id:
        candidate = by_id[finding.candidate_id]
        if candidate.vuln_hint == raw.vuln_type:
            return candidate
    line_start = finding.line_start
    line_end = finding.line_end or line_start
    if line_start is None:
        return None
    for candidate in candidates:
        if candidate.vuln_hint != raw.vuln_type:
            continue
        if _ranges_close(candidate.line_start, candidate.line_end, line_start, line_end):
            return candidate
    return None


def _match_request_candidate(
    finding: ValidFinding, candidates: list[RequestCandidate]
) -> RequestCandidate | None:
    raw = finding.raw
    by_id = {candidate.id: candidate for candidate in candidates}
    if finding.candidate_id and finding.candidate_id in by_id:
        candidate = by_id[finding.candidate_id]
        if candidate.vuln_hint == raw.vuln_type:
            return candidate
    location = finding.location
    for candidate in candidates:
        if candidate.vuln_hint != raw.vuln_type:
            continue
        if f"{candidate.location}.{candidate.name}" == location:
            return candidate
    return None


def _dedupe_confirmed(items: list[dict], request_mode: bool) -> list[dict]:
    items.sort(
        key=lambda item: (
            CHANNEL_RANK.get(item["source_channel"], 9),
            -float(item.get("confidence") or 0),
            SEVERITY_RANK.get(item["severity"], 9),
        )
    )
    result: list[dict] = []
    for item in items:
        duplicate = False
        for existing in result:
            if existing["vuln_type"] != item["vuln_type"]:
                continue
            if request_mode:
                if existing["location"] == item["location"]:
                    duplicate = True
                    break
            else:
                a_start = existing.get("line_start") or 0
                a_end = existing.get("line_end") or a_start
                b_start = item.get("line_start") or 0
                b_end = item.get("line_end") or b_start
                if _ranges_close(a_start, a_end, b_start, b_end):
                    duplicate = True
                    break
        if not duplicate:
            result.append(item)
    return result


def merge_results(
    *,
    valid_findings: list[ValidFinding],
    candidates: list[Candidate] | list[RequestCandidate],
    knowledge_by_candidate: dict[str, list[dict]],
    knowledge_by_type: dict[str, list[dict]],
    allowed_knowledge_ids: set[str],
    filename: str,
    language: str,
    use_candidates: bool,
    request_mode: bool = False,
) -> list[dict]:
    confirmed: list[dict] = []
    matched_candidate_ids: set[str] = set()
    code_candidates = [c for c in candidates if isinstance(c, Candidate)]
    request_candidates = [c for c in candidates if isinstance(c, RequestCandidate)]

    for finding in valid_findings:
        raw = finding.raw
        if request_mode:
            candidate = _match_request_candidate(finding, request_candidates)
        else:
            candidate = _match_candidate(finding, code_candidates)
        channel = "both" if candidate else "llm"
        if candidate:
            matched_candidate_ids.add(candidate.id)
            if request_mode:
                rule_id = candidate.matched_rules[0] if candidate.matched_rules else None
            else:
                rule_id = candidate.rule_id
            knowledge = list(knowledge_by_candidate.get(candidate.id, []))
        else:
            rule_id = None
            knowledge = list(knowledge_by_type.get(raw.vuln_type, []))
        for knowledge_id in raw.knowledge_ids:
            if knowledge_id in allowed_knowledge_ids and all(
                entry.get("id") != knowledge_id for entry in knowledge
            ):
                for entries in knowledge_by_type.values():
                    for entry in entries:
                        if entry.get("id") == knowledge_id:
                            knowledge.append(entry)
                            break
        factors = raw.factors.model_dump()
        severity = compute_severity(raw.vuln_type, factors)
        confidence = compute_confidence(channel, finding.evidence_verified, raw.confidence)
        if request_mode:
            location = finding.location
            line_start = None
            line_end = None
            location_type = "param"
        else:
            line_start = finding.line_start
            line_end = finding.line_end or line_start
            location = f"{filename}:{line_start}"
            location_type = "line"
        confirmed.append(
            {
                "vuln_type": raw.vuln_type,
                "severity": severity,
                "confidence": confidence,
                "location_type": location_type,
                "location": location,
                "line_start": line_start,
                "line_end": line_end,
                "rule_id": rule_id,
                "cwe_id": raw.cwe_id or CWE_BY_TYPE.get(raw.vuln_type),
                "evidence": raw.evidence,
                "description": raw.description
                or f"检测到疑似{VULN_DISPLAY.get(raw.vuln_type, raw.vuln_type)}风险，"
                "用户可控数据到达危险操作。",
                "suggestion": raw.suggestion or FALLBACK_SUGGESTIONS.get(raw.vuln_type, ""),
                "source_channel": channel,
                "knowledge": knowledge[:5],
                "factors": factors,
                "raw": raw.model_dump(),
            }
        )

    confirmed = _dedupe_confirmed(confirmed, request_mode)

    clues: list[dict] = []
    if use_candidates:
        if request_mode:
            unmatched = [
                c for c in request_candidates if c.id not in matched_candidate_ids
            ]
            unmatched.sort(key=lambda c: (VULN_DISPLAY.get(c.vuln_hint, ""), c.location, c.name))
        else:
            unmatched = [c for c in code_candidates if c.id not in matched_candidate_ids]
            unmatched.sort(key=lambda c: (c.line_start, c.rule_id))

        clue_seen: set[tuple[str, object]] = set()
        for candidate in unmatched:
            if request_mode:
                location = f"{candidate.location}.{candidate.name}"
                clue_key: tuple[str, object] = (candidate.vuln_hint, location)
                line_start = line_end = None
                location_type = "param"
                evidence = candidate.original_value
                candidate_id = candidate.id
                clue_rule_id = (
                    candidate.matched_rules[0] if candidate.matched_rules else ""
                )
                safe_patterns: list[str] = []
            else:
                location = f"{filename}:{candidate.line_start}"
                clue_key = (candidate.vuln_hint, candidate.line_start)
                line_start = candidate.line_start
                line_end = candidate.line_end
                location_type = "line"
                evidence = candidate.evidence
                candidate_id = candidate.id
                clue_rule_id = candidate.rule_id
                safe_patterns = list(candidate.safe_patterns)
            if clue_key in clue_seen:
                continue
            clue_seen.add(clue_key)
            factors = {
                "input_controllable": None,
                "auth_required": None,
                "sanitized": bool(safe_patterns),
                "reason": "规则候选未经 LLM 确认，仅作待复核线索",
            }
            severity = compute_severity(candidate.vuln_hint, factors)
            caution = (
                f"；规则识别到的安全写法：{'、'.join(safe_patterns)}"
                if safe_patterns
                else ""
            )
            knowledge = list(knowledge_by_candidate.get(candidate_id, []))
            clues.append(
                {
                    "vuln_type": candidate.vuln_hint,
                    "severity": severity,
                    "confidence": compute_confidence("rule", True, None),
                    "location_type": location_type,
                    "location": location,
                    "line_start": line_start,
                    "line_end": line_end,
                    "rule_id": clue_rule_id,
                    "cwe_id": CWE_BY_TYPE.get(candidate.vuln_hint),
                    "evidence": evidence,
                    "description": (
                        f"规则 {clue_rule_id} 命中候选，但模型未确认其为漏洞，"
                        f"作为待复核线索展示{caution}。"
                    ),
                    "suggestion": FALLBACK_SUGGESTIONS.get(candidate.vuln_hint, "请人工复核该位置。"),
                    "source_channel": "rule",
                    "knowledge": knowledge[:5],
                    "factors": factors,
                    "raw": {
                        "rule_only": True,
                        "rule_id": clue_rule_id,
                        "safe_patterns": safe_patterns,
                        "notes": candidate.notes,
                    },
                }
            )

    all_items = confirmed + clues
    all_items.sort(
        key=lambda item: (
            SEVERITY_RANK.get(item["severity"], 9),
            CHANNEL_RANK.get(item["source_channel"], 9),
            item.get("line_start") or 0,
            item.get("location") or "",
        )
    )
    return all_items
