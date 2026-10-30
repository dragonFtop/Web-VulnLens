from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from app import config
from app.core.extractor.candidates import (
    RISK_PRIORITY,
    Candidate,
    RequestCandidate,
    assign_candidate_ids,
    context_range,
    merge_contexts,
    number_full_text,
    sort_and_limit,
)
from app.core.extractor.rule_engine import extract_candidates, extract_http_candidates
from app.core.knowledge.retriever import get_retriever
from app.core.llm import guard
from app.core.llm.client import LLMClient, Usage
from app.core.llm.prompts import build_detect_messages, build_recheck_messages
from app.core.llm.validate import ValidationStats, ValidFinding, validate_findings
from app.core.parser.code_parser import ParsedCode, parse_code
from app.core.parser.http_parser import ParsedRequest, parse_http_request, request_context_text
from app.core.util import new_id, now_utc, safe_join
from app.db import repository
from app.errors import LLM_AUTH, LLM_RATE_LIMIT, AppError, LLMError
from app.services.postprocess import merge_results

logger = logging.getLogger(__name__)

StageCallback = Callable[[str], None]


@dataclass
class ScanOptions:
    use_candidates: bool = True
    use_knowledge: bool = True
    use_guard: bool = True
    use_cache: bool | None = None
    max_candidates: int | None = None

    @classmethod
    def full(cls) -> "ScanOptions":
        return cls()

    @classmethod
    def baseline(cls) -> "ScanOptions":
        return cls(use_candidates=False, use_knowledge=False, use_guard=False)

    @classmethod
    def window_only(cls) -> "ScanOptions":
        return cls(use_candidates=True, use_knowledge=False, use_guard=False)

    @classmethod
    def knowledge(cls) -> "ScanOptions":
        return cls(use_candidates=True, use_knowledge=True, use_guard=False)


@dataclass
class ScanResult:
    findings: list[dict] = field(default_factory=list)
    suspicious: list[dict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    usage: Usage = field(default_factory=Usage)
    llm_output_invalid: bool = False
    degraded: bool = False
    cached: bool = False
    duration_ms: int = 0
    candidate_count: int = 0
    validation_reasons: list[str] = field(default_factory=list)
    parse_error: str | None = None
    notes: str | None = None
    language: str = ""
    filename: str = ""

    def finalize_summary(self) -> None:
        summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "rule_only": 0}
        for finding in self.findings:
            if finding.get("source_channel") == "rule":
                summary["rule_only"] += 1
            else:
                summary[finding.get("severity", "LOW")] += 1
        self.summary = summary


def _sort_request_candidates(
    candidates: list[RequestCandidate], limit: int
) -> tuple[list[RequestCandidate], bool]:
    ordered = sorted(
        candidates,
        key=lambda c: (
            RISK_PRIORITY.get(c.vuln_hint, 9),
            c.location,
            c.name,
            c.matched_rules[0] if c.matched_rules else "",
        ),
    )
    return ordered[:limit], len(ordered) > limit


class ScanService:
    def __init__(
        self,
        settings: config.Settings | None = None,
        client: LLMClient | None = None,
        retriever=None,
    ) -> None:
        self.settings = settings or config.settings
        self.client = client or LLMClient(self.settings)
        self.retriever = retriever or get_retriever()

    # ------------------------------------------------------------- knowledge
    def _retrieve_knowledge(
        self,
        vuln_types: list[str],
        language: str,
        queries: dict[str, str],
        use_knowledge: bool,
    ) -> tuple[dict[str, list[dict]], dict[str, list[dict]], set[str], list[dict]]:
        by_type: dict[str, list[dict]] = {}
        by_candidate: dict[str, list[dict]] = {}
        allowed: set[str] = set()
        prompt_entries: list[dict] = []
        if not use_knowledge:
            return by_candidate, by_type, allowed, prompt_entries
        for vuln_type in vuln_types:
            entries = self.retriever.retrieve(
                vuln_type,
                language,
                queries.get(vuln_type, ""),
                self.settings.kb_top_k,
            )
            public = [entry.to_public_dict() for entry in entries]
            by_type[vuln_type] = public
            for entry in public:
                allowed.add(entry["id"])
                if all(item["id"] != entry["id"] for item in prompt_entries):
                    prompt_entries.append(entry)
        return by_candidate, by_type, allowed, prompt_entries

    def _knowledge_for_code(
        self, candidates: list[Candidate], parsed: ParsedCode, use_knowledge: bool
    ) -> tuple[dict[str, list[dict]], dict[str, list[dict]], set[str], list[dict]]:
        types: list[str] = []
        queries: dict[str, str] = {}
        for candidate in candidates:
            if candidate.vuln_hint not in types:
                types.append(candidate.vuln_hint)
                queries[candidate.vuln_hint] = ""
            queries[candidate.vuln_hint] += " " + " ".join(
                [candidate.rule_id, candidate.evidence, candidate.notes]
                + candidate.safe_patterns
            )
        if use_knowledge and not types:
            types = ["SQL_INJECTION", "XSS", "COMMAND_INJECTION"]
            queries = {vuln_type: parsed.language for vuln_type in types}
        by_candidate, by_type, allowed, prompt_entries = self._retrieve_knowledge(
            types, parsed.language, queries, use_knowledge
        )
        for candidate in candidates:
            by_candidate[candidate.id] = list(by_type.get(candidate.vuln_hint, []))
        return by_candidate, by_type, allowed, prompt_entries

    def _knowledge_for_request(
        self, candidates: list[RequestCandidate], request: ParsedRequest, use_knowledge: bool
    ) -> tuple[dict[str, list[dict]], dict[str, list[dict]], set[str], list[dict]]:
        types: list[str] = []
        queries: dict[str, str] = {}
        for candidate in candidates:
            if candidate.vuln_hint not in types:
                types.append(candidate.vuln_hint)
                queries[candidate.vuln_hint] = ""
            queries[candidate.vuln_hint] += " " + " ".join(
                [candidate.notes, candidate.original_value, " ".join(candidate.matched_rules)]
            )
        if use_knowledge and not types:
            types = ["SQL_INJECTION", "XSS", "COMMAND_INJECTION"]
            queries = {vuln_type: "http request" for vuln_type in types}
        by_candidate, by_type, allowed, prompt_entries = self._retrieve_knowledge(
            types, "http", queries, use_knowledge
        )
        for candidate in candidates:
            by_candidate[candidate.id] = list(by_type.get(candidate.vuln_hint, []))
        return by_candidate, by_type, allowed, prompt_entries

    # ----------------------------------------------------------------- utils
    @staticmethod
    def _suspicious_for_request(request: ParsedRequest) -> list[dict]:
        from app.core.parser.http_parser import decode_value

        items = guard.scan_text(request.raw)
        for param in request.params:
            decoded = decode_value(param.original_value)
            for variant in decoded.variants:
                if variant["label"] == "原始值":
                    continue
                items.extend(
                    guard.scan_value(
                        variant["value"],
                        context=f"{param.location}.{param.name}",
                    )
                )
        return guard.merge_suspicious(items)

    def _build_result(
        self,
        *,
        findings: list[dict],
        suspicious: list[dict],
        usage: Usage,
        started: float,
        candidate_count: int,
        invalid: bool,
        degraded: bool,
        validation_reasons: list[str],
        parse_error: str | None,
        notes: str | None,
        language: str,
        filename: str,
    ) -> ScanResult:
        result = ScanResult(
            findings=findings,
            suspicious=suspicious,
            usage=usage,
            llm_output_invalid=invalid,
            degraded=degraded,
            cached=usage.cached,
            duration_ms=int((time.perf_counter() - started) * 1000),
            candidate_count=candidate_count,
            validation_reasons=validation_reasons,
            parse_error=parse_error,
            notes=notes,
            language=language,
            filename=filename,
        )
        result.finalize_summary()
        return result

    def _degraded_result(
        self,
        *,
        candidates,
        knowledge_by_candidate,
        knowledge_by_type,
        allowed_ids,
        filename: str,
        language: str,
        request_mode: bool,
        options: ScanOptions,
        suspicious: list[dict],
        usage: Usage,
        started: float,
        invalid_reason: str,
    ) -> ScanResult:
        findings = merge_results(
            valid_findings=[],
            candidates=candidates,
            knowledge_by_candidate=knowledge_by_candidate,
            knowledge_by_type=knowledge_by_type,
            allowed_knowledge_ids=allowed_ids,
            filename=filename,
            language=language,
            use_candidates=options.use_candidates,
            request_mode=request_mode,
        )
        for finding in findings:
            finding["id"] = new_id("v")
        return self._build_result(
            findings=findings,
            suspicious=suspicious,
            usage=usage,
            started=started,
            candidate_count=len(candidates),
            invalid=True,
            degraded=True,
            validation_reasons=[invalid_reason],
            parse_error=None,
            notes="LLM 调用异常，已降级为规则候选结果，仅供人工复核。",
            language=language,
            filename=filename,
        )

    # ------------------------------------------------------------ code scan
    def analyze_code(
        self,
        parsed: ParsedCode,
        options: ScanOptions | None = None,
        *,
        job_id: str = "",
        on_stage: StageCallback | None = None,
    ) -> ScanResult:
        options = options or ScanOptions.full()
        started = time.perf_counter()
        stage = on_stage or (lambda _stage: None)
        stage("EXTRACTING")
        candidates: list[Candidate] = []
        parse_error = None
        if options.use_candidates:
            candidates, parse_error = extract_candidates(parsed)
            limit = options.max_candidates or self.settings.max_candidates
            candidates, truncated_limit = sort_and_limit(candidates, limit)
            assign_candidate_ids(candidates)
        else:
            truncated_limit = False

        max_chars = self.settings.max_llm_code_chars
        if candidates:
            data_text, truncated = merge_contexts(candidates, parsed.lines, max_chars)
        else:
            data_text, truncated = number_full_text(parsed.lines, max_chars)
        if truncated_limit:
            data_text += "\n...(候选点超过上限，已截断)"

        stage("RETRIEVING")
        knowledge_by_candidate, knowledge_by_type, allowed_ids, prompt_knowledge = (
            self._knowledge_for_code(candidates, parsed, options.use_knowledge)
        )

        guard_suspicious = guard.scan_text(parsed.text) if options.use_guard else []
        stage("LLM_ANALYZING")
        messages = build_detect_messages(
            data_text=data_text,
            target_kind="code",
            candidates=[candidate.to_prompt_dict() for candidate in candidates],
            knowledge=prompt_knowledge,
            use_candidates=options.use_candidates,
            use_knowledge=options.use_knowledge,
            use_guard=options.use_guard,
            filename=parsed.filename,
            language=parsed.language,
            truncated=truncated,
        )
        usage = Usage()
        try:
            data, call_usage = self.client.chat_json(
                messages,
                max_tokens=4096,
                use_cache=options.use_cache,
                job_id=job_id,
            )
            usage.merge(call_usage)
        except LLMError as exc:
            if exc.code in {LLM_AUTH, LLM_RATE_LIMIT}:
                raise
            logger.warning("扫描降级 job=%s code=%s", job_id or "-", exc.code)
            return self._degraded_result(
                candidates=candidates,
                knowledge_by_candidate=knowledge_by_candidate,
                knowledge_by_type=knowledge_by_type,
                allowed_ids=allowed_ids,
                filename=parsed.filename,
                language=parsed.language,
                request_mode=False,
                options=options,
                suspicious=guard_suspicious,
                usage=usage,
                started=started,
                invalid_reason=f"{exc.code}: {exc.message}",
            )

        stage("POSTPROCESSING")
        valid, model_suspicious, stats = validate_findings(
            data, parsed=parsed, request=None, candidates=candidates
        )
        suspicious = (
            guard.merge_suspicious(guard_suspicious, model_suspicious)
            if options.use_guard
            else []
        )
        recheck_enabled = options.use_guard and (
            self.settings.guard_recheck if options.use_guard else False
        )
        if recheck_enabled and suspicious:
            stage("LLM_ANALYZING")
            try:
                recheck_data, recheck_usage = self.client.chat_json(
                    build_recheck_messages(messages),
                    max_tokens=4096,
                    use_cache=options.use_cache,
                    job_id=job_id,
                )
                usage.merge(recheck_usage)
                recheck_valid, recheck_suspicious, recheck_stats = validate_findings(
                    recheck_data, parsed=parsed, request=None, candidates=candidates
                )
                suspicious = guard.merge_suspicious(suspicious, recheck_suspicious)
                valid = self._merge_valid(valid, recheck_valid)
                stats = self._merge_stats(stats, recheck_stats)
            except LLMError as exc:
                logger.warning("注入独立复核失败 job=%s code=%s", job_id or "-", exc.code)
                recheck_enabled = False
        stage("POSTPROCESSING")
        findings = merge_results(
            valid_findings=valid,
            candidates=candidates,
            knowledge_by_candidate=knowledge_by_candidate,
            knowledge_by_type=knowledge_by_type,
            allowed_knowledge_ids=allowed_ids,
            filename=parsed.filename,
            language=parsed.language,
            use_candidates=options.use_candidates,
            request_mode=False,
        )
        for finding in findings:
            finding["id"] = new_id("v")
        result = self._build_result(
            findings=findings,
            suspicious=suspicious,
            usage=usage,
            started=started,
            candidate_count=len(candidates),
            invalid=stats.top_level_invalid,
            degraded=False,
            validation_reasons=stats.reasons,
            parse_error=parse_error,
            notes=(
                "检测到疑似提示注入内容，已隔离并保留原文供复核。"
                if suspicious
                else None
            ),
            language=parsed.language,
            filename=parsed.filename,
        )
        return result

    # ------------------------------------------------------------ http scan
    def analyze_http(
        self,
        request: ParsedRequest,
        options: ScanOptions | None = None,
        *,
        filename: str = "request.http",
        job_id: str = "",
        on_stage: StageCallback | None = None,
    ) -> ScanResult:
        options = options or ScanOptions.full()
        started = time.perf_counter()
        stage = on_stage or (lambda _stage: None)
        stage("EXTRACTING")
        candidates: list[RequestCandidate] = []
        if options.use_candidates:
            candidates = extract_http_candidates(request)
            limit = options.max_candidates or self.settings.max_candidates
            candidates, truncated_limit = _sort_request_candidates(candidates, limit)
            assign_candidate_ids(candidates)
        else:
            truncated_limit = False

        stage("RETRIEVING")
        data_text = request_context_text(request, self.settings.max_llm_code_chars)
        knowledge_by_candidate, knowledge_by_type, allowed_ids, prompt_knowledge = (
            self._knowledge_for_request(candidates, request, options.use_knowledge)
        )
        candidate_payload = []
        for candidate in candidates:
            payload = candidate.to_prompt_dict()
            payload["original_value"] = candidate.original_value[:500]
            payload["variants"] = [
                {"label": item["label"], "value": item["value"][:500]}
                for item in candidate.variants[-5:]
            ]
            candidate_payload.append(payload)

        guard_suspicious = self._suspicious_for_request(request) if options.use_guard else []
        stage("LLM_ANALYZING")
        messages = build_detect_messages(
            data_text=data_text,
            target_kind="http",
            candidates=candidate_payload,
            knowledge=prompt_knowledge,
            use_candidates=options.use_candidates,
            use_knowledge=options.use_knowledge,
            use_guard=options.use_guard,
            filename=filename,
            language="http",
            truncated=truncated_limit,
        )
        usage = Usage()
        try:
            data, call_usage = self.client.chat_json(
                messages,
                max_tokens=4096,
                use_cache=options.use_cache,
                job_id=job_id,
            )
            usage.merge(call_usage)
        except LLMError as exc:
            if exc.code in {LLM_AUTH, LLM_RATE_LIMIT}:
                raise
            logger.warning("HTTP 扫描降级 job=%s code=%s", job_id or "-", exc.code)
            return self._degraded_result(
                candidates=candidates,
                knowledge_by_candidate=knowledge_by_candidate,
                knowledge_by_type=knowledge_by_type,
                allowed_ids=allowed_ids,
                filename=filename,
                language="http",
                request_mode=True,
                options=options,
                suspicious=guard_suspicious,
                usage=usage,
                started=started,
                invalid_reason=f"{exc.code}: {exc.message}",
            )

        stage("POSTPROCESSING")
        valid, model_suspicious, stats = validate_findings(
            data, parsed=None, request=request, candidates=candidates
        )
        suspicious = (
            guard.merge_suspicious(guard_suspicious, model_suspicious)
            if options.use_guard
            else []
        )
        if options.use_guard and self.settings.guard_recheck and suspicious:
            stage("LLM_ANALYZING")
            try:
                recheck_data, recheck_usage = self.client.chat_json(
                    build_recheck_messages(messages),
                    max_tokens=4096,
                    use_cache=options.use_cache,
                    job_id=job_id,
                )
                usage.merge(recheck_usage)
                recheck_valid, recheck_suspicious, recheck_stats = validate_findings(
                    recheck_data, parsed=None, request=request, candidates=candidates
                )
                suspicious = guard.merge_suspicious(suspicious, recheck_suspicious)
                valid = self._merge_valid(valid, recheck_valid)
                stats = self._merge_stats(stats, recheck_stats)
            except LLMError as exc:
                logger.warning("HTTP 注入独立复核失败 job=%s code=%s", job_id or "-", exc.code)
        stage("POSTPROCESSING")
        findings = merge_results(
            valid_findings=valid,
            candidates=candidates,
            knowledge_by_candidate=knowledge_by_candidate,
            knowledge_by_type=knowledge_by_type,
            allowed_knowledge_ids=allowed_ids,
            filename=filename,
            language="http",
            use_candidates=options.use_candidates,
            request_mode=True,
        )
        for finding in findings:
            finding["id"] = new_id("v")
        return self._build_result(
            findings=findings,
            suspicious=suspicious,
            usage=usage,
            started=started,
            candidate_count=len(candidates),
            invalid=stats.top_level_invalid,
            degraded=False,
            validation_reasons=stats.reasons,
            parse_error=None,
            notes=(
                "检测到疑似提示注入内容，已隔离并保留原文供复核。"
                if suspicious
                else None
            ),
            language="http",
            filename=filename,
        )

    @staticmethod
    def _merge_valid(first: list[ValidFinding], second: list[ValidFinding]) -> list[ValidFinding]:
        merged = list(first)
        seen = {
            (
                item.raw.vuln_type,
                item.line_start,
                item.location,
                item.raw.evidence.strip(),
            )
            for item in first
        }
        for item in second:
            key = (
                item.raw.vuln_type,
                item.line_start,
                item.location,
                item.raw.evidence.strip(),
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(item)
        return merged

    @staticmethod
    def _merge_stats(first: ValidationStats, second: ValidationStats) -> ValidationStats:
        return ValidationStats(
            raw_count=first.raw_count + second.raw_count,
            accepted=first.accepted + second.accepted,
            rejected=first.rejected + second.rejected,
            reasons=(first.reasons + second.reasons)[:20],
            top_level_invalid=first.top_level_invalid or second.top_level_invalid,
        )

    # -------------------------------------------------------------- run jobs
    def run(self, job_id: str) -> None:
        job = repository.get_job(job_id)
        if not job:
            logger.error("扫描任务不存在 job=%s", job_id)
            return
        started = time.perf_counter()
        repository.update_job(job_id, status="RUNNING", stage="PARSING", error=None)
        try:
            upload = repository.get_upload(job.get("input_ref") or "")
            if not upload:
                raise AppError("E_NOT_FOUND", "上传文件记录不存在", 404)
            stored = safe_join(self.settings.uploads_dir, upload["stored_name"])
            if not stored.is_file():
                raise AppError("E_NOT_FOUND", "上传文件已丢失，请重新上传", 404)
            data = stored.read_bytes()

            if job["input_type"] == "code":
                parsed = parse_code(data, upload["filename"])
                repository.update_job(job_id, language=parsed.language, filename=parsed.filename)
                result = self.analyze_code(
                    parsed,
                    ScanOptions.full(),
                    job_id=job_id,
                    on_stage=lambda stage: repository.update_job(job_id, stage=stage),
                )
                filename = parsed.filename
            else:
                request = parse_http_request(data)
                body_kb = len(request.body.encode("utf-8", errors="replace")) / 1024
                if body_kb > self.settings.max_http_body_kb:
                    raise AppError(
                        "E_INPUT_FORMAT",
                        f"请求 body 超过 {self.settings.max_http_body_kb}KB 限制",
                        400,
                    )
                result = self.analyze_http(
                    request,
                    ScanOptions.full(),
                    filename=upload["filename"] or "request.http",
                    job_id=job_id,
                    on_stage=lambda stage: repository.update_job(job_id, stage=stage),
                )
                repository.update_job(job_id, language="http", filename=upload["filename"])

            repository.save_findings(job_id, result.findings)
            duration = int((time.perf_counter() - started) * 1000)
            repository.update_job(
                job_id,
                status="DONE",
                stage="FINISHED",
                prompt_tokens=result.usage.prompt_tokens,
                completion_tokens=result.usage.completion_tokens,
                duration_ms=duration,
                llm_output_invalid=int(result.llm_output_invalid),
                cached=int(result.cached),
                suspicious_json=json.dumps(result.suspicious, ensure_ascii=False),
                error=None,
            )
            logger.info(
                "扫描完成 job=%s findings=%d rule_only=%d tokens=%d/%d duration_ms=%d",
                job_id,
                len(result.findings),
                result.summary.get("rule_only", 0),
                result.usage.prompt_tokens,
                result.usage.completion_tokens,
                duration,
            )
        except LLMError as exc:
            logger.warning("扫描失败 job=%s code=%s", job_id, exc.code)
            repository.update_job(
                job_id,
                status="FAILED",
                stage=None,
                error=f"{exc.code}: {exc.message}",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        except AppError as exc:
            repository.update_job(
                job_id,
                status="FAILED",
                stage=None,
                error=f"{exc.code}: {exc.message}",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("扫描执行异常 job=%s", job_id)
            repository.update_job(
                job_id,
                status="FAILED",
                stage=None,
                error=f"E_INTERNAL: 系统内部错误（{exc.__class__.__name__}）",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )


def run_scan_job(job_id: str) -> None:
    ScanService().run(job_id)
