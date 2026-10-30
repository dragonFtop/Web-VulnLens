from __future__ import annotations

import argparse
import dataclasses
import json
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import config  # noqa: E402
from app.core.llm.prompts import PROMPT_VERSION  # noqa: E402
from app.core.parser.code_parser import parse_code  # noqa: E402
from app.core.parser.http_parser import parse_http_request  # noqa: E402
from app.errors import LLM_AUTH, LLM_RATE_LIMIT, AppError, LLMError  # noqa: E402
from app.services.scan_service import ScanOptions, ScanResult, ScanService  # noqa: E402

GROUPS = {
    "A": ("整文件基线", ScanOptions.baseline),
    "B": ("候选窗口", ScanOptions.window_only),
    "C": ("候选窗口 + 知识", ScanOptions.knowledge),
    "D": ("候选窗口 + 知识 + 注入防御", ScanOptions.full),
}
CONFIRMED_CHANNELS = {"both", "llm"}
CATEGORIES = ("code", "http", "injection")
CWE_BY_TYPE = {
    "SQL_INJECTION": "CWE-89",
    "XSS": "CWE-79",
    "COMMAND_INJECTION": "CWE-78",
}


@dataclass(frozen=True)
class Sample:
    name: str
    category: str
    input_type: str
    path: Path
    expected: dict

    @property
    def vulnerable(self) -> bool:
        return bool(self.expected.get("vulnerable"))

    @property
    def expected_findings(self) -> list[dict]:
        return list(self.expected.get("findings") or [])


@dataclass
class Outcome:
    sample: Sample
    result: ScanResult | None
    error_code: str | None = None
    error: str | None = None
    duration_ms: int = 0

    @property
    def confirmed(self) -> list[dict]:
        if not self.result:
            return []
        return [
            finding
            for finding in self.result.findings
            if finding.get("source_channel") in CONFIRMED_CHANNELS
        ]

    @property
    def rule_clues(self) -> list[dict]:
        if not self.result:
            return []
        return [
            finding
            for finding in self.result.findings
            if finding.get("source_channel") == "rule"
        ]

    @property
    def suspicious(self) -> bool:
        return bool(self.result and self.result.suspicious)


@dataclass
class MatchCount:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    matched: int = 0
    unmatched_expected: int = 0


@dataclass
class MetricBucket:
    total_samples: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    negative_samples: int = 0
    negative_false_positives: int = 0
    hard_negative_samples: int = 0
    hard_negative_false_positives: int = 0
    confirmed_findings: int = 0
    rule_clues: int = 0
    channel_counts: dict = field(
        default_factory=lambda: {"both": 0, "llm": 0, "rule": 0}
    )
    json_ok: int = 0
    json_fail: int = 0
    json_correction_samples: int = 0
    json_recovered: int = 0
    schema_invalid: int = 0
    llm_errors: int = 0
    error_counts: dict = field(default_factory=dict)
    token_samples: int = 0
    total_tokens: int = 0
    total_duration_ms: int = 0

    def finalize(self) -> dict:
        precision = _safe_div(self.tp, self.tp + self.fp)
        recall = _safe_div(self.tp, self.tp + self.fn)
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision is not None and recall is not None and precision + recall > 0
            else None
        )
        return {
            "samples": self.total_samples,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "hard_negative_fpr": _safe_div(
                self.hard_negative_false_positives, self.hard_negative_samples
            ),
            "negative_fpr": _safe_div(
                self.negative_false_positives, self.negative_samples
            ),
            "hard_negative_samples": self.hard_negative_samples,
            "negative_samples": self.negative_samples,
            "confirmed_findings": self.confirmed_findings,
            "rule_clues": self.rule_clues,
            "channel_counts": dict(self.channel_counts),
            "json_valid_rate": _safe_div(self.json_ok, self.total_samples),
            "json_ok": self.json_ok,
            "json_fail": self.json_fail,
            "json_correction_samples": self.json_correction_samples,
            "json_recovered": self.json_recovered,
            "schema_invalid": self.schema_invalid,
            "llm_errors": self.llm_errors,
            "error_counts": dict(self.error_counts),
            "avg_tokens": (
                round(self.total_tokens / self.token_samples, 1)
                if self.token_samples
                else None
            ),
            "avg_latency_ms": (
                round(self.total_duration_ms / self.total_samples, 1)
                if self.total_samples
                else None
            ),
        }


@dataclass
class InjectionBucket:
    total: int = 0
    success: int = 0
    flagged: int = 0
    vulnerable_expected: int = 0
    vulnerable_detected: int = 0
    false_positives: int = 0
    errors: int = 0

    def finalize(self) -> dict:
        return {
            "samples": self.total,
            "success": self.success,
            "resistance_rate": _safe_div(self.success, self.total),
            "suspicious_flagged": self.flagged,
            "flag_rate": _safe_div(self.flagged, self.total),
            "vulnerable_expected": self.vulnerable_expected,
            "vulnerable_detected": self.vulnerable_detected,
            "false_positives": self.false_positives,
            "errors": self.errors,
        }


def _safe_div(numerator: int, denominator: int) -> float | None:
    if not denominator:
        return None
    return numerator / denominator


def _normalize_location(value: str | None) -> str:
    text = (value or "").strip()
    for prefix in ("http.", "request."):
        if text.startswith(prefix):
            return text[len(prefix):]
    return text


def _span(item: dict) -> tuple[int, int] | None:
    try:
        start = int(item.get("line_start"))
    except (TypeError, ValueError):
        return None
    try:
        end = int(item.get("line_end") or start)
    except (TypeError, ValueError):
        end = start
    return min(start, end), max(start, end)


def finding_matches(expected: dict, predicted: dict, request_mode: bool) -> bool:
    if expected.get("vuln_type") != predicted.get("vuln_type"):
        return False
    if request_mode:
        expected_location = _normalize_location(expected.get("location"))
        predicted_location = _normalize_location(predicted.get("location"))
        return bool(expected_location) and expected_location == predicted_location
    expected_span = _span(expected)
    predicted_span = _span(predicted)
    if not expected_span or not predicted_span:
        return False
    a_start, a_end = expected_span
    b_start, b_end = predicted_span
    if a_start <= b_end and b_start <= a_end:
        return True
    return min(
        abs(a_start - b_start),
        abs(a_start - b_end),
        abs(a_end - b_start),
        abs(a_end - b_end),
    ) <= 2


def count_matches(
    expected_findings: list[dict], predicted_findings: list[dict], request_mode: bool
) -> MatchCount:
    used: set[int] = set()
    matched_expected = 0
    for expected in expected_findings:
        for index, predicted in enumerate(predicted_findings):
            if index in used:
                continue
            if finding_matches(expected, predicted, request_mode):
                used.add(index)
                matched_expected += 1
                break
    total_predicted = len(predicted_findings)
    return MatchCount(
        tp=matched_expected,
        fp=total_predicted - matched_expected,
        fn=len(expected_findings) - matched_expected,
        matched=matched_expected,
        unmatched_expected=len(expected_findings) - matched_expected,
    )


def _load_json(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_samples(
    samples_dir: Path,
    categories: tuple[str, ...],
    limit: int = 0,
) -> dict[str, list[Sample]]:
    result: dict[str, list[Sample]] = {category: [] for category in categories}

    if "code" in categories:
        code_root = samples_dir / "code"
        for expected_path in sorted(code_root.glob("*/expected.json")):
            group_dir = expected_path.parent.name
            for entry in _load_json(expected_path):
                result["code"].append(
                    Sample(
                        name=f"code/{group_dir}/{entry['file']}",
                        category="code",
                        input_type="code",
                        path=expected_path.parent / entry["file"],
                        expected=entry,
                    )
                )

    if "http" in categories:
        http_root = samples_dir / "http"
        for entry in _load_json(http_root / "expected.json"):
            result["http"].append(
                Sample(
                    name=f"http/{entry['file']}",
                    category="http",
                    input_type="http",
                    path=http_root / entry["file"],
                    expected=entry,
                )
            )

    if "injection" in categories:
        injection_root = samples_dir / "injection"
        for entry in _load_json(injection_root / "expected.json"):
            result["injection"].append(
                Sample(
                    name=f"injection/{entry['file']}",
                    category="injection",
                    input_type=entry["input_type"],
                    path=injection_root / entry["file"],
                    expected=entry,
                )
            )

    if limit > 0:
        for category in result:
            result[category] = result[category][:limit]
    return result


def parse_group_list(raw: str, field_name: str) -> list[str]:
    groups = [item.strip().upper() for item in raw.split(",") if item.strip()]
    invalid = [item for item in groups if item not in GROUPS]
    if invalid:
        raise ValueError(f"{field_name} 包含非法配置：{', '.join(invalid)}")
    return groups


def parse_category_list(raw: str) -> tuple[str, ...]:
    categories = tuple(item.strip().lower() for item in raw.split(",") if item.strip())
    invalid = [item for item in categories if item not in CATEGORIES]
    if invalid:
        raise ValueError(f"--only 包含非法类别：{', '.join(invalid)}")
    return categories or CATEGORIES


def _options_for(group: str, use_cache: bool) -> ScanOptions:
    return dataclasses.replace(GROUPS[group][1](), use_cache=use_cache)


def run_sample(
    service: ScanService, sample: Sample, options: ScanOptions
) -> Outcome:
    started = time.perf_counter()
    try:
        if sample.input_type == "code":
            parsed = parse_code(sample.path.read_bytes(), sample.path.name)
            result = service.analyze_code(parsed, options)
        else:
            request = parse_http_request(sample.path.read_bytes())
            result = service.analyze_http(
                request, options, filename=sample.path.name
            )
        return Outcome(sample=sample, result=result, duration_ms=result.duration_ms)
    except (LLMError, AppError, OSError, ValueError) as exc:
        code = getattr(exc, "code", None) or exc.__class__.__name__
        if isinstance(exc, LLMError) and exc.code in {LLM_AUTH, LLM_RATE_LIMIT}:
            raise
        return Outcome(
            sample=sample,
            result=None,
            error_code=code,
            error=getattr(exc, "message", str(exc)),
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


def _is_json_failure(outcome: Outcome) -> bool:
    if outcome.result is None:
        return True
    if outcome.result.degraded:
        return True
    return outcome.result.llm_output_invalid


def _accumulate_detection(outcomes: list[Outcome]) -> dict:
    bucket = MetricBucket()
    for outcome in outcomes:
        bucket.total_samples += 1
        bucket.total_duration_ms += outcome.duration_ms
        sample = outcome.sample
        confirmed = outcome.confirmed
        request_mode = sample.input_type == "http"
        counts = count_matches(sample.expected_findings, confirmed, request_mode)
        bucket.tp += counts.tp
        bucket.fp += counts.fp
        bucket.fn += counts.fn
        bucket.confirmed_findings += len(confirmed)
        bucket.rule_clues += len(outcome.rule_clues)
        for finding in outcome.result.findings if outcome.result else []:
            channel = finding.get("source_channel")
            if channel in bucket.channel_counts:
                bucket.channel_counts[channel] += 1

        if not sample.vulnerable:
            bucket.negative_samples += 1
            if confirmed:
                bucket.negative_false_positives += 1
            if sample.category == "code":
                bucket.hard_negative_samples += 1
                if confirmed:
                    bucket.hard_negative_false_positives += 1

        if outcome.result is not None:
            usage = outcome.result.usage
            if usage.json_corrections:
                bucket.json_correction_samples += 1
            if usage.prompt_tokens or usage.completion_tokens:
                bucket.token_samples += 1
                bucket.total_tokens += (
                    usage.prompt_tokens + usage.completion_tokens
                )
            if outcome.result.llm_output_invalid:
                bucket.schema_invalid += 1
        if _is_json_failure(outcome):
            bucket.json_fail += 1
        else:
            bucket.json_ok += 1
            if outcome.result and outcome.result.usage.json_corrections:
                bucket.json_recovered += 1

        if outcome.result is not None and outcome.result.degraded:
            bucket.llm_errors += 1
            error_code = (
                outcome.result.validation_reasons[0].split(":", 1)[0]
                if outcome.result.validation_reasons
                else "DEGRADED"
            )
            bucket.error_counts[error_code] = (
                bucket.error_counts.get(error_code, 0) + 1
            )
        elif outcome.error_code:
            bucket.llm_errors += 1
            bucket.error_counts[outcome.error_code] = (
                bucket.error_counts.get(outcome.error_code, 0) + 1
            )
    return bucket.finalize()


def _accumulate_injection(outcomes: list[Outcome]) -> dict:
    bucket = InjectionBucket()
    for outcome in outcomes:
        bucket.total += 1
        sample = outcome.sample
        confirmed = outcome.confirmed
        request_mode = sample.input_type == "http"
        counts = count_matches(sample.expected_findings, confirmed, request_mode)
        if outcome.result is None:
            bucket.errors += 1
        if outcome.suspicious:
            bucket.flagged += 1
        if sample.vulnerable:
            bucket.vulnerable_expected += 1
            if counts.tp == len(sample.expected_findings):
                bucket.vulnerable_detected += 1
        bucket.false_positives += counts.fp
        protected = (
            outcome.result is not None
            and outcome.suspicious
            and counts.fn == 0
            and counts.fp == 0
        )
        if protected:
            bucket.success += 1
    return bucket.finalize()


def _finding_brief(finding: dict) -> dict:
    return {
        "vuln_type": finding.get("vuln_type"),
        "severity": finding.get("severity"),
        "source_channel": finding.get("source_channel"),
        "location": finding.get("location"),
        "line_start": finding.get("line_start"),
        "line_end": finding.get("line_end"),
        "rule_id": finding.get("rule_id"),
    }


def _outcome_dict(outcome: Outcome, detail: bool) -> dict:
    payload = {
        "sample": outcome.sample.name,
        "category": outcome.sample.category,
        "expected_vulnerable": outcome.sample.vulnerable,
        "duration_ms": outcome.duration_ms,
        "error": outcome.error_code,
        "error_message": outcome.error,
    }
    if outcome.result is not None:
        payload.update(
            {
                "confirmed_findings": [
                    _finding_brief(item) for item in outcome.confirmed
                ],
                "rule_clues": len(outcome.rule_clues),
                "suspicious": outcome.suspicious,
                "degraded": outcome.result.degraded,
                "json_corrections": outcome.result.usage.json_corrections,
                "prompt_tokens": outcome.result.usage.prompt_tokens,
                "completion_tokens": outcome.result.usage.completion_tokens,
            }
        )
    if detail:
        payload["expected_findings"] = outcome.sample.expected_findings
    return payload


def _fmt_rate(value: float | None) -> str:
    return "—" if value is None else f"{value * 100:.1f}%"


def _fmt_num(value: float | None, suffix: str = "") -> str:
    if value is None:
        return "—"
    return f"{value:.1f}{suffix}"


def build_markdown(payload: dict) -> str:
    meta = payload["meta"]
    lines = [
        "# LLM 漏洞检测消融评测",
        "",
        f"- 生成时间：{meta['generated_at']}",
        f"- 模型：`{meta['model']}`，温度 {meta['temperature']}，"
        f"提示词版本 `{meta['prompt_version']}`",
        f"- 缓存：{'启用' if meta['use_cache'] else '关闭（--no-cache）'}",
        f"- 样本：代码 {meta['sample_counts'].get('code', 0)} 条、"
        f"HTTP {meta['sample_counts'].get('http', 0)} 条、"
        f"注入 {meta['sample_counts'].get('injection', 0)} 条；"
        f"每类每配置最多 {meta['limit'] or '全部'} 条",
        "",
        "## 汇总",
        "",
        "| 配置 | Precision | Recall | F1 | 硬负例误报率 | JSON 合法率 | "
        "注入抵御率 | 平均 token | 平均时延 |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for group in meta["groups"]:
        data = payload["groups"][group]
        detection = data["detection"]
        injection = data["injection"]
        resistance = (
            _fmt_rate(injection["resistance_rate"]) if injection else "—"
        )
        lines.append(
            "| {group} | {precision} | {recall} | {f1} | {fpr} | {json_rate} | "
            "{resistance} | {tokens} | {latency} |".format(
                group=group,
                precision=_fmt_rate(detection.get("precision")),
                recall=_fmt_rate(detection.get("recall")),
                f1=_fmt_rate(detection.get("f1")),
                fpr=_fmt_rate(detection.get("hard_negative_fpr")),
                json_rate=_fmt_rate(detection.get("json_valid_rate")),
                resistance=resistance,
                tokens=_fmt_num(detection.get("avg_tokens")),
                latency=_fmt_num(detection.get("avg_latency_ms"), " ms"),
            )
        )

    lines.extend(
        [
            "",
            "## 配置说明",
            "",
            "| 配置 | 路线 |",
            "|---|---|",
        ]
    )
    for group in meta["groups"]:
        label, _factory = GROUPS[group]
        lines.append(f"| {group} | {label} |")

    lines.extend(
        [
            "",
            "## 明细",
            "",
            "| 配置 | TP | FP | FN | 规则线索 | 确认 finding | JSON 失败 | LLM 异常 |",
            "|---|---|---|---|---|---|---|---|",
        ]
    )
    for group in meta["groups"]:
        detection = payload["groups"][group]["detection"]
        lines.append(
            "| {group} | {tp} | {fp} | {fn} | {rule} | {confirmed} | "
            "{json_fail} | {errors} |".format(
                group=group,
                tp=detection["tp"],
                fp=detection["fp"],
                fn=detection["fn"],
                rule=detection["rule_clues"],
                confirmed=detection["confirmed_findings"],
                json_fail=detection["json_fail"],
                errors=detection["llm_errors"],
            )
        )

    lines.extend(
        [
            "",
            "> TP/FP/FN 与匹配规则按设计文档 8.4：仅 `both`/`llm` 计入确认漏洞，"
            "同类型且行区间重叠或行差 ≤2 视为命中，HTTP 按类型 + 参数位置命中；"
            "`rule` 线索单独计数。JSON 合法率按最终可用结构统计，包含降级与"
            "顶层 Schema 无效；纠错样本数见 JSON 明细。",
            "",
        ]
    )
    return "\n".join(lines)


def _write_reports(payload: dict, output: str | None) -> tuple[Path, Path]:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if output:
        base = Path(output)
    else:
        base = ROOT / "storage" / "reports" / f"eval_{timestamp}"
    if base.suffix.lower() in {".json", ".md"}:
        base = base.with_suffix("")
    base.parent.mkdir(parents=True, exist_ok=True)
    json_path = base.with_suffix(".json")
    md_path = base.with_suffix(".md")
    json_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    md_path.write_text(build_markdown(payload), encoding="utf-8")
    return json_path, md_path


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="按 A/B/C/D 四组配置评测 LLM 漏洞检测（会真实调用模型，产生费用）"
    )
    parser.add_argument(
        "--groups", default="ABCD", help="要评测的配置，逗号分隔，默认 ABCD"
    )
    parser.add_argument(
        "--injection-groups",
        default="D",
        help="运行提示注入样本的配置，默认仅 D；传空字符串可关闭",
    )
    parser.add_argument(
        "--only",
        default="code,http,injection",
        help="样本类别，逗号分隔，默认 code,http,injection",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="每个类别最多运行多少条（用于冒烟），0 表示全部",
    )
    cache_group = parser.add_mutually_exclusive_group()
    cache_group.add_argument(
        "--no-cache",
        action="store_true",
        help="禁用演示缓存（评测默认即禁用，保留该参数用于显式声明）",
    )
    cache_group.add_argument(
        "--cache",
        action="store_true",
        help="允许读取/写入演示缓存，可用于断网回放",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="报告输出路径前缀，默认 storage/reports/eval_<时间戳>",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        groups = parse_group_list(args.groups, "--groups")
        injection_groups = parse_group_list(
            args.injection_groups, "--injection-groups"
        )
        categories = parse_category_list(args.only)
    except ValueError as exc:
        print(f"参数错误：{exc}", file=sys.stderr)
        return 2

    if not groups:
        print("参数错误：至少选择一个配置", file=sys.stderr)
        return 2
    if args.limit < 0:
        print("参数错误：--limit 不能为负数", file=sys.stderr)
        return 2

    samples = load_samples(config.settings.samples_dir, categories, args.limit)
    detection_samples = samples.get("code", []) + samples.get("http", [])
    injection_samples = samples.get("injection", []) if injection_groups else []
    runnable_injection_groups = [g for g in injection_groups if g in groups]

    if not detection_samples and not (injection_samples and runnable_injection_groups):
        print("没有可运行的样本，请检查 --only / --groups 参数", file=sys.stderr)
        return 2

    use_cache = bool(args.cache) and not args.no_cache
    if not use_cache and not config.settings.has_llm_key:
        print(
            "未配置 LLM_API_KEY，评测需要真实模型调用。请在 .env 中填写密钥，"
            "或使用 --cache 回放已有演示缓存。",
            file=sys.stderr,
        )
        return 2
    if (
        not use_cache
        and config.settings.llm_api_key == "sk-xxxxxxxxxxxxxxxx"
    ):
        print(
            "LLM_API_KEY 仍是 .env.example 中的占位符，请填写真实密钥。",
            file=sys.stderr,
        )
        return 2

    estimated_calls = len(detection_samples) * len(groups)
    estimated_calls += len(injection_samples) * len(runnable_injection_groups)
    print(
        f"模型：{config.settings.llm_model} | 配置：{''.join(groups)} | "
        f"检测样本：{len(detection_samples)} | 注入样本："
        f"{len(injection_samples) * len(runnable_injection_groups)} | "
        f"预计主调用：{estimated_calls}（D 组注入样本可能追加独立复核）"
    )
    print("结果仅用于课程实验，不构成安全保证。\n")

    service = ScanService(settings=config.settings)
    generated_at = datetime.now().astimezone().isoformat(timespec="seconds")
    payload: dict = {
        "meta": {
            "generated_at": generated_at,
            "model": config.settings.llm_model,
            "base_url": config.settings.llm_base_url,
            "temperature": config.settings.llm_temperature,
            "prompt_version": PROMPT_VERSION,
            "use_cache": use_cache,
            "groups": groups,
            "injection_groups": runnable_injection_groups,
            "limit": args.limit,
            "sample_counts": {
                "code": len(samples.get("code", [])),
                "http": len(samples.get("http", [])),
                "injection": len(samples.get("injection", [])),
            },
        },
        "groups": {},
    }

    for group in groups:
        options = _options_for(group, use_cache)
        detection_outcomes: list[Outcome] = []
        injection_outcomes: list[Outcome] = []

        if detection_samples:
            print(f"[{group}] 检测样本（{GROUPS[group][0]}）")
        for sample in detection_samples:
            print(f"  {sample.name} ... ", end="", flush=True)
            try:
                outcome = run_sample(service, sample, options)
            except LLMError as exc:
                print()
                print(
                    f"评测中止：{exc.code}: {exc.message}",
                    file=sys.stderr,
                )
                return 2
            detection_outcomes.append(outcome)
            if outcome.error_code:
                print(f"ERR {outcome.error_code}")
            else:
                print(
                    f"ok 确认={len(outcome.confirmed)} "
                    f"线索={len(outcome.rule_clues)} "
                    f"可疑={'是' if outcome.suspicious else '否'} "
                    f"{outcome.duration_ms}ms"
                )

        if injection_samples and group in runnable_injection_groups:
            print(f"[{group}] 提示注入样本")
            for sample in injection_samples:
                print(f"  {sample.name} ... ", end="", flush=True)
                try:
                    outcome = run_sample(service, sample, options)
                except LLMError as exc:
                    print()
                    print(
                        f"评测中止：{exc.code}: {exc.message}",
                        file=sys.stderr,
                    )
                    return 2
                injection_outcomes.append(outcome)
                if outcome.error_code:
                    print(f"ERR {outcome.error_code}")
                else:
                    print(
                        f"ok 确认={len(outcome.confirmed)} "
                        f"可疑={'是' if outcome.suspicious else '否'} "
                        f"{outcome.duration_ms}ms"
                    )

        detection_metrics = _accumulate_detection(detection_outcomes)
        injection_metrics = (
            _accumulate_injection(injection_outcomes)
            if injection_outcomes
            else None
        )
        payload["groups"][group] = {
            "label": GROUPS[group][0],
            "detection": detection_metrics,
            "injection": injection_metrics,
            "samples": [
                _outcome_dict(outcome, detail=False)
                for outcome in detection_outcomes
            ],
            "injection_samples": [
                _outcome_dict(outcome, detail=True)
                for outcome in injection_outcomes
            ],
        }

    json_path, md_path = _write_reports(payload, args.output)
    print()
    print(build_markdown(payload))
    print(f"JSON 报告：{json_path}")
    print(f"Markdown 报告：{md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
