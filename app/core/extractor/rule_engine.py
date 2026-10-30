from __future__ import annotations

import re
from bisect import bisect_left
from dataclasses import dataclass, field

from app.core.extractor.candidates import Candidate, RequestCandidate
from app.core.extractor.py_ast import extract_python_candidates
from app.core.parser.code_parser import ParsedCode
from app.core.parser.http_parser import ParsedRequest, decode_value

WINDOW_RADIUS = 8


@dataclass(frozen=True)
class CodeRule:
    id: str
    vuln_type: str
    languages: tuple[str, ...]
    source: str
    sink: str
    notes: str
    safe_hints: tuple[tuple[str, str], ...] = field(default_factory=tuple)


CODE_RULES: tuple[CodeRule, ...] = (
    CodeRule(
        "SQLI-PHP-001",
        "SQL_INJECTION",
        ("php",),
        r"\$_(GET|POST|REQUEST|COOKIE|SERVER)",
        r"(?i)\b(mysqli_query|mysqli_multi_query|mysql_query|pg_query|->query|->exec)\s*\(",
        "超级全局变量与 SQL 执行调用出现在同一代码窗口",
        (("->prepare", "PDO 预处理"), ("?", "SQL 占位符"), ("intval", "整数强制转换"),
         ("ALLOWED", "疑似白名单")),
    ),
    CodeRule(
        "SQLI-PHP-002",
        "SQL_INJECTION",
        ("php",),
        r"\$_(GET|POST|REQUEST|COOKIE)",
        r"(?i)\b(PDO::query|\\\$pdo->query|\\\$mysqli->query)\s*\(",
        "超级全局变量与查询调用出现在同一代码窗口",
        (("->prepare", "PDO 预处理"), ("?", "SQL 占位符")),
    ),
    CodeRule(
        "XSS-PHP-001",
        "XSS",
        ("php",),
        r"\$_(GET|POST|REQUEST|COOKIE)",
        r"(?i)\b(echo|print)\b",
        "echo/print 直接输出用户可控数据",
        (("htmlspecialchars", "htmlspecialchars 编码"), ("htmlentities", "htmlentities 编码"),
         ("strip_tags", "strip_tags 过滤")),
    ),
    CodeRule(
        "RCE-PHP-001",
        "COMMAND_INJECTION",
        ("php",),
        r"\$_(GET|POST|REQUEST|COOKIE|SERVER)",
        r"(?i)\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(",
        "超级全局变量进入命令执行函数",
        (("escapeshellarg", "escapeshellarg 转义"), ("escapeshellcmd", "escapeshellcmd 转义"),
         ("ALLOWED", "疑似白名单")),
    ),
    CodeRule(
        "SQLI-JS-001",
        "SQL_INJECTION",
        ("javascript",),
        r"(?i)\b(req|request)\s*\.\s*(query|body|params|cookies)\b",
        r"(?i)\.(query|execute)\s*\(",
        "请求参数与动态 SQL 查询出现在同一窗口",
        (("prepare", "预处理语句"), ("\\?", "SQL 占位符"), ("parameterized", "参数化查询")),
    ),
    CodeRule(
        "XSS-JS-001",
        "XSS",
        ("javascript",),
        r"(?i)(\b(req|request)\s*\.\s*(query|body|params|cookies)\b|location\s*\.\s*(search|hash|href)|document\s*\.\s*(URL|referrer))",
        r"(?i)(innerHTML|outerHTML|document\s*\.\s*write(ln)?|insertAdjacentHTML)",
        "不可信数据写入 DOM HTML sink",
        (("DOMPurify", "DOMPurify 清洗"), ("textContent", "textContent 安全赋值"),
         ("escapeHtml", "escapeHtml 转义"), ("sanitize", "sanitize 清洗")),
    ),
    CodeRule(
        "RCE-JS-001",
        "COMMAND_INJECTION",
        ("javascript",),
        r"(?i)\b(req|request)\s*\.\s*(query|body|params|cookies)\b",
        r"(?i)(child_process\s*\.\s*(exec|execSync)|require\(['\"]child_process['\"]\)\.exec|(?<![\w.])eval\s*\(|new\s+Function\s*\()",
        "请求参数进入命令/动态代码执行 sink",
        (("execFile", "execFile 常量程序"), ("ALLOWED", "疑似白名单")),
    ),
    CodeRule(
        "SQLI-001",
        "SQL_INJECTION",
        ("python",),
        r"(?i)(request|flask\.request)\s*\.\s*(args|form|values|GET|POST|json|body)\b",
        r"(?i)\b(execute|executemany)\s*\(",
        "用户输入与 SQL 执行出现在同一窗口",
        (("%s", "SQL 占位符"), ("?", "SQL 占位符"), ("execute(sql", "参数化调用")),
    ),
    CodeRule(
        "XSS-001",
        "XSS",
        ("python",),
        r"(?i)(request|flask\.request)\s*\.\s*(args|form|values|GET|POST|json|body)\b",
        r"(?i)\b(render_template_string|Markup|Response|make_response)\s*\(",
        "用户输入与 HTML 输出 sink 出现在同一窗口",
        (("html.escape", "HTML 转义"), ("markupsafe", "markupsafe 转义"),
         ("autoescape", "自动转义")),
    ),
    CodeRule(
        "RCE-001",
        "COMMAND_INJECTION",
        ("python",),
        r"(?i)(request|flask\.request)\s*\.\s*(args|form|values|GET|POST|json|body)\b",
        r"(?i)\b(os\s*\.\s*(system|popen)|subprocess\s*\.\s*(run|call|Popen|check_output|check_call))\s*\(",
        "用户输入与命令执行 sink 出现在同一窗口",
        (("shlex.quote", "shlex.quote 转义"), ("shell=False", "禁用 shell"),
         ("ALLOWED", "疑似白名单")),
    ),
    CodeRule(
        "RCE-002",
        "COMMAND_INJECTION",
        ("python",),
        r"(?i)(request|flask\.request)\s*\.\s*(args|form|values|GET|POST|json|body)\b",
        r"(?i)(?<![\w.])(eval|exec)\s*\(",
        "用户输入进入动态代码执行 sink",
        (("literal_eval", "literal_eval 仅解析字面量"),),
    ),
)


@dataclass(frozen=True)
class HttpRule:
    id: str
    vuln_type: str
    pattern: re.Pattern
    notes: str


HTTP_RULES: tuple[HttpRule, ...] = (
    HttpRule(
        "HTTP-SQLI-001",
        "SQL_INJECTION",
        re.compile(
            r"(?i)(\bunion\b\s+(all\s+)?\bselect\b"
            r"|['\"]\s*(or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+"
            r"|\b(sleep|benchmark|pg_sleep)\s*\("
            r"|(\bunion\b.{0,20}\bselect\b)"
            r"|/\*.*?\*/"
            r"|\d+\s*=\s*\d+\s*(--|#))"
        ),
        "解码后参数呈现 SQL 注入语法特征",
    ),
    HttpRule(
        "HTTP-XSS-001",
        "XSS",
        re.compile(
            r"(?i)(<script\b|<svg\b|<iframe\b|javascript\s*:|"
            r"on(error|load|click|mouseover|focus)\s*=|"
            r"<img\b[^>]*onerror\s*=|<body\b[^>]*onload\s*=)"
        ),
        "解码后参数包含 HTML/JavaScript 注入载荷",
    ),
    HttpRule(
        "HTTP-RCE-001",
        "COMMAND_INJECTION",
        re.compile(
            r"(?i)([;&|]\s*(cat|ls|whoami|id|curl|wget|bash|sh|nc|ping|powershell|cmd)\b"
            r"|\$\(|\`|"
            r"^\s*(cat|ls|whoami|id|curl|wget|bash|sh)\s+[/\-.])"
        ),
        "解码后参数包含命令拼接/替换特征",
    ),
)


def _safe_hints(text: str, hints: tuple[tuple[str, str], ...]) -> list[str]:
    found: list[str] = []
    lowered = text.lower()
    for token, label in hints:
        try:
            if re.search(token, text, re.IGNORECASE if token.isalpha() else 0):
                found.append(label)
            elif token.lower() in lowered and token.isalpha():
                found.append(label)
        except re.error:
            if token.lower() in lowered:
                found.append(label)
    return sorted(set(found))


def _rule_candidates_for(rule: CodeRule, parsed: ParsedCode) -> list[Candidate]:
    lines = parsed.lines
    source_lines = [
        index + 1 for index, line in enumerate(lines) if re.search(rule.source, line)
    ]
    if not source_lines:
        return []
    sink_re = re.compile(rule.sink)
    candidates: list[Candidate] = []
    for index, line in enumerate(lines):
        if not sink_re.search(line):
            continue
        line_no = index + 1
        low = line_no - WINDOW_RADIUS
        high = line_no + WINDOW_RADIUS
        position = bisect_left(source_lines, low)
        if position >= len(source_lines) or source_lines[position] > high:
            continue
        window_start = max(1, low)
        window_end = min(len(lines), high)
        window_text = "\n".join(lines[window_start - 1 : window_end])
        candidates.append(
            Candidate(
                id="",
                vuln_hint=rule.vuln_type,
                language=parsed.language,
                rule_id=rule.id,
                line_start=line_no,
                line_end=line_no,
                evidence=line.strip()[:1000],
                safe_patterns=_safe_hints(window_text, rule.safe_hints),
                notes=f"{rule.notes}；source 行: {source_lines[position]}",
            )
        )
    return candidates


def extract_rule_candidates(parsed: ParsedCode, *, include_python_fallback: bool = True) -> list[Candidate]:
    candidates: list[Candidate] = []
    for rule in CODE_RULES:
        if parsed.language not in rule.languages:
            continue
        if parsed.language == "python" and not include_python_fallback:
            continue
        candidates.extend(_rule_candidates_for(rule, parsed))
    unique: dict[tuple[str, int], Candidate] = {}
    for candidate in candidates:
        unique.setdefault((candidate.rule_id, candidate.line_start), candidate)
    return list(unique.values())


def extract_candidates(parsed: ParsedCode) -> tuple[list[Candidate], str | None]:
    if parsed.language == "python":
        candidates, parse_error = extract_python_candidates(parsed)
        if parse_error:
            fallback = extract_rule_candidates(parsed, include_python_fallback=True)
            for candidate in fallback:
                candidate.notes = f"AST {parse_error}；已回退为正则候选。{candidate.notes}"
            return fallback, parse_error
        return candidates, None
    return extract_rule_candidates(parsed), None


def extract_http_candidates(request: ParsedRequest) -> list[RequestCandidate]:
    grouped: dict[tuple[str, str, str], RequestCandidate] = {}
    for param in request.params:
        if not param.original_value:
            continue
        decoded = decode_value(param.original_value)
        tested = decoded.variants
        for rule in HTTP_RULES:
            hit_label = None
            hit_value = None
            for variant in tested:
                if rule.pattern.search(variant["value"]):
                    hit_label = variant["label"]
                    hit_value = variant["value"]
                    break
            if hit_label is None:
                continue
            key = (param.location, param.name, rule.vuln_type)
            existing = grouped.get(key)
            if existing:
                if rule.id not in existing.matched_rules:
                    existing.matched_rules.append(rule.id)
                continue
            notes = (
                f"{rule.notes}；命中位置: {hit_label}；命中值: {str(hit_value)[:200]}"
            )
            grouped[key] = RequestCandidate(
                id="",
                vuln_hint=rule.vuln_type,
                location=param.location,
                name=param.name,
                original_value=param.original_value,
                variants=decoded.variants,
                decode_chain=decoded.chain,
                matched_rules=[rule.id],
                notes=notes,
            )
    return list(grouped.values())
