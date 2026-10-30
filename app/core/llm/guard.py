from __future__ import annotations

import re
import secrets

SUSPICIOUS_PATTERNS: tuple[tuple[re.Pattern, str], ...] = (
    (
        re.compile(r"(?i)ignore\s+(all\s+)?(previous|above|prior)\s+instructions?"),
        "英文“忽略先前指令”短语",
    ),
    (
        re.compile(r"(?i)disregard\s+(the\s+)?(previous|above|prior)\s*(instructions?)?"),
        "英文“无视指令”短语",
    ),
    (
        re.compile(r"(?i)forget\s+(all\s+)?(previous|above|prior)\s+instructions?"),
        "英文“忘记先前指令”短语",
    ),
    (re.compile(r"(?i)system\s*[:：]"), "伪造系统提示标记"),
    (re.compile(r"(?i)you\s+are\s+now\s+"), "角色改写指令"),
    (re.compile(r"(?i)do\s+not\s+(report|flag|detect)"), "要求不要报告"),
    (
        re.compile(r"(?i)mark\s+(this|the)\s+(code|file|request|sample)\s+as\s+safe"),
        "要求标记为安全",
    ),
    (re.compile(r"(?i)this\s+(code|file|request|sample)\s+is\s+(safe|secure)"), "声称内容安全"),
    (
        re.compile(r"(?i)(return|respond\s+with|output)\s+(an?\s+)?(empty|no)\s+(findings|vulnerabilities)"),
        "要求输出空结果",
    ),
    (
        re.compile(r"(?i)['\"]?findings['\"]?\s*:\s*\[\s*\]"),
        "伪造空 findings 输出",
    ),
    (re.compile(r"(?i)new\s+(system\s+)?instructions?"), "伪造新指令"),
    (
        re.compile(r"忽略(以上|之前|前面|上述).{0,12}(指令|要求|规则)"),
        "中文“忽略指令”短语",
    ),
    (re.compile(r"(判定|标记|认为).{0,12}(安全|无漏洞)"), "中文“判定安全”短语"),
    (re.compile(r"(不要|禁止).{0,12}(报告|上报|检测)"), "中文“禁止报告”短语"),
    (re.compile(r"新的(系统)?指令"), "中文“新指令”短语"),
    (re.compile(r"(返回|输出).{0,10}(空数组|空结果|无漏洞|findings.{0,4}\[\])"), "要求输出空结果"),
)


def new_nonce() -> str:
    return secrets.token_hex(8)


def neutralize_fences(text: str) -> str:
    return text.replace("```", "'''")


def build_data_block(text: str, nonce: str) -> str:
    return f"<<<CODE_{nonce}>>>\n{text}\n<<<END_CODE_{nonce}>>>"


def scan_text(text: str, *, origin: str | None = None) -> list[dict]:
    results: list[dict] = []
    seen: set[tuple[int | None, str]] = set()
    for line_number, line in enumerate(text.split("\n"), start=1):
        labels: list[str] = []
        for pattern, label in SUSPICIOUS_PATTERNS:
            if pattern.search(line):
                labels.append(label)
        if not labels:
            continue
        quote = line.strip()[:300]
        key = (line_number, quote)
        if key in seen:
            continue
        seen.add(key)
        reason = "；".join(dict.fromkeys(labels))
        entry = {
            "type": "PROMPT_INJECTION",
            "line": line_number,
            "quote": quote,
            "reason": f"疑似试图操纵审计模型：{reason}",
        }
        if origin:
            entry["origin"] = origin
        results.append(entry)
        if len(results) >= 30:
            break
    return results


def scan_value(value: str, *, context: str) -> list[dict]:
    results: list[dict] = []
    for line_number, line in enumerate(value.split("\n"), start=1):
        labels = [label for pattern, label in SUSPICIOUS_PATTERNS if pattern.search(line)]
        if not labels:
            continue
        results.append(
            {
                "type": "PROMPT_INJECTION",
                "line": None,
                "quote": line.strip()[:300],
                "reason": f"参数 {context} 第 {line_number} 行含疑似指令：" + "；".join(dict.fromkeys(labels)),
                "origin": context,
            }
        )
        if len(results) >= 10:
            break
    return results


def merge_suspicious(*groups: list[dict]) -> list[dict]:
    merged: list[dict] = []
    seen: set[str] = set()
    for group in groups:
        for item in group:
            quote = str(item.get("quote", "")).strip()
            if not quote:
                continue
            key = quote[:120]
            if key in seen:
                continue
            seen.add(key)
            merged.append(
                {
                    "type": str(item.get("type") or "PROMPT_INJECTION"),
                    "line": item.get("line") if isinstance(item.get("line"), int) else None,
                    "quote": quote[:300],
                    "reason": str(item.get("reason", ""))[:300],
                    **({"origin": item["origin"]} if item.get("origin") else {}),
                }
            )
    return merged[:30]
