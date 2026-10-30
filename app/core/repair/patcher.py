from __future__ import annotations

import ast
import difflib
import re
from dataclasses import dataclass

from pydantic import ValidationError

from app.core.llm.client import LLMClient, Usage
from app.core.llm.prompts import REPAIR_PROMPT_VERSION, build_repair_messages
from app.core.llm.schemas import RepairResponse
from app.errors import LLM_JSON, LLMError

LINE_NUMBER_PREFIX = re.compile(r"^\s*\d{1,7}\s*\|\s?")


@dataclass
class PatchResult:
    patched_code: str
    explanation: str
    changes: list[dict]
    usage: Usage


def strip_line_number_prefixes(code: str) -> str:
    lines = code.split("\n")
    non_empty = [line for line in lines if line.strip()]
    if not non_empty:
        return code
    prefixed = sum(1 for line in non_empty if LINE_NUMBER_PREFIX.match(line))
    if prefixed / len(non_empty) < 0.6:
        return code
    return "\n".join(LINE_NUMBER_PREFIX.sub("", line) for line in lines)


def syntax_check(code: str, language: str) -> bool | None:
    if language != "python":
        return None
    try:
        ast.parse(code)
    except SyntaxError:
        return False
    return True


def build_diff(original: str, patched: str, filename: str) -> str:
    diff = difflib.unified_diff(
        original.splitlines(True),
        patched.splitlines(True),
        fromfile=filename,
        tofile=f"patched_{filename}",
        lineterm="\n",
    )
    return "".join(diff)


def generate_patch(
    client: LLMClient,
    finding: dict,
    parsed,
    *,
    job_id: str = "",
) -> PatchResult:
    numbered = "\n".join(f"{i + 1} | {line}" for i, line in enumerate(parsed.lines))
    messages = build_repair_messages(
        finding,
        numbered,
        filename=parsed.filename,
        language=parsed.language,
    )
    data, usage = client.chat_json(
        messages,
        max_tokens=8192,
        job_id=job_id,
        prompt_version=REPAIR_PROMPT_VERSION,
    )
    try:
        response = RepairResponse.model_validate(data)
    except ValidationError as exc:
        message = exc.errors()[0].get("msg", "unknown") if exc.errors() else "validation error"
        raise LLMError(LLM_JSON, f"修复结果字段不合法：{message}", 502) from exc

    patched = strip_line_number_prefixes(response.patched_code.replace("\r\n", "\n"))
    if len(patched.strip()) == 0:
        raise LLMError(LLM_JSON, "模型返回了空的修复代码", 502)
    if len(patched) > max(len(parsed.text) * 3, 200_000):
        raise LLMError(LLM_JSON, "修复结果体积异常，已拒绝写入", 502)
    return PatchResult(
        patched_code=patched,
        explanation=response.explanation,
        changes=[change.model_dump() for change in response.changes],
        usage=usage,
    )
