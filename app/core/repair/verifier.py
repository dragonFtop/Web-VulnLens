from __future__ import annotations

from pydantic import ValidationError

from app.core.extractor.rule_engine import extract_candidates
from app.core.llm.client import LLMClient
from app.core.llm.prompts import build_verify_messages
from app.core.llm.schemas import VerifyResponse
from app.core.parser.code_parser import parse_code
from app.errors import LLM_JSON, LLMError

VERIFY_PROMPT_VERSION = "repair-verify-v1.0"


def rescan_clean(code: str, filename: str, language: str, vuln_type: str) -> bool:
    try:
        parsed = parse_code(code, filename)
    except Exception:
        return False
    candidates, _error = extract_candidates(parsed)
    for candidate in candidates:
        if candidate.vuln_hint != vuln_type:
            continue
        if candidate.safe_patterns:
            continue
        return False
    return True


def llm_verify(
    client: LLMClient,
    finding: dict,
    code: str,
    language: str,
    *,
    job_id: str = "",
) -> tuple[bool | None, str]:
    numbered = "\n".join(f"{i + 1} | {line}" for i, line in enumerate(code.split("\n")))
    messages = build_verify_messages(finding, numbered, language=language)
    try:
        data, _usage = client.chat_json(
            messages,
            max_tokens=2048,
            job_id=job_id,
            prompt_version=VERIFY_PROMPT_VERSION,
        )
        response = VerifyResponse.model_validate(data)
    except LLMError as exc:
        return None, f"LLM 复核失败（{exc.code}）"
    except ValidationError:
        raise LLMError(LLM_JSON, "复核结果字段不合法", 502)
    residual = response.residual_risk.strip() or response.notes.strip() or "未说明"
    return bool(response.fixed), residual
