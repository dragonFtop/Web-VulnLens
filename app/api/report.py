from __future__ import annotations

import json
import logging
from typing import Literal

from fastapi import APIRouter, Query, Request
from fastapi.responses import Response

from app import config
from app.api.serializers import finding_to_dict, job_to_dict
from app.core.llm.prompts import PROMPT_VERSION
from app.core.util import now_utc, safe_join
from app.db import repository
from app.errors import AppError

logger = logging.getLogger(__name__)
router = APIRouter()

DISCLAIMER = (
    "本报告由静态分析与 LLM 辅助生成，不覆盖运行时配置、依赖漏洞与业务逻辑漏洞，"
    "不构成安全保证。HTTP 请求分析仅针对请求负载中的可疑特征，未向目标站点发送任何请求。"
    "修复结果必须经人工复核后方可上线。仅可用于自有代码或已获得授权的材料。"
)


def _report_context(request: Request, job_id: str) -> tuple[dict, dict]:
    job_row = repository.get_job(job_id)
    if not job_row:
        raise AppError("E_NOT_FOUND", "扫描任务不存在", 404)
    findings = [finding_to_dict(item) for item in repository.get_findings(job_id)]
    job = job_to_dict(job_row)
    context = {
        "request": request,
        "job": job,
        "findings": findings,
        "summary": job["summary"],
        "suspicious_content": repository.get_suspicious(job_row),
        "generated_at": now_utc(),
        "disclaimer": DISCLAIMER,
        "config_snapshot": {
            "model": config.settings.llm_model,
            "temperature": config.settings.llm_temperature,
            "json_mode": config.settings.llm_json_mode,
            "demo_cache": config.settings.demo_cache,
            "guard_recheck": config.settings.guard_recheck,
            "max_candidates": config.settings.max_candidates,
            "kb_top_k": config.settings.kb_top_k,
            "max_llm_code_chars": config.settings.max_llm_code_chars,
            "prompt_version": PROMPT_VERSION,
            "result_cached": job["cached"],
            "llm_output_invalid": job["llm_output_invalid"],
        },
        "prompt_version": PROMPT_VERSION,
    }
    return job, context


@router.get("/scans/{job_id}/report")
def export_report(
    request: Request,
    job_id: str,
    fmt: Literal["html", "json"] = Query("html", alias="format"),
) -> Response:
    job, context = _report_context(request, job_id)

    if fmt == "json":
        payload = {
            "job": job,
            "findings": [finding_to_dict(item) for item in repository.get_findings(job_id)],
            "suspicious_content": context["suspicious_content"],
            "config": context["config_snapshot"],
            "generated_at": context["generated_at"],
            "disclaimer": DISCLAIMER,
        }
        body = json.dumps(payload, ensure_ascii=False, indent=2)
        return Response(
            content=body,
            media_type="application/json; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="report_{job_id}.json"'
            },
        )

    templates = request.app.state.templates
    html = templates.get_template("report.html").render(context)
    try:
        path = safe_join(config.settings.reports_dir, f"report_{job_id}.html")
        path.write_text(html, encoding="utf-8")
    except OSError:
        logger.warning("报告文件写入失败 job=%s", job_id)
    return Response(
        content=html,
        media_type="text/html; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="report_{job_id}.html"'},
    )
