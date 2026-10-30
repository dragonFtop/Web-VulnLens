from __future__ import annotations

import logging
from typing import Literal

from fastapi import APIRouter, BackgroundTasks
from pydantic import BaseModel

from app import config
from app.api.serializers import finding_to_dict, job_to_dict
from app.api.upload import save_upload
from app.core.parser.code_parser import EXT_LANGUAGE
from app.core.parser.http_parser import parse_http_request
from app.core.util import new_job_id, safe_join
from app.db import repository
from app.errors import AppError
from app.services.scan_service import run_scan_job

logger = logging.getLogger(__name__)
router = APIRouter()

CODE_LANGUAGES = set(EXT_LANGUAGE.values())


class ScanCreateRequest(BaseModel):
    input_type: Literal["code", "http"]
    file_id: str | None = None
    raw_http: str | None = None


def _create_http_upload(raw_http: str) -> dict:
    if not raw_http or not raw_http.strip():
        raise AppError("E_INPUT_FORMAT", "HTTP 请求内容为空", 400)
    if "\x00" in raw_http:
        raise AppError("E_INPUT_FORMAT", "HTTP 请求包含非法空字节", 400)
    raw_bytes = raw_http.encode("utf-8", errors="replace")
    limit = config.settings.max_upload_mb * 1024 * 1024
    if len(raw_bytes) > limit:
        raise AppError(
            "E_UPLOAD_SIZE",
            f"请求内容超过 {config.settings.max_upload_mb}MB 限制",
            413,
        )
    request = parse_http_request(raw_http)
    body_kb = len(request.body.encode("utf-8", errors="replace")) / 1024
    if body_kb > config.settings.max_http_body_kb:
        raise AppError(
            "E_INPUT_FORMAT",
            f"请求 body 超过 {config.settings.max_http_body_kb}KB 限制",
            400,
        )
    result = save_upload("request.http", raw_bytes, "http")
    upload = repository.get_upload(result["file_id"])
    if not upload:
        raise AppError("E_INTERNAL", "创建请求记录失败", 500)
    return upload


@router.post("/scans")
def create_scan(payload: ScanCreateRequest, background: BackgroundTasks) -> dict:
    if payload.input_type == "code":
        if not payload.file_id:
            raise AppError("E_INPUT_FORMAT", "code 类型任务需要提供 file_id", 400)
        upload = repository.get_upload(payload.file_id)
        if not upload:
            raise AppError("E_NOT_FOUND", "上传文件记录不存在，请重新上传", 404)
        if upload.get("language") not in CODE_LANGUAGES:
            raise AppError("E_INPUT_FORMAT", "上传文件不是受支持的代码类型", 400)
        stored = safe_join(config.settings.uploads_dir, upload["stored_name"])
        if not stored.is_file():
            raise AppError("E_NOT_FOUND", "上传文件已丢失，请重新上传", 404)
        filename = upload["filename"]
        language = upload["language"]
    else:
        if not payload.raw_http:
            raise AppError("E_INPUT_FORMAT", "http 类型任务需要提供 raw_http", 400)
        upload = _create_http_upload(payload.raw_http)
        filename = "request.http"
        language = "http"

    job_id = new_job_id()
    repository.create_job(
        job_id,
        payload.input_type,
        upload["id"],
        filename,
        language,
        config.settings.llm_model,
    )
    background.add_task(run_scan_job, job_id)
    logger.info("创建扫描任务 job=%s type=%s", job_id, payload.input_type)
    return {"job_id": job_id, "status": "PENDING"}


@router.get("/scans/{job_id}")
def get_scan(job_id: str) -> dict:
    job = repository.get_job(job_id)
    if not job:
        raise AppError("E_NOT_FOUND", "扫描任务不存在", 404)
    return job_to_dict(job)


@router.get("/scans/{job_id}/findings")
def get_scan_findings(job_id: str) -> dict:
    job = repository.get_job(job_id)
    if not job:
        raise AppError("E_NOT_FOUND", "扫描任务不存在", 404)
    return {
        "job_id": job_id,
        "findings": [finding_to_dict(item) for item in repository.get_findings(job_id)],
        "suspicious_content": repository.get_suspicious(job),
        "summary": repository.count_findings_by_severity(job_id),
    }
