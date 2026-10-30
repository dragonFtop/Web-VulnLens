from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, File, UploadFile

from app import config
from app.core.parser.code_parser import EXT_LANGUAGE, decode_bytes
from app.core.util import new_id, safe_join, sha256_bytes
from app.db import repository
from app.errors import AppError

logger = logging.getLogger(__name__)
router = APIRouter()

ALLOWED_EXTENSIONS = set(EXT_LANGUAGE)


def sanitize_filename(raw: str | None) -> str:
    if not raw or not raw.strip():
        raise AppError("E_UPLOAD_TYPE", "文件名不能为空", 400)
    if "\x00" in raw:
        raise AppError("E_UPLOAD_TYPE", "文件名包含非法字符", 400)
    name = raw.replace("\\", "/").rsplit("/", 1)[-1].strip()
    if not name or name in {".", ".."}:
        raise AppError("E_UPLOAD_TYPE", "文件名不合法", 400)
    if len(name) > 200:
        raise AppError("E_UPLOAD_TYPE", "文件名过长", 400)
    return name


def save_upload(filename: str, data: bytes, language: str) -> dict:
    if not data:
        raise AppError("E_INPUT_FORMAT", "文件内容为空", 400)
    decode_bytes(data)

    upload_id = new_id("f")
    stored_name = f"{upload_id}{Path(filename).suffix.lower()}"
    path = safe_join(config.settings.uploads_dir, stored_name)
    try:
        path.write_bytes(data)
    except OSError as exc:
        raise AppError("E_INTERNAL", "保存上传文件失败", 500) from exc

    digest = sha256_bytes(data)
    repository.create_upload(upload_id, filename, language, stored_name, digest, len(data))
    logger.info("上传完成 id=%s size=%d language=%s", upload_id, len(data), language)
    return {
        "file_id": upload_id,
        "filename": filename,
        "language": language,
        "size": len(data),
        "sha256": digest,
    }


@router.post("/upload")
async def upload_file(file: UploadFile = File(...)) -> dict:
    filename = sanitize_filename(file.filename)
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise AppError("E_UPLOAD_TYPE", "仅支持 .py/.php/.js 代码文件", 400)

    limit = config.settings.max_upload_mb * 1024 * 1024
    data = await file.read(limit + 1)
    if len(data) > limit:
        raise AppError(
            "E_UPLOAD_SIZE",
            f"文件超过 {config.settings.max_upload_mb}MB 大小限制",
            413,
        )
    return save_upload(filename, data, EXT_LANGUAGE[suffix])
