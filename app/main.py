from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import config
from app.api import history, repairs, report, scans, upload
from app.api.serializers import STATUS_DISPLAY, job_to_dict, finding_to_dict
from app.core.parser.code_parser import decode_bytes
from app.core.util import safe_join
from app.db import repository
from app.db.database import init_db
from app.errors import AppError
from app.services.repair_service import RepairService
from app.web.presentation import (
    build_code_lines,
    build_diff_lines,
    build_http_view,
    build_raw_lines,
)

WEB_DIR = Path(__file__).resolve().parent / "web"
STATIC_DIR = WEB_DIR / "static"
TEMPLATE_DIR = WEB_DIR / "templates"

logging.basicConfig(
    level=getattr(logging, config.settings.log_level, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(module)s | %(message)s",
)
logger = logging.getLogger(__name__)

templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


def _fmt_duration(value) -> str:
    if value is None:
        return "—"
    try:
        ms = int(value)
    except (TypeError, ValueError):
        return "—"
    return f"{ms} ms" if ms < 1000 else f"{ms / 1000:.1f} s"


def _fmt_confidence(value) -> str:
    try:
        return f"{float(value):.0%}"
    except (TypeError, ValueError):
        return "—"


templates.env.filters["duration"] = _fmt_duration
templates.env.filters["confidence"] = _fmt_confidence
templates.env.globals.update(
    app_name="Web VulnLens",
    app_disclaimer=(
        "仅用于自有代码或已授权材料。静态分析与 LLM 辅助结论不构成安全保证，"
        "修复结果必须人工复核后方可上线。"
    ),
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    config.settings.ensure_dirs()
    init_db()
    interrupted = repository.mark_running_jobs_failed("服务重启导致中断")
    if interrupted:
        logger.warning("已标记 %d 个中断任务为 FAILED", interrupted)
    logger.info(
        "服务启动 | model=%s | base_url=%s | demo_cache=%s | repair=%s | guard=%s",
        config.settings.llm_model,
        config.settings.llm_base_url,
        config.settings.demo_cache,
        config.settings.repair_enabled,
        config.settings.guard_recheck,
    )
    yield


app = FastAPI(
    title="Web VulnLens",
    description="基于 LLM 的 Web 代码漏洞智能检测与修复工具",
    version="1.0.0",
    lifespan=lifespan,
)
app.state.templates = templates
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

app.include_router(upload.router, prefix="/api", tags=["上传"])
app.include_router(scans.router, prefix="/api", tags=["扫描"])
app.include_router(history.router, prefix="/api", tags=["历史"])
app.include_router(repairs.router, prefix="/api", tags=["修复"])
app.include_router(report.router, prefix="/api", tags=["报告"])


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
    )
    path = request.url.path
    if not (path == "/docs" or path.startswith("/docs/") or path in {"/redoc", "/openapi.json"}):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; img-src 'self' data:; font-src 'self'; "
            "connect-src 'self'; object-src 'none'; base-uri 'self'; "
            "form-action 'self'; frame-ancestors 'none'",
        )
    if path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


def _wants_json(request: Request) -> bool:
    return request.url.path.startswith("/api/")


def _error_response(request: Request, code: str, message: str, status_code: int):
    if _wants_json(request):
        return JSONResponse(
            status_code=status_code, content={"error": {"code": code, "message": message}}
        )
    return templates.TemplateResponse(
        request,
        "error.html",
        {"code": code, "message": message, "status_code": status_code},
        status_code=status_code,
    )


@app.exception_handler(AppError)
async def handle_app_error(request: Request, exc: AppError):
    if _wants_json(request):
        return JSONResponse(status_code=exc.http_status, content=exc.to_dict())
    return templates.TemplateResponse(
        request,
        "error.html",
        {
            "code": exc.code,
            "message": exc.message,
            "status_code": exc.http_status,
            "job_id": exc.job_id,
        },
        status_code=exc.http_status,
    )


@app.exception_handler(RequestValidationError)
async def handle_validation_error(request: Request, exc: RequestValidationError):
    return _error_response(request, "E_INPUT_FORMAT", "请求参数格式不正确", 400)


@app.exception_handler(StarletteHTTPException)
async def handle_http_error(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 404:
        return _error_response(request, "E_NOT_FOUND", "页面或资源不存在", 404)
    if exc.status_code == 405:
        return _error_response(request, "E_INPUT_FORMAT", "请求方法不被允许", 405)
    return _error_response(request, "E_INTERNAL", "请求处理失败", exc.status_code)


@app.exception_handler(Exception)
async def handle_unexpected(request: Request, exc: Exception):
    logger.exception("未处理异常 path=%s", request.url.path)
    return _error_response(request, "E_INTERNAL", "系统内部错误，请查看日志", 500)


def _read_upload_text(upload: dict | None) -> str:
    if not upload:
        return ""
    try:
        path = safe_join(config.settings.uploads_dir, upload["stored_name"])
        if not path.is_file():
            return ""
        data = path.read_bytes()
    except (OSError, ValueError, KeyError):
        return ""
    try:
        return decode_bytes(data)[0]
    except AppError:
        return data.decode("utf-8", errors="replace")


def _hljs_language(language: str | None) -> str:
    mapping = {
        "python": "python",
        "php": "php",
        "javascript": "javascript",
        "http": "http",
    }
    return mapping.get(language or "", "plaintext")


@app.get("/", include_in_schema=False)
def index_page(request: Request):
    jobs, total = repository.list_jobs(page=1, per_page=5)
    recent = [job_to_dict(job) for job in jobs]
    meta = {
        "model": config.settings.llm_model,
        "base_url": config.settings.llm_base_url,
        "has_key": config.settings.has_llm_key,
        "demo_cache": config.settings.demo_cache,
        "repair_enabled": config.settings.repair_enabled,
        "guard_recheck": config.settings.guard_recheck,
        "max_upload_mb": config.settings.max_upload_mb,
        "max_http_body_kb": config.settings.max_http_body_kb,
        "max_candidates": config.settings.max_candidates,
        "kb_top_k": config.settings.kb_top_k,
    }
    return templates.TemplateResponse(
        request,
        "index.html",
        {"page": "index", "recent_jobs": recent, "recent_total": total, "meta": meta},
    )


@app.get("/scans/{job_id}", include_in_schema=False)
def scan_page(request: Request, job_id: str):
    job_row = repository.get_job(job_id)
    if not job_row:
        raise AppError("E_NOT_FOUND", "扫描任务不存在", 404)

    findings = [
        finding_to_dict(item) for item in repository.get_findings(job_id)
    ]
    for finding in findings:
        latest = repository.latest_repair_for_finding(finding["id"])
        finding["latest_repair"] = latest
    suspicious = repository.get_suspicious(job_row)
    job = job_to_dict(job_row)
    upload_row = repository.get_upload(job_row.get("input_ref") or "")
    text = _read_upload_text(upload_row)

    code_lines: list[dict] = []
    raw_lines: list[dict] = []
    http_view = None
    truncated = False
    if job_row["input_type"] == "code":
        all_lines = build_code_lines(text, findings, suspicious)
        truncated = len(all_lines) > 3000
        code_lines = all_lines[:3000]
    else:
        all_lines = build_raw_lines(text, suspicious)
        truncated = len(all_lines) > 2000
        raw_lines = all_lines[:2000]
        http_view = build_http_view(text)

    return templates.TemplateResponse(
        request,
        "scan.html",
        {
            "page": "scan",
            "job": job,
            "findings": findings,
            "suspicious_content": suspicious,
            "code_lines": code_lines,
            "raw_lines": raw_lines,
            "http_view": http_view,
            "code_language": _hljs_language(job.get("language")),
            "truncated": truncated,
            "repair_enabled": config.settings.repair_enabled,
        },
    )


@app.get("/repairs/{repair_id}", include_in_schema=False)
def repair_page(request: Request, repair_id: str):
    detail = RepairService().get_detail(repair_id)
    finding_raw = detail.get("finding")
    finding = finding_to_dict(finding_raw) if finding_raw else None
    job_view = None
    if finding_raw:
        job_row = repository.get_job(finding_raw["job_id"])
        if job_row:
            job_view = job_to_dict(job_row)

    return templates.TemplateResponse(
        request,
        "repair.html",
        {
            "page": "repair",
            "repair": detail,
            "finding": finding,
            "job": job_view,
            "diff_lines": build_diff_lines(detail.get("diff") or ""),
            "code_language": _hljs_language((job_view or {}).get("language")),
            "repair_enabled": config.settings.repair_enabled,
        },
    )


@app.get("/history", include_in_schema=False)
def history_page(request: Request):
    try:
        page_number = max(int(request.query_params.get("page", "1")), 1)
    except ValueError:
        page_number = 1
    status_raw = request.query_params.get("status", "")
    status = status_raw if status_raw in STATUS_DISPLAY else None
    per_page = 20
    jobs, total = repository.list_jobs(page=page_number, per_page=per_page, status=status)
    pages = max((total + per_page - 1) // per_page, 1)
    if page_number > pages:
        page_number = pages
        jobs, total = repository.list_jobs(
            page=page_number, per_page=per_page, status=status
        )
    return templates.TemplateResponse(
        request,
        "history.html",
        {
            "page": "history",
            "jobs": [job_to_dict(job) for job in jobs],
            "total": total,
            "page_number": page_number,
            "pages": pages,
            "status_filter": status_raw if status_raw in STATUS_DISPLAY else "",
            "status_options": list(STATUS_DISPLAY.items()),
        },
    )
