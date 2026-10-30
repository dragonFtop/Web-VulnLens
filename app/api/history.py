from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Query

from app.api.serializers import job_to_dict
from app.db import repository

router = APIRouter()

StatusFilter = Literal["PENDING", "RUNNING", "DONE", "FAILED"]


@router.get("/scans")
def list_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: StatusFilter | None = None,
) -> dict:
    jobs, total = repository.list_jobs(page=page, per_page=per_page, status=status)
    pages = max((total + per_page - 1) // per_page, 1)
    return {
        "page": page,
        "per_page": per_page,
        "pages": pages,
        "total": total,
        "items": [job_to_dict(job) for job in jobs],
    }
