from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import FileResponse

from app.services.repair_service import RepairService

router = APIRouter()


@router.post("/findings/{finding_id}/repair")
def create_repair(finding_id: str) -> dict:
    return RepairService().create_repair(finding_id)


@router.get("/repairs/{repair_id}")
def get_repair(repair_id: str) -> dict:
    return RepairService().get_detail(repair_id)


@router.get("/repairs/{repair_id}/download")
def download_repair(repair_id: str) -> FileResponse:
    path, filename = RepairService().get_download(repair_id)
    return FileResponse(path, filename=filename, media_type="application/octet-stream")
