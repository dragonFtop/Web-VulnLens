from __future__ import annotations

from app.core.extractor.candidates import VULN_DISPLAY
from app.db import repository

SEVERITY_DISPLAY = {"HIGH": "高危", "MEDIUM": "中危", "LOW": "低危"}
CHANNEL_DISPLAY = {"both": "双通道确认", "llm": "LLM 补漏", "rule": "待复核线索"}
STATUS_DISPLAY = {"PENDING": "排队中", "RUNNING": "执行中", "DONE": "已完成", "FAILED": "失败"}
STAGE_DISPLAY = {
    "PARSING": "解析输入",
    "EXTRACTING": "提取特征",
    "RETRIEVING": "检索知识",
    "LLM_ANALYZING": "模型分析",
    "POSTPROCESSING": "结果校验",
    "FINISHED": "已完成",
}
SEVERITY_CLASS = {"HIGH": "danger", "MEDIUM": "warning", "LOW": "secondary"}
CHANNEL_CLASS = {"both": "danger", "llm": "warning", "rule": "clue"}
STATUS_CLASS = {"PENDING": "secondary", "RUNNING": "info", "DONE": "success", "FAILED": "danger"}


def job_to_dict(job: dict) -> dict:
    status = job.get("status") or "PENDING"
    stage = job.get("stage")
    return {
        "id": job["id"],
        "status": status,
        "status_display": STATUS_DISPLAY.get(status, status),
        "status_class": STATUS_CLASS.get(status, "secondary"),
        "stage": stage,
        "stage_display": STAGE_DISPLAY.get(stage or "", ""),
        "input_type": job["input_type"],
        "filename": job.get("filename"),
        "language": job.get("language"),
        "model": job.get("model"),
        "summary": repository.count_findings_by_severity(job["id"]),
        "prompt_tokens": int(job.get("prompt_tokens") or 0),
        "completion_tokens": int(job.get("completion_tokens") or 0),
        "duration_ms": job.get("duration_ms"),
        "llm_output_invalid": bool(job.get("llm_output_invalid") or 0),
        "cached": bool(job.get("cached") or 0),
        "error": job.get("error"),
        "created_at": job.get("created_at"),
    }


def finding_to_dict(finding: dict) -> dict:
    vuln_type = finding.get("vuln_type") or ""
    severity = finding.get("severity") or "LOW"
    channel = finding.get("source_channel") or "rule"
    knowledge = finding.get("knowledge") or []
    return {
        "id": finding["id"],
        "vuln_type": vuln_type,
        "vuln_type_display": VULN_DISPLAY.get(vuln_type, vuln_type),
        "severity": severity,
        "severity_display": SEVERITY_DISPLAY.get(severity, severity),
        "severity_class": SEVERITY_CLASS.get(severity, "secondary"),
        "confidence": finding.get("confidence"),
        "source_channel": channel,
        "source_display": CHANNEL_DISPLAY.get(channel, channel),
        "source_class": CHANNEL_CLASS.get(channel, "secondary"),
        "location_type": finding.get("location_type"),
        "location": finding.get("location"),
        "line_start": finding.get("line_start"),
        "line_end": finding.get("line_end"),
        "rule_id": finding.get("rule_id"),
        "cwe_id": finding.get("cwe_id"),
        "evidence": finding.get("evidence") or "",
        "description": finding.get("description") or "",
        "suggestion": finding.get("suggestion") or "",
        "knowledge_ids": [
            entry.get("id") for entry in knowledge if isinstance(entry, dict) and entry.get("id")
        ],
        "knowledge": knowledge,
        "factors": finding.get("factors") or {},
        "raw": finding.get("raw") or {},
        "created_at": finding.get("created_at"),
    }


def repair_to_dict(repair: dict, download_url: str | None = None) -> dict:
    def flag(value):
        return None if value is None else bool(value)

    payload = {
        "repair_id": repair["id"],
        "finding_id": repair["finding_id"],
        "syntax_ok": flag(repair.get("syntax_ok")),
        "rescan_clean": flag(repair.get("rescan_clean")),
        "llm_verified": flag(repair.get("llm_verified")),
        "verified": flag(repair.get("verified")),
        "notes": repair.get("notes") or "",
        "created_at": repair.get("created_at"),
    }
    if download_url:
        payload["download_url"] = download_url
    return payload
