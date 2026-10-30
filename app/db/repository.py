from __future__ import annotations

import json
from typing import Any, Iterable

from app.core.util import now_utc
from app.db.database import get_connection

_JOB_FIELDS = {
    "status",
    "stage",
    "model",
    "prompt_tokens",
    "completion_tokens",
    "duration_ms",
    "llm_output_invalid",
    "cached",
    "suspicious_json",
    "error",
    "filename",
    "language",
}


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _loads(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------- uploads


def create_upload(
    upload_id: str,
    filename: str,
    language: str | None,
    stored_name: str,
    sha256: str,
    size: int,
) -> None:
    conn = get_connection()
    try:
        with conn:
            conn.execute(
                "INSERT INTO uploads (id, filename, language, stored_name, sha256, size, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (upload_id, filename, language, stored_name, sha256, size, now_utc()),
            )
    finally:
        conn.close()


def get_upload(upload_id: str) -> dict | None:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM uploads WHERE id = ?", (upload_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def find_upload_by_sha(sha256: str) -> dict | None:
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM uploads WHERE sha256 = ? ORDER BY created_at DESC LIMIT 1",
            (sha256,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


# ------------------------------------------------------------------ jobs


def create_job(
    job_id: str,
    input_type: str,
    input_ref: str | None,
    filename: str | None,
    language: str | None,
    model: str,
) -> None:
    conn = get_connection()
    try:
        with conn:
            conn.execute(
                "INSERT INTO scan_jobs (id, input_type, input_ref, filename, language, status,"
                " stage, model, created_at) VALUES (?, ?, ?, ?, ?, 'PENDING', 'PARSING', ?, ?)",
                (job_id, input_type, input_ref, filename, language, model, now_utc()),
            )
    finally:
        conn.close()


def update_job(job_id: str, **fields: Any) -> None:
    payload = {k: v for k, v in fields.items() if k in _JOB_FIELDS}
    if not payload:
        return
    assignments = ", ".join(f"{key} = ?" for key in payload)
    values = list(payload.values()) + [job_id]
    conn = get_connection()
    try:
        with conn:
            conn.execute(f"UPDATE scan_jobs SET {assignments} WHERE id = ?", values)
    finally:
        conn.close()


def get_job(job_id: str) -> dict | None:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_jobs(page: int = 1, per_page: int = 20, status: str | None = None) -> tuple[list[dict], int]:
    page = max(page, 1)
    per_page = min(max(per_page, 1), 100)
    offset = (page - 1) * per_page
    where = ""
    params: list[Any] = []
    if status in {"PENDING", "RUNNING", "DONE", "FAILED"}:
        where = " WHERE status = ?"
        params.append(status)
    conn = get_connection()
    try:
        total = conn.execute(f"SELECT COUNT(*) FROM scan_jobs{where}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM scan_jobs{where} ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?",
            [*params, per_page, offset],
        ).fetchall()
        return [dict(row) for row in rows], int(total)
    finally:
        conn.close()


def mark_running_jobs_failed(message: str) -> int:
    conn = get_connection()
    try:
        with conn:
            cursor = conn.execute(
                "UPDATE scan_jobs SET status = 'FAILED', stage = NULL, error = ?"
                " WHERE status IN ('PENDING', 'RUNNING')",
                (message,),
            )
            return cursor.rowcount
    finally:
        conn.close()


def set_suspicious(job_id: str, suspicious: list[dict]) -> None:
    update_job(job_id, suspicious_json=_dumps(suspicious))


def get_suspicious(job: dict) -> list[dict]:
    return _loads(job.get("suspicious_json"), [])


# -------------------------------------------------------------- findings


def save_findings(job_id: str, findings: Iterable[dict]) -> None:
    conn = get_connection()
    try:
        with conn:
            for item in findings:
                conn.execute(
                    "INSERT INTO findings (id, job_id, vuln_type, severity, confidence,"
                    " location_type, location, line_start, line_end, rule_id, cwe_id, evidence,"
                    " description, suggestion, source_channel, knowledge_json, factors_json,"
                    " raw_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        item["id"],
                        job_id,
                        item["vuln_type"],
                        item["severity"],
                        item.get("confidence"),
                        item.get("location_type"),
                        item.get("location"),
                        item.get("line_start"),
                        item.get("line_end"),
                        item.get("rule_id"),
                        item.get("cwe_id"),
                        item.get("evidence"),
                        item.get("description"),
                        item.get("suggestion"),
                        item["source_channel"],
                        _dumps(item.get("knowledge", [])),
                        _dumps(item.get("factors", {})),
                        _dumps(item.get("raw", {})),
                        now_utc(),
                    ),
                )
    finally:
        conn.close()


def _finding_row(row) -> dict:
    item = dict(row)
    item["knowledge"] = _loads(item.pop("knowledge_json", None), [])
    item["factors"] = _loads(item.pop("factors_json", None), {})
    item["raw"] = _loads(item.pop("raw_json", None), {})
    return item


def get_findings(job_id: str) -> list[dict]:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM findings WHERE job_id = ? ORDER BY"
            " CASE severity WHEN 'HIGH' THEN 0 WHEN 'MEDIUM' THEN 1 ELSE 2 END,"
            " line_start, created_at",
            (job_id,),
        ).fetchall()
        return [_finding_row(row) for row in rows]
    finally:
        conn.close()


def get_finding(finding_id: str) -> dict | None:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return _finding_row(row) if row else None
    finally:
        conn.close()


def count_findings_by_severity(job_id: str) -> dict:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT severity, source_channel, COUNT(*) AS n FROM findings"
            " WHERE job_id = ? GROUP BY severity, source_channel",
            (job_id,),
        ).fetchall()
    finally:
        conn.close()
    summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "rule_only": 0}
    for row in rows:
        if row["source_channel"] == "rule":
            summary["rule_only"] += row["n"]
        else:
            summary[row["severity"]] += row["n"]
    return summary


# --------------------------------------------------------------- repairs


def create_repair(
    repair_id: str,
    finding_id: str,
    patch_diff: str | None,
    patched_path: str | None,
    syntax_ok: bool | None,
    rescan_clean: bool | None,
    llm_verified: bool | None,
    verified: bool | None,
    notes: str,
) -> None:
    def flag(value: bool | None) -> int | None:
        return None if value is None else int(value)

    conn = get_connection()
    try:
        with conn:
            conn.execute(
                "INSERT INTO repairs (id, finding_id, patch_diff, patched_path, syntax_ok,"
                " rescan_clean, llm_verified, verified, notes, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    repair_id,
                    finding_id,
                    patch_diff,
                    patched_path,
                    flag(syntax_ok),
                    flag(rescan_clean),
                    flag(llm_verified),
                    flag(verified),
                    notes,
                    now_utc(),
                ),
            )
    finally:
        conn.close()


def get_repair(repair_id: str) -> dict | None:
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM repairs WHERE id = ?", (repair_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def latest_repair_for_finding(finding_id: str) -> dict | None:
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM repairs WHERE finding_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1",
            (finding_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()
