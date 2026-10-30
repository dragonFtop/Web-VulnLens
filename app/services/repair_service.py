from __future__ import annotations

import logging
from pathlib import Path

from app import config
from app.core.llm.client import LLMClient
from app.core.parser.code_parser import parse_code
from app.core.repair.patcher import build_diff, generate_patch, syntax_check
from app.core.repair.verifier import llm_verify, rescan_clean
from app.core.util import new_id, safe_join
from app.db import repository
from app.errors import AppError, LLMError

logger = logging.getLogger(__name__)


class RepairService:
    def __init__(
        self,
        settings: config.Settings | None = None,
        client: LLMClient | None = None,
    ) -> None:
        self.settings = settings or config.settings
        self.client = client or LLMClient(self.settings)

    def create_repair(self, finding_id: str) -> dict:
        if not self.settings.repair_enabled:
            raise AppError("E_REPAIR_DISABLED", "修复功能未启用", 400)
        finding = repository.get_finding(finding_id)
        if not finding:
            raise AppError("E_NOT_FOUND", "漏洞记录不存在", 404)
        job = repository.get_job(finding["job_id"])
        if not job:
            raise AppError("E_NOT_FOUND", "扫描任务不存在", 404)
        if job["input_type"] != "code":
            raise AppError(
                "E_INPUT_FORMAT",
                "仅代码类任务支持自动修复；请求类结果请参考修复建议人工处理",
                400,
            )
        if finding["source_channel"] == "rule":
            raise AppError(
                "E_INPUT_FORMAT",
                "待复核线索未经模型确认，不能自动修复；请先人工确认漏洞",
                400,
            )
        upload = repository.get_upload(job.get("input_ref") or "")
        if not upload:
            raise AppError("E_NOT_FOUND", "原始上传文件记录不存在", 404)
        stored = safe_join(self.settings.uploads_dir, upload["stored_name"])
        if not stored.is_file():
            raise AppError("E_NOT_FOUND", "原始文件已丢失，请重新上传", 404)
        data = stored.read_bytes()
        if len(data) > self.settings.repair_max_file_kb * 1024:
            raise AppError(
                "E_REPAIR_TOO_LARGE",
                f"文件超过 {self.settings.repair_max_file_kb}KB，仅提供修复建议，"
                "请参考漏洞卡片中的建议人工修改",
                400,
            )
        parsed = parse_code(data, upload["filename"])
        if len(parsed.lines) > 2000:
            raise AppError(
                "E_REPAIR_TOO_LARGE",
                "文件超过 2000 行，仅提供修复建议，请人工修改",
                400,
            )

        repair_id = new_id("r")
        logger.info("生成修复 repair=%s finding=%s", repair_id, finding_id)
        patch = generate_patch(self.client, finding, parsed, job_id=job["id"])
        diff = build_diff(parsed.text, patch.patched_code, parsed.filename)
        syntax_ok = syntax_check(patch.patched_code, parsed.language)

        ext = Path(parsed.filename).suffix.lower()
        if ext not in {".py", ".php", ".js"}:
            ext = ".txt"
        stored_name = f"{repair_id}{ext}"
        patched_path = safe_join(self.settings.patched_dir, stored_name)
        try:
            patched_path.write_text(patch.patched_code, encoding="utf-8")
        except OSError as exc:
            raise AppError("E_INTERNAL", "写入修复文件失败", 500) from exc

        if syntax_ok is False:
            rescan = False
            llm_checked: bool | None = None
            residual = ""
        else:
            rescan = rescan_clean(
                patch.patched_code, parsed.filename, parsed.language, finding["vuln_type"]
            )
            llm_checked = None
            residual = ""
            if self.settings.repair_verify_llm:
                try:
                    llm_checked, residual = llm_verify(
                        self.client,
                        finding,
                        patch.patched_code,
                        parsed.language,
                        job_id=job["id"],
                    )
                except LLMError as exc:
                    logger.warning("修复 LLM 复核失败 repair=%s code=%s", repair_id, exc.code)
                    llm_checked = None
                    residual = f"LLM 复核失败（{exc.code}）"

        if parsed.language == "python":
            verified = bool(syntax_ok) and rescan
        else:
            verified = rescan and llm_checked is not False

        notes_parts = []
        if patch.explanation:
            notes_parts.append(patch.explanation.strip())
        notes_parts.append(
            "验证：语法"
            + ("通过" if syntax_ok is True else "未通过" if syntax_ok is False else "跳过（需人工复核）")
            + "；复扫" + ("未再发现目标漏洞候选" if rescan else "仍发现目标类型候选")
            + "；LLM 复核"
            + ("通过" if llm_checked is True else "未通过" if llm_checked is False else "未执行或失败")
            + "。"
        )
        if residual:
            notes_parts.append(f"残余风险：{residual}")
        notes_parts.append("修复结果仅供参考，上线前必须人工复核。")
        notes = "\n".join(notes_parts)

        repository.create_repair(
            repair_id,
            finding_id,
            diff,
            stored_name,
            syntax_ok,
            rescan,
            llm_checked,
            verified,
            notes,
        )
        return {
            "repair_id": repair_id,
            "finding_id": finding_id,
            "syntax_ok": syntax_ok,
            "rescan_clean": rescan,
            "llm_verified": llm_checked,
            "verified": verified,
            "download_url": f"/api/repairs/{repair_id}/download",
            "notes": notes,
            "usage": {
                "prompt_tokens": patch.usage.prompt_tokens,
                "completion_tokens": patch.usage.completion_tokens,
                "latency_ms": patch.usage.latency_ms,
                "cached": patch.usage.cached,
            },
        }

    def get_detail(self, repair_id: str) -> dict:
        repair = repository.get_repair(repair_id)
        if not repair:
            raise AppError("E_NOT_FOUND", "修复记录不存在", 404)
        finding = repository.get_finding(repair["finding_id"])
        patched_code = ""
        if repair.get("patched_path"):
            try:
                path = safe_join(self.settings.patched_dir, repair["patched_path"])
                if path.is_file():
                    patched_code = path.read_text(encoding="utf-8", errors="replace")
            except ValueError:
                patched_code = ""
        return {
            "repair_id": repair["id"],
            "finding_id": repair["finding_id"],
            "finding": finding,
            "diff": repair.get("patch_diff") or "",
            "patched_code": patched_code,
            "syntax_ok": None if repair["syntax_ok"] is None else bool(repair["syntax_ok"]),
            "rescan_clean": None
            if repair["rescan_clean"] is None
            else bool(repair["rescan_clean"]),
            "llm_verified": None
            if repair["llm_verified"] is None
            else bool(repair["llm_verified"]),
            "verified": None if repair["verified"] is None else bool(repair["verified"]),
            "notes": repair.get("notes") or "",
            "created_at": repair.get("created_at"),
            "download_url": f"/api/repairs/{repair_id}/download",
        }

    def get_download(self, repair_id: str) -> tuple[Path, str]:
        repair = repository.get_repair(repair_id)
        if not repair:
            raise AppError("E_NOT_FOUND", "修复记录不存在", 404)
        if not repair.get("patched_path"):
            raise AppError("E_NOT_FOUND", "该修复记录没有可下载的补丁", 404)
        path = safe_join(self.settings.patched_dir, repair["patched_path"])
        if not path.is_file():
            raise AppError("E_NOT_FOUND", "补丁文件不存在", 404)
        finding = repository.get_finding(repair["finding_id"])
        job = repository.get_job(finding["job_id"]) if finding else None
        original = (job or {}).get("filename") or "patched.txt"
        download_name = f"patched_{Path(original).name}"
        return path, download_name
