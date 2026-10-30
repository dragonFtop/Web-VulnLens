from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


class ConfigError(RuntimeError):
    pass


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"配置项 {name} 必须是整数") from exc


def _float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"配置项 {name} 必须是数字") from exc


@dataclass(frozen=True)
class Settings:
    base_dir: Path
    storage_dir: Path
    uploads_dir: Path
    patched_dir: Path
    reports_dir: Path
    cache_dir: Path
    samples_dir: Path
    db_path: Path

    llm_api_key: str
    llm_base_url: str
    llm_model: str
    llm_temperature: float
    llm_timeout: int
    llm_max_retries: int
    llm_json_mode: bool

    max_upload_mb: int
    max_http_body_kb: int
    max_llm_code_chars: int
    max_candidates: int
    kb_top_k: int

    repair_enabled: bool
    repair_max_file_kb: int
    repair_verify_llm: bool
    demo_cache: bool
    guard_recheck: bool

    log_level: str

    @property
    def has_llm_key(self) -> bool:
        return bool(self.llm_api_key.strip())

    def ensure_dirs(self) -> None:
        for path in (
            self.storage_dir,
            self.uploads_dir,
            self.patched_dir,
            self.reports_dir,
            self.cache_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)


def load_settings() -> Settings:
    storage_dir = BASE_DIR / "storage"
    db_raw = os.getenv("DB_PATH", "storage/app.db").strip() or "storage/app.db"
    db_path = Path(db_raw)
    if not db_path.is_absolute():
        db_path = BASE_DIR / db_path

    settings = Settings(
        base_dir=BASE_DIR,
        storage_dir=storage_dir,
        uploads_dir=storage_dir / "uploads",
        patched_dir=storage_dir / "patched",
        reports_dir=storage_dir / "reports",
        cache_dir=storage_dir / "cache",
        samples_dir=BASE_DIR / "samples",
        db_path=db_path,
        llm_api_key=os.getenv("LLM_API_KEY", "").strip(),
        llm_base_url=os.getenv("LLM_BASE_URL", "https://api.deepseek.com/v1").strip(),
        llm_model=os.getenv("LLM_MODEL", "deepseek-chat").strip(),
        llm_temperature=_float("LLM_TEMPERATURE", 0.1),
        llm_timeout=_int("LLM_TIMEOUT", 60),
        llm_max_retries=_int("LLM_MAX_RETRIES", 2),
        llm_json_mode=_bool("LLM_JSON_MODE", True),
        max_upload_mb=_int("MAX_UPLOAD_MB", 1),
        max_http_body_kb=_int("MAX_HTTP_BODY_KB", 256),
        max_llm_code_chars=_int("MAX_LLM_CODE_CHARS", 24000),
        max_candidates=_int("MAX_CANDIDATES", 20),
        kb_top_k=_int("KB_TOP_K", 3),
        repair_enabled=_bool("REPAIR_ENABLED", True),
        repair_max_file_kb=_int("REPAIR_MAX_FILE_KB", 100),
        repair_verify_llm=_bool("REPAIR_VERIFY_LLM", True),
        demo_cache=_bool("DEMO_CACHE", True),
        guard_recheck=_bool("GUARD_RECHECK", True),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
    )

    settings.ensure_dirs()
    if not settings.has_llm_key and not settings.demo_cache:
        raise ConfigError(
            "未配置 LLM_API_KEY，且 DEMO_CACHE 未开启。请在 .env 中填写密钥，"
            "或开启 DEMO_CACHE 使用本地缓存结果。"
        )
    return settings


settings = load_settings()
