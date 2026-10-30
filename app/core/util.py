from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from pathlib import Path


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(4)}"


def new_job_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"j_{stamp}_{secrets.token_hex(4)}"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_join(base: Path, *parts: str) -> Path:
    base_resolved = base.resolve()
    target = base_resolved.joinpath(*parts).resolve()
    if base_resolved != target and base_resolved not in target.parents:
        raise ValueError("path traversal detected")
    return target


def truncate_text(text: str, limit: int) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[:limit], True
