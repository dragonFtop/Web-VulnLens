from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from app import config
from app.core.llm.client import Usage
from app.db.database import init_db

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


class FakeLLM:
    def __init__(self, responses: list[dict]) -> None:
        self.responses = list(responses)
        self.calls: list[dict] = []

    def chat_json(
        self,
        messages,
        *,
        max_tokens: int = 4096,
        use_cache=None,
        job_id: str = "",
        prompt_version: str = "",
    ):
        if not self.responses:
            raise AssertionError("测试中的 LLM 调用次数超出预期")
        self.calls.append(
            {
                "messages": messages,
                "max_tokens": max_tokens,
                "job_id": job_id,
                "prompt_version": prompt_version,
                "use_cache": use_cache,
            }
        )
        data = self.responses.pop(0)
        return data, Usage(
            prompt_tokens=120,
            completion_tokens=40,
            latency_ms=15,
            calls=1,
        )


@pytest.fixture()
def isolated_settings(tmp_path, monkeypatch):
    settings = dataclasses.replace(
        config.settings,
        base_dir=tmp_path,
        storage_dir=tmp_path / "storage",
        uploads_dir=tmp_path / "storage" / "uploads",
        patched_dir=tmp_path / "storage" / "patched",
        reports_dir=tmp_path / "storage" / "reports",
        cache_dir=tmp_path / "storage" / "cache",
        db_path=tmp_path / "test.db",
        samples_dir=SAMPLES_DIR,
        llm_api_key="test-key",
        demo_cache=False,
        repair_verify_llm=False,
        guard_recheck=False,
        llm_max_retries=0,
        llm_timeout=5,
    )
    settings.ensure_dirs()
    monkeypatch.setattr(config, "settings", settings)
    init_db(settings.db_path)
    return settings


def read_sample(relative: str) -> bytes:
    return (SAMPLES_DIR / relative).read_bytes()
