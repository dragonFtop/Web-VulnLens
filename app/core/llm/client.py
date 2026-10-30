from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from openai import (
    APIConnectionError,
    APIStatusError,
    APITimeoutError,
    AuthenticationError,
    BadRequestError,
    OpenAI,
    PermissionDeniedError,
    RateLimitError,
)

from app import config
from app.core.llm.prompts import PROMPT_VERSION
from app.errors import LLM_AUTH, LLM_JSON, LLM_RATE_LIMIT, LLM_TIMEOUT, LLMError

logger = logging.getLogger(__name__)

RETRY_DELAYS = (2, 5)


@dataclass
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: int = 0
    cached: bool = False
    cached_at: str | None = None
    calls: int = 0
    json_corrections: int = 0

    def merge(self, other: "Usage") -> None:
        self.prompt_tokens += other.prompt_tokens
        self.completion_tokens += other.completion_tokens
        self.latency_ms += other.latency_ms
        self.calls += other.calls
        self.json_corrections += other.json_corrections
        self.cached = self.cached or other.cached
        if other.cached_at:
            self.cached_at = other.cached_at


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_json_object(content: str) -> dict | None:
    if not content:
        return None
    text = content.strip().lstrip("﻿")
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else ""
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
    decoder = json.JSONDecoder()
    starts = [index for index, char in enumerate(text) if char in "[{"]
    for start in starts:
        try:
            value, _ = decoder.raw_decode(text[start:])
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(value, dict):
            return value
        if isinstance(value, list):
            return {"findings": value}
    return None


class LLMClient:
    def __init__(self, settings: config.Settings | None = None) -> None:
        self.settings = settings or config.settings

    # ------------------------------------------------------------------ cache
    def cache_key(
        self, messages: list[dict], max_tokens: int, prompt_version: str = PROMPT_VERSION
    ) -> str:
        payload = {
            "version": prompt_version,
            "model": self.settings.llm_model,
            "temperature": self.settings.llm_temperature,
            "json_mode": self.settings.llm_json_mode,
            "max_tokens": max_tokens,
            "messages": messages,
        }
        blob = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    def _cache_path(self, key: str) -> Path:
        return self.settings.cache_dir / f"{key}.json"

    def _read_cache(self, key: str) -> tuple[dict, Usage] | None:
        path = self._cache_path(key)
        if not path.is_file():
            return None
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            content = raw.get("content")
            if not isinstance(content, str):
                return None
            data = parse_json_object(content)
            if data is None:
                return None
            usage = Usage(
                prompt_tokens=int(raw.get("prompt_tokens") or 0),
                completion_tokens=int(raw.get("completion_tokens") or 0),
                latency_ms=0,
                cached=True,
                cached_at=raw.get("created_at"),
                calls=0,
            )
            return data, usage
        except (OSError, ValueError, TypeError):
            return None

    def _write_cache(self, key: str, content: str, prompt_tokens: int, completion_tokens: int) -> None:
        path = self._cache_path(key)
        payload = {
            "created_at": _now_utc(),
            "model": self.settings.llm_model,
            "prompt_version": PROMPT_VERSION,

            "content": content,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
        }
        tmp = path.with_suffix(".tmp")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            tmp.replace(path)
        except OSError:
            logger.warning("写入演示缓存失败: %s", path.name)
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass

    # -------------------------------------------------------------------- API
    def _build_client(self) -> OpenAI:
        return OpenAI(
            api_key=self.settings.llm_api_key,
            base_url=self.settings.llm_base_url,
            timeout=self.settings.llm_timeout,
            max_retries=0,
        )

    def _sleep_before_retry(self, attempt: int) -> None:
        delay = RETRY_DELAYS[attempt] if attempt < len(RETRY_DELAYS) else RETRY_DELAYS[-1]
        time.sleep(delay)

    def _call_once(self, messages: list[dict], max_tokens: int) -> tuple[str, int, int]:
        client = self._build_client()
        kwargs = {
            "model": self.settings.llm_model,
            "messages": messages,
            "temperature": self.settings.llm_temperature,
            "max_tokens": max_tokens,
        }
        if self.settings.llm_json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        try:
            response = client.chat.completions.create(**kwargs)
        except BadRequestError as exc:
            message = str(exc)
            if "response_format" in message or "json" in message.lower():
                kwargs.pop("response_format", None)
                response = client.chat.completions.create(**kwargs)
            else:
                raise LLMError("E_INTERNAL", f"模型拒绝请求：{message[:200]}", 500) from exc
        content = response.choices[0].message.content if response.choices else None
        usage = response.usage
        prompt_tokens = int(getattr(usage, "prompt_tokens", 0) or 0)
        completion_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
        return content or "", prompt_tokens, completion_tokens

    def _call_with_retries(
        self, messages: list[dict], max_tokens: int
    ) -> tuple[str, int, int, int]:
        retries = 0
        attempts = 0
        while True:
            try:
                content, prompt_tokens, completion_tokens = self._call_once(messages, max_tokens)
                return content, prompt_tokens, completion_tokens, retries
            except (AuthenticationError, PermissionDeniedError) as exc:
                raise LLMError(LLM_AUTH, "LLM 密钥无效或无权限，请检查 API Key 配置", 502) from exc
            except RateLimitError as exc:
                message = str(exc)
                if "balance" in message.lower() or "insufficient" in message.lower():
                    raise LLMError(LLM_RATE_LIMIT, "LLM 账户额度不足", 503) from exc
                if attempts < self.settings.llm_max_retries:
                    self._sleep_before_retry(attempts)
                    attempts += 1
                    retries += 1
                    continue
                raise LLMError(LLM_RATE_LIMIT, "LLM 请求过于频繁，已重试仍失败", 503) from exc
            except APITimeoutError as exc:
                if attempts < self.settings.llm_max_retries:
                    self._sleep_before_retry(attempts)
                    attempts += 1
                    retries += 1
                    continue
                raise LLMError(LLM_TIMEOUT, "模型响应超时，请重试", 504) from exc
            except APIConnectionError as exc:
                if attempts < self.settings.llm_max_retries:
                    self._sleep_before_retry(attempts)
                    attempts += 1
                    retries += 1
                    continue
                raise LLMError(LLM_TIMEOUT, "无法连接模型服务，请检查网络或 LLM_BASE_URL", 504) from exc
            except APIStatusError as exc:
                status = exc.status_code
                if status in (401, 403):
                    raise LLMError(LLM_AUTH, "LLM 密钥无效或无权限，请检查 API Key 配置", 502) from exc
                if status == 402:
                    raise LLMError(LLM_RATE_LIMIT, "LLM 账户额度不足", 503) from exc
                if status == 429 or status >= 500:
                    if attempts < self.settings.llm_max_retries:
                        self._sleep_before_retry(attempts)
                        attempts += 1
                        retries += 1
                        continue
                    code = LLM_RATE_LIMIT if status == 429 else "E_INTERNAL"
                    raise LLMError(code, f"模型服务异常（HTTP {status}）", 503) from exc
                raise LLMError("E_INTERNAL", f"模型请求失败（HTTP {status}）", 500) from exc
            except LLMError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise LLMError("E_INTERNAL", f"模型调用异常：{exc.__class__.__name__}", 500) from exc

    # ------------------------------------------------------------------ public
    def chat_json(
        self,
        messages: list[dict],
        *,
        max_tokens: int = 4096,
        use_cache: bool | None = None,
        job_id: str = "",
        prompt_version: str = PROMPT_VERSION,
    ) -> tuple[dict, Usage]:
        allow_cache = self.settings.demo_cache if use_cache is None else use_cache
        key = self.cache_key(messages, max_tokens, prompt_version)
        if allow_cache:
            cached = self._read_cache(key)
            if cached is not None:
                data, usage = cached
                logger.info(
                    "LLM cache hit | job=%s | model=%s | prompt_tokens=%d | completion_tokens=%d",
                    job_id or "-", self.settings.llm_model, usage.prompt_tokens,
                    usage.completion_tokens,
                )
                return data, usage

        if not self.settings.has_llm_key:
            raise LLMError(
                LLM_AUTH,
                "未配置 LLM_API_KEY，且未命中演示缓存。请在 .env 中填写密钥，或预先填充缓存。",
                502,
                job_id or None,
            )

        started = time.perf_counter()
        content, prompt_tokens, completion_tokens, retries = self._call_with_retries(
            messages, max_tokens
        )
        data = parse_json_object(content)
        json_corrections = 0
        if data is None:
            json_corrections = 1
            correction = list(messages) + [
                {"role": "assistant", "content": content[:12000] or "(空输出)"},
                {
                    "role": "user",
                    "content": "上一条输出无法解析为 JSON。请严格只输出一个合法 JSON 对象，"
                    "不要 Markdown 代码围栏，不要任何解释文字，必须符合先前给出的 Schema。",
                },
            ]
            content2, prompt_tokens2, completion_tokens2, retries2 = self._call_with_retries(
                correction, max_tokens
            )
            prompt_tokens += prompt_tokens2
            completion_tokens += completion_tokens2
            retries += retries2
            data = parse_json_object(content2)
            if data is None:
                raise LLMError(LLM_JSON, "模型输出无法解析为 JSON（已自动纠错一次）", 502)
            content = content2

        latency_ms = int((time.perf_counter() - started) * 1000)
        usage = Usage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            latency_ms=latency_ms,
            cached=False,
            calls=1,
            json_corrections=json_corrections,
        )
        if allow_cache:
            self._write_cache(key, content, prompt_tokens, completion_tokens)
        logger.info(
            "LLM call | job=%s | model=%s | prompt_tokens=%d | completion_tokens=%d | "
            "latency_ms=%d | retries=%d",
            job_id or "-", self.settings.llm_model, prompt_tokens, completion_tokens,
            latency_ms, retries,
        )
        return data, usage
