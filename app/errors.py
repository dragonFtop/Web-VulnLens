from __future__ import annotations


class AppError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        http_status: int = 400,
        job_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.job_id = job_id

    def to_dict(self) -> dict:
        payload = {"code": self.code, "message": self.message}
        if self.job_id:
            payload["job_id"] = self.job_id
        return {"error": payload}


class LLMError(AppError):
    """LLM 调用层错误，沿用统一错误码。"""


LLM_AUTH = "E_LLM_AUTH"
LLM_TIMEOUT = "E_LLM_TIMEOUT"
LLM_RATE_LIMIT = "E_LLM_RATE_LIMIT"
LLM_JSON = "E_LLM_JSON"
