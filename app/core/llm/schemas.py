from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

VulnType = Literal["SQL_INJECTION", "XSS", "COMMAND_INJECTION"]
Severity = Literal["HIGH", "MEDIUM", "LOW"]


class Factors(BaseModel):
    model_config = ConfigDict(extra="ignore")

    input_controllable: bool | None = None
    auth_required: bool | None = None
    sanitized: bool | None = None
    reason: str = ""


class SuspiciousContent(BaseModel):
    model_config = ConfigDict(extra="ignore")

    type: str = "PROMPT_INJECTION"
    line: int | None = None
    quote: str = ""
    reason: str = ""


class RawFinding(BaseModel):
    model_config = ConfigDict(extra="ignore")

    candidate_id: str | None = None
    vuln_type: VulnType
    cwe_id: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    location: str | None = None
    evidence: str
    severity_hint: Severity | None = None
    factors: Factors = Field(default_factory=Factors)
    confidence: float = 0.5
    description: str = ""
    suggestion: str = ""
    knowledge_ids: list[str] = Field(default_factory=list)


class RawResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    findings: list[RawFinding] = Field(default_factory=list)
    suspicious_content: list[SuspiciousContent] = Field(default_factory=list)


class RepairChange(BaseModel):
    model_config = ConfigDict(extra="ignore")

    line: int | None = None
    before: str = ""
    after: str = ""


class RepairResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    patched_code: str
    explanation: str = ""
    changes: list[RepairChange] = Field(default_factory=list)


class VerifyResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    fixed: bool = False
    residual_risk: str = ""
    notes: str = ""
