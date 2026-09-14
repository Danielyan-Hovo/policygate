from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=1, max_length=128)
    rule_version: str = "1.0"
    severity: Severity
    message: str = Field(min_length=1)
    location: str = "/"
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str | None = None
    fingerprint: str


class EvaluationReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    document_version: str
    findings: list[Finding] = Field(default_factory=list)
    passed: bool
    policy_version: str = "1.0"

    @property
    def errors(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.severity == Severity.ERROR]


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=128)
    version: str = "1.0"
    description: str = ""
    severity: Severity = Severity.ERROR
    selector: dict[str, Any] = Field(default_factory=dict)
    assertion: dict[str, Any] = Field(default_factory=dict)
    exceptions: list[dict[str, Any]] = Field(default_factory=list)
