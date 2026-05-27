"""Data models for validation findings and reports."""

from pydantic import BaseModel, Field
from datetime import datetime


class Finding(BaseModel):
    """A single validation finding."""

    rule_id: str
    severity: str = Field(
        ..., description="Severity level: CRITICAL, HIGH, MEDIUM, LOW, INFO"
    )
    message: str
    path: str | None = None
    line: int | None = None


class ValidationReport(BaseModel):
    """Complete validation report."""

    spec_title: str
    spec_version: str
    findings: list[Finding] = Field(default_factory=list)
    total_findings: int
    passed: bool
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}
