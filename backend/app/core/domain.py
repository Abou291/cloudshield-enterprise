from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class Asset(BaseModel):
    resource_id: str
    resource_type: str
    account_id: str = "local-demo"
    region: str = "global"
    name: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)


class RiskBreakdown(BaseModel):
    score: int = Field(ge=0, le=100)
    reasons: list[str]
    factors: dict[str, float]


class Finding(BaseModel):
    fingerprint: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    resource_id: str
    resource_type: str
    account_id: str
    region: str
    evidence: dict[str, Any]
    recommendation: str
    status: FindingStatus = FindingStatus.OPEN
    risk: RiskBreakdown
    first_seen_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ScanResult(BaseModel):
    scan_id: str
    source: str
    assets_scanned: int
    findings_count: int
    findings: list[Finding]
    completed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

