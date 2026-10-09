from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class FindingRecord(Base):
    # V1 records have no ownership: never assign them to a tenant implicitly.
    __tablename__ = "tenant_findings"

    tenant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    resource_id: Mapped[str] = mapped_column(String(512), index=True)
    resource_type: Mapped[str] = mapped_column(String(64), index=True)
    account_id: Mapped[str] = mapped_column(String(32), index=True)
    region: Mapped[str] = mapped_column(String(64))
    evidence: Mapped[dict] = mapped_column(JSON)
    recommendation: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(24), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, index=True)
    risk_reasons: Mapped[list] = mapped_column(JSON)
    risk_factors: Mapped[dict] = mapped_column(JSON)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ScanRecord(Base):
    __tablename__ = "scan_runs"
    scan_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    source: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    assets_scanned: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    error_code: Mapped[str | None] = mapped_column(String(64))


class ScanLock(Base):
    __tablename__ = "scan_locks"
    tenant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(36))


class AuditRecord(Base):
    __tablename__ = "audit_events"
    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    subject: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(64))
    object_id: Mapped[str] = mapped_column(String(36))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AlertRecord(Base):
    """A behaviour alert raised by the monitor. ``alert_id`` makes ingestion idempotent."""

    __tablename__ = "monitor_alerts"
    tenant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    source: Mapped[str] = mapped_column(String(16))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    principal: Mapped[str] = mapped_column(String(512))
    source_ip: Mapped[str] = mapped_column(String(64))
    region: Mapped[str] = mapped_column(String(32))
    summary: Mapped[str] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    notified: Mapped[bool] = mapped_column(default=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class MonitorState(Base):
    """Per-tenant cursor, learned baseline and last-run health for the monitor."""

    __tablename__ = "monitor_state"
    tenant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    cursor: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    baseline: Mapped[dict] = mapped_column(JSON, default=dict)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[str] = mapped_column(String(16), default="never")
    last_errors: Mapped[list] = mapped_column(JSON, default=list)
    events_seen: Mapped[int] = mapped_column(Integer, default=0)
    alerts_new: Mapped[int] = mapped_column(Integer, default=0)
