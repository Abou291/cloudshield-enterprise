from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import Identity, Operator
from app.core.config import AwsConnection, get_settings
from app.core.domain import (
    AuditEvent,
    Finding,
    FindingStatus,
    ScanHistory,
    ScanResult,
    Severity,
)
from app.db.models import AlertRecord, AuditRecord, MonitorState, ScanRecord
from app.db.session import engine, get_db
from app.monitoring.events import Alert
from app.monitoring.notify import send_webhook, validate_webhook_url
from app.monitoring.runtime import build_service
from app.monitoring.service import health as monitor_health
from app.scanners.aws import AwsInventoryProvider
from app.scanners.fixture import FixtureInventoryProvider
from app.services.assistant import ask_llm
from app.services.backup import DesktopBackupService
from app.services.compliance import build_compliance_posture
from app.services.desktop_connection import DesktopConnectionStore
from app.services.diagnostics import (
    aws_diagnostics,
    base_diagnostics,
    classify_aws_error,
)
from app.services.findings import FindingRepository
from app.services.reporting import (
    build_attack_paths,
    build_executive_summary,
    build_security_report,
)
from app.services.scans import ScanBusyError, ScanFailedError, ScanService

router = APIRouter(prefix="/api/v1")
FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "demo_inventory.json"
DatabaseSession = Annotated[Session, Depends(get_db)]
Limit = Annotated[int, Query(ge=1, le=500)]
Offset = Annotated[int, Query(ge=0, le=100000)]


@router.get("/session")
def session(principal: Identity) -> dict:
    settings = get_settings()
    desktop_connection = DesktopConnectionStore(settings.desktop_config_path).get()
    return {
        **principal.model_dump(),
        "desktop": settings.desktop_mode,
        "aws_enabled": (
            principal.tenant_id in settings.aws_connections
            or (settings.desktop_mode and desktop_connection is not None)
        ),
    }


class DesktopAwsConnectionInput(AwsConnection):
    pass


class AssistantRequest(BaseModel):
    question: str
    source: Literal["demo-fixture", "aws"] = "demo-fixture"


class AssistantResponse(BaseModel):
    answer: str
    model: str
    findings_used: int


class RestoreBackupRequest(BaseModel):
    confirmation: str


class FindingStatusInput(BaseModel):
    status: FindingStatus


@router.post("/assistant", response_model=AssistantResponse)
def assistant(
    payload: AssistantRequest,
    db: DatabaseSession,
    principal: Identity,
) -> AssistantResponse:
    question = payload.question.strip()
    if not question or len(question) > 2000:
        raise HTTPException(422, "Question must contain between 1 and 2000 characters")
    findings = FindingRepository(db, principal.tenant_id, payload.source).list(None, 30, 0)
    try:
        answer, model = ask_llm(get_settings(), question, findings)
    except RuntimeError as exc:
        raise HTTPException(503, "Security copilot provider is temporarily unavailable") from exc
    return AssistantResponse(answer=answer, model=model, findings_used=len(findings))


class DesktopAwsConnectionView(BaseModel):
    role_arn: str
    account_id: str
    region: str
    profile_name: str | None = None
    scan_all_regions: bool = False


def local_connection() -> AwsConnection | None:
    settings = get_settings()
    if not settings.desktop_mode:
        return None
    return DesktopConnectionStore(settings.desktop_config_path).get()


@router.get("/connections/aws", response_model=DesktopAwsConnectionView)
def get_desktop_aws_connection(principal: Operator) -> DesktopAwsConnectionView:
    connection = local_connection()
    if connection is None:
        raise HTTPException(404, "No desktop AWS connection configured")
    return DesktopAwsConnectionView(
        role_arn=connection.role_arn,
        account_id=connection.account_id,
        region=connection.region,
        profile_name=connection.profile_name,
        scan_all_regions=connection.scan_all_regions,
    )


@router.put("/connections/aws", response_model=DesktopAwsConnectionView)
def save_desktop_aws_connection(
    payload: DesktopAwsConnectionInput, principal: Operator
) -> DesktopAwsConnectionView:
    settings = get_settings()
    if not settings.desktop_mode:
        raise HTTPException(404, "AWS desktop configuration is unavailable")
    DesktopConnectionStore(settings.desktop_config_path).save(payload)
    return DesktopAwsConnectionView(
        role_arn=payload.role_arn,
        account_id=payload.account_id,
        region=payload.region,
        profile_name=payload.profile_name,
        scan_all_regions=payload.scan_all_regions,
    )


@router.post("/connections/aws/test", response_model=DesktopAwsConnectionView)
def test_desktop_aws_connection(
    payload: DesktopAwsConnectionInput, principal: Operator
) -> DesktopAwsConnectionView:
    settings = get_settings()
    if not settings.desktop_mode:
        raise HTTPException(404, "AWS desktop configuration is unavailable")
    try:
        AwsInventoryProvider(
            payload.region,
            payload.role_arn,
            payload.external_id,
            payload.account_id,
            payload.profile_name,
            payload.scan_all_regions,
        )
    except Exception as exc:
        code, message = classify_aws_error(exc)
        raise HTTPException(422, f"{code}: {message}") from exc
    return DesktopAwsConnectionView(
        role_arn=payload.role_arn,
        account_id=payload.account_id,
        region=payload.region,
        profile_name=payload.profile_name,
        scan_all_regions=payload.scan_all_regions,
    )


@router.get("/diagnostics")
def diagnostics(db: DatabaseSession, principal: Identity) -> dict:
    settings = get_settings()
    result = base_diagnostics(db, settings)
    result["tenant_id"] = principal.tenant_id
    result["aws_configured"] = principal.tenant_id in settings.aws_connections or (
        settings.desktop_mode and local_connection() is not None
    )
    return result


@router.post("/diagnostics/aws")
def diagnostics_aws(principal: Operator) -> dict:
    settings = get_settings()
    connection = settings.aws_connections.get(principal.tenant_id) or local_connection()
    if connection is None:
        raise HTTPException(404, "No AWS connection is configured")
    return aws_diagnostics(connection)


def desktop_backup_service() -> DesktopBackupService:
    settings = get_settings()
    if not settings.desktop_mode or settings.desktop_config_path is None:
        raise HTTPException(404, "Desktop backup is unavailable")
    return DesktopBackupService(
        settings.database_url,
        settings.desktop_config_path.parent / "backups",
    )


@router.post("/backups")
def create_backup(principal: Operator) -> dict:
    try:
        return desktop_backup_service().create()
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.post("/backups/restore-latest")
def restore_latest_backup(payload: RestoreBackupRequest, principal: Operator) -> dict:
    if payload.confirmation != "RESTORE":
        raise HTTPException(422, "Explicit RESTORE confirmation is required")
    service = desktop_backup_service()
    engine.dispose()
    try:
        return service.restore_latest()
    except RuntimeError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get("/reports/security")
def security_report(
    db: DatabaseSession,
    principal: Identity,
    source: Literal["demo-fixture", "aws"] = "aws",
) -> dict:
    findings = FindingRepository(db, principal.tenant_id, source).list(None, 500, 0)
    scans = list(
        db.scalars(
            select(ScanRecord)
            .where(ScanRecord.tenant_id == principal.tenant_id)
            .order_by(ScanRecord.started_at.desc(), ScanRecord.scan_id)
            .limit(100)
        )
    )
    return build_security_report(principal.tenant_id, source, findings, scans)


@router.get("/executive-summary")
def executive_summary(
    db: DatabaseSession,
    principal: Identity,
    source: Literal["demo-fixture", "aws"] = "aws",
) -> dict:
    findings = FindingRepository(db, principal.tenant_id, source).list(None, 500, 0)
    return build_executive_summary(findings)


@router.get("/attack-paths")
def attack_paths(
    db: DatabaseSession,
    principal: Identity,
    source: Literal["demo-fixture", "aws"] = "aws",
) -> list[dict]:
    findings = FindingRepository(db, principal.tenant_id, source).list(None, 500, 0)
    return build_attack_paths(findings)


@router.get("/compliance")
def compliance_posture(
    db: DatabaseSession,
    principal: Identity,
    source: Literal["demo-fixture", "aws"] = "aws",
) -> dict:
    findings = FindingRepository(db, principal.tenant_id, source).list(None, 500, 0)
    return build_compliance_posture(findings)


@router.get("/health")
def health() -> dict[str, str | None]:
    return {"status": "ok", "instance": get_settings().instance_nonce}


@router.get("/findings", response_model=list[Finding])
def list_findings(
    db: DatabaseSession,
    principal: Identity,
    severity: Severity | None = None,
    source: Literal["demo-fixture", "aws"] = "demo-fixture",
    limit: Limit = 100,
    offset: Offset = 0,
    include_resolved: bool = False,
) -> list[Finding]:
    return FindingRepository(db, principal.tenant_id, source).list(
        severity,
        limit,
        offset,
        include_resolved,
    )


@router.patch("/findings/{fingerprint}/status", response_model=Finding)
def update_finding_status(
    fingerprint: str,
    payload: FindingStatusInput,
    db: DatabaseSession,
    principal: Operator,
    source: Literal["demo-fixture", "aws"] = "demo-fixture",
) -> Finding:
    repository = FindingRepository(db, principal.tenant_id, source)
    finding = repository.set_status(fingerprint, payload.status)
    if finding is None:
        raise HTTPException(404, "Finding not found")
    db.add(
        AuditRecord(
            event_id=str(uuid4()),
            tenant_id=principal.tenant_id,
            subject=principal.subject,
            action=f"finding.{payload.status.value}",
            object_id=fingerprint[:36],
            timestamp=datetime.now(UTC),
        )
    )
    db.commit()
    return finding


@router.get("/scans", response_model=list[ScanHistory])
def scan_history(
    db: DatabaseSession, principal: Identity, limit: Limit = 100, offset: Offset = 0
) -> list[ScanRecord]:
    return list(
        db.scalars(
            select(ScanRecord)
            .where(
                ScanRecord.tenant_id == principal.tenant_id,
            )
            .order_by(ScanRecord.started_at.desc(), ScanRecord.scan_id)
            .offset(offset)
            .limit(limit)
        )
    )


@router.get("/scans/{scan_id}", response_model=ScanHistory)
def scan_detail(scan_id: str, db: DatabaseSession, principal: Identity) -> ScanRecord:
    record = db.scalar(
        select(ScanRecord).where(
            ScanRecord.scan_id == scan_id,
            ScanRecord.tenant_id == principal.tenant_id,
        )
    )
    if record is None:
        raise HTTPException(404, "Scan not found")
    return record


@router.get("/audit", response_model=list[AuditEvent])
def audit_events(
    db: DatabaseSession, principal: Identity, limit: Limit = 100, offset: Offset = 0
) -> list[AuditRecord]:
    return list(
        db.scalars(
            select(AuditRecord)
            .where(
                AuditRecord.tenant_id == principal.tenant_id,
            )
            .order_by(AuditRecord.timestamp.desc(), AuditRecord.event_id)
            .offset(offset)
            .limit(limit)
        )
    )


def execute_scan(service: ScanService) -> ScanResult:
    try:
        return service.run()
    except ScanBusyError as exc:
        raise HTTPException(409, "A scan is already active for this organization") from exc
    except ScanFailedError as exc:
        raise HTTPException(503, "Scan failed; previous findings were preserved") from exc


@router.post("/scans/demo", response_model=ScanResult, status_code=status.HTTP_201_CREATED)
def run_demo_scan(db: DatabaseSession, principal: Operator) -> ScanResult:
    return execute_scan(
        ScanService(
            db,
            lambda: FixtureInventoryProvider(FIXTURE_PATH),
            "demo-fixture",
            principal,
        )
    )


@router.post("/scans/aws", response_model=ScanResult, status_code=status.HTTP_201_CREATED)
def run_aws_scan(db: DatabaseSession, principal: Operator) -> ScanResult:
    settings = get_settings()
    connection = settings.aws_connections.get(principal.tenant_id) or local_connection()
    if connection is None or (principal.demo and not settings.desktop_mode):
        raise HTTPException(
            403,
            "AWS scanning requires an authenticated, configured organization",
        )
    try:
        provider = AwsInventoryProvider(
            connection.region,
            connection.role_arn,
            connection.external_id,
            connection.account_id,
            connection.profile_name,
            connection.scan_all_regions,
        )
    except Exception as exc:
        code, message = classify_aws_error(exc)
        raise HTTPException(422, f"{code}: {message}") from exc
    return execute_scan(
        ScanService(
            db,
            lambda: provider,
            "aws",
            principal,
        )
    )


def _monitor_connection(principal: Identity) -> AwsConnection:
    settings = get_settings()
    connection = settings.aws_connections.get(principal.tenant_id) or local_connection()
    if connection is None or (principal.demo and not settings.desktop_mode):
        raise HTTPException(403, "Monitoring requires an authenticated, configured organization")
    return connection


@router.get("/monitoring/status")
def monitoring_status(db: DatabaseSession, principal: Identity) -> dict:
    settings = get_settings()
    state = db.get(MonitorState, principal.tenant_id)
    open_alerts = db.scalars(
        select(AlertRecord).where(
            AlertRecord.tenant_id == principal.tenant_id, AlertRecord.status == "open"
        )
    ).all()
    summary = _monitor_health(state, settings.monitor_interval_seconds)
    summary["interval_seconds"] = settings.monitor_interval_seconds
    summary["webhook_configured"] = bool(settings.monitor_webhook_url)
    summary["open_alerts"] = len(open_alerts)
    return summary


def _monitor_health(state: MonitorState | None, interval_seconds: int) -> dict:
    return monitor_health(state, interval_seconds, datetime.now(UTC))


@router.get("/monitoring/alerts")
def monitoring_alerts(
    db: DatabaseSession,
    principal: Identity,
    status_filter: Annotated[Literal["open", "acknowledged"] | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[dict]:
    query = select(AlertRecord).where(AlertRecord.tenant_id == principal.tenant_id)
    if status_filter:
        query = query.where(AlertRecord.status == status_filter)
    rows = db.scalars(query.order_by(AlertRecord.occurred_at.desc()).limit(limit))
    return [
        {
            "alert_id": r.alert_id,
            "rule_id": r.rule_id,
            "title": r.title,
            "severity": r.severity,
            "source": r.source,
            "occurred_at": r.occurred_at.isoformat(),
            "principal": r.principal,
            "source_ip": r.source_ip,
            "region": r.region,
            "summary": r.summary,
            "status": r.status,
        }
        for r in rows
    ]


@router.post("/monitoring/alerts/{alert_id}/ack")
def acknowledge_alert(alert_id: str, db: DatabaseSession, principal: Operator) -> dict:
    record = db.get(AlertRecord, (principal.tenant_id, alert_id))
    if record is None:
        raise HTTPException(404, "Alert not found")
    record.status = "acknowledged"
    db.commit()
    return {"alert_id": alert_id, "status": record.status}


@router.post("/monitoring/run")
def monitoring_run(db: DatabaseSession, principal: Operator) -> dict:
    connection = _monitor_connection(principal)
    try:
        service = build_service(db, principal.tenant_id, connection, get_settings())
    except Exception as exc:
        code, message = classify_aws_error(exc)
        raise HTTPException(422, f"{code}: {message}") from exc
    return service.run_cycle()


@router.post("/monitoring/test-webhook")
def monitoring_test_webhook(principal: Operator) -> dict:
    url = get_settings().monitor_webhook_url
    if not url:
        raise HTTPException(409, "No webhook configured (CLOUDSHIELD_MONITOR_WEBHOOK_URL)")
    validate_webhook_url(url)
    test = Alert(
        rule_id="TEST",
        title="AegisShield webhook test",
        severity="low",
        occurred_at=datetime.now(UTC),
        principal="test",
        source_ip="",
        region="",
        summary="This is a test notification; no action is required.",
        dedupe_key="test",
    )
    return {"delivered": send_webhook(url, [test])}
