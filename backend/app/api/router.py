from pathlib import Path
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import Identity, Operator
from app.core.config import AwsConnection, get_settings
from app.core.domain import AuditEvent, Finding, ScanHistory, ScanResult, Severity
from app.db.models import AuditRecord, ScanRecord
from app.db.session import get_db
from app.scanners.aws import AwsInventoryProvider
from app.scanners.fixture import FixtureInventoryProvider
from app.services.desktop_connection import DesktopConnectionStore
from app.services.findings import FindingRepository
from app.services.assistant import ask_llm
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


@router.post("/assistant", response_model=AssistantResponse)
def assistant(payload: AssistantRequest, db: DatabaseSession, principal: Identity) -> AssistantResponse:
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
        role_arn=connection.role_arn, account_id=connection.account_id, region=connection.region
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
        role_arn=payload.role_arn, account_id=payload.account_id, region=payload.region
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
            payload.region, payload.role_arn, payload.external_id, payload.account_id
        )
    except Exception as exc:
        raise HTTPException(
            422, "AWS role validation failed. Check AWS SSO/profile and trust policy."
        ) from exc
    return DesktopAwsConnectionView(
        role_arn=payload.role_arn, account_id=payload.account_id, region=payload.region
    )


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/findings", response_model=list[Finding])
def list_findings(
    db: DatabaseSession,
    principal: Identity,
    severity: Severity | None = None,
    source: Literal["demo-fixture", "aws"] = "demo-fixture",
    limit: Limit = 100,
    offset: Offset = 0,
) -> list[Finding]:
    return FindingRepository(db, principal.tenant_id, source).list(severity, limit, offset)


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
        raise HTTPException(403, "AWS scanning requires an authenticated, configured organization")
    return execute_scan(
        ScanService(
            db,
            lambda: AwsInventoryProvider(
                connection.region,
                connection.role_arn,
                connection.external_id,
                connection.account_id,
            ),
            "aws",
            principal,
        )
    )
