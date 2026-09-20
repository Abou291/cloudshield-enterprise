from pathlib import Path
from typing import Annotated

from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.domain import Finding, ScanResult, Severity
from app.db.session import get_db
from app.scanners.aws import AwsInventoryProvider
from app.scanners.fixture import FixtureInventoryProvider
from app.services.findings import FindingRepository
from app.services.scans import ScanService

router = APIRouter(prefix="/api/v1")
FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "demo_inventory.json"
DatabaseSession = Annotated[Session, Depends(get_db)]


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/findings", response_model=list[Finding])
def list_findings(
    db: DatabaseSession,
    severity: Severity | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[Finding]:
    return FindingRepository(db).list(severity=severity, limit=limit)


@router.post("/scans/demo", response_model=ScanResult, status_code=status.HTTP_201_CREATED)
def run_demo_scan(db: DatabaseSession) -> ScanResult:
    provider = FixtureInventoryProvider(FIXTURE_PATH)
    return ScanService(db, provider, source="demo-fixture").run()


@router.post("/scans/aws", response_model=ScanResult, status_code=status.HTTP_201_CREATED)
def run_aws_scan(db: DatabaseSession) -> ScanResult:
    settings = get_settings()
    try:
        provider = AwsInventoryProvider(settings.aws_region, settings.aws_role_arn)
        return ScanService(db, provider, source="aws").run()
    except (BotoCoreError, ClientError, NoCredentialsError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AWS scan failed. Verify read-only credentials, region and role trust policy.",
        ) from exc
