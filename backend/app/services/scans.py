from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.auth import Principal
from app.core.domain import ScanResult
from app.db.models import AuditRecord, ScanLock, ScanRecord
from app.scanners.base import InventoryProvider
from app.services.findings import FindingRepository
from app.services.rules import RuleEngine

APP_ROOT = Path(__file__).resolve().parents[1]


class ScanBusyError(Exception):
    """One durable scan lock per tenant; no unsafe automatic lease expiry."""


class ScanFailedError(Exception):
    """Public error contains no upstream exception or credential material."""


class ScanService:
    def __init__(
        self,
        db: Session,
        provider_factory: Callable[[], InventoryProvider],
        source: str,
        principal: Principal,
    ) -> None:
        self.db = db
        self.provider_factory = provider_factory
        self.source = source
        self.principal = principal

    def audit(self, action: str, scan_id: str) -> None:
        self.db.add(
            AuditRecord(
                event_id=str(uuid4()),
                tenant_id=self.principal.tenant_id,
                subject=self.principal.subject,
                action=action,
                object_id=scan_id,
                timestamp=datetime.now(UTC),
            )
        )

    def run(self) -> ScanResult:
        scan_id = str(uuid4())
        record = ScanRecord(
            scan_id=scan_id,
            tenant_id=self.principal.tenant_id,
            source=self.source,
            status="running",
            started_at=datetime.now(UTC),
        )
        self.db.add(ScanLock(tenant_id=self.principal.tenant_id, scan_id=scan_id))
        try:
            self.db.flush()
        except IntegrityError as exc:
            self.db.rollback()
            raise ScanBusyError from exc
        self.db.add(record)
        self.audit("scan.started", scan_id)
        self.db.commit()
        try:
            assets = self.provider_factory().collect()
            findings = RuleEngine.from_directory(APP_ROOT / "rules").evaluate(assets)
            for finding in findings:
                finding.source = self.source
            repository = FindingRepository(self.db, self.principal.tenant_id, self.source)
            repository.upsert_many(findings)
            record.status = "succeeded"
            record.assets_scanned = len(assets)
            record.findings_count = len(findings)
            record.completed_at = datetime.now(UTC)
            self.audit("scan.succeeded", scan_id)
            self.release_lock(scan_id)
            self.db.commit()
            return ScanResult(
                scan_id=scan_id,
                source=self.source,
                assets_scanned=len(assets),
                findings_count=len(findings),
                findings=findings,
                completed_at=record.completed_at,
            )
        except Exception as exc:
            self.db.rollback()
            record = self.db.get(ScanRecord, scan_id)
            record.status = "failed"
            record.error_code = "SCAN_FAILED"
            record.completed_at = datetime.now(UTC)
            self.audit("scan.failed", scan_id)
            self.release_lock(scan_id)
            self.db.commit()
            raise ScanFailedError("Scan failed; previous findings were preserved") from exc

    def release_lock(self, scan_id: str) -> None:
        self.db.execute(
            delete(ScanLock).where(
                ScanLock.tenant_id == self.principal.tenant_id,
                ScanLock.scan_id == scan_id,
            )
        )
