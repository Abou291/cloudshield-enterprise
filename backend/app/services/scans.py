from pathlib import Path
from uuid import uuid4

from sqlalchemy.orm import Session

from app.core.domain import ScanResult
from app.scanners.base import InventoryProvider
from app.services.findings import FindingRepository
from app.services.rules import RuleEngine

APP_ROOT = Path(__file__).resolve().parents[1]


class ScanService:
    def __init__(self, db: Session, provider: InventoryProvider, source: str) -> None:
        self.db = db
        self.provider = provider
        self.source = source
        self.rule_engine = RuleEngine.from_directory(APP_ROOT / "rules")

    def run(self) -> ScanResult:
        assets = self.provider.collect()
        findings = self.rule_engine.evaluate(assets)
        FindingRepository(self.db).upsert_many(findings)
        return ScanResult(
            scan_id=str(uuid4()),
            source=self.source,
            assets_scanned=len(assets),
            findings_count=len(findings),
            findings=findings,
        )
