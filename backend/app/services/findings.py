from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.domain import Finding, FindingStatus, RiskBreakdown, Severity
from app.db.models import FindingRecord


def to_domain(record: FindingRecord) -> Finding:
    return Finding(
        fingerprint=record.fingerprint,
        source=record.source,
        rule_id=record.rule_id,
        title=record.title,
        description=record.description,
        severity=Severity(record.severity),
        resource_id=record.resource_id,
        resource_type=record.resource_type,
        account_id=record.account_id,
        region=record.region,
        evidence=record.evidence,
        recommendation=record.recommendation,
        status=FindingStatus(record.status),
        risk=RiskBreakdown(
            score=record.risk_score,
            reasons=record.risk_reasons,
            factors=record.risk_factors,
        ),
        first_seen_at=record.first_seen_at,
        last_seen_at=record.last_seen_at,
    )


class FindingRepository:
    def __init__(self, db: Session, tenant_id: str, source: str = "demo-fixture") -> None:
        self.db = db
        self.tenant_id = tenant_id
        self.source = source

    def upsert_many(self, findings: list[Finding]) -> None:
        now = datetime.now(UTC)
        for finding in findings:
            record = self.db.get(
                FindingRecord,
                (self.tenant_id, self.source, finding.fingerprint),
            )
            previous_status = record.status if record is not None else None
            if record is None:
                record = FindingRecord(
                    fingerprint=finding.fingerprint,
                    tenant_id=self.tenant_id,
                    source=self.source,
                    first_seen_at=finding.first_seen_at,
                )
                self.db.add(record)
            record.rule_id = finding.rule_id
            record.title = finding.title
            record.description = finding.description
            record.severity = finding.severity.value
            record.resource_id = finding.resource_id
            record.resource_type = finding.resource_type
            record.account_id = finding.account_id
            record.region = finding.region
            record.evidence = finding.evidence
            record.recommendation = finding.recommendation
            if previous_status == FindingStatus.ACKNOWLEDGED.value:
                record.status = FindingStatus.ACKNOWLEDGED.value
            elif previous_status is None:
                record.status = finding.status.value
            else:
                record.status = FindingStatus.OPEN.value
            record.risk_score = finding.risk.score
            record.risk_reasons = finding.risk.reasons
            record.risk_factors = finding.risk.factors
            record.last_seen_at = now
        self.db.flush()

    def reconcile(
        self,
        findings: list[Finding],
        inspected_resources: set[tuple[str, str, str, str]] | None = None,
    ) -> None:
        """Persist the current scan and resolve active findings no longer observed."""
        current_fingerprints = {finding.fingerprint for finding in findings}
        self.upsert_many(findings)
        active_records = self.db.scalars(
            select(FindingRecord).where(
                FindingRecord.tenant_id == self.tenant_id,
                FindingRecord.source == self.source,
                FindingRecord.status != FindingStatus.RESOLVED.value,
            )
        ).all()
        for record in active_records:
            if inspected_resources is not None and (
                record.account_id, record.region, record.resource_type, record.resource_id
            ) not in inspected_resources:
                continue
            if record.fingerprint not in current_fingerprints:
                record.status = FindingStatus.RESOLVED.value
        self.db.flush()

    def set_status(self, fingerprint: str, status: FindingStatus) -> Finding | None:
        record = self.db.get(
            FindingRecord,
            (self.tenant_id, self.source, fingerprint),
        )
        if record is None:
            return None
        record.status = status.value
        self.db.flush()
        return to_domain(record)

    def list(
        self,
        severity: Severity | None = None,
        limit: int | None = 100,
        offset: int = 0,
        include_resolved: bool = False,
    ) -> list[Finding]:
        query = (
            select(FindingRecord)
            .where(
                FindingRecord.tenant_id == self.tenant_id,
                FindingRecord.source == self.source,
            )
            .order_by(FindingRecord.risk_score.desc(), FindingRecord.fingerprint)
            .offset(offset)
            .limit(limit)
        )
        if severity:
            query = query.where(FindingRecord.severity == severity.value)
        if not include_resolved:
            query = query.where(FindingRecord.status != FindingStatus.RESOLVED.value)
        return [to_domain(record) for record in self.db.scalars(query).all()]
