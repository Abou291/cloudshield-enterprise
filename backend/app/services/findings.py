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
            record = self.db.get(FindingRecord, (self.tenant_id, self.source, finding.fingerprint))
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
            record.status = finding.status.value
            record.risk_score = finding.risk.score
            record.risk_reasons = finding.risk.reasons
            record.risk_factors = finding.risk.factors
            record.last_seen_at = now
        self.db.flush()

    def list(
        self, severity: Severity | None = None, limit: int = 100, offset: int = 0
    ) -> list[Finding]:
        query = (
            select(FindingRecord)
            .where(FindingRecord.tenant_id == self.tenant_id, FindingRecord.source == self.source)
            .order_by(FindingRecord.risk_score.desc(), FindingRecord.fingerprint)
            .offset(offset)
            .limit(limit)
        )
        if severity:
            query = query.where(FindingRecord.severity == severity.value)
        return [to_domain(record) for record in self.db.scalars(query).all()]
