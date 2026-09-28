from app.core.domain import Finding, FindingStatus, RiskBreakdown, Severity
from app.db.session import SessionLocal
from app.services.findings import FindingRepository


def sample_finding(fingerprint: str = "a" * 64) -> Finding:
    return Finding(
        fingerprint=fingerprint,
        source="aws",
        rule_id="TEST-001",
        title="Test finding",
        description="Lifecycle test",
        severity=Severity.HIGH,
        resource_id="resource-1",
        resource_type="test_resource",
        account_id="111111111111",
        region="eu-west-3",
        evidence={"unsafe": True},
        recommendation="Fix it",
        risk=RiskBreakdown(
            score=70,
            reasons=["test"],
            factors={"technical_severity": 30.0},
        ),
    )


def test_reconcile_resolves_missing_and_reopens_reappearing_findings() -> None:
    with SessionLocal() as db:
        repository = FindingRepository(db, "tenant-a", "aws")
        finding = sample_finding()

        repository.reconcile([finding])
        db.commit()
        repository.set_status(finding.fingerprint, FindingStatus.ACKNOWLEDGED)
        db.commit()
        assert repository.list()[0].status == FindingStatus.ACKNOWLEDGED

        repository.reconcile([finding])
        db.commit()
        assert repository.list()[0].status == FindingStatus.ACKNOWLEDGED

        repository.reconcile([])
        db.commit()
        assert repository.list() == []
        resolved = repository.list(include_resolved=True)
        assert resolved[0].status == FindingStatus.RESOLVED

        repository.reconcile([finding])
        db.commit()
        reopened = repository.list()
        assert reopened[0].status == FindingStatus.OPEN


def test_status_update_is_source_and_tenant_scoped() -> None:
    with SessionLocal() as db:
        repository = FindingRepository(db, "tenant-a", "aws")
        finding = sample_finding()
        repository.reconcile([finding])
        db.commit()

        other_tenant = FindingRepository(db, "tenant-b", "aws")
        assert other_tenant.set_status(
            finding.fingerprint,
            FindingStatus.RESOLVED,
        ) is None

        other_source = FindingRepository(db, "tenant-a", "demo-fixture")
        assert other_source.set_status(
            finding.fingerprint,
            FindingStatus.RESOLVED,
        ) is None
