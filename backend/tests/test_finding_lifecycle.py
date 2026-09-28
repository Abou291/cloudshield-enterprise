from app.core.auth import Principal
from app.core.domain import Asset, Finding, FindingStatus, RiskBreakdown, Severity
from app.db.session import SessionLocal
from app.services.findings import FindingRepository
from app.services.scans import ScanService


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


class CoverageGapProvider:
    def collect(self) -> list[Asset]:
        return [
            Asset(
                resource_id="coverage:eks:eu-west-3",
                resource_type="coverage_gap",
                account_id="111111111111",
                region="eu-west-3",
                name="eks",
                attributes={
                    "service": "eks",
                    "reason": "AccessDenied",
                    "available": False,
                },
            )
        ]


def test_incomplete_coverage_does_not_auto_resolve_previous_findings() -> None:
    with SessionLocal() as db:
        repository = FindingRepository(db, "tenant-a", "aws")
        finding = sample_finding()
        repository.reconcile([finding])
        db.commit()

        service = ScanService(
            db,
            CoverageGapProvider,
            "aws",
            Principal(
                tenant_id="tenant-a",
                subject="tester",
                role="operator",
            ),
        )
        result = service.run()

        assert any(item.rule_id == "COV-001" for item in result.findings)
        current = repository.list()
        assert any(item.fingerprint == finding.fingerprint for item in current)
        assert any(item.rule_id == "COV-001" for item in current)
