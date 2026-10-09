from pathlib import Path

from app.scanners.fixture import FixtureInventoryProvider
from app.services.rules import RuleEngine

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "app/fixtures/demo_inventory.json"


def test_fixture_produces_expected_findings() -> None:
    assets = FixtureInventoryProvider(FIXTURE).collect()
    findings = RuleEngine.from_directory(ROOT / "app/rules").evaluate(assets)

    assert len(assets) == 4
    assert len(findings) == 7
    assert {finding.rule_id for finding in findings} == {
        "IAM-001",
        "IAM-002",
        "IAM-003",
        "S3-001",
        "S3-002",
        "S3-003",
        "NET-001",
    }
    assert findings[0].risk.score == 100


def test_finding_fingerprint_is_stable() -> None:
    assets = FixtureInventoryProvider(FIXTURE).collect()
    engine = RuleEngine.from_directory(ROOT / "app/rules")

    first = [finding.fingerprint for finding in engine.evaluate(assets)]
    second = [finding.fingerprint for finding in engine.evaluate(assets)]

    assert first == second


def test_attack_paths_need_two_findings_on_the_same_resource():
    from app.core.domain import Finding, RiskBreakdown, Severity
    from app.services.reporting import build_attack_paths

    def finding(resource: str, rule: str, **factors: float) -> Finding:
        return Finding(
            fingerprint=f"{resource}-{rule}".ljust(64, "x"),
            source="aws",
            rule_id=rule,
            title=rule,
            description=rule,
            severity=Severity.HIGH,
            resource_id=resource,
            resource_type="s3_bucket",
            account_id="111111111111",
            region="eu-west-3",
            evidence={},
            recommendation="fix",
            risk=RiskBreakdown(score=80, reasons=[], factors=factors),
        )

    same = [
        finding("bucket-a", "S3-001", internet_exposure=1.0, sensitive_data=1.0),
        finding("bucket-a", "S3-002", internet_exposure=1.0, sensitive_data=1.0),
    ]
    assert [p["kind"] for p in build_attack_paths(same)] == ["exposed-sensitive-resource"]

    scattered = [
        finding("bucket-a", "S3-001", internet_exposure=1.0),
        finding("bucket-b", "S3-002", sensitive_data=1.0),
        finding("role-c", "IAM-002", privileged=1.0),
    ]
    assert build_attack_paths(scattered) == []
