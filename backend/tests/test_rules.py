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
