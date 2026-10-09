import pytest

from app.core.domain import Asset, FindingStatus
from app.services.compliance import build_compliance_posture, load_frameworks
from app.services.rules import RuleEngine
from app.services.scans import APP_ROOT


def rule_ids() -> set[str]:
    return {rule.id for rule in RuleEngine.from_directory(APP_ROOT / "rules").rules}


def test_every_mapped_rule_exists() -> None:
    known = rule_ids()
    for framework in load_frameworks():
        for control in framework["controls"]:
            assert set(control["rules"]) <= known, (framework["id"], control["id"])


def test_control_identifiers_are_unique_per_framework() -> None:
    for framework in load_frameworks():
        ids = [control["id"] for control in framework["controls"]]
        assert len(ids) == len(set(ids)), framework["id"]


def finding_for(asset: Asset):
    return RuleEngine.from_directory(APP_ROOT / "rules").evaluate([asset])


def public_bucket() -> Asset:
    return Asset(
        resource_id="arn:aws:s3:::b",
        resource_type="s3_bucket",
        name="b",
        attributes={"public": True, "block_public_access": False, "enforces_tls": True},
    )


def test_failing_controls_are_reported_per_framework() -> None:
    posture = build_compliance_posture(finding_for(public_bucket()))
    cis = next(item for item in posture["frameworks"] if item["id"] == "cis-aws-3.0")
    status = {control["id"]: control["status"] for control in cis["controls"]}
    assert status["2.1.4"] == "failing"
    assert status["1.5"] == "no_findings_observed"
    assert cis["controls_failing"] == 1
    assert "not that the control is satisfied" in posture["caveat"]


def test_resolved_findings_do_not_fail_controls() -> None:
    findings = finding_for(public_bucket())
    for item in findings:
        item.status = FindingStatus.RESOLVED
    posture = build_compliance_posture(findings)
    assert all(framework["controls_failing"] == 0 for framework in posture["frameworks"])


def test_coverage_gap_downgrades_passing_controls_to_unknown() -> None:
    gap = Asset(
        resource_id="coverage:rds",
        resource_type="coverage_gap",
        name="rds",
        attributes={"available": False},
    )
    posture = build_compliance_posture(finding_for(gap))
    assert posture["coverage_incomplete"] is True
    assert all(
        control["status"] == "unknown"
        for framework in posture["frameworks"]
        for control in framework["controls"]
    )


@pytest.mark.parametrize("framework_id", ["cis-aws-3.0", "aws-fsbp"])
def test_frameworks_are_loaded(framework_id: str) -> None:
    assert framework_id in {framework["id"] for framework in load_frameworks()}


def test_compliance_endpoint_after_demo_scan(client) -> None:
    client.post("/api/v1/scans/demo")
    response = client.get("/api/v1/compliance?source=demo-fixture")
    assert response.status_code == 200
    body = response.json()
    assert {item["id"] for item in body["frameworks"]} >= {"cis-aws-3.0", "aws-fsbp"}
    report = client.get("/api/v1/reports/security?source=demo-fixture").json()
    assert "compliance" in report
