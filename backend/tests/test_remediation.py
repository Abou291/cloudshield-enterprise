from datetime import UTC, datetime

from app.core.domain import Finding, RiskBreakdown, Severity
from app.services.remediation import build_remediation_plan


def finding(rule_id: str, resource_id: str, evidence: dict | None = None) -> Finding:
    now = datetime.now(UTC)
    return Finding(
        fingerprint="a" * 64,
        rule_id=rule_id,
        title="test",
        description="test",
        severity=Severity.HIGH,
        resource_id=resource_id,
        resource_type="test",
        account_id="123456789012",
        region="eu-west-3",
        evidence=evidence or {},
        recommendation="Review and fix safely.",
        risk=RiskBreakdown(score=80, reasons=["test"], factors={"severity": 1.0}),
        first_seen_at=now,
        last_seen_at=now,
    )


def test_s3_plan_is_guided_and_never_automatic() -> None:
    plan = build_remediation_plan(finding("S3-001", "arn:aws:s3:::customer-data"))
    assert plan.requires_human_approval is True
    assert plan.automatic_execution is False
    assert "put-public-access-block" in (plan.steps[1].command or "")
    assert "customer-data" in (plan.steps[1].command or "")


def test_network_plan_targets_group_without_execution() -> None:
    plan = build_remediation_plan(
        finding(
            "NET-001",
            "sg-0123456789:tcp:22:22:0.0.0.0/0",
            {"cidr": "0.0.0.0/0", "protocol": "tcp", "from_port": 22, "to_port": 22},
        )
    )
    assert "revoke-security-group-ingress" in (plan.steps[1].command or "")
    assert "sg-0123456789" in (plan.steps[1].command or "")
    assert plan.steps[1].destructive is True


def test_unknown_rule_gets_safe_manual_plan() -> None:
    plan = build_remediation_plan(finding("CUSTOM-999", "resource"))
    assert all(step.command is None for step in plan.steps)
    assert plan.automatic_execution is False
