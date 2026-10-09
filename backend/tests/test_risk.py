from app.core.domain import Asset, Severity
from app.services.risk import RiskEngine


def test_risk_score_is_explainable_and_bounded() -> None:
    asset = Asset(
        resource_id="bucket",
        resource_type="s3_bucket",
        name="bucket",
        context={
            "internet_exposed": True,
            "environment": "production",
            "sensitive_data": True,
        },
    )

    result = RiskEngine().score(Severity.CRITICAL, asset, confidence=0.98)

    assert result.score == 100
    assert "Internet exposure +22" in result.reasons
    assert result.factors["sensitive_data"] == 1.0


def test_low_context_finding_stays_low() -> None:
    asset = Asset(resource_id="asset", resource_type="other", name="asset")

    result = RiskEngine().score(Severity.LOW, asset, confidence=0.5)

    assert result.score == 5


def _worst_and_best(severity: Severity) -> tuple[int, int]:
    everything = Asset(
        resource_id="a",
        resource_type="x",
        name="a",
        context={
            "internet_exposed": True,
            "environment": "production",
            "sensitive_data": True,
            "privileged": True,
        },
    )
    nothing = Asset(resource_id="b", resource_type="x", name="b")
    engine = RiskEngine()
    return (
        engine.score(severity, nothing, confidence=0.0).score,
        engine.score(severity, everything, confidence=1.0).score,
    )


def test_context_never_lifts_a_finding_out_of_its_severity_band() -> None:
    order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    ranges = [_worst_and_best(severity) for severity in order]
    for (_, best_below), (worst_above, _) in zip(ranges, ranges[1:], strict=False):
        assert best_below < worst_above
    assert ranges[-1][1] == 100


def test_low_finding_on_sensitive_production_asset_ranks_below_account_level_high() -> None:
    engine = RiskEngine()
    bucket = Asset(
        resource_id="b",
        resource_type="s3_bucket",
        name="b",
        context={"environment": "production", "sensitive_data": True},
    )
    account = Asset(resource_id="acct", resource_type="cloudtrail", name="trail")
    low_on_bucket = engine.score(
        Severity.LOW, bucket, 0.8, ["production_asset", "sensitive_data"]
    ).score
    high_account = engine.score(Severity.HIGH, account, 0.97, []).score
    assert high_account > low_on_bucket


def test_irrelevant_context_factors_are_ignored() -> None:
    engine = RiskEngine()
    exposed = Asset(
        resource_id="b",
        resource_type="s3_bucket",
        name="b",
        context={"internet_exposed": True},
    )
    plain = Asset(resource_id="c", resource_type="s3_bucket", name="c")
    with_factor = engine.score(Severity.LOW, exposed, 0.9, ["production_asset"])
    without = engine.score(Severity.LOW, plain, 0.9, ["production_asset"])
    assert with_factor.score == without.score
    assert not any("Internet exposure" in reason for reason in with_factor.reasons)


def test_rule_rejects_unknown_context_factor() -> None:
    import pytest
    from pydantic import ValidationError

    from app.services.rules import Rule

    with pytest.raises(ValidationError):
        Rule(
            id="X-1",
            name="x",
            description="x",
            resource_type="x",
            severity=Severity.LOW,
            confidence=0.5,
            conditions=[],
            remediation="x",
            context_factors=["internet_exposure", "bogus"],
        )
