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

    assert result.score == 13
