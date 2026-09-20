from dataclasses import dataclass

from app.core.domain import Asset, RiskBreakdown, Severity


@dataclass(frozen=True)
class RiskWeights:
    severity: dict[Severity, int]
    exposure: int = 22
    production: int = 15
    sensitive_data: int = 18
    privileged: int = 15
    high_confidence: int = 10


DEFAULT_WEIGHTS = RiskWeights(
    severity={
        Severity.LOW: 8,
        Severity.MEDIUM: 20,
        Severity.HIGH: 30,
        Severity.CRITICAL: 40,
    }
)


class RiskEngine:
    """Computes a bounded and explainable contextual score.

    An additive model is deliberately used in V1 because it is easier to audit,
    tune and explain than an arbitrary multiplication of ordinal factors.
    """

    def __init__(self, weights: RiskWeights = DEFAULT_WEIGHTS) -> None:
        self.weights = weights

    def score(self, severity: Severity, asset: Asset, confidence: float) -> RiskBreakdown:
        reasons = [f"Technical severity ({severity.value}) +{self.weights.severity[severity]}"]
        score = self.weights.severity[severity]

        exposure = bool(asset.context.get("internet_exposed"))
        production = asset.context.get("environment") == "production"
        sensitive_data = bool(asset.context.get("sensitive_data"))
        privileged = bool(asset.context.get("privileged"))

        factors = {
            "technical_severity": float(self.weights.severity[severity]),
            "internet_exposure": float(exposure),
            "production_asset": float(production),
            "sensitive_data": float(sensitive_data),
            "privileged": float(privileged),
            "confidence": round(confidence, 2),
        }

        contextual = (
            ("Internet exposure", exposure, self.weights.exposure),
            ("Production asset", production, self.weights.production),
            ("Sensitive data", sensitive_data, self.weights.sensitive_data),
            ("Administrative privilege", privileged, self.weights.privileged),
        )
        for label, enabled, points in contextual:
            if enabled:
                score += points
                reasons.append(f"{label} +{points}")

        confidence_points = round(self.weights.high_confidence * max(0.0, min(1.0, confidence)))
        score += confidence_points
        reasons.append(f"Detection confidence ({confidence:.0%}) +{confidence_points}")

        return RiskBreakdown(score=min(score, 100), reasons=reasons, factors=factors)

