from dataclasses import dataclass

from app.core.domain import Asset, RiskBreakdown, Severity

# Context factors a rule may declare as relevant to its own risk.
FACTOR_KEYS = ("internet_exposure", "production_asset", "sensitive_data", "privileged")
# Used when a rule does not declare its own list. Administrative privilege only matters for
# identity checks, so it must be requested explicitly.
DEFAULT_FACTORS = ("internet_exposure", "production_asset", "sensitive_data")


@dataclass(frozen=True)
class RiskWeights:
    """Severity fixes the band of the score; context only moves it inside that band."""

    bands: dict[Severity, tuple[int, int]]
    exposure: int = 22
    production: int = 15
    sensitive_data: int = 18
    privileged: int = 15
    # Share of the position inside the band that comes from detection confidence.
    confidence_share: float = 0.3
    # Position used when a rule has no relevant context factor (account-level checks).
    neutral_context: float = 0.5


DEFAULT_WEIGHTS = RiskWeights(
    bands={
        Severity.LOW: (1, 25),
        Severity.MEDIUM: (26, 50),
        Severity.HIGH: (51, 75),
        Severity.CRITICAL: (76, 100),
    }
)


class RiskEngine:
    """Computes a bounded, explainable score ordered first by severity, then by context.

    The band is set by the technical severity, so a low-severity finding on a sensitive
    production asset can never outrank a high-severity finding. Inside the band, the
    position combines the context factors that matter for the rule (a missing bucket
    access log is not made riskier by the bucket being internet-facing) and the
    detection confidence. The decomposition stays additive and auditable.
    """

    def __init__(self, weights: RiskWeights = DEFAULT_WEIGHTS) -> None:
        self.weights = weights

    def score(
        self,
        severity: Severity,
        asset: Asset,
        confidence: float,
        relevant_factors: tuple[str, ...] | list[str] | None = None,
    ) -> RiskBreakdown:
        low, high = self.weights.bands[severity]
        relevant = set(DEFAULT_FACTORS if relevant_factors is None else relevant_factors)

        exposure = bool(asset.context.get("internet_exposed"))
        production = asset.context.get("environment") == "production"
        sensitive_data = bool(asset.context.get("sensitive_data"))
        privileged = bool(asset.context.get("privileged"))

        factors = {
            "technical_severity": float(low),
            "internet_exposure": float(exposure),
            "production_asset": float(production),
            "sensitive_data": float(sensitive_data),
            "privileged": float(privileged),
            "confidence": round(confidence, 2),
        }

        # Provenance of derived context (tag, resource type...) is shown next to the
        # points so the score can be audited; declared values carry no suffix.
        sources = asset.context.get("context_sources") or {}
        contextual = (
            ("Internet exposure", exposure, self.weights.exposure, "internet_exposure"),
            ("Production asset", production, self.weights.production, "production_asset"),
            ("Sensitive data", sensitive_data, self.weights.sensitive_data, "sensitive_data"),
            ("Administrative privilege", privileged, self.weights.privileged, "privileged"),
        )
        reasons = [f"Technical severity ({severity.value}) sets the {low}-{high} band"]
        applied = 0
        available = 0
        for label, enabled, points, key in contextual:
            if key not in relevant:
                continue
            available += points
            if enabled:
                applied += points
                origin = sources.get(key)
                reasons.append(f"{label} +{points}" + (f" ({origin})" if origin else ""))

        clamped = max(0.0, min(1.0, confidence))
        context_position = applied / available if available else self.weights.neutral_context
        share = self.weights.confidence_share
        position = (1 - share) * context_position + share * clamped
        score = low + round((high - low) * position)

        if not available:
            reasons.append("No context factor applies to this check: neutral position in band")
        reasons.append(f"Detection confidence ({clamped:.0%}) shapes {share:.0%} of the position")
        factors["band_position"] = round(position, 2)
        return RiskBreakdown(score=min(score, high), reasons=reasons, factors=factors)
