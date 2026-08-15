from __future__ import annotations

from dataclasses import dataclass

from app.risk.models import RiskInput


@dataclass(frozen=True, slots=True)
class RiskFactor:
    """A weighted risk-scoring factor."""

    name: str
    weight: float


DEFAULT_FACTORS: tuple[RiskFactor, ...] = (
    RiskFactor("severity", 0.25),
    RiskFactor("confidence", 0.10),
    RiskFactor("asset_criticality", 0.15),
    RiskFactor("user_risk", 0.10),
    RiskFactor("ioc_reputation", 0.08),
    RiskFactor("threat_intelligence", 0.08),
    RiskFactor("frequency", 0.04),
    RiskFactor("correlation_strength", 0.10),
    RiskFactor("mitre_technique", 0.05),
    RiskFactor("historical_context", 0.05),
)

SEVERITY_VALUES: dict[str, float] = {
    "info": 0.10,
    "low": 0.30,
    "medium": 0.50,
    "high": 0.75,
    "critical": 1.00,
}


def normalized_factors(
    risk_input: RiskInput,
    factors: tuple[RiskFactor, ...] = DEFAULT_FACTORS,
) -> dict[str, float]:
    """Normalize all supported risk inputs into bounded 0..1 factors."""
    values = {
        "severity": SEVERITY_VALUES.get(
            risk_input.severity.lower(),
            SEVERITY_VALUES["medium"],
        ),
        "confidence": risk_input.confidence,
        "asset_criticality": risk_input.asset_criticality,
        "user_risk": risk_input.user_risk,
        "ioc_reputation": risk_input.ioc_reputation,
        "threat_intelligence": risk_input.threat_intelligence,
        "frequency": risk_input.frequency,
        "correlation_strength": risk_input.correlation_strength,
        "mitre_technique": risk_input.mitre_technique,
        "historical_context": risk_input.historical_context,
    }

    return {
        factor.name: values[factor.name]
        for factor in factors
    }
