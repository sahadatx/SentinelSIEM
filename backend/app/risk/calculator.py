from __future__ import annotations

from app.risk.factors import (
    DEFAULT_FACTORS,
    RiskFactor,
    normalized_factors,
)
from app.risk.models import RiskInput
from app.risk.score import RiskScore


class RiskCalculator:
    """Deterministic, weighted and explainable risk calculator."""

    CRITICAL_SEVERITY_MIN_SCORE = 60.0

    def __init__(
        self,
        factors: tuple[RiskFactor, ...] = DEFAULT_FACTORS,
    ) -> None:
        if not factors:
            raise ValueError("at least one risk factor is required")

        if any(factor.weight < 0 for factor in factors):
            raise ValueError("risk factor weights cannot be negative")

        total_weight = sum(
            factor.weight for factor in factors
        )

        if total_weight <= 0:
            raise ValueError(
                "risk factor weights must have a positive total"
            )

        self._factors = factors
        self._total_weight = total_weight

    def calculate(
        self,
        risk_input: RiskInput,
    ) -> RiskScore:
        """Calculate a normalized risk score from 0 to 100."""
        values = normalized_factors(
            risk_input,
            self._factors,
        )

        weighted_score = sum(
            values[factor.name] * factor.weight
            for factor in self._factors
        )

        score = (
            weighted_score / self._total_weight
        ) * 100.0

        score = round(
            max(0.0, min(100.0, score)),
            2,
        )

        priority = self._classify_priority(
            score=score,
            severity=risk_input.severity,
        )

        rationale = tuple(
            f"{factor.name}={values[factor.name]:.2f}"
            for factor in self._factors
            if values[factor.name] > 0
        )

        return RiskScore(
            value=score,
            priority=priority,
            rationale=rationale,
        )

    @classmethod
    def _classify_priority(
        cls,
        score: float,
        severity: str,
    ) -> str:
        """
        Classify risk using score thresholds.

        Critical severity receives critical priority when the
        calculated score reaches the critical-severity floor.
        This prevents a critical detection from being reduced
        to high priority solely because some optional context
        factors are unavailable.
        """
        normalized_severity = severity.lower()

        if (
            normalized_severity == "critical"
            and score >= cls.CRITICAL_SEVERITY_MIN_SCORE
        ):
            return "critical"

        if score >= 80:
            return "critical"

        if score >= 60:
            return "high"

        if score >= 30:
            return "medium"

        return "low"
