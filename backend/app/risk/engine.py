from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from app.risk.calculator import RiskCalculator
from app.risk.factors import normalized_factors
from app.risk.models import RiskAssessment, RiskInput
from app.risk.prioritizer import RiskPrioritizer


class RiskScoringEngine:
    """Calculate, explain, and prioritize risk assessments."""

    def __init__(
        self,
        calculator: RiskCalculator | None = None,
        prioritizer: RiskPrioritizer | None = None,
    ) -> None:
        self._calculator = calculator or RiskCalculator()
        self._prioritizer = prioritizer or RiskPrioritizer()

    def assess(self, risk_input: RiskInput) -> RiskAssessment:
        score = self._calculator.calculate(risk_input)
        factors = normalized_factors(risk_input)
        explanation = (
            f"Weighted risk score calculated as {score.value:.2f}/100.",
            f"Priority classified as {score.priority}.",
            *score.rationale,
        )
        return self._prioritizer.from_score(
            source_id=risk_input.source_id,
            assessment_id=str(uuid4()),
            score=score,
            factors=factors,
            explanation=explanation,
            assessed_at=datetime.now(UTC),
        )

    def prioritize(
        self,
        assessments: list[RiskAssessment],
    ) -> list[RiskAssessment]:
        return self._prioritizer.prioritize(assessments)
