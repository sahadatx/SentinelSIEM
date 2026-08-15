from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from app.risk.models import RiskAssessment
from app.risk.score import RiskScore


class RiskPrioritizer:
    """Stable priority ordering for risk assessments."""

    ORDER = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
    }

    def prioritize(
        self,
        assessments: Iterable[RiskAssessment],
    ) -> list[RiskAssessment]:
        """Return assessments ordered by priority and score."""
        return sorted(
            assessments,
            key=lambda item: (
                self.ORDER.get(item.priority, 99),
                -item.score,
            ),
        )

    @staticmethod
    def from_score(
        source_id: str,
        assessment_id: str,
        score: RiskScore,
        factors: dict[str, float],
        explanation: tuple[str, ...],
        assessed_at: datetime,
    ) -> RiskAssessment:
        """Build an auditable risk assessment from a calculated score."""
        return RiskAssessment(
            assessment_id=assessment_id,
            source_id=source_id,
            score=score.value,
            priority=score.priority,
            factors=factors,
            explanation=explanation,
            assessed_at=assessed_at,
        )
