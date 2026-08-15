from __future__ import annotations

from app.risk.calculator import RiskCalculator
from app.risk.engine import RiskScoringEngine
from app.risk.models import RiskInput
from app.risk.prioritizer import RiskPrioritizer


def test_high_risk_assessment_is_explainable() -> None:
    assessment = RiskScoringEngine().assess(
        RiskInput(
            source_id="detection-001",
            severity="critical",
            confidence=0.95,
            asset_criticality=1.0,
            user_risk=0.8,
            ioc_reputation=0.9,
            threat_intelligence=0.9,
            frequency=0.8,
            correlation_strength=0.95,
            mitre_technique=0.8,
            historical_context=0.7,
        )
    )

    assert assessment.score >= 80
    assert assessment.priority == "critical"
    assert assessment.factors
    assert assessment.explanation


def test_low_risk_stays_low() -> None:
    score = RiskCalculator().calculate(
        RiskInput(
            source_id="event-001",
            severity="low",
            confidence=0.1,
        )
    )

    assert score.value < 30
    assert score.priority == "low"


def test_prioritizer_orders_highest_priority_first() -> None:
    engine = RiskScoringEngine()

    assessments = [
        engine.assess(
            RiskInput(
                source_id="low",
                severity="low",
            )
        ),
        engine.assess(
            RiskInput(
                source_id="critical",
                severity="critical",
                confidence=1.0,
                asset_criticality=1.0,
                correlation_strength=1.0,
            )
        ),
    ]

    ordered = RiskPrioritizer().prioritize(assessments)

    assert ordered[0].priority == "critical"
