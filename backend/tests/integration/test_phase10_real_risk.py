from __future__ import annotations

from app.risk.engine import RiskScoringEngine
from app.risk.models import RiskInput


def test_real_phase10_risk_scoring() -> None:
    engine = RiskScoringEngine()

    assessment = engine.assess(
        RiskInput(
            source_id="account-compromise",
            severity="high",
            confidence=0.95,
            asset_criticality=0.90,
            user_risk=0.70,
            ioc_reputation=0.60,
            threat_intelligence=0.80,
            frequency=0.75,
            correlation_strength=0.95,
            mitre_technique=0.80,
            historical_context=0.65,
            metadata={
                "correlation_rule": "account-compromise",
                "evidence_count": 2,
            },
        )
    )

    assert 0 <= assessment.score <= 100
    assert assessment.priority in {"low", "medium", "high", "critical"}
    assert assessment.source_id == "account-compromise"
    assert len(assessment.factors) == 10
    assert len(assessment.explanation) >= 3

    print("\n" + "=" * 70)
    print("REAL PHASE 10 RISK SCORING TEST PASSED")
    print("=" * 70)
    print(f"Source             : {assessment.source_id}")
    print(f"Risk score         : {assessment.score:.2f}/100")
    print(f"Priority           : {assessment.priority}")
    print(f"Factors evaluated  : {len(assessment.factors)}")
    print("=" * 70)
