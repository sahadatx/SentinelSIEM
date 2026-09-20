import pytest

from app.mitre.service import MitreService


@pytest.mark.asyncio
async def test_real_phase14_mitre_workflow():
    s = MitreService()

    await s.map_detection(
        detection_id="real-suspicious-login",
        technique_id="T1078",
        tactic_ids=("TA0001", "TA0003", "TA0004", "TA0005"),
        confidence=0.90,
    )

    await s.map_detection(
        detection_id="real-brute-force",
        technique_id="T1110",
        subtechnique_id="T1110.001",
        tactic_ids=("TA0006",),
        confidence=0.95,
    )

    await s.map_detection(
        detection_id="real-ssh",
        technique_id="T1021",
        subtechnique_id="T1021.004",
        tactic_ids=("TA0008",),
        confidence=0.92,
    )

    assert s.tactic("TA0006").name == "Credential Access"
    assert s.subtechnique("T1021.004").parent_id == "T1021"

    mappings = await s.mappings_for_detection("real-brute-force")

    assert len(mappings) == 1
    assert mappings[0].technique_id == "T1110"
    assert mappings[0].subtechnique_id == "T1110.001"

    coverage = await s.coverage()

    assert coverage.mapped_techniques == 3
    assert "T1078" in coverage.mapped_technique_ids
    assert "T1110" in coverage.mapped_technique_ids
    assert "T1021" in coverage.mapped_technique_ids


@pytest.mark.asyncio
async def test_real_phase14_analytics():
    s = MitreService()

    await s.map_detection(
        detection_id="analytics-login",
        technique_id="T1078",
        tactic_ids=("TA0001",),
        confidence=0.90,
    )

    await s.map_detection(
        detection_id="analytics-brute-force",
        technique_id="T1110",
        subtechnique_id="T1110.001",
        tactic_ids=("TA0006",),
        confidence=0.95,
    )

    analytics = await s.analytics()

    assert analytics.total_techniques == 15
    assert analytics.full_techniques == 1
    assert analytics.partial_techniques == 1
    assert analytics.unmapped_techniques == 13
    assert analytics.unmapped_techniques >= 0
    assert 0 <= analytics.coverage_percent <= 100


@pytest.mark.asyncio
async def test_real_phase14_matrix():
    s = MitreService()

    matrix = await s.matrix()

    assert len(matrix) == 15

    first = matrix[0]

    assert "technique" in first
    assert "coverage" in first
    assert "subtechniques" in first
    assert "mappings" in first
