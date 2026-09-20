import pytest

from app.mitre.service import MitreService


@pytest.mark.asyncio
async def test_mapping_and_coverage():
    s = MitreService()

    await s.map_detection(
        detection_id="brute-force-plugin",
        technique_id="T1110",
        subtechnique_id="T1110.001",
        tactic_ids=("TA0006",),
        confidence=0.95,
    )

    result = await s.coverage()

    assert result.mapped_techniques == 1
    assert "T1110" in result.mapped_technique_ids


@pytest.mark.asyncio
async def test_navigator():
    s = MitreService()

    await s.map_detection(
        detection_id="ssh",
        technique_id="T1021",
        subtechnique_id="T1021.004",
        tactic_ids=("TA0008",),
        confidence=0.9,
    )

    layer = await s.navigator_layer()

    assert layer.domain == "enterprise-attack"
    assert any(
        technique.techniqueID == "T1021.004"
        for technique in layer.techniques
    )


@pytest.mark.asyncio
async def test_invalid_mapping():
    s = MitreService()

    with pytest.raises(KeyError):
        await s.map_detection(
            detection_id="bad",
            technique_id="T9999",
        )


@pytest.mark.asyncio
async def test_subtechnique_parent_validation():
    s = MitreService()

    with pytest.raises(ValueError):
        await s.map_detection(
            detection_id="bad-parent",
            technique_id="T1110",
            subtechnique_id="T1021.004",
            tactic_ids=("TA0006",),
            confidence=0.9,
        )
