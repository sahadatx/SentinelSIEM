from pydantic import ValidationError
import pytest
from app.mitre import MitreService

def test_lookup():
    s = MitreService()
    assert s.tactic("TA0006").name == "Credential Access"
    assert s.technique("T1110").name == "Brute Force"
    assert s.subtechnique("T1110.001").parent_id == "T1110"

def test_mapping_and_coverage():
    s = MitreService()
    s.map_detection(detection_id="brute-force-plugin", technique_id="T1110",
                    subtechnique_id="T1110.001", tactic_ids=("TA0006",), confidence=.95)
    result = s.coverage()
    assert result.mapped_techniques == 1
    assert result.coverage_percent == round(100/15, 2)

def test_navigator():
    s = MitreService()
    s.map_detection(detection_id="ssh", technique_id="T1021",
                    subtechnique_id="T1021.004", tactic_ids=("TA0008",), confidence=.9)
    layer = s.navigator_layer()
    assert layer.domain == "enterprise-attack"
    assert layer.techniques[0].techniqueID == "T1021.004"

def test_invalid_mapping():
    s = MitreService()
    with pytest.raises(KeyError):
        s.map_detection(detection_id="bad", technique_id="T9999")
    with pytest.raises(ValueError):
        s.map_detection(detection_id="bad-parent", technique_id="T1078",
                        subtechnique_id="T1110.001")

def test_invalid_model():
    from app.mitre.models import MitreTechnique
    with pytest.raises(ValidationError):
        MitreTechnique(id="BAD", name="bad")
