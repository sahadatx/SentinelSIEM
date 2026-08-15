from app.mitre import MitreService

def test_real_phase14_mitre_workflow():
    s = MitreService()
    s.map_detection(detection_id="real-suspicious-login", technique_id="T1078",
                    tactic_ids=("TA0001","TA0003","TA0004","TA0005"), confidence=.90)
    s.map_detection(detection_id="real-brute-force", technique_id="T1110",
                    subtechnique_id="T1110.001", tactic_ids=("TA0006",), confidence=.95)
    s.map_detection(detection_id="real-ssh", technique_id="T1021",
                    subtechnique_id="T1021.004", tactic_ids=("TA0008",), confidence=.92)

    assert s.tactic("TA0006").name == "Credential Access"
    assert s.subtechnique("T1021.004").parent_id == "T1021"
    assert len(s.mappings_for_detection("real-brute-force")) == 1

    coverage = s.coverage()
    assert coverage.total_techniques == 15
    assert coverage.mapped_techniques == 3
    assert coverage.coverage_percent == 20.0

    layer = s.navigator_layer(description="Phase 14 real validation")
    assert {x.techniqueID for x in layer.techniques} == {"T1078","T1110.001","T1021.004"}

    print("=" * 72)
    print("SENTINELSIEM — REAL PHASE 14 MITRE VALIDATION")
    print("=" * 72)
    print(f"Techniques covered : {coverage.mapped_techniques}/{coverage.total_techniques}")
    print(f"Coverage           : {coverage.coverage_percent:.2f}%")
    print(f"Navigator entries  : {len(layer.techniques)}")
    print("[PASS] Phase 14 MITRE ATT&CK integration")
