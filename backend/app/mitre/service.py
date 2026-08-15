"""Application-facing MITRE service."""
from .manager import MitreManager
from .models import DetectionMapping

class MitreService:
    def __init__(self, manager=None):
        self.manager = manager or MitreManager()
    def tactic(self, tactic_id): return self.manager.tactics.get(tactic_id)
    def technique(self, technique_id): return self.manager.techniques.get(technique_id)
    def subtechnique(self, subtechnique_id): return self.manager.techniques.get_subtechnique(subtechnique_id)
    def map_detection(self, *, detection_id, technique_id, subtechnique_id=None,
                      tactic_ids=(), confidence=1.0, source="sentinelsiem", description=""):
        return self.manager.map_detection(DetectionMapping(
            detection_id=detection_id, technique_id=technique_id,
            subtechnique_id=subtechnique_id, tactic_ids=tactic_ids,
            confidence=confidence, source=source, description=description))
    def mappings_for_detection(self, detection_id):
        return self.manager.mappings.for_detection(detection_id)
    def coverage(self): return self.manager.coverage.calculate()
    def navigator_layer(self, name="SentinelSIEM MITRE Coverage", description=""):
        return self.manager.coverage.navigator_layer(name, description)
