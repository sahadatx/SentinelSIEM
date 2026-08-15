"""MITRE orchestration layer."""
from .tactics import TacticCatalog
from .techniques import TechniqueCatalog
from .mappings import MappingRegistry
from .coverage import CoverageAnalyzer
from .models import DetectionMapping

class MitreManager:
    def __init__(self, tactics=None, techniques=None, mappings=()):
        self.tactics = tactics or TacticCatalog()
        self.techniques = techniques or TechniqueCatalog()
        self.mappings = MappingRegistry(mappings)
        self.coverage = CoverageAnalyzer(self.techniques, self.mappings)
    def map_detection(self, mapping: DetectionMapping):
        technique = (self.techniques.get_subtechnique(mapping.subtechnique_id)
                     if mapping.subtechnique_id else self.techniques.get(mapping.technique_id))
        if mapping.subtechnique_id and technique.parent_id != mapping.technique_id:
            raise ValueError(f"{mapping.subtechnique_id} is not a child of {mapping.technique_id}")
        unknown = set(mapping.tactic_ids) - set(self.tactics.ids())
        if unknown: raise ValueError(f"unknown MITRE tactics: {sorted(unknown)}")
        return self.mappings.register(mapping)
