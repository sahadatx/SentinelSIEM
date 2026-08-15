"""Detection-to-MITRE mapping registry."""
from .models import DetectionMapping, NavigatorTechnique

class MappingRegistry:
    def __init__(self, mappings=()):
        self._items = {}
        for mapping in mappings: self.register(mapping)
    def register(self, mapping: DetectionMapping):
        key = (mapping.detection_id, mapping.technique_id, mapping.subtechnique_id)
        existing = self._items.get(key)
        if existing is not None and existing != mapping:
            raise ValueError(f"conflicting MITRE mapping: {key}")
        self._items[key] = mapping
        return mapping
    def for_detection(self, detection_id: str):
        return tuple(self._items[k] for k in sorted(self._items) if k[0] == detection_id)
    def mapped_technique_ids(self):
        return frozenset(x.technique_id for x in self._items.values())
    def navigator_techniques(self):
        scores = {}
        for item in self._items.values():
            tid = item.subtechnique_id or item.technique_id
            scores[tid] = max(scores.get(tid, 0.0), item.confidence)
        return [NavigatorTechnique(techniqueID=k, score=v) for k, v in sorted(scores.items())]
