from __future__ import annotations

from .common import APIModel


class MitreTacticResponse(APIModel):
    id: str
    name: str
    description: str


class MitreTechniqueResponse(APIModel):
    id: str
    name: str
    tactic_ids: tuple[str, ...]
    description: str


class MitreCoverageResponse(APIModel):
    total_techniques: int
    mapped_techniques: int
    coverage_percent: float
    mapped_technique_ids: tuple[str, ...]
    unmapped_technique_ids: tuple[str, ...]
