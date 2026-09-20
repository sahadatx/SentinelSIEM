"""API schemas for MITRE ATT&CK.

The schemas in this module define the public HTTP contracts for the
SentinelSIEM MITRE subsystem.

Architecture
------------

MITRE ATT&CK knowledge is read-only and dataset-backed:

    enterprise-attack.json
             ↓
        PostgreSQL
             ↓
      MitreRepository
             ↓
       MitreService
             ↓
          API
             ↓
      MITRE frontend

Detection → MITRE mappings are a separate SentinelSIEM capability.
Mapping request/response schemas are therefore retained for the
detection-mapping API, but they are not MITRE knowledge CRUD schemas.

There is intentionally:

    - no MITRE knowledge create schema;
    - no MITRE knowledge update schema;
    - no MITRE knowledge delete schema;
    - no MITRE_MANAGE permission contract.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import Field

from ...mitre.models import CoverageState
from .common import APIModel


# ============================================================================
# Common / Pagination
# ============================================================================


class MitrePaginationResponse(APIModel):
    """Pagination metadata for MITRE collection endpoints."""

    page: int = Field(
        ge=1,
    )
    page_size: int = Field(
        ge=1,
        le=30,
    )
    total: int = Field(
        ge=0,
    )
    total_pages: int = Field(
        ge=0,
    )


# ============================================================================
# Tactics
# ============================================================================


class MitreTacticResponse(APIModel):
    """Public MITRE tactic representation."""

    id: str
    external_id: str | None = None
    name: str
    description: str = ""


class MitreTacticListResponse(APIModel):
    """Paginated MITRE tactic collection."""

    items: tuple[MitreTacticResponse, ...]
    pagination: MitrePaginationResponse


# ============================================================================
# Platforms
# ============================================================================


class MitrePlatformResponse(APIModel):
    """Public MITRE platform representation."""

    id: str
    name: str


class MitrePlatformListResponse(APIModel):
    """Paginated MITRE platform collection."""

    items: tuple[MitrePlatformResponse, ...]
    pagination: MitrePaginationResponse


# ============================================================================
# Techniques
# ============================================================================


class MitreTechniqueResponse(APIModel):
    """Public top-level MITRE technique representation."""

    id: str
    external_id: str | None = None
    name: str
    type: str = "TECHNIQUE"
    tactic_ids: tuple[str, ...] = ()
    platform_ids: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ()
    description: str = ""


class MitreSubTechniqueResponse(APIModel):
    """Public MITRE sub-technique representation."""

    id: str
    external_id: str | None = None
    name: str
    type: str = "SUB_TECHNIQUE"
    parent_id: str
    tactic_ids: tuple[str, ...] = ()
    platform_ids: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ()
    description: str = ""


class MitreTechniqueListResponse(APIModel):
    """Paginated MITRE technique collection."""

    items: tuple[
        MitreTechniqueResponse | MitreSubTechniqueResponse,
        ...
    ]
    pagination: MitrePaginationResponse


# ============================================================================
# References
# ============================================================================


class MitreReferenceResponse(APIModel):
    """External reference attached to an ATT&CK object."""

    source_name: str
    url: str | None = None
    external_id: str | None = None
    description: str | None = None


# ============================================================================
# Mitigations
# ============================================================================


class MitreMitigationResponse(APIModel):
    """MITRE ATT&CK mitigation information."""

    id: str
    external_id: str | None = None
    name: str
    description: str = ""
    references: tuple[MitreReferenceResponse, ...] = ()


# ============================================================================
# Detection Mapping
# ============================================================================


class MitreMappingResponse(APIModel):
    """Public SentinelSIEM Detection → MITRE mapping."""

    mapping_id: UUID
    detection_id: str
    technique_id: str
    subtechnique_id: str | None
    tactic_ids: tuple[str, ...]
    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )
    source: str
    description: str
    created_at: datetime


class MitreMappingCreateRequest(APIModel):
    """Request for creating a Detection → MITRE mapping.

    This schema belongs to the SentinelSIEM detection-mapping capability,
    not to the read-only MITRE ATT&CK knowledge base.
    """

    detection_id: str = Field(
        min_length=1,
        max_length=128,
    )

    technique_id: str = Field(
        min_length=2,
        max_length=32,
    )

    subtechnique_id: str | None = Field(
        default=None,
        min_length=2,
        max_length=32,
    )

    tactic_ids: tuple[str, ...] = ()

    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
    )

    source: str = Field(
        default="sentinelsiem",
        min_length=1,
        max_length=128,
    )

    description: str = Field(
        default="",
        max_length=2000,
    )


class MitreMappingListResponse(APIModel):
    """Collection of Detection → MITRE mappings."""

    items: tuple[MitreMappingResponse, ...]


# ============================================================================
# Coverage
# ============================================================================


class MitreCoverageResponse(APIModel):
    """Aggregate MITRE detection coverage.

    Preserved for compatibility with the existing coverage API.
    """

    total_techniques: int = Field(
        ge=0,
    )

    mapped_techniques: int = Field(
        ge=0,
    )

    coverage_percent: float = Field(
        ge=0.0,
        le=100.0,
    )

    mapped_technique_ids: tuple[str, ...] = ()

    unmapped_technique_ids: tuple[str, ...] = ()


class MitreCoverageStateResponse(APIModel):
    """Detailed coverage state for an individual technique."""

    technique_id: str

    state: CoverageState

    mapping_count: int = Field(
        ge=0,
    )

    detection_count: int = Field(
        ge=0,
    )

    subtechnique_count: int = Field(
        ge=0,
    )

    mapped_subtechnique_count: int = Field(
        ge=0,
    )

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )


# ============================================================================
# Coverage Summary
# ============================================================================


class MitreCoverageSummaryResponse(APIModel):
    """Coverage summary used by the MITRE workspace."""

    total_techniques: int = Field(
        ge=0,
    )

    covered: int = Field(
        ge=0,
    )

    partially_covered: int = Field(
        ge=0,
    )

    not_covered: int = Field(
        ge=0,
    )

    coverage_percent: float = Field(
        ge=0.0,
        le=100.0,
    )


class MitreTacticCoverageResponse(APIModel):
    """Coverage percentage for one MITRE tactic."""

    tactic_id: str
    coverage_percent: float = Field(
        ge=0.0,
        le=100.0,
    )


# ============================================================================
# Matrix
# ============================================================================


class MitreMatrixTechniqueResponse(APIModel):
    """Matrix-ready representation of one top-level ATT&CK technique."""

    id: str
    external_id: str | None = None
    name: str
    type: str = "TECHNIQUE"

    tactic_ids: tuple[str, ...] = ()
    platform_ids: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ()

    description: str = ""

    coverage: MitreCoverageStateResponse

    subtechniques: tuple[
        MitreSubTechniqueResponse,
        ...
    ] = ()

    # SentinelSIEM relationship data.
    mapping_ids: tuple[UUID, ...] = ()
    detection_ids: tuple[str, ...] = ()


class MitreMatrixTacticResponse(APIModel):
    """One tactic column in the Enterprise ATT&CK matrix."""

    id: str
    external_id: str | None = None
    name: str
    description: str = ""

    techniques: tuple[
        MitreMatrixTechniqueResponse,
        ...
    ] = ()

    coverage_percent: float = Field(
        ge=0.0,
        le=100.0,
    )


class MitreMatrixResponse(APIModel):
    """Complete Enterprise ATT&CK matrix response."""

    tactics: tuple[
        MitreMatrixTacticResponse,
        ...
    ] = ()

    total_techniques: int = Field(
        ge=0,
    )

    full_techniques: int = Field(
        ge=0,
    )

    partial_techniques: int = Field(
        ge=0,
    )

    unmapped_techniques: int = Field(
        ge=0,
    )

    coverage_percent: float = Field(
        ge=0.0,
        le=100.0,
    )


# ============================================================================
# Analytics
# ============================================================================


class MitreAnalyticsResponse(APIModel):
    """MITRE coverage analytics for the SOC workspace."""

    total_techniques: int = Field(
        ge=0,
    )

    full_techniques: int = Field(
        ge=0,
    )

    partial_techniques: int = Field(
        ge=0,
    )

    unmapped_techniques: int = Field(
        ge=0,
    )

    coverage_percent: float = Field(
        ge=0.0,
        le=100.0,
    )

    by_tactic: dict[str, float] = {}

    technique_detection_counts: dict[str, int] = {}

    top_detected_technique_ids: tuple[str, ...] = ()


# ============================================================================
# Technique Detail
# ============================================================================


class MitreTechniqueDetailResponse(APIModel):
    """Complete technique detail response.

    This is the backend contract for the MITRE technique detail page/drawer.
    """

    technique: MitreTechniqueResponse

    coverage: MitreCoverageStateResponse

    subtechniques: tuple[
        MitreSubTechniqueResponse,
        ...
    ] = ()

    references: tuple[
        MitreReferenceResponse,
        ...
    ] = ()

    mitigations: tuple[
        MitreMitigationResponse,
        ...
    ] = ()

    detection_guidance: str = ""

    # SentinelSIEM relationships.
    mappings: tuple[
        MitreMappingResponse,
        ...
    ] = ()

    detection_ids: tuple[str, ...] = ()

    event_ids: tuple[UUID, ...] = ()

    alert_ids: tuple[UUID, ...] = ()

    incident_ids: tuple[UUID, ...] = ()

    ioc_ids: tuple[str, ...] = ()

    asset_ids: tuple[str, ...] = ()


# ============================================================================
# Relationships
# ============================================================================


class MitreTechniqueRelationshipsResponse(APIModel):
    """Relationship information for a MITRE technique."""

    technique_id: str

    mapping_ids: tuple[UUID, ...] = ()

    detection_ids: tuple[str, ...] = ()

    event_ids: tuple[UUID, ...] = ()

    alert_ids: tuple[UUID, ...] = ()

    incident_ids: tuple[UUID, ...] = ()

    ioc_ids: tuple[str, ...] = ()

    asset_ids: tuple[str, ...] = ()

    subtechnique_ids: tuple[str, ...] = ()


# ============================================================================
# Statistics
# ============================================================================


class MitreStatisticsResponse(APIModel):
    """Statistics displayed on the main MITRE workspace."""

    tactics: int = Field(
        ge=0,
    )

    techniques: int = Field(
        ge=0,
    )

    subtechniques: int = Field(
        ge=0,
    )

    coverage_percent: float = Field(
        ge=0.0,
        le=100.0,
    )


# ============================================================================
# Knowledge Object Response
# ============================================================================


class MitreKnowledgeResponse(APIModel):
    """High-level read-only MITRE knowledge response."""

    tactics: tuple[
        MitreTacticResponse,
        ...
    ] = ()

    platforms: tuple[
        MitrePlatformResponse,
        ...
    ] = ()

    statistics: MitreStatisticsResponse


# ============================================================================
# Exports
# ============================================================================


__all__ = [
    "MitreAnalyticsResponse",
    "MitreCoverageResponse",
    "MitreCoverageStateResponse",
    "MitreCoverageSummaryResponse",
    "MitreMappingCreateRequest",
    "MitreMappingListResponse",
    "MitreMappingResponse",
    "MitreMatrixResponse",
    "MitreMatrixTacticResponse",
    "MitreMatrixTechniqueResponse",
    "MitreMitigationResponse",
    "MitrePaginationResponse",
    "MitrePlatformListResponse",
    "MitrePlatformResponse",
    "MitreReferenceResponse",
    "MitreStatisticsResponse",
    "MitreSubTechniqueResponse",
    "MitreTacticCoverageResponse",
    "MitreTacticListResponse",
    "MitreTacticResponse",
    "MitreTechniqueDetailResponse",
    "MitreTechniqueListResponse",
    "MitreTechniqueRelationshipsResponse",
    "MitreTechniqueResponse",
    "MitreKnowledgeResponse",
]