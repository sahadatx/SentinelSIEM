"""
Strict MITRE ATT&CK domain contracts.

This module contains persistence-independent domain contracts for the
SentinelSIEM MITRE ATT&CK subsystem.

Architecture
------------

MITRE ATT&CK Knowledge:

    Official MITRE ATT&CK STIX/JSON
                │
                ▼
            Importer
                │
                ▼
           PostgreSQL
                │
                ▼
           Repository
                │
                ▼
             Service
                │
                ▼
              API/UI


SentinelSIEM Detection → MITRE Mapping:

    Detection
        │
        ▼
    Detection Mapping
        │
        ▼
    Coverage / Analytics


Important boundary
------------------
MITRE ATT&CK knowledge and SentinelSIEM detection mappings are separate
domains.

MITRE knowledge is dataset-backed and read-only to API/UI consumers.

Detection mappings are SentinelSIEM application data and may continue to
use the existing mapping persistence/runtime implementation.

This module intentionally contains no SQLAlchemy models, database sessions,
OpenSearch objects, HTTP clients, or persistence-specific behavior.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ============================================================================
# Identifier validation
# ============================================================================

_TACTIC_PATTERN = re.compile(r"^TA\d{4}$")
_TECHNIQUE_PATTERN = re.compile(r"^T\d{4}$")
_SUBTECHNIQUE_PATTERN = re.compile(r"^T\d{4}\.\d{3}$")


def utc_now() -> datetime:
    """Return the current timezone-aware UTC timestamp."""
    return datetime.now(UTC)


def _normalize_text(value: str) -> str:
    """Normalize free-form text by removing surrounding whitespace."""
    return value.strip()


def _validate_tactic_id(value: str) -> str:
    """Validate a MITRE ATT&CK tactic identifier."""
    value = _normalize_text(value)

    if not _TACTIC_PATTERN.fullmatch(value):
        raise ValueError("invalid MITRE tactic ID")

    return value


def _validate_technique_id(value: str) -> str:
    """Validate a top-level MITRE ATT&CK technique identifier."""
    value = _normalize_text(value)

    if not _TECHNIQUE_PATTERN.fullmatch(value):
        raise ValueError("invalid MITRE technique ID")

    return value


def _validate_subtechnique_id(value: str) -> str:
    """Validate a MITRE ATT&CK sub-technique identifier."""
    value = _normalize_text(value)

    if not _SUBTECHNIQUE_PATTERN.fullmatch(value):
        raise ValueError("invalid MITRE sub-technique ID")

    return value


def _validate_any_technique_id(value: str) -> str:
    """Validate either a technique or sub-technique identifier."""
    value = _normalize_text(value)

    if (
        not _TECHNIQUE_PATTERN.fullmatch(value)
        and not _SUBTECHNIQUE_PATTERN.fullmatch(value)
    ):
        raise ValueError("invalid MITRE technique identifier")

    return value


def _deduplicate(values: tuple[str, ...]) -> tuple[str, ...]:
    """
    Preserve insertion order while removing duplicate values.
    """
    return tuple(dict.fromkeys(values))


def _normalize_string_tuple(
    values: tuple[str, ...],
) -> tuple[str, ...]:
    """
    Normalize and deduplicate a tuple of strings.
    """
    normalized = tuple(
        _normalize_text(value)
        for value in values
    )

    if any(not value for value in normalized):
        raise ValueError("identifier cannot be empty")

    return _deduplicate(normalized)


# ============================================================================
# Coverage
# ============================================================================


class CoverageState(StrEnum):
    """
    Coverage state calculated from SentinelSIEM detection mappings.
    """

    FULL = "full"
    PARTIAL = "partial"
    UNMAPPED = "unmapped"


# ============================================================================
# MITRE Tactic
# ============================================================================


class MitreTactic(BaseModel):
    """
    Immutable MITRE ATT&CK tactic.

    Example:
        TA0001
        Initial Access
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    id: str
    external_id: str | None = None
    name: str
    description: str = ""

    @field_validator("id")
    @classmethod
    def valid_id(cls, value: str) -> str:
        return _validate_tactic_id(value)

    @field_validator("name")
    @classmethod
    def nonempty_name(cls, value: str) -> str:
        value = _normalize_text(value)

        if not value:
            raise ValueError("tactic name cannot be empty")

        return value

    @field_validator("description")
    @classmethod
    def normalize_description(cls, value: str) -> str:
        return _normalize_text(value)


# ============================================================================
# MITRE Platform
# ============================================================================


class MitrePlatform(BaseModel):
    """
    Immutable MITRE ATT&CK platform.

    Platform identifiers are intentionally not constrained to the
    TA/T#### identifier formats because MITRE platform names are represented
    differently in the Enterprise ATT&CK dataset.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    id: str
    name: str
    description: str = ""

    @field_validator("id")
    @classmethod
    def valid_id(cls, value: str) -> str:
        value = _normalize_text(value)

        if not value:
            raise ValueError("platform ID cannot be empty")

        return value

    @field_validator("name")
    @classmethod
    def nonempty_name(cls, value: str) -> str:
        value = _normalize_text(value)

        if not value:
            raise ValueError("platform name cannot be empty")

        return value

    @field_validator("description")
    @classmethod
    def normalize_description(cls, value: str) -> str:
        return _normalize_text(value)


# ============================================================================
# MITRE Reference
# ============================================================================


class MitreReference(BaseModel):
    """
    Immutable external reference associated with MITRE ATT&CK knowledge.

    A reference can contain:
      - source name
      - URL
      - ATT&CK external ID
      - reference description
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    source_name: str = Field(
        min_length=1,
        max_length=255,
    )

    url: str | None = None

    external_id: str | None = Field(
        default=None,
        max_length=255,
    )

    description: str = ""

    @field_validator("source_name")
    @classmethod
    def normalize_source_name(cls, value: str) -> str:
        value = _normalize_text(value)

        if not value:
            raise ValueError("reference source name cannot be empty")

        return value

    @field_validator("url")
    @classmethod
    def normalize_url(cls, value: str | None) -> str | None:
        if value is None:
            return None

        value = _normalize_text(value)

        return value or None

    @field_validator("external_id")
    @classmethod
    def normalize_external_id(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        value = _normalize_text(value)

        return value or None

    @field_validator("description")
    @classmethod
    def normalize_description(cls, value: str) -> str:
        return _normalize_text(value)


# ============================================================================
# MITRE Relationship
# ============================================================================


class MitreRelationshipType(StrEnum):
    """
    Relationship types used by SentinelSIEM's normalized ATT&CK domain.

    The STIX relationship type itself is preserved separately by the
    persistence layer. These values describe relationships exposed through
    the application/domain layer.
    """

    TECHNIQUE_TACTIC = "technique_tactic"
    TECHNIQUE_PLATFORM = "technique_platform"
    TECHNIQUE_SUBTECHNIQUE = "technique_subtechnique"
    TECHNIQUE_REFERENCE = "technique_reference"


class MitreTechniqueRelationship(BaseModel):
    """
    Immutable relationship between MITRE ATT&CK knowledge objects.

    This is a domain read model. The PostgreSQL repository additionally
    preserves the original STIX relationship identifier and relationship
    type in siem_mitre_relationships.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    relationship_id: UUID = Field(
        default_factory=uuid4,
    )

    relationship_type: MitreRelationshipType

    source_id: str = Field(
        min_length=1,
        max_length=255,
    )

    target_id: str = Field(
        min_length=1,
        max_length=255,
    )

    description: str = ""

    @field_validator("source_id", "target_id")
    @classmethod
    def normalize_ids(cls, value: str) -> str:
        value = _normalize_text(value)

        if not value:
            raise ValueError(
                "relationship identifier cannot be empty",
            )

        return value

    @field_validator("description")
    @classmethod
    def normalize_description(cls, value: str) -> str:
        return _normalize_text(value)


# ============================================================================
# MITRE Technique
# ============================================================================


class MitreTechnique(BaseModel):
    """
    Immutable top-level MITRE ATT&CK technique.

    Knowledge fields:
      - id
      - name
      - description
      - tactic IDs
      - platform IDs

    Sub-techniques are represented by MitreSubTechnique.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    id: str
    external_id: str | None = None
    name: str

    description: str = ""

    tactic_ids: tuple[str, ...] = ()
    platform_ids: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ()

    @field_validator("id")
    @classmethod
    def valid_id(cls, value: str) -> str:
        return _validate_any_technique_id(value)

    @field_validator("name")
    @classmethod
    def nonempty_name(cls, value: str) -> str:
        value = _normalize_text(value)

        if not value:
            raise ValueError("technique name cannot be empty")

        return value

    @field_validator("description")
    @classmethod
    def normalize_description(cls, value: str) -> str:
        return _normalize_text(value)

    @field_validator("tactic_ids")
    @classmethod
    def valid_tactics(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        normalized = tuple(
            _validate_tactic_id(item)
            for item in value
        )

        return _deduplicate(normalized)

    @field_validator("platform_ids")
    @classmethod
    def valid_platforms(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _normalize_string_tuple(value)


# ============================================================================
# MITRE Sub-technique
# ============================================================================


class MitreSubTechnique(BaseModel):
    """
    Immutable MITRE ATT&CK sub-technique.

    Example:

        id:
            T1059.001

        parent_id:
            T1059
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    id: str
    external_id: str | None = None
    name: str
    parent_id: str

    description: str = ""

    tactic_ids: tuple[str, ...] = ()
    platform_ids: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ()

    @field_validator("id")
    @classmethod
    def valid_id(cls, value: str) -> str:
        return _validate_subtechnique_id(value)

    @field_validator("name")
    @classmethod
    def nonempty_name(cls, value: str) -> str:
        value = _normalize_text(value)

        if not value:
            raise ValueError("sub-technique name cannot be empty")

        return value

    @field_validator("parent_id")
    @classmethod
    def valid_parent_id(cls, value: str) -> str:
        return _validate_technique_id(value)

    @field_validator("description")
    @classmethod
    def normalize_description(cls, value: str) -> str:
        return _normalize_text(value)

    @field_validator("tactic_ids")
    @classmethod
    def valid_tactics(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        normalized = tuple(
            _validate_tactic_id(item)
            for item in value
        )

        return _deduplicate(normalized)

    @field_validator("platform_ids")
    @classmethod
    def valid_platforms(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _normalize_string_tuple(value)


# ============================================================================
# Detection → MITRE Mapping
# ============================================================================


class DetectionMapping(BaseModel):
    """
    Immutable relationship between a SentinelSIEM detection and MITRE ATT&CK.

    This is NOT MITRE knowledge CRUD.

    ATT&CK knowledge:
        official dataset → PostgreSQL

    Detection mapping:
        SentinelSIEM detection → MITRE technique
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    mapping_id: UUID = Field(
        default_factory=uuid4,
    )

    detection_id: str = Field(
        min_length=1,
        max_length=200,
    )

    technique_id: str

    subtechnique_id: str | None = None

    tactic_ids: tuple[str, ...] = ()

    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
    )

    source: str = Field(
        default="sentinelsiem",
        min_length=1,
        max_length=200,
    )

    description: str = ""

    created_at: datetime = Field(
        default_factory=utc_now,
    )

    @field_validator("detection_id")
    @classmethod
    def normalize_detection_id(cls, value: str) -> str:
        value = _normalize_text(value)

        if not value:
            raise ValueError("detection ID cannot be empty")

        return value

    @field_validator("technique_id")
    @classmethod
    def valid_technique_id(cls, value: str) -> str:
        return _validate_technique_id(value)

    @field_validator("subtechnique_id")
    @classmethod
    def valid_subtechnique_id(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        return _validate_subtechnique_id(value)

    @field_validator("tactic_ids")
    @classmethod
    def valid_tactic_ids(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        normalized = tuple(
            _validate_tactic_id(item)
            for item in value
        )

        return _deduplicate(normalized)

    @field_validator("source")
    @classmethod
    def normalize_source(cls, value: str) -> str:
        value = _normalize_text(value)

        if not value:
            raise ValueError("mapping source cannot be empty")

        return value

    @field_validator("description")
    @classmethod
    def normalize_description(cls, value: str) -> str:
        return _normalize_text(value)


# ============================================================================
# Technique Coverage
# ============================================================================


class TechniqueCoverage(BaseModel):
    """
    Calculated coverage information for one MITRE ATT&CK technique.

    Coverage is derived from SentinelSIEM detection mappings and is not part
    of the official ATT&CK knowledge dataset.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    technique_id: str

    state: CoverageState = CoverageState.UNMAPPED

    mapping_count: int = Field(
        default=0,
        ge=0,
    )

    detection_count: int = Field(
        default=0,
        ge=0,
    )

    subtechnique_count: int = Field(
        default=0,
        ge=0,
    )

    mapped_subtechnique_count: int = Field(
        default=0,
        ge=0,
    )

    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    @field_validator("technique_id")
    @classmethod
    def valid_technique_id(cls, value: str) -> str:
        return _validate_technique_id(value)


# ============================================================================
# Technique Detail
# ============================================================================


class TechniqueDetail(BaseModel):
    """
    Rich read-side representation of a MITRE ATT&CK technique.

    Combines:

      1. ATT&CK knowledge
         - technique
         - references
         - sub-techniques

      2. SentinelSIEM calculated state
         - coverage
         - detection mappings

      3. Operational references
         - events
         - alerts
         - incidents
         - IOCs
         - assets

    Detailed event/alert/incident/IOC/asset resources remain owned by their
    respective SentinelSIEM modules.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    technique: MitreTechnique | MitreSubTechnique

    coverage: TechniqueCoverage

    subtechniques: tuple[MitreSubTechnique, ...] = ()

    references: tuple[MitreReference, ...] = ()

    mappings: tuple[DetectionMapping, ...] = ()

    detection_ids: tuple[str, ...] = ()

    event_ids: tuple[UUID, ...] = ()

    alert_ids: tuple[UUID, ...] = ()

    incident_ids: tuple[UUID, ...] = ()

    ioc_ids: tuple[str, ...] = ()

    asset_ids: tuple[str, ...] = ()


# ============================================================================
# Coverage Analytics
# ============================================================================


class CoverageAnalytics(BaseModel):
    """
    Aggregate calculated MITRE ATT&CK coverage analytics.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    total_techniques: int = Field(
        default=0,
        ge=0,
    )

    full_techniques: int = Field(
        default=0,
        ge=0,
    )

    partial_techniques: int = Field(
        default=0,
        ge=0,
    )

    unmapped_techniques: int = Field(
        default=0,
        ge=0,
    )

    coverage_percent: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
    )

    by_tactic: dict[str, float] = Field(
        default_factory=dict,
    )

    technique_detection_counts: dict[str, int] = Field(
        default_factory=dict,
    )

    top_detected_technique_ids: tuple[str, ...] = ()


# ============================================================================
# Matrix
# ============================================================================


class MatrixTechnique(BaseModel):
    """
    Technique representation used by the ATT&CK matrix.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    technique_id: str
    name: str

    tactic_ids: tuple[str, ...] = ()
    platform_ids: tuple[str, ...] = ()

    coverage: CoverageState = CoverageState.UNMAPPED

    subtechnique_count: int = Field(
        default=0,
        ge=0,
    )

    @field_validator("technique_id")
    @classmethod
    def valid_technique_id(cls, value: str) -> str:
        return _validate_technique_id(value)

    @field_validator("name")
    @classmethod
    def nonempty_name(cls, value: str) -> str:
        value = _normalize_text(value)

        if not value:
            raise ValueError("matrix technique name cannot be empty")

        return value

    @field_validator("tactic_ids")
    @classmethod
    def valid_tactic_ids(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        normalized = tuple(
            _validate_tactic_id(item)
            for item in value
        )

        return _deduplicate(normalized)

    @field_validator("platform_ids")
    @classmethod
    def valid_platform_ids(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        return _normalize_string_tuple(value)


class MatrixTactic(BaseModel):
    """
    One tactic column in the Enterprise ATT&CK matrix.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    tactic: MitreTactic

    techniques: tuple[MatrixTechnique, ...] = ()


class Matrix(BaseModel):
    """
    Complete Enterprise ATT&CK matrix read model.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    tactics: tuple[MatrixTactic, ...] = ()

    generated_at: datetime = Field(
        default_factory=utc_now,
    )


# ============================================================================
# Navigator
# ============================================================================


class NavigatorTechnique(BaseModel):
    """
    MITRE ATT&CK Navigator technique representation.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    techniqueID: str

    enabled: bool = True

    score: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
    )

    @field_validator("techniqueID")
    @classmethod
    def valid_technique_id(cls, value: str) -> str:
        return _validate_any_technique_id(value)


class NavigatorLayer(BaseModel):
    """
    MITRE ATT&CK Navigator layer generated from SentinelSIEM coverage.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    version: str = "4.5"

    name: str = "SentinelSIEM MITRE Coverage"

    domain: str = "enterprise-attack"

    description: str = ""

    techniques: list[NavigatorTechnique] = Field(
        default_factory=list,
    )

    generated_at: datetime = Field(
        default_factory=utc_now,
    )

    @field_validator("version")
    @classmethod
    def normalize_version(cls, value: str) -> str:
        value = _normalize_text(value)

        if not value:
            raise ValueError("Navigator version cannot be empty")

        return value

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        value = _normalize_text(value)

        if not value:
            raise ValueError("Navigator layer name cannot be empty")

        return value

    @field_validator("domain")
    @classmethod
    def normalize_domain(cls, value: str) -> str:
        value = _normalize_text(value)

        if not value:
            raise ValueError("Navigator domain cannot be empty")

        return value

    @field_validator("description")
    @classmethod
    def normalize_description(cls, value: str) -> str:
        return _normalize_text(value)


# ============================================================================
# Legacy / Compatibility Coverage Result
# ============================================================================


class CoverageResult(BaseModel):
    """
    Backward-compatible aggregate MITRE coverage result.

    Retained for existing Phase-14 consumers and existing API contracts.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

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

    @field_validator(
        "mapped_technique_ids",
        "unmapped_technique_ids",
    )
    @classmethod
    def normalize_technique_ids(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        normalized = tuple(
            _validate_technique_id(item)
            for item in value
        )

        return _deduplicate(normalized)


# ============================================================================
# Public API
# ============================================================================


__all__ = [
    "CoverageAnalytics",
    "CoverageResult",
    "CoverageState",
    "DetectionMapping",
    "Matrix",
    "MatrixTactic",
    "MatrixTechnique",
    "MitrePlatform",
    "MitreReference",
    "MitreRelationshipType",
    "MitreSubTechnique",
    "MitreTactic",
    "MitreTechnique",
    "MitreTechniqueRelationship",
    "NavigatorLayer",
    "NavigatorTechnique",
    "TechniqueCoverage",
    "TechniqueDetail",
    "utc_now",
]