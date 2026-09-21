from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


# ============================================================================
# IOC Type
# ============================================================================


class IOCType(StrEnum):
    """
    Supported indicator types.
    """

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    HOSTNAME = "hostname"


# ============================================================================
# IOC Severity
# ============================================================================


class IOCSeverity(StrEnum):
    """
    Threat severity assigned to an IOC.

    Severity is intentionally separate from reputation.

    Severity:
        info
        low
        medium
        high
        critical

    Reputation:
        unknown
        benign
        suspicious
        malicious
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ============================================================================
# IOC Status
# ============================================================================


class IOCStatus(StrEnum):
    """
    IOC lifecycle status.

    ACTIVE:
        IOC is currently trusted as an active threat-intelligence indicator.

    EXPIRED:
        IOC passed its configured expiration time.

    REVOKED:
        IOC has been explicitly invalidated by an authorized action.

    IOC deletion is intentionally not part of the lifecycle. Historical
    indicators remain available for investigation, correlation and audit.
    """

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


# ============================================================================
# IOC Reputation
# ============================================================================


class Reputation(StrEnum):
    """
    Threat reputation assigned to an IOC.
    """

    UNKNOWN = "unknown"
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


# ============================================================================
# IOC Relationships
# ============================================================================


class IOCRelationships(BaseModel):
    """
    Cross-module relationships for a threat indicator.

    IDs remain lightweight references. Detailed resource enrichment is
    resolved by the corresponding service/repository/module.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    event_ids: tuple[str, ...] = ()
    alert_ids: tuple[UUID, ...] = ()
    incident_ids: tuple[UUID, ...] = ()
    asset_ids: tuple[str, ...] = ()
    mitre_technique_ids: tuple[str, ...] = ()


# ============================================================================
# Canonical IOC Domain Model
# ============================================================================


class IOC(BaseModel):
    """
    Canonical Threat Intelligence IOC domain model.

    This is the authoritative domain representation used by:

        API
        Service
        Manager
        Repository
        Enrichment
        Matching

    Persistence-specific details remain outside the domain model.

    IOC records are retained rather than hard-deleted so historical
    intelligence can continue to support investigation, correlation,
    reporting and audit workflows.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    # ------------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------------

    ioc_id: UUID = Field(
        default_factory=uuid4,
    )

    # ------------------------------------------------------------------------
    # Indicator
    # ------------------------------------------------------------------------

    ioc_type: IOCType

    value: str = Field(
        min_length=1,
        max_length=4096,
    )

    normalized_value: str = Field(
        min_length=1,
        max_length=4096,
    )

    # ------------------------------------------------------------------------
    # Assessment
    # ------------------------------------------------------------------------

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    severity: IOCSeverity = IOCSeverity.MEDIUM

    reputation: Reputation = Reputation.UNKNOWN

    status: IOCStatus = IOCStatus.ACTIVE

    # ------------------------------------------------------------------------
    # Provenance
    # ------------------------------------------------------------------------

    source: str = Field(
        min_length=1,
        max_length=255,
    )

    feed: str | None = Field(
        default=None,
        max_length=255,
    )

    # ------------------------------------------------------------------------
    # Analyst / Human Context
    # ------------------------------------------------------------------------

    description: str | None = Field(
        default=None,
        max_length=8192,
    )

    tags: tuple[str, ...] = ()

    # ------------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------------

    first_seen: datetime

    last_seen: datetime

    expiration: datetime | None = None

    # ------------------------------------------------------------------------
    # Additional Metadata
    # ------------------------------------------------------------------------

    metadata: dict[str, str] = Field(
        default_factory=dict,
    )

    # ------------------------------------------------------------------------
    # Cross-module Relationships
    # ------------------------------------------------------------------------

    relationships: IOCRelationships = Field(
        default_factory=IOCRelationships,
    )


# ============================================================================
# IOC Create Model
# ============================================================================


class IOCCreate(BaseModel):
    """
    Domain input model used when creating a new IOC.

    API-layer representations such as confidence 0..100 are converted
    before this model is constructed.

    New IOCs default to ACTIVE. Explicit lifecycle transitions such as
    REVOKED should be handled through the appropriate service operation
    rather than deletion.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    # ------------------------------------------------------------------------
    # Indicator
    # ------------------------------------------------------------------------

    ioc_type: IOCType

    value: str = Field(
        min_length=1,
        max_length=4096,
    )

    # ------------------------------------------------------------------------
    # Assessment
    # ------------------------------------------------------------------------

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    severity: IOCSeverity = IOCSeverity.MEDIUM

    reputation: Reputation = Reputation.UNKNOWN

    status: IOCStatus = IOCStatus.ACTIVE

    # ------------------------------------------------------------------------
    # Provenance
    # ------------------------------------------------------------------------

    source: str = Field(
        min_length=1,
        max_length=255,
    )

    feed: str | None = Field(
        default=None,
        max_length=255,
    )

    # ------------------------------------------------------------------------
    # Analyst / Human Context
    # ------------------------------------------------------------------------

    description: str | None = Field(
        default=None,
        max_length=8192,
    )

    tags: tuple[str, ...] = ()

    # ------------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------------

    expiration: datetime | None = None

    # ------------------------------------------------------------------------
    # Additional Metadata
    # ------------------------------------------------------------------------

    metadata: dict[str, str] = Field(
        default_factory=dict,
    )

    # ------------------------------------------------------------------------
    # Cross-module Relationships
    # ------------------------------------------------------------------------

    relationships: IOCRelationships = Field(
        default_factory=IOCRelationships,
    )


# ============================================================================
# IOC Match Model
# ============================================================================


class IOCMatch(BaseModel):
    """
    Lightweight IOC representation returned by matching/enrichment.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    ioc_id: UUID

    ioc_type: IOCType

    value: str

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    severity: IOCSeverity

    reputation: Reputation

    status: IOCStatus

    source: str

    feed: str | None = None

    tags: tuple[str, ...] = ()


# ============================================================================
# Time Helper
# ============================================================================


def utcnow() -> datetime:
    """
    Return the current timezone-aware UTC datetime.
    """

    return datetime.now(UTC)


# ============================================================================
# Public Exports
# ============================================================================


__all__ = [
    "IOCType",
    "IOCSeverity",
    "IOCStatus",
    "Reputation",
    "IOCRelationships",
    "IOC",
    "IOCCreate",
    "IOCMatch",
    "utcnow",
]