from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ============================================================================
# Incident Enums
# ============================================================================


class IncidentStatus(StrEnum):
    """Canonical Incident lifecycle states."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class IncidentSeverity(StrEnum):
    """Canonical Incident severity classification."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


# ============================================================================
# Incident Create Model
# ============================================================================


class IncidentCreate(BaseModel):
    """
    Validated input for creating a Security Incident.

    Generated/server-controlled fields are intentionally excluded:
    - incident_id
    - incident_number
    - status
    - created_by
    - created_at
    - updated_at
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    title: str = Field(
        min_length=1,
        max_length=300,
    )

    description: str = Field(
        min_length=1,
        max_length=5000,
    )

    severity: IncidentSeverity

    # ------------------------------------------------------------------------
    # Optional relationship data
    #
    # These are useful for Alert -> Incident promotion and investigation
    # workflows. They are not user-facing classification fields.
    # ------------------------------------------------------------------------

    tags: tuple[str, ...] = ()

    alert_ids: tuple[UUID, ...] = ()

    evidence_ids: tuple[str, ...] = ()

    related_event_ids: tuple[str, ...] = ()

    related_ioc_ids: tuple[str, ...] = ()

    asset_ids: tuple[str, ...] = ()

    # ------------------------------------------------------------------------
    # Optional initial assignment
    #
    # The actual user/role validation is performed at the application/API
    # boundary using User Management. The Incident domain stores the user ID.
    # ------------------------------------------------------------------------

    initial_assignee: UUID | None = None

    # ------------------------------------------------------------------------
    # Text normalization
    # ------------------------------------------------------------------------

    @field_validator(
        "title",
        "description",
        mode="before",
    )
    @classmethod
    def normalize_text(
        cls,
        value: str,
    ) -> str:
        """Trim user-provided text."""

        if not isinstance(value, str):
            return value

        return value.strip()

    # ------------------------------------------------------------------------
    # Tag normalization
    # ------------------------------------------------------------------------

    @field_validator(
        "tags",
        mode="before",
    )
    @classmethod
    def normalize_tags(
        cls,
        value: object,
    ) -> tuple[str, ...]:
        """
        Normalize incident tags.

        Empty values are discarded.
        Tags are lower-cased and deduplicated while preserving order.
        """

        if value is None:
            return ()

        if isinstance(value, str):
            value = (value,)

        if not isinstance(
            value,
            (list, tuple, set, frozenset),
        ):
            return value

        normalized: list[str] = []
        seen: set[str] = set()

        for item in value:
            if not isinstance(item, str):
                continue

            tag = item.strip()

            if not tag:
                continue

            normalized_tag = tag.lower()

            if normalized_tag in seen:
                continue

            seen.add(normalized_tag)
            normalized.append(normalized_tag)

        return tuple(normalized)


# ============================================================================
# Incident Aggregate
# ============================================================================


class Incident(BaseModel):
    """
    Immutable Security Incident aggregate.

    The Incident is the central SOC investigation object connecting:
    - alerts
    - evidence
    - events
    - IOCs
    - assets
    - assignment
    - investigation lifecycle
    - audit history

    Server-controlled fields such as identity, status, creator and timestamps
    are part of the persisted Incident aggregate and are not supplied by the
    normal create request.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    # ------------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------------

    incident_id: UUID = Field(
        default_factory=uuid4,
    )

    incident_number: str = Field(
        min_length=1,
        max_length=32,
    )

    # ------------------------------------------------------------------------
    # Core Incident Information
    # ------------------------------------------------------------------------

    title: str = Field(
        min_length=1,
        max_length=300,
    )

    description: str = Field(
        min_length=1,
        max_length=5000,
    )

    severity: IncidentSeverity

    status: IncidentStatus = IncidentStatus.OPEN

    # ------------------------------------------------------------------------
    # Classification / Investigation Metadata
    #
    # Priority and ownership_group are intentionally NOT part of the final
    # Incident contract.
    # ------------------------------------------------------------------------

    tags: tuple[str, ...] = ()

    # ------------------------------------------------------------------------
    # Related SOC Objects
    # ------------------------------------------------------------------------

    alert_ids: tuple[UUID, ...] = ()

    evidence_ids: tuple[str, ...] = ()

    related_event_ids: tuple[str, ...] = ()

    related_ioc_ids: tuple[str, ...] = ()

    asset_ids: tuple[str, ...] = ()

    # ------------------------------------------------------------------------
    # Assignment
    # ------------------------------------------------------------------------

    assigned_to: UUID | None = None

    # ------------------------------------------------------------------------
    # Creation / Update Metadata
    # ------------------------------------------------------------------------

    created_by: str = Field(
        min_length=1,
        max_length=300,
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )

    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )

    # ------------------------------------------------------------------------
    # Lifecycle Timestamps
    # ------------------------------------------------------------------------

    resolved_at: datetime | None = None

    closed_at: datetime | None = None

    # ------------------------------------------------------------------------
    # Text normalization
    # ------------------------------------------------------------------------

    @field_validator(
        "incident_number",
        "title",
        "description",
        "created_by",
        mode="before",
    )
    @classmethod
    def normalize_text(
        cls,
        value: str,
    ) -> str:
        """Trim persisted text values."""

        if not isinstance(value, str):
            return value

        return value.strip()

    # ------------------------------------------------------------------------
    # Tag normalization
    # ------------------------------------------------------------------------

    @field_validator(
        "tags",
        mode="before",
    )
    @classmethod
    def normalize_tags(
        cls,
        value: object,
    ) -> tuple[str, ...]:
        """
        Normalize incident tags.

        Tags are lower-cased, trimmed, deduplicated and empty values are
        removed while preserving their original order.
        """

        if value is None:
            return ()

        if isinstance(value, str):
            value = (value,)

        if not isinstance(
            value,
            (list, tuple, set, frozenset),
        ):
            return value

        normalized: list[str] = []
        seen: set[str] = set()

        for item in value:
            if not isinstance(item, str):
                continue

            tag = item.strip()

            if not tag:
                continue

            normalized_tag = tag.lower()

            if normalized_tag in seen:
                continue

            seen.add(normalized_tag)
            normalized.append(normalized_tag)

        return tuple(normalized)


# ============================================================================
# Incident Audit
# ============================================================================


class IncidentAuditEntry(BaseModel):
    """
    Immutable audit record for an Incident mutation.

    The audit model supports:
    - incident creation
    - generic Incident updates
    - assignment/reassignment
    - severity changes
    - status changes
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    audit_id: UUID = Field(
        default_factory=uuid4,
    )

    incident_id: UUID

    action: str = Field(
        min_length=1,
        max_length=100,
    )

    actor: str = Field(
        min_length=1,
        max_length=300,
    )

    # ------------------------------------------------------------------------
    # Status transition
    # ------------------------------------------------------------------------

    from_status: IncidentStatus | None = None

    to_status: IncidentStatus | None = None

    # ------------------------------------------------------------------------
    # Severity transition
    # ------------------------------------------------------------------------

    from_severity: IncidentSeverity | None = None

    to_severity: IncidentSeverity | None = None

    # ------------------------------------------------------------------------
    # Assignment transition
    # ------------------------------------------------------------------------

    from_assignee: UUID | None = None

    to_assignee: UUID | None = None

    # ------------------------------------------------------------------------
    # Generic field-level change information
    #
    # Used when an Incident update changes title/description or another
    # mutable field that does not require a dedicated typed pair above.
    # ------------------------------------------------------------------------

    field_name: str | None = Field(
        default=None,
        max_length=100,
    )

    from_value: str | None = Field(
        default=None,
        max_length=5000,
    )

    to_value: str | None = Field(
        default=None,
        max_length=5000,
    )

    # ------------------------------------------------------------------------
    # Audit reason
    # ------------------------------------------------------------------------

    reason: str = Field(
        default="",
        max_length=5000,
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )

    # ------------------------------------------------------------------------
    # Normalization
    # ------------------------------------------------------------------------

    @field_validator(
        "action",
        "actor",
        "field_name",
        "from_value",
        "to_value",
        "reason",
        mode="before",
    )
    @classmethod
    def normalize_text(
        cls,
        value: str | None,
    ) -> str | None:
        """Trim optional and required audit text values."""

        if value is None:
            return None

        if not isinstance(value, str):
            return value

        return value.strip()


# ============================================================================
# Investigation Note
# ============================================================================


class InvestigationNote(BaseModel):
    """Immutable structured investigator note."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    note_id: UUID = Field(
        default_factory=uuid4,
    )

    incident_id: UUID

    author: str = Field(
        min_length=1,
        max_length=300,
    )

    content: str = Field(
        min_length=1,
        max_length=10000,
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )

    @field_validator(
        "author",
        "content",
        mode="before",
    )
    @classmethod
    def normalize_text(
        cls,
        value: str,
    ) -> str:
        """Normalize investigation note text."""

        if not isinstance(value, str):
            return value

        return value.strip()


# ============================================================================
# Evidence
# ============================================================================


class EvidenceRecord(BaseModel):
    """Immutable evidence record attached to an Incident."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    evidence_id: str = Field(
        min_length=1,
        max_length=300,
    )

    incident_id: UUID

    evidence_type: str = Field(
        min_length=1,
        max_length=100,
    )

    reference: str = Field(
        min_length=1,
        max_length=2000,
    )

    collected_by: str = Field(
        min_length=1,
        max_length=300,
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )

    @field_validator(
        "evidence_id",
        "evidence_type",
        "reference",
        "collected_by",
        mode="before",
    )
    @classmethod
    def normalize_text(
        cls,
        value: str,
    ) -> str:
        """Normalize evidence text values."""

        if not isinstance(value, str):
            return value

        return value.strip()


# ============================================================================
# Incident Timeline
# ============================================================================


class TimelineEntry(BaseModel):
    """Immutable chronological Incident timeline entry."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    entry_id: UUID = Field(
        default_factory=uuid4,
    )

    incident_id: UUID

    event_type: str = Field(
        min_length=1,
        max_length=100,
    )

    description: str = Field(
        min_length=1,
        max_length=5000,
    )

    actor: str = Field(
        min_length=1,
        max_length=300,
    )

    occurred_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )

    @field_validator(
        "event_type",
        "description",
        "actor",
        mode="before",
    )
    @classmethod
    def normalize_text(
        cls,
        value: str,
    ) -> str:
        """Normalize timeline text values."""

        if not isinstance(value, str):
            return value

        return value.strip()


# ============================================================================
# Public API
# ============================================================================


__all__ = [
    "IncidentStatus",
    "IncidentSeverity",
    "IncidentCreate",
    "Incident",
    "IncidentAuditEntry",
    "InvestigationNote",
    "EvidenceRecord",
    "TimelineEntry",
]