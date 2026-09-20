from __future__ import annotations

"""
SentinelSIEM — Incident API Schemas.

API-facing request/response contracts for the Incident module.

Canonical Incident contract
----------------------------

Lifecycle:

    open
    investigating
    contained
    resolved
    closed

Severity:

    critical
    high
    medium
    low
    informational

Assignment:

    assigned_to / initial_assignee -> User UUID | None

The API layer must not introduce:

    - priority
    - ownership_group
    - last_updated_at
    - first_seen_at

Incident identity, status, timestamps and audit state are owned by the
Incident domain/manager.
"""

from datetime import datetime
from uuid import UUID

from pydantic import ConfigDict, Field, field_validator

from app.api.schemas.common import APIModel
from app.incidents.models import (
    EvidenceRecord,
    Incident,
    IncidentAuditEntry,
    IncidentCreate,
    InvestigationNote,
    TimelineEntry,
)


# =============================================================================
# Shared Helpers
# =============================================================================


def _normalize_text(value: object) -> object:
    """Trim string values while preserving non-string values for validation."""

    if not isinstance(value, str):
        return value

    return value.strip()


def _normalize_optional_text(value: object) -> object:
    """Trim optional strings and convert empty strings to None."""

    if value is None:
        return None

    if not isinstance(value, str):
        return value

    normalized = value.strip()

    return normalized or None


def _normalize_tags(value: object) -> tuple[str, ...]:
    """
    Normalize Incident tags.

    Tags are:

        - trimmed
        - lower-cased
        - deduplicated
        - empty values removed
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

        tag = item.strip().lower()

        if not tag:
            continue

        if tag in seen:
            continue

        seen.add(tag)
        normalized.append(tag)

    return tuple(normalized)


def _normalize_string_sequence(value: object) -> object:
    """
    Normalize a sequence of relationship identifiers.

    Empty values are removed and duplicate values are preserved only once.
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
            item = str(item)

        item = item.strip()

        if not item or item in seen:
            continue

        seen.add(item)
        normalized.append(item)

    return tuple(normalized)


# =============================================================================
# Incident Create
# =============================================================================


class IncidentCreateRequest(APIModel):
    """
    Request body for creating a security Incident.

    Generated fields such as:

        - incident_id
        - incident_number
        - status
        - created_at
        - updated_at
        - resolved_at
        - closed_at

    are intentionally excluded.

    A newly created Incident receives OPEN status from the domain manager.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    title: str = Field(
        min_length=1,
        max_length=300,
    )

    description: str = Field(
        default="",
        max_length=5000,
    )

    severity: str = Field(
        min_length=1,
        max_length=50,
    )

    tags: tuple[str, ...] = ()

    alert_ids: tuple[UUID, ...] = ()

    evidence_ids: tuple[str, ...] = ()

    related_event_ids: tuple[str, ...] = ()

    related_ioc_ids: tuple[str, ...] = ()

    asset_ids: tuple[str, ...] = ()

    assigned_to: UUID | None = None

    @field_validator(
        "title",
        "description",
        "severity",
        mode="before",
    )
    @classmethod
    def normalize_text(
        cls,
        value: object,
    ) -> object:
        """Normalize required text fields."""

        return _normalize_text(value)

    @field_validator(
        "tags",
        mode="before",
    )
    @classmethod
    def normalize_tags(
        cls,
        value: object,
    ) -> tuple[str, ...]:
        """Normalize and deduplicate Incident tags."""

        return _normalize_tags(value)

    @field_validator(
        "evidence_ids",
        "related_event_ids",
        "related_ioc_ids",
        "asset_ids",
        mode="before",
    )
    @classmethod
    def normalize_relationship_ids(
        cls,
        value: object,
    ) -> object:
        """Normalize string relationship collections."""

        return _normalize_string_sequence(value)

    def to_domain(self) -> IncidentCreate:
        """Convert the API request into the domain IncidentCreate model."""

        payload = self.model_dump(
            mode="python",
        )

        # Public API uses ``assigned_to``.
        # The domain IncidentCreate model uses ``initial_assignee``.
        payload["initial_assignee"] = payload.pop(
            "assigned_to",
            None,
        )

        return IncidentCreate.model_validate(
            payload,
        )


# =============================================================================
# Incident Update
# =============================================================================


class IncidentUpdateRequest(APIModel):
    """
    Request body for editing mutable Incident fields.

    Supported fields:

        - title
        - description
        - severity
        - assigned_to
        - status

    ``assigned_to`` and ``status`` are included here because the canonical
    Incident edit workflow exposes them as mutable Incident fields.

    API/application authorization and User Management validation remain
    outside this schema.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    title: str | None = Field(
        default=None,
        min_length=1,
        max_length=300,
    )

    description: str | None = Field(
        default=None,
        max_length=5000,
    )

    severity: str | None = Field(
        default=None,
        min_length=1,
        max_length=50,
    )

    assigned_to: UUID | None = None

    status: str | None = Field(
        default=None,
        min_length=1,
        max_length=50,
    )

    @field_validator(
        "title",
        "description",
        "severity",
        "status",
        mode="before",
    )
    @classmethod
    def normalize_text(
        cls,
        value: object,
    ) -> object:
        """Normalize optional update text fields."""

        if value is None:
            return None

        return _normalize_text(value)


# =============================================================================
# Incident Assignment
# =============================================================================


class IncidentAssignmentRequest(APIModel):
    """
    Request body for Incident assignment/reassignment.

    ``None`` explicitly means unassign the Incident.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    assignee: UUID | None = None


# =============================================================================
# Incident Transition
# =============================================================================


class IncidentTransitionRequest(APIModel):
    """
    Request body for a validated Incident lifecycle transition.

    Canonical lifecycle:

        OPEN
          ↓
        INVESTIGATING
          ↓
        CONTAINED
          ↓
        RESOLVED
          ↓
        CLOSED
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    status: str = Field(
        min_length=1,
        max_length=50,
    )

    reason: str = Field(
        default="",
        max_length=2000,
    )

    @field_validator(
        "status",
        "reason",
        mode="before",
    )
    @classmethod
    def normalize_text(
        cls,
        value: object,
    ) -> object:
        """Normalize transition fields."""

        return _normalize_text(value)


# =============================================================================
# Incident Statistics / KPI
# =============================================================================


class IncidentStatisticsResponse(APIModel):
    """
    Backend-authoritative Incident KPI response.

    KPI contract:

        total
        open
        investigating
        critical
        high
        resolved
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    total: int = Field(
        default=0,
        ge=0,
    )

    open: int = Field(
        default=0,
        ge=0,
    )

    investigating: int = Field(
        default=0,
        ge=0,
    )

    critical: int = Field(
        default=0,
        ge=0,
    )

    high: int = Field(
        default=0,
        ge=0,
    )

    resolved: int = Field(
        default=0,
        ge=0,
    )


class IncidentSummaryResponse(IncidentStatisticsResponse):
    """
    Backward-compatible alias for the Incident statistics response.

    New API code should use IncidentStatisticsResponse.
    """

    pass


# =============================================================================
# Filter Options
# =============================================================================


class IncidentFilterOptionsResponse(APIModel):
    """
    Backend-authoritative Incident filter options.

    Values originate from the persistence layer.

    Assignees contain User UUIDs. Human-readable User names/roles are
    resolved through User Management at the application/API layer.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    statuses: tuple[str, ...] = ()

    severities: tuple[str, ...] = ()

    assignees: tuple[UUID, ...] = ()


# =============================================================================
# Related Alert
# =============================================================================


class RelatedAlertResponse(APIModel):
    """Enriched Alert reference associated with an Incident."""

    model_config = ConfigDict(
        extra="forbid",
    )

    alert_id: UUID

    title: str = ""

    description: str = ""

    severity: str = ""

    status: str = ""

    source_type: str = ""

    rule_id: str | None = None

    rule_name: str | None = None

    event_ids: tuple[str, ...] = ()

    first_seen_at: datetime | None = None

    last_seen_at: datetime | None = None


# =============================================================================
# Related Event
# =============================================================================


class RelatedEventResponse(APIModel):
    """Enriched Event reference associated with an Incident."""

    model_config = ConfigDict(
        extra="forbid",
    )

    event_id: str

    timestamp: datetime | None = None

    action: str | None = None

    outcome: str | None = None

    severity: str | None = None

    category: str | None = None

    source_ip: str | None = None

    source: str | None = None

    actor: str | None = None

    target: str | None = None


# =============================================================================
# Related IOC
# =============================================================================


class RelatedIOCResponse(APIModel):
    """Enriched IOC reference associated with an Incident."""

    model_config = ConfigDict(
        extra="forbid",
    )

    ioc_id: str

    indicator: str = ""

    indicator_type: str = ""

    value: str = ""

    confidence: int | None = Field(
        default=None,
        ge=0,
        le=100,
    )

    severity: str | None = None

    status: str | None = None

    source: str | None = None


# =============================================================================
# Related Asset
# =============================================================================


class RelatedAssetResponse(APIModel):
    """Enriched Asset reference associated with an Incident."""

    model_config = ConfigDict(
        extra="forbid",
    )

    asset_id: str

    name: str = ""

    hostname: str | None = None

    asset_type: str | None = None

    status: str | None = None

    criticality: str | None = None

    ip_address: str | None = None


# =============================================================================
# Incident Response
# =============================================================================


class IncidentResponse(APIModel):
    """
    Standard Incident API representation.

    Contains canonical Incident identity, lifecycle, severity, assignment,
    relationships and timestamps.

    Human-readable assignee information should be resolved separately from
    User Management rather than duplicated into the Incident document.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    incident_id: UUID

    incident_number: str

    title: str

    description: str

    severity: str

    status: str

    tags: tuple[str, ...]

    alert_ids: tuple[UUID, ...]

    evidence_ids: tuple[str, ...]

    related_event_ids: tuple[str, ...]

    related_ioc_ids: tuple[str, ...]

    asset_ids: tuple[str, ...]

    assigned_to: UUID | None = None

    created_by: str

    created_at: datetime

    updated_at: datetime

    resolved_at: datetime | None = None

    closed_at: datetime | None = None

    @classmethod
    def from_model(
        cls,
        incident: Incident,
    ) -> IncidentResponse:
        """Convert an Incident domain model into an API response."""

        return cls.model_validate(
            incident.model_dump(
                mode="python",
            ),
        )


# =============================================================================
# Incident Detail Response
# =============================================================================


class IncidentDetailResponse(IncidentResponse):
    """
    Full Incident detail response.

    Includes enriched relationships and investigation history.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    related_alerts: tuple[RelatedAlertResponse, ...] = ()

    related_events: tuple[RelatedEventResponse, ...] = ()

    related_iocs: tuple[RelatedIOCResponse, ...] = ()

    affected_assets: tuple[RelatedAssetResponse, ...] = ()

    notes: tuple["IncidentNoteResponse", ...] = ()

    evidence: tuple["IncidentEvidenceResponse", ...] = ()

    timeline: tuple["IncidentTimelineResponse", ...] = ()

    audit_history: tuple["IncidentAuditResponse", ...] = ()


# =============================================================================
# Investigation Note Create
# =============================================================================


class IncidentNoteCreateRequest(APIModel):
    """Request body for adding an Incident investigation note."""

    model_config = ConfigDict(
        extra="forbid",
    )

    author: str = Field(
        min_length=1,
        max_length=300,
    )

    content: str = Field(
        min_length=1,
        max_length=10000,
    )

    @field_validator(
        "author",
        "content",
        mode="before",
    )
    @classmethod
    def normalize_text(
        cls,
        value: object,
    ) -> object:
        """Normalize note text."""

        return _normalize_text(value)


# =============================================================================
# Investigation Note Response
# =============================================================================


class IncidentNoteResponse(APIModel):
    """API representation of an Incident investigation note."""

    model_config = ConfigDict(
        extra="forbid",
    )

    note_id: UUID

    incident_id: UUID

    author: str

    content: str

    created_at: datetime

    @classmethod
    def from_model(
        cls,
        note: InvestigationNote,
    ) -> IncidentNoteResponse:
        """Convert a domain note into an API response."""

        return cls.model_validate(
            note.model_dump(
                mode="python",
            ),
        )


# =============================================================================
# Evidence Create
# =============================================================================


class IncidentEvidenceCreateRequest(APIModel):
    """Request body for attaching evidence to an Incident."""

    model_config = ConfigDict(
        extra="forbid",
    )

    evidence_id: str = Field(
        min_length=1,
        max_length=300,
    )

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
        value: object,
    ) -> object:
        """Normalize evidence fields."""

        return _normalize_text(value)


# =============================================================================
# Evidence Response
# =============================================================================


class IncidentEvidenceResponse(APIModel):
    """API representation of Incident evidence."""

    model_config = ConfigDict(
        extra="forbid",
    )

    evidence_id: str

    incident_id: UUID

    evidence_type: str

    reference: str

    collected_by: str

    created_at: datetime

    @classmethod
    def from_model(
        cls,
        evidence: EvidenceRecord,
    ) -> IncidentEvidenceResponse:
        """Convert a domain evidence record into an API response."""

        return cls.model_validate(
            evidence.model_dump(
                mode="python",
            ),
        )


# =============================================================================
# Timeline Response
# =============================================================================


class IncidentTimelineResponse(APIModel):
    """API representation of an Incident timeline entry."""

    model_config = ConfigDict(
        extra="forbid",
    )

    entry_id: UUID

    incident_id: UUID

    event_type: str

    description: str

    actor: str

    occurred_at: datetime

    @classmethod
    def from_model(
        cls,
        entry: TimelineEntry,
    ) -> IncidentTimelineResponse:
        """Convert a domain timeline entry into an API response."""

        return cls.model_validate(
            entry.model_dump(
                mode="python",
            ),
        )


# =============================================================================
# Audit Response
# =============================================================================


class IncidentAuditResponse(APIModel):
    """
    API representation of an Incident audit entry.

    Supports both status-specific and generic field-level audit changes.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    audit_id: UUID

    incident_id: UUID

    action: str

    actor: str

    field_name: str | None = None

    from_value: str | None = None

    to_value: str | None = None

    from_status: str | None = None

    to_status: str | None = None

    from_severity: str | None = None

    to_severity: str | None = None

    from_assignee: UUID | None = None

    to_assignee: UUID | None = None

    reason: str

    created_at: datetime

    @classmethod
    def from_model(
        cls,
        entry: IncidentAuditEntry,
    ) -> IncidentAuditResponse:
        """Convert an Incident audit entry into an API response."""

        return cls.model_validate(
            entry.model_dump(
                mode="python",
            ),
        )


# =============================================================================
# Pagination
# =============================================================================


class IncidentListResponse(APIModel):
    """Paginated Incident list response."""

    model_config = ConfigDict(
        extra="forbid",
    )

    items: tuple[IncidentResponse, ...]

    total: int = Field(
        ge=0,
    )

    offset: int = Field(
        default=0,
        ge=0,
    )

    limit: int = Field(
        default=100,
        ge=1,
        le=1000,
    )


# =============================================================================
# Public API
# =============================================================================


__all__ = [
    "IncidentCreateRequest",
    "IncidentUpdateRequest",
    "IncidentAssignmentRequest",
    "IncidentTransitionRequest",
    "IncidentStatisticsResponse",
    "IncidentSummaryResponse",
    "IncidentFilterOptionsResponse",
    "IncidentResponse",
    "IncidentDetailResponse",
    "IncidentListResponse",
    "IncidentNoteCreateRequest",
    "IncidentNoteResponse",
    "IncidentEvidenceCreateRequest",
    "IncidentEvidenceResponse",
    "IncidentTimelineResponse",
    "IncidentAuditResponse",
    "RelatedAlertResponse",
    "RelatedEventResponse",
    "RelatedIOCResponse",
    "RelatedAssetResponse",
]
