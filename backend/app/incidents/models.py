from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class IncidentStatus(StrEnum):
    """Supported incident lifecycle states."""

    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


class IncidentSeverity(StrEnum):
    """Incident severity classification."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentCreate(BaseModel):
    """Validated input for creating a security incident."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=300)
    description: str = Field(default="", max_length=5000)
    severity: IncidentSeverity
    alert_ids: tuple[UUID, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    related_event_ids: tuple[str, ...] = ()
    related_ioc_ids: tuple[str, ...] = ()
    asset_ids: tuple[str, ...] = ()
    initial_assignee: str | None = None
    ownership_group: str | None = None


class Incident(BaseModel):
    """Immutable incident aggregate managed by the incident service."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    incident_id: UUID = Field(default_factory=uuid4)
    title: str
    description: str = ""
    severity: IncidentSeverity
    status: IncidentStatus = IncidentStatus.NEW
    alert_ids: tuple[UUID, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    related_event_ids: tuple[str, ...] = ()
    related_ioc_ids: tuple[str, ...] = ()
    asset_ids: tuple[str, ...] = ()
    assigned_to: str | None = None
    ownership_group: str | None = None
    first_seen_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    resolved_at: datetime | None = None
    closed_at: datetime | None = None


class IncidentAuditEntry(BaseModel):
    """Immutable audit record for an incident action."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    incident_id: UUID
    action: str
    actor: str
    from_status: IncidentStatus | None = None
    to_status: IncidentStatus | None = None
    reason: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class InvestigationNote(BaseModel):
    """A structured investigator note."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    note_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    author: str
    content: str = Field(min_length=1, max_length=10000)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class EvidenceRecord(BaseModel):
    """Evidence attached to an incident."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: str = Field(min_length=1, max_length=300)
    incident_id: UUID
    evidence_type: str = Field(min_length=1, max_length=100)
    reference: str = Field(min_length=1, max_length=2000)
    collected_by: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class TimelineEntry(BaseModel):
    """Chronological incident timeline entry."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    entry_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    event_type: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1, max_length=5000)
    actor: str
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
