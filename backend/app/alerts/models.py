from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class AlertStatus(StrEnum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    CLOSED = "closed"
    SUPPRESSED = "suppressed"


class AlertSourceType(StrEnum):
    DETECTION = "detection"
    CORRELATION = "correlation"


class AlertSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertCreate(BaseModel):
    """Immutable input used to create an alert from a detection/correlation result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_type: AlertSourceType
    source_id: str = Field(min_length=1, max_length=256)
    rule_id: str = Field(min_length=1, max_length=256)
    title: str = Field(min_length=1, max_length=512)
    description: str = Field(default="", max_length=4096)
    severity: AlertSeverity
    risk_score: float = Field(ge=0, le=100)
    priority: str = Field(min_length=1, max_length=32)
    evidence_ids: tuple[str, ...] = ()
    asset_id: str | None = Field(default=None, max_length=256)
    user_id: str | None = Field(default=None, max_length=256)
    deduplication_key: str | None = Field(default=None, max_length=512)


class Alert(BaseModel):
    """Auditable alert entity and lifecycle state."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    alert_id: UUID = Field(default_factory=uuid4)
    source_type: AlertSourceType
    source_id: str
    rule_id: str
    title: str
    description: str
    severity: AlertSeverity
    risk_score: float = Field(ge=0, le=100)
    priority: str
    status: AlertStatus = AlertStatus.NEW
    evidence_ids: tuple[str, ...] = ()
    asset_id: str | None = None
    user_id: str | None = None
    assigned_to: str | None = None
    ownership_group: str | None = None
    deduplication_key: str
    occurrence_count: int = Field(default=1, ge=1)
    first_seen_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    acknowledged_at: datetime | None = None
    investigating_at: datetime | None = None
    escalated_at: datetime | None = None
    resolved_at: datetime | None = None
    closed_at: datetime | None = None
    suppressed_at: datetime | None = None
    sla_due_at: datetime | None = None
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AlertAuditEntry(BaseModel):
    """Immutable lifecycle audit record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    audit_id: UUID = Field(default_factory=uuid4)
    alert_id: UUID
    action: str = Field(min_length=1, max_length=128)
    actor: str = Field(min_length=1, max_length=256)
    from_status: AlertStatus | None = None
    to_status: AlertStatus | None = None
    reason: str = Field(default="", max_length=2048)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
