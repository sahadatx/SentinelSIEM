from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from .enums import EventCategory, EventOutcome, EventSeverity, EventSourceType


class EventSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class RawEventInput(EventSchema):
    timestamp: datetime
    source: str
    source_type: EventSourceType
    raw_event: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class CanonicalEventSchema(EventSchema):
    event_id: UUID
    timestamp: datetime
    ingestion_timestamp: datetime
    source: str
    source_type: EventSourceType
    hostname: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None
    username: str | None = None
    process: str | None = None
    command: str | None = None
    action: str | None = None
    outcome: EventOutcome = EventOutcome.UNKNOWN
    severity: EventSeverity = EventSeverity.INFO
    category: EventCategory = EventCategory.OTHER
    raw_event: str
    normalized_data: dict[str, Any] = Field(default_factory=dict)
    enrichment: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
