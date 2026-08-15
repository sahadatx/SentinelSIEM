from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .enums import EventCategory, EventOutcome, EventSeverity, EventSourceType, EventStage
from .identifiers import new_event_id
from .validation import require_utc_datetime, validate_metadata


class EventModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        str_strip_whitespace=True,
    )


class RawEvent(EventModel):
    event_id: UUID = Field(default_factory=new_event_id)
    timestamp: datetime
    ingestion_timestamp: datetime
    source: str
    source_type: EventSourceType
    raw_event: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    stage: EventStage = EventStage.RAW

    @field_validator("timestamp", "ingestion_timestamp")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return require_utc_datetime(value)

    @field_validator("source")
    @classmethod
    def validate_source(cls, value: str) -> str:
        if not value:
            raise ValueError("source must not be empty")
        return value

    @field_validator("metadata")
    @classmethod
    def copy_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        return validate_metadata(value)


class ParsedEvent(RawEvent):
    parsed_data: dict[str, Any] = Field(default_factory=dict)
    stage: EventStage = EventStage.PARSED


class NormalizedEvent(ParsedEvent):
    normalized_data: dict[str, Any] = Field(default_factory=dict)
    stage: EventStage = EventStage.NORMALIZED


class CanonicalSecurityEvent(NormalizedEvent):
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
    stage: EventStage = EventStage.CANONICAL


class EnrichedEvent(CanonicalSecurityEvent):
    enrichment: dict[str, Any] = Field(default_factory=dict)
    stage: EventStage = EventStage.ENRICHED
