from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import Field

from app.domain.events.models import (
    CanonicalSecurityEvent,
    EnrichedEvent,
)

from .common import APIModel


class EventQuery(APIModel):
    query: str | None = Field(
        default=None,
        max_length=500,
    )
    source: str | None = Field(
        default=None,
        max_length=200,
    )
    source_ip: str | None = Field(
        default=None,
        max_length=64,
    )
    severity: str | None = Field(
        default=None,
        max_length=32,
    )
    category: str | None = Field(
        default=None,
        max_length=64,
    )
    start_time: datetime | None = None
    end_time: datetime | None = None
    page: int = Field(
        default=1,
        ge=1,
    )
    page_size: int = Field(
        default=50,
        ge=1,
        le=1000,
    )


class EventResponse(APIModel):
    event_id: UUID
    timestamp: datetime
    ingestion_timestamp: datetime

    source: str
    source_type: str

    hostname: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None

    source_port: int | None = None
    destination_port: int | None = None

    protocol: str | None = None
    username: str | None = None
    process: str | None = None
    command: str | None = None

    action: str | None = None
    outcome: str
    severity: str
    category: str

    raw_event: str

    # Preserve source-specific parsed fields exposed by the
    # canonical event model.
    parsed_data: dict[str, Any]

    normalized_data: dict[str, Any]

    enrichment: dict[str, Any] | None = None

    metadata: dict[str, Any]
    stage: str

    @classmethod
    def from_event(
        cls,
        event: CanonicalSecurityEvent | EnrichedEvent,
    ) -> "EventResponse":
        """
        Convert a domain event into the public API response model.

        The domain model is serialized first so enums and UUID/datetime
        values are converted into API-safe JSON-compatible values.
        """
        return cls.model_validate(
            event.model_dump(mode="json"),
        )
