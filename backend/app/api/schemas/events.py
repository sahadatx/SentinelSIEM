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
    """Query parameters supported by the Events API."""

    # ------------------------------------------------------------------
    # Free-text search
    # ------------------------------------------------------------------

    query: str | None = Field(
        default=None,
        max_length=500,
        description=(
            "Free-text search across username, action, command, "
            "process, and raw event."
        ),
    )

    # ------------------------------------------------------------------
    # Event source filters
    # ------------------------------------------------------------------

    source: str | None = Field(
        default=None,
        max_length=200,
    )

    source_ip: str | None = Field(
        default=None,
        max_length=64,
    )

    destination_ip: str | None = Field(
        default=None,
        max_length=64,
    )

    # ------------------------------------------------------------------
    # Event identity / activity filters
    # ------------------------------------------------------------------

    username: str | None = Field(
        default=None,
        max_length=255,
    )

    action: str | None = Field(
        default=None,
        max_length=128,
    )

    outcome: str | None = Field(
        default=None,
        max_length=64,
    )

    # ------------------------------------------------------------------
    # Security classification filters
    # ------------------------------------------------------------------

    severity: str | None = Field(
        default=None,
        max_length=32,
    )

    category: str | None = Field(
        default=None,
        max_length=64,
    )

    # ------------------------------------------------------------------
    # Time range
    # ------------------------------------------------------------------

    start_time: datetime | None = None

    end_time: datetime | None = None

    # ------------------------------------------------------------------
    # Pagination
    # ------------------------------------------------------------------

    page: int = Field(
        default=1,
        ge=1,
    )

    page_size: int = Field(
        default=50,
        ge=1,
        le=1000,
    )


class EventFilterOptions(APIModel):
    """
    Dynamic values available to Events filter dropdowns.

    Values are supplied by the backend from persisted event data.

    The frontend must not maintain a hardcoded list of event values.
    """

    sources: list[str] = Field(
        default_factory=list,
    )

    users: list[str] = Field(
        default_factory=list,
    )

    actions: list[str] = Field(
        default_factory=list,
    )

    outcomes: list[str] = Field(
        default_factory=list,
    )

    severities: list[str] = Field(
        default_factory=list,
    )

    categories: list[str] = Field(
        default_factory=list,
    )


class EventStatisticsResponse(APIModel):
    """
    Aggregate statistics for the Events page.

    Counts represent the complete filtered dataset and are
    independent of pagination.
    """

    total: int = Field(
        default=0,
        ge=0,
        description=(
            "Total number of events matching the active filters."
        ),
    )

    critical: int = Field(
        default=0,
        ge=0,
        description=(
            "Number of critical events matching the active filters."
        ),
    )

    high: int = Field(
        default=0,
        ge=0,
        description=(
            "Number of high-severity events matching the active filters."
        ),
    )

    medium: int = Field(
        default=0,
        ge=0,
        description=(
            "Number of medium-severity events matching the active filters."
        ),
    )

    low: int = Field(
        default=0,
        ge=0,
        description=(
            "Number of low-severity events matching the active filters."
        ),
    )

    info: int = Field(
        default=0,
        ge=0,
        description=(
            "Number of informational events matching the active filters."
        ),
    )


class EventResponse(APIModel):
    """Public API representation of a persisted security event."""

    # ------------------------------------------------------------------
    # Event identity and timestamps
    # ------------------------------------------------------------------

    event_id: UUID

    timestamp: datetime

    ingestion_timestamp: datetime

    # ------------------------------------------------------------------
    # Source
    # ------------------------------------------------------------------

    source: str

    source_type: str

    hostname: str | None = None

    source_ip: str | None = None

    destination_ip: str | None = None

    source_port: int | None = None

    destination_port: int | None = None

    # ------------------------------------------------------------------
    # Network / process context
    # ------------------------------------------------------------------

    protocol: str | None = None

    username: str | None = None

    process: str | None = None

    command: str | None = None

    # ------------------------------------------------------------------
    # Security event classification
    # ------------------------------------------------------------------

    action: str | None = None

    outcome: str

    severity: str

    category: str

    # ------------------------------------------------------------------
    # Original event data
    # ------------------------------------------------------------------

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
    ) -> EventResponse:
        """
        Convert a domain event into the public API response model.

        The domain model is serialized first so enums, UUIDs, and
        datetime values are converted into API-safe JSON-compatible
        values.
        """
        return cls.model_validate(
            event.model_dump(mode="json"),
        )