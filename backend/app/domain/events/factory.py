from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .enums import EventSourceType
from .models import RawEvent
from .schema import RawEventInput


# =========================================================
# Raw Event Factory
# =========================================================


def create_raw_event(
    source: str,
    source_type: EventSourceType,
    raw_event: str,
    *,
    timestamp: datetime | None = None,
    metadata: dict[str, Any] | None = None,
) -> RawEvent:
    """
    Create a RawEvent at the ingestion boundary.

    Responsibilities:
        - Assign the event timestamp when one is not supplied.
        - Assign the ingestion timestamp.
        - Preserve the original source information.
        - Preserve the original raw payload.
        - Preserve optional ingestion metadata.

    Canonicalization is intentionally NOT performed here.

    Production event flow:

        Raw payload
            ↓
        RawEvent
            ↓
        ParsingRouter
            ↓
        ParsingPipeline
            ↓
        ParsedEvent
            ↓
        NormalizedEvent
            ↓
        CanonicalSecurityEvent
    """

    event_time = (
        timestamp
        if timestamp is not None
        else datetime.now(UTC)
    )

    return RawEvent(
        timestamp=event_time,
        ingestion_timestamp=datetime.now(UTC),
        source=source,
        source_type=source_type,
        raw_event=raw_event,
        metadata=(
            dict(metadata)
            if metadata is not None
            else {}
        ),
    )


# =========================================================
# Schema → Domain Factory
# =========================================================


def create_raw_event_from_schema(
    payload: RawEventInput,
) -> RawEvent:
    """
    Create a RawEvent from the validated ingestion schema.

    The schema remains responsible for input validation.
    This factory remains responsible for constructing the
    domain RawEvent.

    No parsing, normalization, enrichment, or canonicalization
    is performed here.
    """

    return create_raw_event(
        source=payload.source,
        source_type=payload.source_type,
        raw_event=payload.raw_event,
        timestamp=payload.timestamp,
        metadata=payload.metadata,
    )


# =========================================================
# Public API
# =========================================================


__all__ = [
    "create_raw_event",
    "create_raw_event_from_schema",
]