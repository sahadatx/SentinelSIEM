from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .enums import EventSourceType
from .models import CanonicalSecurityEvent, RawEvent
from .schema import RawEventInput


def create_raw_event(
    source: str,
    source_type: EventSourceType,
    raw_event: str,
    *,
    timestamp: datetime | None = None,
    metadata: dict[str, Any] | None = None,
) -> RawEvent:
    """Build the first domain representation at the ingestion boundary."""
    event_time = timestamp or datetime.now(UTC)
    return RawEvent(
        timestamp=event_time,
        ingestion_timestamp=datetime.now(UTC),
        source=source,
        source_type=source_type,
        raw_event=raw_event,
        metadata=metadata or {},
    )


def create_raw_event_from_schema(payload: RawEventInput) -> RawEvent:
    return create_raw_event(
        source=payload.source,
        source_type=payload.source_type,
        raw_event=payload.raw_event,
        timestamp=payload.timestamp,
        metadata=payload.metadata,
    )


def to_canonical_event(event: RawEvent, **fields: Any) -> CanonicalSecurityEvent:
    """Create a canonical event while preserving source/raw/metadata context."""
    data = event.model_dump()
    data.pop("stage", None)

    return CanonicalSecurityEvent(
        **data,
        **fields,
    )
