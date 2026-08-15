from __future__ import annotations

from datetime import UTC, datetime

from app.domain.events.enums import EventSourceType
from app.domain.events.factory import create_raw_event, create_raw_event_from_schema
from app.domain.events.schema import RawEventInput


def test_factory_preserves_explicit_timestamp() -> None:
    timestamp = datetime(2026, 8, 14, 10, 0, tzinfo=UTC)
    event = create_raw_event("web01", EventSourceType.HTTP, "GET /", timestamp=timestamp)

    assert event.timestamp == timestamp


def test_schema_factory_builds_domain_event() -> None:
    payload = RawEventInput(
        timestamp=datetime(2026, 8, 14, 10, 0, tzinfo=UTC),
        source="web01",
        source_type=EventSourceType.HTTP,
        raw_event="GET /login",
    )

    event = create_raw_event_from_schema(payload)

    assert event.source == "web01"
    assert event.raw_event == "GET /login"
    assert event.source_type == EventSourceType.HTTP
