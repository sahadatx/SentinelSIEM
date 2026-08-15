from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.domain.events.enums import EventSourceType
from app.domain.events.schema import CanonicalEventSchema, RawEventInput


def test_raw_event_input_is_strict() -> None:
    payload = RawEventInput(
        timestamp=datetime.now(UTC),
        source="syslog01",
        source_type=EventSourceType.SYSLOG,
        raw_event="Accepted password",
    )

    assert payload.source_type == EventSourceType.SYSLOG


def test_canonical_schema_rejects_invalid_port() -> None:
    with pytest.raises(ValidationError):
        CanonicalEventSchema(
            event_id=uuid4(),
            timestamp=datetime.now(UTC),
            ingestion_timestamp=datetime.now(UTC),
            source="syslog01",
            source_type=EventSourceType.SYSLOG,
            raw_event="event",
            destination_port=-1,
        )
