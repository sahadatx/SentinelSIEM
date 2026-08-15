from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.domain.events.enums import (
    EventCategory,
    EventOutcome,
    EventSeverity,
    EventSourceType,
    EventStage,
)
from app.domain.events.factory import create_raw_event, to_canonical_event
from app.domain.events.models import CanonicalSecurityEvent, RawEvent


def test_raw_event_generates_unique_identifier() -> None:
    first = create_raw_event(
        "auth01",
        EventSourceType.SYSLOG,
        "login failed",
    )
    second = create_raw_event(
        "auth01",
        EventSourceType.SYSLOG,
        "login failed",
    )

    assert first.event_id != second.event_id
    assert first.stage == EventStage.RAW


def test_raw_event_requires_timezone_aware_timestamp() -> None:
    with pytest.raises(ValidationError):
        RawEvent(
            timestamp=datetime(2026, 8, 14),
            ingestion_timestamp=datetime.now(UTC),
            source="auth01",
            source_type=EventSourceType.SYSLOG,
            raw_event="event",
        )


def test_canonical_event_contains_security_fields() -> None:
    raw = create_raw_event(
        "auth01",
        EventSourceType.SYSLOG,
        "login failed",
    )

    event = to_canonical_event(
        raw,
        source_ip="192.0.2.10",
        destination_ip="198.51.100.20",
        source_port=54321,
        destination_port=22,
        username="analyst",
        action="login",
        outcome=EventOutcome.FAILURE,
        severity=EventSeverity.HIGH,
        category=EventCategory.AUTHENTICATION,
    )

    assert isinstance(event, CanonicalSecurityEvent)
    assert event.stage == EventStage.CANONICAL
    assert event.source_ip == "192.0.2.10"
    assert event.destination_port == 22
    assert event.outcome == EventOutcome.FAILURE
    assert event.severity == EventSeverity.HIGH


def test_ports_are_bounded() -> None:
    raw = create_raw_event(
        "network01",
        EventSourceType.TCP,
        "connection",
    )

    with pytest.raises(ValidationError):
        to_canonical_event(
            raw,
            destination_port=70000,
        )


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        RawEvent.model_validate(
            {
                "timestamp": datetime.now(UTC),
                "ingestion_timestamp": datetime.now(UTC),
                "source": "auth01",
                "source_type": EventSourceType.SYSLOG,
                "raw_event": "event",
                "unexpected_field": "not allowed",
            }
        )
