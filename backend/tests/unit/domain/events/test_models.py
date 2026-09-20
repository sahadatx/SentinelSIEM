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
from app.domain.events.factory import create_raw_event
from app.domain.events.models import CanonicalSecurityEvent, RawEvent
from app.parsing.canonical import canonicalize_linux_auth


# =========================================================
# Raw Event
# =========================================================


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


# =========================================================
# Canonical Event
# =========================================================


def test_canonical_event_contains_security_fields() -> None:
    raw = create_raw_event(
        "auth01",
        EventSourceType.SYSLOG,
        "login failed",
    )

    event = CanonicalSecurityEvent(
        **raw.model_dump(
            exclude={"stage"},
        ),
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

    assert isinstance(
        event,
        CanonicalSecurityEvent,
    )

    assert event.stage == EventStage.CANONICAL
    assert event.event_id == raw.event_id

    assert event.source_ip == "192.0.2.10"
    assert event.destination_ip == "198.51.100.20"

    assert event.source_port == 54321
    assert event.destination_port == 22

    assert event.username == "analyst"
    assert event.action == "login"

    assert event.outcome == EventOutcome.FAILURE
    assert event.severity == EventSeverity.HIGH
    assert event.category == EventCategory.AUTHENTICATION


def test_linux_auth_canonicalization_preserves_event_identity() -> None:
    raw = create_raw_event(
        "auth01",
        EventSourceType.SYSLOG,
        "login failed",
    )

    event = canonicalize_linux_auth(
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

    assert isinstance(
        event,
        CanonicalSecurityEvent,
    )

    assert event.event_id == raw.event_id
    assert event.stage == EventStage.CANONICAL

    assert event.source == raw.source
    assert event.source_type == raw.source_type
    assert event.raw_event == raw.raw_event
    assert event.timestamp == raw.timestamp
    assert event.ingestion_timestamp == raw.ingestion_timestamp


# =========================================================
# Validation
# =========================================================


def test_ports_are_bounded() -> None:
    raw = create_raw_event(
        "network01",
        EventSourceType.TCP,
        "connection",
    )

    with pytest.raises(ValidationError):
        CanonicalSecurityEvent(
            **raw.model_dump(
                exclude={"stage"},
            ),
            destination_port=70000,
        )


def test_source_port_must_be_valid() -> None:
    raw = create_raw_event(
        "network01",
        EventSourceType.TCP,
        "connection",
    )

    with pytest.raises(ValidationError):
        CanonicalSecurityEvent(
            **raw.model_dump(
                exclude={"stage"},
            ),
            source_port=70000,
        )


def test_negative_destination_port_is_rejected() -> None:
    raw = create_raw_event(
        "network01",
        EventSourceType.TCP,
        "connection",
    )

    with pytest.raises(ValidationError):
        CanonicalSecurityEvent(
            **raw.model_dump(
                exclude={"stage"},
            ),
            destination_port=-1,
        )


# =========================================================
# Strict Domain Validation
# =========================================================


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


def test_canonical_event_rejects_unknown_fields() -> None:
    raw = create_raw_event(
        "auth01",
        EventSourceType.SYSLOG,
        "login failed",
    )

    with pytest.raises(ValidationError):
        CanonicalSecurityEvent.model_validate(
            {
                **raw.model_dump(
                    exclude={"stage"},
                ),
                "unexpected_field": "not allowed",
            }
        )
