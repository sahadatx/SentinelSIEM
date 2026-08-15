from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.domain.events.enums import EventCategory, EventOutcome, EventSeverity, EventSourceType
from app.domain.events.factory import create_raw_event
from app.domain.events.models import CanonicalSecurityEvent, EnrichedEvent


@pytest.fixture
def real_enriched_event() -> EnrichedEvent:
    raw = create_raw_event(
        source="linux-auth-prod-01",
        source_type=EventSourceType.SYSLOG,
        raw_event="Failed password for admin from 192.0.2.50 port 49152 ssh2",
        timestamp=datetime(2026, 8, 14, 20, 15, 32, tzinfo=UTC),
    )
    canonical = CanonicalSecurityEvent(
        **{k: v for k, v in raw.model_dump().items() if k != "stage"},
        hostname="prod-web-01",
        source_ip="192.0.2.50",
        source_port=49152,
        protocol="ssh",
        username="admin",
        action="login",
        outcome=EventOutcome.FAILURE,
        severity=EventSeverity.HIGH,
        category=EventCategory.AUTHENTICATION,
    )
    return EnrichedEvent(
        **{k: v for k, v in canonical.model_dump().items() if k != "stage"},
        enrichment={"asset": {"criticality": "high"}},
    )
