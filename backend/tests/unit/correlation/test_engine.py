from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.correlation.engine import CorrelationEngine
from app.correlation.registry import CorrelationRuleRegistry
from app.correlation.schema import (
    CorrelationCondition,
    CorrelationMode,
    CorrelationRule,
)
from app.domain.events.enums import (
    EventCategory,
    EventOutcome,
    EventSeverity,
    EventSourceType,
)
from app.domain.events.models import CanonicalSecurityEvent


def event(
    timestamp: datetime,
    outcome: EventOutcome,
    source_ip: str = "192.168.10.55",
) -> CanonicalSecurityEvent:
    return CanonicalSecurityEvent(
        timestamp=timestamp,
        ingestion_timestamp=timestamp,
        source="sshd",
        source_type=EventSourceType.SYSLOG,
        raw_event="realistic sshd authentication event",
        metadata={"hostname": "sentinel-host"},
        parsed_data={"source_ip": source_ip},
        normalized_data={"source_ip": source_ip},
        source_ip=source_ip,
        destination_port=22,
        protocol="tcp",
        action="login",
        outcome=outcome,
        severity=EventSeverity.MEDIUM,
        category=EventCategory.AUTHENTICATION,
    )


def test_threshold_correlation() -> None:
    rule = CorrelationRule(
        id="failed-auth",
        name="Failed auth threshold",
        description="Five failures",
        mode=CorrelationMode.THRESHOLD,
        window_seconds=300,
        group_by=("source_ip",),
        threshold=5,
    )
    engine = CorrelationEngine(CorrelationRuleRegistry([rule]))
    base = datetime(2026, 8, 15, 10, 0, tzinfo=UTC)

    results = engine.evaluate_many(
        [event(base + timedelta(seconds=i), EventOutcome.FAILURE) for i in range(5)]
    )

    assert len(results) == 1
    assert results[0].rule_id == "failed-auth"
    assert results[0].evidence_count == 5


def test_sequence_correlation() -> None:
    rule = CorrelationRule(
        id="compromise",
        name="Possible compromise",
        description="Failure then success",
        mode=CorrelationMode.SEQUENCE,
        window_seconds=300,
        group_by=("source_ip",),
        conditions=(
            CorrelationCondition(field="outcome", equals="failure"),
            CorrelationCondition(field="outcome", equals="success"),
        ),
    )
    engine = CorrelationEngine(CorrelationRuleRegistry([rule]))
    base = datetime(2026, 8, 15, 10, 0, tzinfo=UTC)

    results = engine.evaluate_many(
        [
            event(base, EventOutcome.FAILURE),
            event(base + timedelta(seconds=30), EventOutcome.SUCCESS),
        ]
    )

    assert len(results) == 1
    assert results[0].rule_id == "compromise"
    assert results[0].evidence_count == 2


def test_grouping_prevents_cross_source_correlation() -> None:
    rule = CorrelationRule(
        id="failed-auth",
        name="Failed auth threshold",
        description="Three failures",
        mode=CorrelationMode.THRESHOLD,
        window_seconds=300,
        group_by=("source_ip",),
        threshold=3,
    )
    engine = CorrelationEngine(CorrelationRuleRegistry([rule]))
    base = datetime(2026, 8, 15, 10, 0, tzinfo=UTC)

    results = engine.evaluate_many(
        [
            event(base, EventOutcome.FAILURE, "10.0.0.1"),
            event(base + timedelta(seconds=1), EventOutcome.FAILURE, "10.0.0.2"),
            event(base + timedelta(seconds=2), EventOutcome.FAILURE, "10.0.0.1"),
        ]
    )

    assert results == ()
