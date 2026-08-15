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


def make_event(timestamp: datetime, outcome: EventOutcome) -> CanonicalSecurityEvent:
    return CanonicalSecurityEvent(
        timestamp=timestamp,
        ingestion_timestamp=timestamp,
        source="sshd",
        source_type=EventSourceType.SYSLOG,
        raw_event=(
            "Aug 15 10:15:32 sentinel-host sshd[4242]: "
            "authentication event from 192.168.10.55"
        ),
        metadata={"hostname": "sentinel-host", "facility": "auth"},
        parsed_data={"username": "admin", "source_ip": "192.168.10.55"},
        normalized_data={"username": "admin", "source_ip": "192.168.10.55"},
        hostname="sentinel-host",
        source_ip="192.168.10.55",
        source_port=54321,
        destination_port=22,
        protocol="tcp",
        username="admin",
        process="sshd",
        action="login",
        outcome=outcome,
        severity=EventSeverity.MEDIUM,
        category=EventCategory.AUTHENTICATION,
    )


def test_real_phase09_multi_event_correlation() -> None:
    rule = CorrelationRule(
        id="account-compromise",
        name="Possible Account Compromise",
        description="Failed authentication followed by successful authentication.",
        mode=CorrelationMode.SEQUENCE,
        window_seconds=300,
        group_by=("source_ip", "username"),
        conditions=(
            CorrelationCondition(field="outcome", equals="failure"),
            CorrelationCondition(field="outcome", equals="success"),
        ),
        severity="high",
    )

    engine = CorrelationEngine(CorrelationRuleRegistry([rule]))
    base = datetime(2026, 8, 15, 10, 15, 32, tzinfo=UTC)

    failed = make_event(base, EventOutcome.FAILURE)
    successful = make_event(base + timedelta(seconds=45), EventOutcome.SUCCESS)

    results = engine.evaluate_many([failed, successful])

    assert len(results) == 1
    assert results[0].rule_id == "account-compromise"
    assert results[0].evidence_count == 2
    assert str(failed.event_id) in results[0].event_ids
    assert str(successful.event_id) in results[0].event_ids

    print("\n" + "=" * 70)
    print("REAL PHASE 09 CORRELATION TEST PASSED")
    print("=" * 70)
    print("Events processed   : 2")
    print("Correlation rules  : 1")
    print(f"Correlation results : {len(results)}")
    print(f"Rule triggered     : {results[0].rule_id}")
    print(f"Evidence count     : {results[0].evidence_count}")
    print("=" * 70)
