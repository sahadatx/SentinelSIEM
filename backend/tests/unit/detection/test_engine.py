from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from app.detection.engine import DetectionEngine
from app.detection.registry import DetectionRuleRegistry
from app.detection.schema import DetectionRule
from app.detection.suppression import DetectionSuppression
from app.domain.events.models import CanonicalSecurityEvent


def make_event(
    *,
    outcome: str = "failure",
    source_ip: str = "192.168.10.55",
) -> CanonicalSecurityEvent:
    """Create a valid canonical security event for detection tests."""
    return CanonicalSecurityEvent(
        event_id=uuid4(),
        timestamp=datetime.now(UTC),
        ingestion_timestamp=datetime.now(UTC),
        source="sshd",
        source_type="syslog",
        hostname="sentinel-host",
        source_ip=source_ip,
        destination_ip=None,
        source_port=54321,
        destination_port=22,
        protocol="tcp",
        username="admin",
        process="sshd",
        command=None,
        action="login",
        outcome=outcome,
        severity="medium",
        category="authentication",
        raw_event="Failed password for invalid user admin",
        normalized_data={},
        metadata={},
    )


def make_rule() -> DetectionRule:
    """Create a detection rule for failed SSH authentication."""
    return DetectionRule.model_validate(
        {
            "id": "suspicious-login",
            "name": "Suspicious Login Failure",
            "description": "Detect a failed SSH authentication attempt.",
            "severity": "medium",
            "category": "authentication",
            "conditions": [
                {
                    "field": "source",
                    "operator": "equals",
                    "value": "sshd",
                },
                {
                    "field": "action",
                    "operator": "equals",
                    "value": "login",
                },
                {
                    "field": "outcome",
                    "operator": "equals",
                    "value": "failure",
                },
            ],
            "tags": ["authentication", "ssh"],
        }
    )


def test_detection_engine_matches_event() -> None:
    """Verify that a matching event produces a detection result."""
    registry = DetectionRuleRegistry()
    registry.register(make_rule())

    engine = DetectionEngine(registry)
    results = engine.evaluate(make_event())

    assert len(results) == 1
    assert results[0].rule_id == "suspicious-login"
    assert results[0].event_id
    assert results[0].suppressed is False


def test_detection_engine_rejects_non_matching_event() -> None:
    """Verify that a non-matching event produces no detection."""
    registry = DetectionRuleRegistry()
    registry.register(make_rule())

    engine = DetectionEngine(registry)
    results = engine.evaluate(make_event(outcome="success"))

    assert results == ()


def test_detection_engine_suppresses_duplicate_event_rule_match() -> None:
    """Verify duplicate event/rule matches are suppressed."""
    event = make_event()

    registry = DetectionRuleRegistry()
    registry.register(make_rule())

    engine = DetectionEngine(
        registry,
        suppression=DetectionSuppression(ttl_seconds=60),
    )

    first = engine.evaluate(event)
    second = engine.evaluate(event)

    assert first[0].suppressed is False
    assert second[0].suppressed is True


def test_registry_rejects_duplicate_rule() -> None:
    """Verify duplicate detection rules are rejected."""
    registry = DetectionRuleRegistry()
    registry.register(make_rule())

    try:
        registry.register(make_rule())
    except ValueError as exc:
        assert "duplicate detection rule" in str(exc)
    else:
        raise AssertionError(
            "duplicate rule registration must fail"
        )
