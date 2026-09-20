from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.detection.engine import DetectionEngine
from app.detection.plugin import DetectorMetadata, DetectorPlugin
from app.detection.plugin_registry import DetectorPluginRegistry
from app.detection.registry import DetectionRuleRegistry
from app.detection.result import DetectionResult
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


class StubDetectorPlugin(DetectorPlugin):
    """Deterministic detector plugin used to test engine integration."""

    metadata = DetectorMetadata(
        id="stub-detector",
        name="Stub Detector",
        version="1.0.0",
        description="Test detector plugin.",
    )

    def initialize(
        self,
        config: Mapping[str, Any] | None = None,
    ) -> None:
        return None

    def detect(
        self,
        event: CanonicalSecurityEvent,
    ) -> tuple[DetectionResult, ...]:
        return (
            DetectionResult(
                rule_id="stub-detector-rule",
                rule_name="Stub Detector Rule",
                event_id=event.event_id,
                severity="high",
                category="test",
                description="Stub detector matched the event.",
            ),
        )


class FailingDetectorPlugin(DetectorPlugin):
    """Detector plugin that intentionally fails for error-path testing."""

    metadata = DetectorMetadata(
        id="failing-detector",
        name="Failing Detector",
        version="1.0.0",
        description="Test detector that raises an exception.",
    )

    def initialize(
        self,
        config: Mapping[str, Any] | None = None,
    ) -> None:
        return None

    def detect(
        self,
        event: CanonicalSecurityEvent,
    ) -> tuple[DetectionResult, ...]:
        raise RuntimeError("detector failure")


def test_detection_engine_matches_event() -> None:
    """Verify that a matching event produces a detection result."""
    registry = DetectionRuleRegistry()
    registry.register(make_rule())

    engine = DetectionEngine(registry)
    event = make_event()

    results = engine.evaluate(event)

    assert len(results) == 1
    assert results[0].rule_id == "suspicious-login"
    assert results[0].rule_name == "Suspicious Login Failure"
    assert results[0].event_id == event.event_id
    assert results[0].severity == "medium"
    assert results[0].category == "authentication"
    assert results[0].description == (
        "Detect a failed SSH authentication attempt."
    )
    assert results[0].tags == ("authentication", "ssh")
    assert results[0].suppressed is False


def test_detection_engine_rejects_non_matching_event() -> None:
    """Verify that a non-matching event produces no detection."""
    registry = DetectionRuleRegistry()
    registry.register(make_rule())

    engine = DetectionEngine(registry)

    results = engine.evaluate(make_event(outcome="success"))

    assert results == ()


def test_detection_engine_skips_disabled_rule() -> None:
    """Verify disabled rules are not evaluated."""
    registry = DetectionRuleRegistry()

    rule = make_rule().model_copy(
        update={"enabled": False},
    )
    registry.register(rule)

    engine = DetectionEngine(registry)

    results = engine.evaluate(make_event())

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

    assert len(first) == 1
    assert len(second) == 1

    assert first[0].rule_id == "suspicious-login"
    assert first[0].event_id == event.event_id
    assert first[0].suppressed is False

    assert second[0].rule_id == "suspicious-login"
    assert second[0].event_id == event.event_id
    assert second[0].suppressed is True


def test_detection_engine_evaluate_many() -> None:
    """Verify multiple canonical events can be evaluated."""
    registry = DetectionRuleRegistry()
    registry.register(make_rule())

    engine = DetectionEngine(registry)

    first_event = make_event(
        source_ip="192.168.10.55",
    )
    second_event = make_event(
        source_ip="192.168.10.56",
    )

    results = engine.evaluate_many(
        [first_event, second_event],
    )

    assert len(results) == 2

    assert {result.event_id for result in results} == {
        first_event.event_id,
        second_event.event_id,
    }

    assert all(
        result.rule_id == "suspicious-login"
        for result in results
    )

    assert all(
        result.suppressed is False
        for result in results
    )


def test_detection_engine_executes_enabled_plugin() -> None:
    """Verify enabled detector plugins contribute results."""
    plugin_registry = DetectorPluginRegistry()
    plugin_registry.register(StubDetectorPlugin())

    engine = DetectionEngine(
        DetectionRuleRegistry(),
        plugin_registry=plugin_registry,
    )

    event = make_event()

    results = engine.evaluate(event)

    assert len(results) == 1
    assert results[0].rule_id == "stub-detector-rule"
    assert results[0].rule_name == "Stub Detector Rule"
    assert results[0].event_id == event.event_id
    assert results[0].severity == "high"
    assert results[0].category == "test"
    assert results[0].suppressed is False


def test_detection_engine_skips_disabled_plugin() -> None:
    """Verify disabled detector plugins are not executed."""
    plugin_registry = DetectorPluginRegistry()
    plugin_registry.register(
        StubDetectorPlugin(),
        enabled=False,
    )

    engine = DetectionEngine(
        DetectionRuleRegistry(),
        plugin_registry=plugin_registry,
    )

    results = engine.evaluate(make_event())

    assert results == ()


def test_detection_engine_propagates_plugin_failure() -> None:
    """Verify plugin failures propagate through the engine."""
    plugin_registry = DetectorPluginRegistry()
    plugin_registry.register(FailingDetectorPlugin())

    engine = DetectionEngine(
        DetectionRuleRegistry(),
        plugin_registry=plugin_registry,
    )

    event = make_event()

    try:
        engine.evaluate(event)
    except RuntimeError as exc:
        assert str(exc) == "detector failure"
    else:
        raise AssertionError(
            "plugin failure must propagate",
        )


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
            "duplicate rule registration must fail",
        )
