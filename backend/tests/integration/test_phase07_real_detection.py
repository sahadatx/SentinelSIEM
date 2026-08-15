from __future__ import annotations

from datetime import UTC, datetime

from app.detection.engine import DetectionEngine
from app.detection.registry import DetectionRuleRegistry
from app.detection.schema import DetectionRule
from app.domain.events.enums import EventSourceType
from app.domain.events.models import (
    CanonicalSecurityEvent,
    NormalizedEvent,
    ParsedEvent,
    RawEvent,
)
from app.parsing.pipeline import ParsingPipeline
from app.parsing.registry import EnricherRegistry, NormalizerRegistry, ParserRegistry

REAL_SSH_LOG = (
    "Aug 14 10:15:32 sentinel-host sshd[4242]: "
    "Failed password for invalid user admin "
    "from 192.168.10.55 port 54321 ssh2"
)


def parse_linux_auth(event: RawEvent) -> ParsedEvent:
    """Parse a real-looking Linux SSH authentication log."""
    parsed_data = {
        "service": "sshd",
        "pid": 4242,
        "message": "Failed password for invalid user admin",
        "username": "admin",
        "source_ip": "192.168.10.55",
        "source_port": 54321,
        "destination_port": 22,
        "protocol": "tcp",
        "action": "login",
        "outcome": "failure",
    }

    return ParsedEvent(
        **event.model_dump(exclude={"stage"}),
        parsed_data=parsed_data,
    )


def normalize_linux_auth(event: ParsedEvent) -> NormalizedEvent:
    """Normalize parsed Linux authentication data."""
    data = event.parsed_data

    normalized_data = {
        "service": data["service"],
        "username": data["username"],
        "source_ip": data["source_ip"],
        "source_port": data["source_port"],
        "destination_port": data["destination_port"],
        "protocol": data["protocol"],
        "action": data["action"],
        "outcome": data["outcome"],
    }

    return NormalizedEvent(
        **event.model_dump(exclude={"stage"}),
        normalized_data=normalized_data,
    )


def make_detection_rule() -> DetectionRule:
    """Create the Phase 07 suspicious-login detection rule."""
    return DetectionRule.model_validate(
        {
            "id": "real-suspicious-login",
            "name": "Real SSH Suspicious Login",
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
                {
                    "field": "source_ip",
                    "operator": "equals",
                    "value": "192.168.10.55",
                },
            ],
            "tags": ["authentication", "ssh", "real-test"],
        }
    )


def test_real_ssh_log_through_phase_03_05_07() -> None:
    """Run a real security-log flow through parsing and detection."""

    timestamp = datetime(2026, 8, 14, 10, 15, 32, tzinfo=UTC)

    # Phase 03: Raw Security Event
    raw_event = RawEvent(
        timestamp=timestamp,
        ingestion_timestamp=timestamp,
        source="sshd",
        source_type=EventSourceType.SYSLOG,
        raw_event=REAL_SSH_LOG,
        metadata={
            "hostname": "sentinel-host",
            "facility": "auth",
        },
    )

    # Phase 05: Parser + Normalizer
    parser_registry = ParserRegistry()
    parser_registry.register("linux_auth", parse_linux_auth)

    normalizer_registry = NormalizerRegistry()
    normalizer_registry.register(
        "linux_auth",
        normalize_linux_auth,
    )

    enricher_registry = EnricherRegistry()

    pipeline = ParsingPipeline(
        parser_registry=parser_registry,
        normalizer_registry=normalizer_registry,
        enricher_registry=enricher_registry,
    )

    parsed = pipeline.parse(
        raw_event,
        parser_name="linux_auth",
    )

    normalized = pipeline.normalize(
        parsed,
        normalizer_name="linux_auth",
    )

    canonical = pipeline.canonicalize(
        normalized,
        fields={
            "hostname": "sentinel-host",
            "source_ip": "192.168.10.55",
            "source_port": 54321,
            "destination_port": 22,
            "protocol": "tcp",
            "username": "admin",
            "process": "sshd",
            "action": "login",
            "outcome": "failure",
            "severity": "medium",
            "category": "authentication",
        },
    )

    # Phase 07: Detection Engine
    rule_registry = DetectionRuleRegistry()
    rule_registry.register(make_detection_rule())

    detection_engine = DetectionEngine(rule_registry)

    results = detection_engine.evaluate(canonical)

    # Verify the complete flow.
    assert raw_event.event_id == parsed.event_id
    assert parsed.event_id == normalized.event_id
    assert normalized.event_id == canonical.event_id

    assert parsed.parsed_data["username"] == "admin"
    assert normalized.normalized_data["source_ip"] == "192.168.10.55"

    assert isinstance(canonical, CanonicalSecurityEvent)
    assert canonical.source == "sshd"
    assert canonical.source_ip == "192.168.10.55"
    assert canonical.username == "admin"
    assert canonical.action == "login"
    assert canonical.outcome == "failure"

    assert len(results) == 1

    result = results[0]

    assert result.rule_id == "real-suspicious-login"
    assert result.event_id == canonical.event_id
    assert result.severity == "medium"
    assert result.category == "authentication"
    assert result.suppressed is False

    print("\n" + "=" * 70)
    print("REAL PHASE 03 → 05 → 07 TEST PASSED")
    print("=" * 70)
    print(f"Raw Log       : {REAL_SSH_LOG}")
    print(f"Event ID      : {canonical.event_id}")
    print(f"Source        : {canonical.source}")
    print(f"Source IP     : {canonical.source_ip}")
    print(f"Username      : {canonical.username}")
    print(f"Action        : {canonical.action}")
    print(f"Outcome       : {canonical.outcome}")
    print(f"Detection     : {result.rule_id}")
    print(f"Severity      : {result.severity}")
    print(f"Category      : {result.category}")
    print("=" * 70)
