from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from app.detection.engine import DetectionEngine
from app.detection.manager import DetectorPluginManager
from app.detection.registry import DetectionRuleRegistry
from app.domain.events.enums import EventCategory, EventOutcome, EventSeverity, EventSourceType
from app.domain.events.models import CanonicalSecurityEvent


def make_real_event() -> CanonicalSecurityEvent:
    timestamp = datetime(2026, 8, 15, 10, 15, 32, tzinfo=UTC)

    return CanonicalSecurityEvent(
        timestamp=timestamp,
        ingestion_timestamp=timestamp,
        source="sshd",
        source_type=EventSourceType.SYSLOG,
        raw_event=(
            "Aug 15 10:15:32 sentinel-host sshd[4242]: "
            "Failed password for invalid user admin "
            "from 192.168.10.55 port 54321 ssh2"
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
        outcome=EventOutcome.FAILURE,
        severity=EventSeverity.MEDIUM,
        category=EventCategory.AUTHENTICATION,
    )


def test_real_phase08_plugin_discovery_and_execution() -> None:
    manager = DetectorPluginManager()
    count = manager.discover_and_register(Path("plugins/detectors"))
    manager.initialize()

    assert count == 6

    engine = DetectionEngine(
        DetectionRuleRegistry(),
        plugin_registry=manager.registry,
    )

    results = engine.evaluate(make_real_event())
    plugin_ids = {result.rule_id for result in results}

    assert "suspicious-login-plugin" in plugin_ids
    assert "brute-force-plugin" in plugin_ids

    print("\n" + "=" * 70)
    print("REAL PHASE 08 PLUGIN TEST PASSED")
    print("=" * 70)
    print(f"Plugins discovered : {count}")
    print(f"Plugin results     : {len(results)}")
    print(f"Detected plugins   : {sorted(plugin_ids)}")
    print("=" * 70)

    manager.shutdown()
