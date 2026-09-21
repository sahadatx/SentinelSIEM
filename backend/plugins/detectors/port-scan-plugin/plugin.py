from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.detection.plugin import DetectorEvent, DetectorMetadata, DetectorPlugin
from app.detection.result import DetectionResult


class PortScanPlugin(DetectorPlugin):
    metadata = DetectorMetadata(
        id="port-scan-plugin",
        name="Port Scan Detector",
        version="1.0.0",
        description="Detect network events associated with port scanning.",
        author="SentinelSIEM",
        tags=("network", "reconnaissance", "port-scan"),
    )

    def initialize(self, config: Mapping[str, Any] | None = None) -> None:
        return None

    def detect(self, event: DetectorEvent) -> Sequence[DetectionResult]:
        action = (event.action or "").lower()
        message = event.raw_event.lower()

        indicators = (
            "port scan",
            "portscan",
            "nmap",
            "masscan",
            "syn scan",
            "tcp scan",
        )

        if action not in {"port_scan", "portscan", "scan"} and not any(
            indicator in message for indicator in indicators
        ):
            return ()

        return (
            DetectionResult(
                rule_id=self.metadata.id,
                rule_name=self.metadata.name,
                event_id=event.event_id,
                severity="medium",
                category="network",
                description="Detect network activity associated with port scanning.",
                tags=self.metadata.tags,
            ),
        )


def create_plugin() -> DetectorPlugin:
    return PortScanPlugin()
