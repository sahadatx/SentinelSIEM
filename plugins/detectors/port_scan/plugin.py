from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.detection.plugin import DetectorEvent, DetectorMetadata, DetectorPlugin
from app.detection.result import DetectionResult


class PortScanDetector(DetectorPlugin):
    metadata = DetectorMetadata(
        id="port-scan-plugin",
        name="Port Scan Detector",
        version="1.0.0",
        description="Detect a network connection target.",
        author="SentinelSIEM",
        tags=("network", "reconnaissance"),
    )

    def initialize(self, config: Mapping[str, Any] | None = None) -> None:
        del config

    def detect(self, event: DetectorEvent) -> Sequence[DetectionResult]:
        if event.source_ip is None or event.destination_port is None:
            return ()

        return (
            DetectionResult(
                rule_id=self.metadata.id,
                rule_name=self.metadata.name,
                event_id=event.event_id,
                severity="low",
                category="network",
                description="Detector plugin identified a network connection target.",
                tags=self.metadata.tags,
            ),
        )


def create_plugin() -> DetectorPlugin:
    return PortScanDetector()
