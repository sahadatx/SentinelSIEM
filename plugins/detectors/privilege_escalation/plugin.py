from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.detection.plugin import DetectorEvent, DetectorMetadata, DetectorPlugin
from app.detection.result import DetectionResult


class PrivilegeEscalationDetector(DetectorPlugin):
    metadata = DetectorMetadata(
        id="privilege-escalation-plugin",
        name="Privilege Escalation Detector",
        version="1.0.0",
        description="Detect explicitly marked privilege escalation events.",
        author="SentinelSIEM",
        tags=("privilege", "escalation"),
    )

    def initialize(self, config: Mapping[str, Any] | None = None) -> None:
        del config

    def detect(self, event: DetectorEvent) -> Sequence[DetectionResult]:
        if event.action != "privilege_escalation":
            return ()

        return (
            DetectionResult(
                rule_id=self.metadata.id,
                rule_name=self.metadata.name,
                event_id=event.event_id,
                severity="high",
                category="privilege_escalation",
                description="Detector plugin identified a privilege escalation event.",
                tags=self.metadata.tags,
            ),
        )


def create_plugin() -> DetectorPlugin:
    return PrivilegeEscalationDetector()
