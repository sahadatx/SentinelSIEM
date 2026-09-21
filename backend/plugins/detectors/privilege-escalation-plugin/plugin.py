from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.detection.plugin import DetectorEvent, DetectorMetadata, DetectorPlugin
from app.detection.result import DetectionResult


class PrivilegeEscalationPlugin(DetectorPlugin):
    metadata = DetectorMetadata(
        id="privilege-escalation-plugin",
        name="Privilege Escalation Detector",
        version="1.0.0",
        description="Detect indicators of privilege escalation activity.",
        author="SentinelSIEM",
        tags=("privilege", "escalation", "system"),
    )

    def initialize(self, config: Mapping[str, Any] | None = None) -> None:
        return None

    def detect(self, event: DetectorEvent) -> Sequence[DetectionResult]:
        message = event.raw_event.lower()
        action = (event.action or "").lower()

        indicators = (
            "privilege escalation",
            "privilege_escalation",
            "sudo",
            "setuid",
            "setgid",
            "uid=0",
            "root shell",
        )

        if action not in {"privilege_escalation", "privilege-escalation"} and not any(
            indicator in message for indicator in indicators
        ):
            return ()

        return (
            DetectionResult(
                rule_id=self.metadata.id,
                rule_name=self.metadata.name,
                event_id=event.event_id,
                severity="critical",
                category="authorization",
                description="Detect indicators of privilege escalation activity.",
                tags=self.metadata.tags,
            ),
        )


def create_plugin() -> DetectorPlugin:
    return PrivilegeEscalationPlugin()
