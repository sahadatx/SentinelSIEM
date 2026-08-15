from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.detection.plugin import DetectorEvent, DetectorMetadata, DetectorPlugin
from app.detection.result import DetectionResult


class SuspiciousLoginDetector(DetectorPlugin):
    metadata = DetectorMetadata(
        id="suspicious-login-plugin",
        name="Suspicious Login Detector",
        version="1.0.0",
        description="Detect failed authentication attempts.",
        author="SentinelSIEM",
        tags=("authentication", "ssh"),
    )

    def initialize(self, config: Mapping[str, Any] | None = None) -> None:
        del config

    def detect(self, event: DetectorEvent) -> Sequence[DetectionResult]:
        if event.action != "login" or event.outcome != "failure":
            return ()

        return (
            DetectionResult(
                rule_id=self.metadata.id,
                rule_name=self.metadata.name,
                event_id=event.event_id,
                severity="medium",
                category="authentication",
                description="Detector plugin identified a failed login.",
                tags=self.metadata.tags,
            ),
        )


def create_plugin() -> DetectorPlugin:
    return SuspiciousLoginDetector()
