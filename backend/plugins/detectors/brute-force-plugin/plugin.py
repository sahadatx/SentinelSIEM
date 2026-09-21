from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.detection.plugin import DetectorEvent, DetectorMetadata, DetectorPlugin
from app.detection.result import DetectionResult


class BruteForcePlugin(DetectorPlugin):
    metadata = DetectorMetadata(
        id="brute-force-plugin",
        name="Brute Force Detector",
        version="1.0.0",
        description="Detect failed authentication activity associated with brute-force attempts.",
        author="SentinelSIEM",
        tags=("authentication", "brute-force", "ssh"),
    )

    def initialize(self, config: Mapping[str, Any] | None = None) -> None:
        return None

    def detect(self, event: DetectorEvent) -> Sequence[DetectionResult]:
        if not (
            event.source == "sshd" and event.action == "login" and str(event.outcome) == "failure"
        ):
            return ()

        return (
            DetectionResult(
                rule_id=self.metadata.id,
                rule_name=self.metadata.name,
                event_id=event.event_id,
                severity="high",
                category="authentication",
                description=(
                    "Detect a failed authentication attempt that may indicate brute-force activity."
                ),
                tags=self.metadata.tags,
            ),
        )


def create_plugin() -> DetectorPlugin:
    return BruteForcePlugin()
