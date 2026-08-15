from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.detection.plugin import DetectorEvent, DetectorMetadata, DetectorPlugin
from app.detection.result import DetectionResult


class BruteForceDetector(DetectorPlugin):
    metadata = DetectorMetadata(
        id="brute-force-plugin",
        name="Brute Force Detector",
        version="1.0.0",
        description="Detect an individual failed authentication event.",
        author="SentinelSIEM",
        tags=("authentication", "brute-force"),
    )

    def initialize(self, config: Mapping[str, Any] | None = None) -> None:
        del config

    def detect(self, event: DetectorEvent) -> Sequence[DetectionResult]:
        if event.outcome != "failure" or event.action != "login":
            return ()

        return (
            DetectionResult(
                rule_id=self.metadata.id,
                rule_name=self.metadata.name,
                event_id=event.event_id,
                severity="medium",
                category="authentication",
                description="Detector plugin identified a failed authentication event.",
                tags=self.metadata.tags,
            ),
        )


def create_plugin() -> DetectorPlugin:
    return BruteForceDetector()
