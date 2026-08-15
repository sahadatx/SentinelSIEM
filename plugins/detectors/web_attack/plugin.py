from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.detection.plugin import DetectorEvent, DetectorMetadata, DetectorPlugin
from app.detection.result import DetectionResult


class WebAttackDetector(DetectorPlugin):
    metadata = DetectorMetadata(
        id="web-attack-plugin",
        name="Web Attack Detector",
        version="1.0.0",
        description="Detect common suspicious web request indicators.",
        author="SentinelSIEM",
        tags=("web", "attack"),
    )

    def initialize(self, config: Mapping[str, Any] | None = None) -> None:
        del config

    def detect(self, event: DetectorEvent) -> Sequence[DetectionResult]:
        command = (event.command or "").lower()

        if not any(marker in command for marker in ("../", "union select", "<script")):
            return ()

        return (
            DetectionResult(
                rule_id=self.metadata.id,
                rule_name=self.metadata.name,
                event_id=event.event_id,
                severity="high",
                category="web_attack",
                description="Detector plugin identified a suspicious web attack indicator.",
                tags=self.metadata.tags,
            ),
        )


def create_plugin() -> DetectorPlugin:
    return WebAttackDetector()
