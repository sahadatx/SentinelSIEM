from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.detection.plugin import DetectorEvent, DetectorMetadata, DetectorPlugin
from app.detection.result import DetectionResult


class WebAttackPlugin(DetectorPlugin):
    metadata = DetectorMetadata(
        id="web-attack-plugin",
        name="Web Attack Detector",
        version="1.0.0",
        description="Detect common web attack indicators in security events.",
        author="SentinelSIEM",
        tags=("web", "attack"),
    )

    def initialize(self, config: Mapping[str, Any] | None = None) -> None:
        return None

    def detect(self, event: DetectorEvent) -> Sequence[DetectionResult]:
        message = event.raw_event.lower()
        action = (event.action or "").lower()

        indicators = (
            "sql injection",
            "sqli",
            "xss",
            "cross-site scripting",
            "path traversal",
            "../",
            "command injection",
            "web attack",
        )

        if action not in {"web_attack", "web-attack"} and not any(
            indicator in message for indicator in indicators
        ):
            return ()

        return (
            DetectionResult(
                rule_id=self.metadata.id,
                rule_name=self.metadata.name,
                event_id=event.event_id,
                severity="high",
                category="web",
                description="Detect indicators of a web application attack.",
                tags=self.metadata.tags,
            ),
        )


def create_plugin() -> DetectorPlugin:
    return WebAttackPlugin()
