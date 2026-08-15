from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.detection.result import DetectionResult
from app.domain.events.models import CanonicalSecurityEvent, EnrichedEvent


@dataclass(frozen=True, slots=True)
class DetectorMetadata:
    """Identity and capability metadata for a detector plugin."""

    id: str
    name: str
    version: str
    description: str
    author: str = ""
    enabled_by_default: bool = True
    tags: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.id or not self.id.isascii():
            raise ValueError("plugin id must be a non-empty ASCII string")

        if not self.name.strip():
            raise ValueError("plugin name must not be empty")

        if not self.version.strip():
            raise ValueError("plugin version must not be empty")

        if not self.description.strip():
            raise ValueError("plugin description must not be empty")


DetectorEvent = CanonicalSecurityEvent | EnrichedEvent


class DetectorPlugin(ABC):
    """Contract implemented by every Phase 08 detector plugin."""

    metadata: DetectorMetadata

    @abstractmethod
    def initialize(
        self,
        config: Mapping[str, Any] | None = None,
    ) -> None:
        """Initialize the plugin with explicit configuration."""

    @abstractmethod
    def detect(
        self,
        event: DetectorEvent,
    ) -> Sequence[DetectionResult]:
        """Evaluate one event and return zero or more detection results."""

    def shutdown(self) -> None:
        """Release plugin resources."""
        return None
