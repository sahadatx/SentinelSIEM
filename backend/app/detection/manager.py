from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from app.detection.discovery import DetectorPluginDiscovery
from app.detection.plugin_registry import DetectorPluginRegistry


class DetectorPluginManager:
    """Coordinate plugin discovery, registration, initialization, and shutdown."""

    def __init__(
        self,
        registry: DetectorPluginRegistry | None = None,
    ) -> None:
        self.registry = registry or DetectorPluginRegistry()

    def discover_and_register(self, root: Path) -> int:
        discovered = DetectorPluginDiscovery(root).discover()

        for plugin in discovered:
            self.registry.register(plugin)

        return len(discovered)

    def initialize(
        self,
        config: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> None:
        self.registry.initialize(config)

    def shutdown(self) -> None:
        self.registry.shutdown()
