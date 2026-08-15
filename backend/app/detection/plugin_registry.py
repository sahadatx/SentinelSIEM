from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from app.detection.plugin import DetectorPlugin


@dataclass(frozen=True, slots=True)
class RegisteredDetector:
    plugin: DetectorPlugin
    enabled: bool


class DetectorPluginRegistry:
    """Validated in-memory registry for detector plugins."""

    def __init__(self) -> None:
        self._plugins: dict[str, RegisteredDetector] = {}

    def register(
        self,
        plugin: DetectorPlugin,
        *,
        enabled: bool | None = None,
    ) -> None:
        plugin_id = plugin.metadata.id
        if plugin_id in self._plugins:
            raise ValueError(f"duplicate detector plugin: {plugin_id}")

        active = (
            plugin.metadata.enabled_by_default
            if enabled is None
            else enabled
        )
        self._plugins[plugin_id] = RegisteredDetector(
            plugin=plugin,
            enabled=active,
        )

    def get(self, plugin_id: str) -> DetectorPlugin | None:
        registered = self._plugins.get(plugin_id)
        return registered.plugin if registered else None

    def all(self) -> tuple[DetectorPlugin, ...]:
        return tuple(item.plugin for item in self._plugins.values())

    def enabled(self) -> tuple[DetectorPlugin, ...]:
        return tuple(
            item.plugin
            for item in self._plugins.values()
            if item.enabled
        )

    def set_enabled(self, plugin_id: str, enabled: bool) -> None:
        registered = self._plugins.get(plugin_id)
        if registered is None:
            raise KeyError(f"unknown detector plugin: {plugin_id}")

        self._plugins[plugin_id] = RegisteredDetector(
            plugin=registered.plugin,
            enabled=enabled,
        )

    def initialize(
        self,
        config: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> None:
        configurations = config or {}
        for plugin_id, registered in self._plugins.items():
            registered.plugin.initialize(configurations.get(plugin_id, {}))

    def shutdown(self) -> None:
        for registered in self._plugins.values():
            registered.plugin.shutdown()

    def clear(self) -> None:
        self._plugins.clear()
