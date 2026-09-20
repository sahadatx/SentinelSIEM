from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from app.detection.plugin import DetectorPlugin


@dataclass(frozen=True, slots=True)
class RegisteredDetector:
    """
    Runtime registration state for one detector plugin.
    """

    plugin: DetectorPlugin
    enabled: bool


class DetectorPluginRegistry:
    """
    Validated in-memory registry for detector plugins.

    Responsibilities
    ----------------
    - Register detector plugins.
    - Retrieve registered plugins.
    - List all/enabled plugins.
    - Enable/disable plugins.
    - Initialize/shutdown plugins.
    - Provide runtime plugin counts.

    Non-responsibilities
    --------------------
    - Does not perform RBAC.
    - Does not evaluate events.
    - Does not persist plugin configuration.
    - Does not create alerts or incidents.
    """

    def __init__(self) -> None:
        self._plugins: dict[str, RegisteredDetector] = {}

    # ========================================================================
    # Registration
    # ========================================================================

    def register(
        self,
        plugin: DetectorPlugin,
        *,
        enabled: bool | None = None,
    ) -> None:
        """
        Register one detector plugin.

        Raises
        ------
        TypeError
            If the supplied object is not a DetectorPlugin.

        ValueError
            If a plugin with the same ID is already registered.
        """
        if not isinstance(plugin, DetectorPlugin):
            raise TypeError(
                "detector plugin registry requires DetectorPlugin",
            )

        plugin_id = plugin.metadata.id

        if plugin_id in self._plugins:
            raise ValueError(
                f"duplicate detector plugin: {plugin_id}",
            )

        active = (
            plugin.metadata.enabled_by_default
            if enabled is None
            else bool(enabled)
        )

        self._plugins[plugin_id] = RegisteredDetector(
            plugin=plugin,
            enabled=active,
        )

    # ========================================================================
    # Lookup
    # ========================================================================

    def get(
        self,
        plugin_id: str,
    ) -> DetectorPlugin | None:
        """
        Return a detector plugin by ID.

        Returns None when the plugin does not exist.
        """
        registered = self._plugins.get(plugin_id)

        return (
            registered.plugin
            if registered is not None
            else None
        )

    def all(self) -> tuple[DetectorPlugin, ...]:
        """
        Return all registered detector plugins.
        """
        return tuple(
            item.plugin
            for item in self._plugins.values()
        )

    def enabled(self) -> tuple[DetectorPlugin, ...]:
        """
        Return only enabled detector plugins.
        """
        return tuple(
            item.plugin
            for item in self._plugins.values()
            if item.enabled
        )

    # ========================================================================
    # Counts
    # ========================================================================

    def count(self) -> int:
        """
        Return the total number of registered detector plugins.
        """
        return len(self._plugins)

    def enabled_count(self) -> int:
        """
        Return the number of enabled detector plugins.
        """
        return sum(
            1
            for item in self._plugins.values()
            if item.enabled
        )

    def disabled_count(self) -> int:
        """
        Return the number of disabled detector plugins.
        """
        return self.count() - self.enabled_count()

    # ========================================================================
    # Enable / Disable
    # ========================================================================

    def set_enabled(
        self,
        plugin_id: str,
        enabled: bool,
    ) -> None:
        """
        Enable or disable a registered detector plugin.

        Raises
        ------
        KeyError
            If the plugin does not exist.
        """
        registered = self._plugins.get(plugin_id)

        if registered is None:
            raise KeyError(
                f"unknown detector plugin: {plugin_id}",
            )

        self._plugins[plugin_id] = RegisteredDetector(
            plugin=registered.plugin,
            enabled=bool(enabled),
        )

    # ========================================================================
    # Lifecycle
    # ========================================================================

    def initialize(
        self,
        config: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> None:
        """
        Initialize all registered detector plugins.

        Each plugin receives only its own configuration mapping.
        """
        configurations = config or {}

        for plugin_id, registered in self._plugins.items():
            registered.plugin.initialize(
                configurations.get(
                    plugin_id,
                    {},
                ),
            )

    def shutdown(self) -> None:
        """
        Shut down all registered detector plugins.
        """
        for registered in self._plugins.values():
            registered.plugin.shutdown()

    # ========================================================================
    # Lifecycle / Testing
    # ========================================================================

    def clear(self) -> None:
        """
        Remove all registered detector plugins.

        Intended for controlled startup and test lifecycle operations.
        """
        self._plugins.clear()


__all__ = [
    "RegisteredDetector",
    "DetectorPluginRegistry",
]