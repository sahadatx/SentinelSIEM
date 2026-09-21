from __future__ import annotations

from dataclasses import dataclass

from app.core.config import Settings
from app.core.version import __version__


@dataclass(frozen=True, slots=True)
class SystemInfo:
    """Internal system information returned by the system service."""

    service: str
    version: str
    environment: str
    capabilities: tuple[str, ...]


class SystemService:
    """Application service for SentinelSIEM system information."""

    _CAPABILITIES: tuple[str, ...] = (
        "api",
        "websocket",
        "events",
        "alerts",
        "incidents",
        "threat-intelligence",
        "mitre",
    )

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def get_system_info(self) -> SystemInfo:
        """Return current SentinelSIEM system information."""

        return SystemInfo(
            service=self._settings.app_name,
            version=__version__,
            environment=self._settings.environment,
            capabilities=self._CAPABILITIES,
        )
