from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator

from app.domain.events.models import RawEvent


class Collector(ABC):
    """Contract for log collectors.

    Collectors acquire raw records; they do not parse, normalize, detect,
    correlate, store, or generate alerts.
    """

    def __init__(self, name: str) -> None:
        if not name.strip():
            raise ValueError("collector name must not be empty")

        self.name = name
        self._running = False

    @property
    def running(self) -> bool:
        return self._running

    async def start(self) -> None:
        self._running = True

    async def stop(self) -> None:
        self._running = False

    @abstractmethod
    def collect(self) -> AsyncIterator[RawEvent]:
        """Yield raw security events from the collector."""
        raise NotImplementedError
