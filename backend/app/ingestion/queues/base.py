from __future__ import annotations

from abc import ABC, abstractmethod

from app.domain.events.models import RawEvent


class EventQueue(ABC):
    """Minimal asynchronous queue contract."""

    @abstractmethod
    async def put(self, event: RawEvent) -> None:
        raise NotImplementedError

    @abstractmethod
    async def get(self) -> RawEvent:
        raise NotImplementedError

    @abstractmethod
    def qsize(self) -> int:
        raise NotImplementedError
