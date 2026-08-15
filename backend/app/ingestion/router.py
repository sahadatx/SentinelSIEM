from __future__ import annotations

from app.domain.events.enums import EventSourceType
from app.domain.events.models import RawEvent


class ReceiverRouter:
    """Routes raw payloads to the receiver selected by source type."""

    def __init__(self) -> None:
        self._receivers: dict[EventSourceType, object] = {}

    def register(self, source_type: EventSourceType, receiver: object) -> None:
        if source_type in self._receivers:
            raise ValueError(f"receiver already registered: {source_type}")
        self._receivers[source_type] = receiver

    def get(self, source_type: EventSourceType) -> object:
        try:
            return self._receivers[source_type]
        except KeyError as exc:
            raise KeyError(f"receiver not registered: {source_type}") from exc

    def route(self, event: RawEvent) -> object:
        return self.get(event.source_type)
