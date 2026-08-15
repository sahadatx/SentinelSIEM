from __future__ import annotations

from datetime import datetime

from app.domain.events.enums import EventSourceType
from app.domain.events.factory import create_raw_event
from app.domain.events.models import RawEvent


class TCPReceiver:
    """Convert an accepted TCP payload into a RawEvent."""

    def receive(
        self,
        payload: str,
        *,
        source: str,
        timestamp: datetime | None = None,
    ) -> RawEvent:
        return create_raw_event(
            source=source,
            source_type=EventSourceType.TCP,
            raw_event=payload,
            timestamp=timestamp,
        )
