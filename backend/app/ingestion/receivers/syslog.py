from __future__ import annotations

from datetime import datetime

from app.domain.events.enums import EventSourceType
from app.domain.events.factory import create_raw_event
from app.domain.events.models import RawEvent


class SyslogReceiver:
    """Convert an accepted syslog payload into a RawEvent."""

    def receive(
        self,
        payload: str,
        *,
        source: str,
        timestamp: datetime | None = None,
    ) -> RawEvent:
        return create_raw_event(
            source=source,
            source_type=EventSourceType.SYSLOG,
            raw_event=payload,
            timestamp=timestamp,
        )
