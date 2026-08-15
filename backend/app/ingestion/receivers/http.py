from __future__ import annotations

from datetime import datetime
from typing import Any

from app.domain.events.enums import EventSourceType
from app.domain.events.factory import create_raw_event
from app.domain.events.models import RawEvent


class HTTPReceiver:
    """Convert an HTTP-ingested payload into a RawEvent."""

    def receive(
        self,
        payload: str,
        *,
        source: str,
        metadata: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> RawEvent:
        return create_raw_event(
            source=source,
            source_type=EventSourceType.HTTP,
            raw_event=payload,
            metadata=metadata,
            timestamp=timestamp,
        )
