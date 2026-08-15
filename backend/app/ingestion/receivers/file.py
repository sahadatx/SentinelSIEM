from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from app.domain.events.enums import EventSourceType
from app.domain.events.factory import create_raw_event
from app.domain.events.models import RawEvent


class FileReceiver:
    """Convert file/log lines into RawEvent objects."""

    def receive_line(
        self,
        line: str,
        *,
        source: str,
        timestamp: datetime | None = None,
    ) -> RawEvent:
        return create_raw_event(
            source=source,
            source_type=EventSourceType.FILE,
            raw_event=line.rstrip("\n"),
            timestamp=timestamp,
        )

    def receive_lines(
        self,
        lines: Iterable[str],
        *,
        source: str,
    ) -> list[RawEvent]:
        return [self.receive_line(line, source=source) for line in lines]
