from __future__ import annotations

from datetime import UTC, datetime

from app.domain.events.models import RawEvent
from app.ingestion.queues.dead_letter import DeadLetterRecord, InMemoryDeadLetterQueue


class DeadLetterService:
    """Routes permanently failed events to the dead-letter queue."""

    def __init__(self, queue: InMemoryDeadLetterQueue | None = None) -> None:
        self.queue = queue or InMemoryDeadLetterQueue()

    async def store(self, event: RawEvent, *, reason: str, attempts: int) -> None:
        await self.queue.put(
            DeadLetterRecord(
                event=event,
                reason=reason,
                attempts=attempts,
                failed_at=datetime.now(UTC),
            )
        )
