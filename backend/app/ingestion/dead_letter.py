from __future__ import annotations

from datetime import UTC, datetime

from app.core.metrics import REGISTRY
from app.domain.events.models import RawEvent
from app.ingestion.queues.dead_letter import (
    DeadLetterRecord,
    InMemoryDeadLetterQueue,
)


class DeadLetterService:
    """Route permanently failed ingestion events to a dead-letter queue."""

    def __init__(
        self,
        queue: InMemoryDeadLetterQueue | None = None,
    ) -> None:
        """Initialize the dead-letter service.

        Args:
            queue:
                Optional dead-letter queue implementation.
                An in-memory queue is used by default.
        """
        self.queue = queue or InMemoryDeadLetterQueue()

    async def store(
        self,
        event: RawEvent,
        *,
        reason: str,
        attempts: int,
    ) -> None:
        """Store a permanently failed event in the dead-letter queue.

        Args:
            event:
                The raw event that could not be processed successfully.
            reason:
                Human-readable description of the final failure.
            attempts:
                Number of processing attempts performed before the event
                was routed to the dead-letter queue.
        """
        record = DeadLetterRecord(
            event=event,
            reason=reason,
            attempts=attempts,
            failed_at=datetime.now(UTC),
        )

        await self.queue.put(record)

        REGISTRY.inc_counter(
            "siem_dlq_events_total",
            help_text=("Total events routed to the dead-letter queue."),
        )
