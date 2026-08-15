from __future__ import annotations

from collections.abc import Awaitable, Callable

from app.domain.events.models import RawEvent
from app.ingestion.backpressure import BackpressurePolicy
from app.ingestion.dead_letter import DeadLetterService
from app.ingestion.queues.base import EventQueue
from app.ingestion.retry import RetryPolicy, with_retry

EventProcessor = Callable[[RawEvent], Awaitable[None]]


class IngestionPipeline:
    """Queue-backed ingestion processing pipeline.

    This phase stops at ingestion. Parsing/normalization and downstream
    security analytics are deliberately not implemented here.
    """

    def __init__(
        self,
        queue: EventQueue,
        processor: EventProcessor,
        *,
        backpressure: BackpressurePolicy | None = None,
        retry_policy: RetryPolicy | None = None,
        dead_letter: DeadLetterService | None = None,
    ) -> None:
        self.queue = queue
        self.processor = processor
        self.backpressure = backpressure or BackpressurePolicy(max_queue_size=10_000)
        self.retry_policy = retry_policy or RetryPolicy()
        self.dead_letter = dead_letter or DeadLetterService()

    async def submit(self, event: RawEvent) -> None:
        if not self.backpressure.accepts(self.queue.qsize()):
            raise RuntimeError("ingestion queue is at capacity")
        await self.queue.put(event)

    async def process_one(self) -> None:
        event = await self.queue.get()

        try:
            await with_retry(
                lambda: self.processor(event),
                policy=self.retry_policy,
            )
        except Exception as exc:
            await self.dead_letter.store(
                event,
                reason=str(exc) or exc.__class__.__name__,
                attempts=self.retry_policy.max_attempts,
            )
