from __future__ import annotations

from collections.abc import Awaitable, Callable

from app.core.metrics import REGISTRY, Timer
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

    Observability metrics track submissions, queue depth, processing
    outcomes, failures, and processing latency.
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
        self.backpressure = (
            backpressure
            or BackpressurePolicy(max_queue_size=10_000)
        )
        self.retry_policy = retry_policy or RetryPolicy()
        self.dead_letter = dead_letter or DeadLetterService()

        self._set_queue_depth_metric()

    def _set_queue_depth_metric(self) -> None:
        REGISTRY.set_gauge(
            "siem_ingestion_queue_depth",
            float(self.queue.qsize()),
            help_text="Current ingestion queue depth.",
        )

    async def submit(self, event: RawEvent) -> None:
        queue_size = self.queue.qsize()

        if not self.backpressure.accepts(queue_size):
            REGISTRY.inc_counter(
                "siem_ingestion_submission_rejections_total",
                help_text=(
                    "Total ingestion submissions rejected because "
                    "the queue reached capacity."
                ),
            )

            self._set_queue_depth_metric()

            raise RuntimeError(
                "ingestion queue is at capacity"
            )

        await self.queue.put(event)

        REGISTRY.inc_counter(
            "siem_ingestion_submitted_total",
            help_text=(
                "Total events successfully submitted "
                "to the ingestion queue."
            ),
        )

        self._set_queue_depth_metric()

    async def process_one(self) -> None:
        event = await self.queue.get()

        self._set_queue_depth_metric()

        try:
            with Timer(
                REGISTRY,
                "siem_ingestion_processing_duration_seconds",
                help_text=(
                    "Ingestion event processing duration "
                    "in seconds."
                ),
            ):
                await with_retry(
                    lambda: self.processor(event),
                    policy=self.retry_policy,
                )

        except Exception as exc:
            REGISTRY.inc_counter(
                "siem_ingestion_processing_failures_total",
                help_text=(
                    "Total ingestion processing failures "
                    "after retry exhaustion."
                ),
            )

            await self.dead_letter.store(
                event,
                reason=(
                    str(exc)
                    or exc.__class__.__name__
                ),
                attempts=self.retry_policy.max_attempts,
            )

            return

        REGISTRY.inc_counter(
            "siem_ingestion_processed_total",
            help_text=(
                "Total events successfully processed "
                "by the ingestion pipeline."
            ),
        )

        self._set_queue_depth_metric()