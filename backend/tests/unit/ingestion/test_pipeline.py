from __future__ import annotations

from uuid import UUID

import pytest

from app.domain.events.enums import EventSourceType
from app.domain.events.factory import create_raw_event
from app.domain.events.models import RawEvent
from app.ingestion.dead_letter import DeadLetterService
from app.ingestion.pipeline import IngestionPipeline
from app.ingestion.queues.base import EventQueue


class FakeQueue(EventQueue):
    def __init__(self) -> None:
        self.items: list[RawEvent] = []

    async def put(self, event: RawEvent) -> None:
        self.items.append(event)

    async def get(self) -> RawEvent:
        return self.items.pop(0)

    def qsize(self) -> int:
        return len(self.items)


@pytest.mark.anyio
async def test_pipeline_processes_event() -> None:
    processed: list[UUID] = []

    async def processor(event: RawEvent) -> None:
        processed.append(event.event_id)

    event = create_raw_event(
        "auth01",
        EventSourceType.SYSLOG,
        "login failed",
    )

    pipeline = IngestionPipeline(
        FakeQueue(),
        processor,
    )

    await pipeline.submit(event)
    await pipeline.process_one()

    assert processed == [event.event_id]


@pytest.mark.anyio
async def test_pipeline_sends_permanent_failure_to_dlq() -> None:
    async def processor(event: RawEvent) -> None:
        raise RuntimeError("processor failed")

    dlq = DeadLetterService()

    event = create_raw_event(
        "auth01",
        EventSourceType.SYSLOG,
        "bad event",
    )

    pipeline = IngestionPipeline(
        FakeQueue(),
        processor,
        dead_letter=dlq,
    )

    await pipeline.submit(event)
    await pipeline.process_one()

    assert dlq.queue.size() == 1

    record = (await dlq.queue.all())[0]

    assert record.event.event_id == event.event_id
    assert record.attempts == 3
