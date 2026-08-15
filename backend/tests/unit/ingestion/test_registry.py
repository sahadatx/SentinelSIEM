from collections.abc import AsyncIterator

import pytest

from app.domain.events.enums import EventSourceType
from app.domain.events.models import RawEvent
from app.ingestion.collectors.base import Collector
from app.ingestion.collectors.registry import CollectorRegistry
from app.ingestion.router import ReceiverRouter


class StubCollector(Collector):
    def collect(self) -> AsyncIterator[RawEvent]:
        async def generator() -> AsyncIterator[RawEvent]:
            if False:
                yield RawEvent.model_construct()

        return generator()


def test_collector_registry_rejects_duplicates() -> None:
    registry = CollectorRegistry()
    registry.register(StubCollector("syslog"))

    with pytest.raises(ValueError):
        registry.register(StubCollector("syslog"))


def test_receiver_router_registers_source_type() -> None:
    router = ReceiverRouter()
    receiver = object()

    router.register(EventSourceType.SYSLOG, receiver)

    assert router.get(EventSourceType.SYSLOG) is receiver
