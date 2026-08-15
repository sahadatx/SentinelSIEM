from __future__ import annotations

from collections.abc import Iterable

from app.ingestion.collectors.base import Collector


class IngestionManager:
    """Lifecycle manager for registered collectors."""

    def __init__(self, collectors: Iterable[Collector] = ()) -> None:
        self._collectors = list(collectors)

    def add_collector(self, collector: Collector) -> None:
        if any(item.name == collector.name for item in self._collectors):
            raise ValueError(f"collector already registered: {collector.name}")
        self._collectors.append(collector)

    async def start(self) -> None:
        for collector in self._collectors:
            await collector.start()

    async def stop(self) -> None:
        for collector in reversed(self._collectors):
            await collector.stop()

    @property
    def collectors(self) -> tuple[Collector, ...]:
        return tuple(self._collectors)
