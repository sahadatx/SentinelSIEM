from __future__ import annotations

from app.ingestion.collectors.base import Collector


class CollectorRegistry:
    """Explicit registry for collector instances."""

    def __init__(self) -> None:
        self._collectors: dict[str, Collector] = {}

    def register(self, collector: Collector) -> None:
        if collector.name in self._collectors:
            raise ValueError(f"collector already registered: {collector.name}")
        self._collectors[collector.name] = collector

    def get(self, name: str) -> Collector:
        try:
            return self._collectors[name]
        except KeyError as exc:
            raise KeyError(f"collector not registered: {name}") from exc

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._collectors))
