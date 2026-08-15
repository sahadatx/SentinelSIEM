from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.threat_intelligence.models import IOCMatch


class IOCMatchCache:
    """Small bounded-TTL cache for threat-intelligence match results."""

    def __init__(self, ttl_seconds: int = 300) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._ttl = timedelta(seconds=ttl_seconds)
        self._items: dict[str, tuple[datetime, tuple[IOCMatch, ...]]] = {}

    def get(self, key: str) -> tuple[IOCMatch, ...] | None:
        item = self._items.get(key)
        if item is None:
            return None

        created_at, value = item
        if datetime.now(UTC) - created_at >= self._ttl:
            self._items.pop(key, None)
            return None

        return value

    def set(self, key: str, value: tuple[IOCMatch, ...]) -> None:
        self._items[key] = (datetime.now(UTC), value)

    def clear(self) -> None:
        self._items.clear()
