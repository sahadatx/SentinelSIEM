from __future__ import annotations

from datetime import UTC, datetime, timedelta


class DetectionSuppression:
    """Small in-memory suppression guard for duplicate rule/event matches.

    Persistent or distributed suppression belongs to later alert/correlation layers.
    """

    def __init__(self, *, ttl_seconds: int = 60) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be greater than zero")
        self.ttl = timedelta(seconds=ttl_seconds)
        self._entries: dict[tuple[str, str], datetime] = {}

    def is_suppressed(self, rule_id: str, event_id: str) -> bool:
        key = (rule_id, event_id)
        expires_at = self._entries.get(key)
        now = datetime.now(UTC)
        if expires_at is None:
            return False
        if expires_at <= now:
            self._entries.pop(key, None)
            return False
        return True

    def suppress(self, rule_id: str, event_id: str) -> None:
        self._entries[(rule_id, event_id)] = datetime.now(UTC) + self.ttl

    def clear(self) -> None:
        self._entries.clear()
