from __future__ import annotations

import json
from typing import Any

from app.domain.events.models import RawEvent
from app.ingestion.queues.base import EventQueue


class RedisEventQueue(EventQueue):
    """Redis queue adapter.

    The Redis client is injected, keeping the ingestion domain independent of
    a concrete Redis library. The client must expose async rpush and blpop.
    """

    def __init__(self, client: Any, queue_name: str = "siem:events") -> None:
        if not queue_name.strip():
            raise ValueError("queue_name must not be empty")
        self._client = client
        self.queue_name = queue_name
        self._size = 0

    async def put(self, event: RawEvent) -> None:
        payload = event.model_dump(mode="json")
        await self._client.rpush(self.queue_name, json.dumps(payload))
        self._size += 1

    async def get(self) -> RawEvent:
        _key, payload = await self._client.blpop(self.queue_name)
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8")
        self._size = max(0, self._size - 1)
        return RawEvent.model_validate(json.loads(payload))

    def qsize(self) -> int:
        return self._size
