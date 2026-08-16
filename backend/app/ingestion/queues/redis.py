from __future__ import annotations

import json
from typing import Any

from app.core.metrics import REGISTRY, Timer
from app.domain.events.models import RawEvent
from app.ingestion.queues.base import EventQueue

_REDIS_QUEUE_LATENCY_HELP = (
    "Redis queue operation latency in seconds."
)
_REDIS_QUEUE_FAILURES_HELP = (
    "Total Redis queue operation failures."
)


class RedisEventQueue(EventQueue):
    """Redis queue adapter.

    The Redis client is injected, keeping the ingestion domain independent
    of a concrete Redis library. The client must expose async rpush and blpop.
    """

    def __init__(
        self,
        client: Any,
        queue_name: str = "siem:events",
    ) -> None:
        if not queue_name.strip():
            raise ValueError("queue_name must not be empty")

        self._client = client
        self.queue_name = queue_name
        self._size = 0

    async def put(self, event: RawEvent) -> None:
        payload = event.model_dump(mode="json")

        try:
            with Timer(
                REGISTRY,
                "siem_redis_operation_latency_seconds",
                help_text=_REDIS_QUEUE_LATENCY_HELP,
                labels={"operation": "rpush"},
            ):
                await self._client.rpush(
                    self.queue_name,
                    json.dumps(payload),
                )

        except Exception:
            REGISTRY.inc_counter(
                "siem_redis_operation_failures_total",
                help_text="Total Redis operation failures.",
                labels={"operation": "rpush"},
            )
            raise

        self._size += 1

    async def get(self) -> RawEvent:
        try:
            with Timer(
                REGISTRY,
                "siem_redis_operation_latency_seconds",
                help_text=_REDIS_QUEUE_LATENCY_HELP,
                labels={"operation": "blpop"},
            ):
                _key, payload = await self._client.blpop(
                    self.queue_name
                )

        except Exception:
            REGISTRY.inc_counter(
                "siem_redis_operation_failures_total",
                help_text="Total Redis operation failures.",
                labels={"operation": "blpop"},
            )
            raise

        if isinstance(payload, bytes):
            payload = payload.decode("utf-8")

        self._size = max(0, self._size - 1)

        return RawEvent.model_validate(json.loads(payload))

    def qsize(self) -> int:
        return self._size