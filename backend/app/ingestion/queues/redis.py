from __future__ import annotations

import json
from typing import Any

from app.core.metrics import REGISTRY, Timer
from app.domain.events.models import RawEvent
from app.ingestion.queues.base import EventQueue

_REDIS_QUEUE_LATENCY_HELP = "Redis queue operation latency in seconds."

_REDIS_QUEUE_FAILURES_HELP = "Total Redis queue operation failures."


class RedisEventQueue(EventQueue):
    """Redis-backed ingestion queue adapter.

    The Redis client is injected so the ingestion domain remains
    independent of the concrete Redis implementation. The injected
    client must provide asynchronous ``rpush`` and ``blpop`` methods.
    """

    def __init__(
        self,
        client: Any,
        queue_name: str = "siem:events",
    ) -> None:
        """Initialize the Redis event queue."""
        if not queue_name.strip():
            raise ValueError("queue_name must not be empty")

        self._client = client
        self.queue_name = queue_name
        self._size = 0

    async def put(
        self,
        event: RawEvent,
    ) -> None:
        """Serialize and append an event to the Redis queue."""
        payload = event.model_dump(
            mode="json",
        )

        try:
            serialized_payload = json.dumps(
                payload,
                separators=(",", ":"),
            )

            with Timer(
                REGISTRY,
                "siem_redis_operation_latency_seconds",
                help_text=_REDIS_QUEUE_LATENCY_HELP,
                labels={"operation": "rpush"},
            ):
                await self._client.rpush(
                    self.queue_name,
                    serialized_payload,
                )

        except Exception:
            REGISTRY.inc_counter(
                "siem_redis_operation_failures_total",
                help_text=_REDIS_QUEUE_FAILURES_HELP,
                labels={"operation": "rpush"},
            )
            raise

        self._size += 1

    async def get(self) -> RawEvent:
        """Block until an event is available and deserialize it."""
        try:
            with Timer(
                REGISTRY,
                "siem_redis_operation_latency_seconds",
                help_text=_REDIS_QUEUE_LATENCY_HELP,
                labels={"operation": "blpop"},
            ):
                result = await self._client.blpop(
                    self.queue_name,
                )

        except Exception:
            REGISTRY.inc_counter(
                "siem_redis_operation_failures_total",
                help_text=_REDIS_QUEUE_FAILURES_HELP,
                labels={"operation": "blpop"},
            )
            raise

        if not result:
            raise RuntimeError("Redis BLPOP returned no result.")

        _key, payload = result

        if isinstance(payload, bytes):
            payload = payload.decode(
                "utf-8",
            )

        if not isinstance(payload, str):
            raise TypeError("Redis event payload must be a string or bytes.")

        try:
            decoded_payload = json.loads(
                payload,
            )
        except json.JSONDecodeError as exc:
            REGISTRY.inc_counter(
                "siem_redis_operation_failures_total",
                help_text=_REDIS_QUEUE_FAILURES_HELP,
                labels={"operation": "decode"},
            )
            raise ValueError("Redis event payload contains invalid JSON.") from exc

        self._size = max(
            0,
            self._size - 1,
        )

        try:
            return RawEvent.model_validate(
                decoded_payload,
            )
        except Exception:
            REGISTRY.inc_counter(
                "siem_redis_operation_failures_total",
                help_text=_REDIS_QUEUE_FAILURES_HELP,
                labels={"operation": "validate"},
            )
            raise

    def qsize(self) -> int:
        """Return the locally tracked queue depth."""
        return self._size
