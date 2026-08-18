from __future__ import annotations

import json
from typing import Any

from redis.asyncio import Redis
from redis.asyncio.client import PubSub

from app.core.metrics import REGISTRY, Timer

_REDIS_CLIENT_LATENCY_HELP = (
    "Redis client operation latency in seconds."
)
_REDIS_FAILURES_HELP = (
    "Total Redis operation failures."
)
_REDIS_HEALTH_HELP = (
    "Redis health status (1=healthy, 0=unhealthy)."
)

# Cross-process Redis Pub/Sub channel used to deliver
# persisted security events to the backend WebSocket layer.
WEBSOCKET_EVENTS_CHANNEL = "siem:websocket:events"


class RedisClient:
    """Lifecycle wrapper for Redis async connections."""

    def __init__(self, url: str) -> None:
        self._client: Redis = Redis.from_url(
            url,
            decode_responses=False,
        )

    @property
    def client(self) -> Redis:
        """Return the underlying Redis client."""
        return self._client

    async def ping(self) -> bool:
        """Check Redis availability and update health metrics."""
        try:
            with Timer(
                REGISTRY,
                "siem_redis_client_operation_latency_seconds",
                help_text=_REDIS_CLIENT_LATENCY_HELP,
                labels={"operation": "ping"},
            ):
                result = bool(
                    await self._client.ping(),
                )

        except Exception:
            REGISTRY.inc_counter(
                "siem_redis_operation_failures_total",
                help_text=_REDIS_FAILURES_HELP,
                labels={"operation": "ping"},
            )
            REGISTRY.set_gauge(
                "siem_redis_health",
                0.0,
                help_text=_REDIS_HEALTH_HELP,
            )
            raise

        REGISTRY.set_gauge(
            "siem_redis_health",
            1.0 if result else 0.0,
            help_text=_REDIS_HEALTH_HELP,
        )

        return result

    async def publish_json(
        self,
        channel: str,
        payload: dict[str, Any],
    ) -> int:
        """
        Publish a JSON-compatible payload to a Redis channel.

        Returns the number of Redis subscribers that received
        the published message.
        """
        serialized = json.dumps(
            payload,
            separators=(",", ":"),
            ensure_ascii=False,
        )

        try:
            return int(
                await self._client.publish(
                    channel,
                    serialized,
                ),
            )

        except Exception:
            REGISTRY.inc_counter(
                "siem_redis_operation_failures_total",
                help_text=_REDIS_FAILURES_HELP,
                labels={"operation": "publish"},
            )
            raise

    def create_pubsub(self) -> PubSub:
        """
        Create an asynchronous Redis Pub/Sub consumer.

        The returned PubSub object is owned by the caller and must
        be unsubscribed/closed by that caller.
        """
        return self._client.pubsub(
            ignore_subscribe_messages=True,
        )

    async def close(self) -> None:
        """Close the underlying Redis client."""
        await self._client.aclose()