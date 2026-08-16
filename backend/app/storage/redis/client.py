from __future__ import annotations

from redis.asyncio import Redis

from app.core.metrics import REGISTRY, Timer

_REDIS_HEALTH_HELP = (
    "Redis health status (1=healthy, 0=unhealthy)."
)
_REDIS_PING_FAILURES_HELP = "Total Redis health check failures."


class RedisClient:
    """Lifecycle wrapper for Redis async connections."""

    def __init__(self, url: str) -> None:
        self._client: Redis = Redis.from_url(
            url,
            decode_responses=False,
        )

    @property
    def client(self) -> Redis:
        return self._client

    async def ping(self) -> bool:
        try:
            with Timer(
                REGISTRY,
                "siem_redis_operation_latency_seconds",
                help_text="Redis operation latency in seconds.",
                labels={"operation": "ping"},
            ):
                result = bool(await self._client.ping())

        except Exception:
            REGISTRY.inc_counter(
                "siem_redis_operation_failures_total",
                help_text="Total Redis operation failures.",
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

    async def close(self) -> None:
        await self._client.aclose()