from __future__ import annotations

from redis.asyncio import Redis


class RedisClient:
    """Lifecycle wrapper for Redis async connections."""

    def __init__(self, url: str) -> None:
        self._client: Redis = Redis.from_url(url, decode_responses=False)

    @property
    def client(self) -> Redis:
        return self._client

    async def ping(self) -> bool:
        return bool(await self._client.ping())

    async def close(self) -> None:
        await self._client.aclose()
