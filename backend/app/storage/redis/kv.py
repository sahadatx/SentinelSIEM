from __future__ import annotations

from typing import Protocol, cast


class RedisClientProtocol(Protocol):
    """Minimal Redis client interface required by the repository."""

    async def get(self, key: str) -> object:
        """Retrieve a value by key."""
        ...

    async def set(
        self,
        key: str,
        value: bytes,
        *,
        ex: int | None = None,
    ) -> object:
        """Store a value with an optional expiration."""
        ...

    async def delete(self, key: str) -> object:
        """Delete a key."""
        ...


class RedisKeyValueRepository:
    """Redis-backed key-value repository for cache and temporary state."""

    def __init__(self, client: RedisClientProtocol) -> None:
        self.client = client

    async def get(self, key: str) -> bytes | None:
        """Retrieve a value by key."""
        value = await self.client.get(key)
        return cast(bytes | None, value)

    async def set(
        self,
        key: str,
        value: bytes,
        *,
        ttl: int | None = None,
    ) -> None:
        """Store a value with an optional positive TTL."""
        if ttl is not None and ttl <= 0:
            raise ValueError(
                "ttl must be greater than zero"
            )

        await self.client.set(
            key,
            value,
            ex=ttl,
        )

    async def delete(self, key: str) -> None:
        """Delete a value by key."""
        await self.client.delete(key)
