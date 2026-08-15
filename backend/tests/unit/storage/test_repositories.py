from __future__ import annotations

from typing import Any

import pytest

from app.storage.opensearch.events import OpenSearchEventRepository
from app.storage.redis.kv import RedisKeyValueRepository


class FakeIndices:
    """Fake OpenSearch indices API used by unit tests."""

    def __init__(self) -> None:
        self.created = False

    async def exists(self, *, index: str) -> bool:
        return self.created

    async def create(
        self,
        *,
        index: str,
        body: dict[str, object],
    ) -> None:
        self.created = True


class FakeOpenSearch:
    """In-memory OpenSearch replacement for unit tests."""

    def __init__(self) -> None:
        self.indices = FakeIndices()
        self.documents: dict[str, dict[str, object]] = {}

    async def index(
        self,
        *,
        index: str,
        id: str,
        body: dict[str, object],
        refresh: bool,
    ) -> None:
        self.documents[id] = body

    async def get(
        self,
        *,
        index: str,
        id: str,
    ) -> dict[str, object]:
        if id not in self.documents:

            class NotFound(Exception):
                status_code = 404

            raise NotFound()

        return {
            "_source": self.documents[id],
        }

    async def count(
        self,
        *,
        index: str,
    ) -> dict[str, int]:
        return {
            "count": len(self.documents),
        }

    async def search(
        self,
        *,
        index: str,
        body: dict[str, object],
        size: int,
    ) -> dict[str, object]:
        documents = list(
            self.documents.values()
        )[:size]

        return {
            "hits": {
                "total": {
                    "value": len(documents),
                },
                "hits": [
                    {
                        "_source": document,
                    }
                    for document in documents
                ],
            }
        }


class FakeRedis:
    """In-memory Redis replacement for unit tests."""

    def __init__(self) -> None:
        self.values: dict[str, bytes] = {}

    async def get(
        self,
        key: str,
    ) -> bytes | None:
        return self.values.get(key)

    async def set(
        self,
        key: str,
        value: bytes,
        *,
        ex: int | None = None,
    ) -> bool:
        self.values[key] = value
        return True

    async def delete(
        self,
        key: str,
    ) -> int:
        return int(
            self.values.pop(key, None) is not None
        )


@pytest.mark.anyio
async def test_opensearch_event_repository_round_trip(
    real_enriched_event: Any,
) -> None:
    repository = OpenSearchEventRepository(
        FakeOpenSearch()
    )

    await repository.ensure_index()

    await repository.save(
        real_enriched_event
    )

    loaded = await repository.get(
        real_enriched_event.event_id
    )

    assert loaded is not None
    assert (
        loaded.event_id
        == real_enriched_event.event_id
    )
    assert loaded.stage.value == "enriched"
    assert await repository.count() == 1


@pytest.mark.anyio
async def test_redis_repository_round_trip() -> None:
    repository = RedisKeyValueRepository(
        FakeRedis()
    )

    await repository.set(
        "phase06:test",
        b"value",
        ttl=60,
    )

    assert (
        await repository.get("phase06:test")
        == b"value"
    )

    await repository.delete(
        "phase06:test"
    )

    assert (
        await repository.get("phase06:test")
        is None
    )


@pytest.mark.anyio
async def test_redis_repository_rejects_invalid_ttl() -> None:
    repository = RedisKeyValueRepository(
        FakeRedis()
    )

    with pytest.raises(
        ValueError,
        match="greater than zero",
    ):
        await repository.set(
            "phase06:test",
            b"value",
            ttl=0,
        )
