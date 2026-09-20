from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import pytest

from app.domain.events.models import (
    CanonicalSecurityEvent,
    EnrichedEvent,
)
from app.storage.opensearch.events import OpenSearchEventRepository
from app.storage.redis.kv import RedisKeyValueRepository


class FakeIndices:
    """Fake OpenSearch indices API used by unit tests."""

    def __init__(self) -> None:
        self.created = False
        self.created_body: dict[str, object] | None = None

        self.mapping: dict[str, object] = {
            "siem-events-v1": {
                "mappings": {
                    "properties": {},
                },
            },
        }

        self.put_mapping_calls: list[dict[str, object]] = []
        self.put_settings_calls: list[dict[str, object]] = []

    async def exists(
        self,
        *,
        index: str,
    ) -> bool:
        return self.created

    async def create(
        self,
        *,
        index: str,
        body: dict[str, object],
    ) -> None:
        self.created = True
        self.created_body = body

        self.mapping[index] = {
            "mappings": body.get("mappings", {}),
        }

    async def get_mapping(
        self,
        *,
        index: str,
    ) -> dict[str, object]:
        return self.mapping

    async def put_mapping(
        self,
        *,
        index: str,
        body: dict[str, object],
    ) -> None:
        self.put_mapping_calls.append(body)

        properties = body.get("properties", {})

        index_mapping = self.mapping.setdefault(
            index,
            {
                "mappings": {
                    "properties": {},
                },
            },
        )

        mappings = index_mapping.setdefault(
            "mappings",
            {},
        )

        existing_properties = mappings.setdefault(
            "properties",
            {},
        )

        if (
            isinstance(existing_properties, dict)
            and isinstance(properties, dict)
        ):
            existing_properties.update(properties)

    async def put_settings(
        self,
        *,
        index: str,
        body: dict[str, object],
    ) -> None:
        self.put_settings_calls.append(body)


class FakeOpenSearch:
    """In-memory OpenSearch replacement for unit tests."""

    def __init__(self) -> None:
        self.indices = FakeIndices()
        self.documents: dict[str, dict[str, object]] = {}

        self.last_search_body: dict[str, object] | None = None
        self.last_search_size: int | None = None
        self.last_search_from: int | None = None

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
        self.last_search_body = body
        self.last_search_size = size

        search_from = body.get("from", 0)

        if not isinstance(search_from, int):
            raise TypeError(
                "search from must be an integer",
            )

        self.last_search_from = search_from

        all_documents = list(
            self.documents.values(),
        )

        documents = all_documents[
            search_from: search_from + size
        ]

        return {
            "hits": {
                "total": {
                    "value": len(all_documents),
                },
                "hits": [
                    {
                        "_source": document,
                    }
                    for document in documents
                ],
            },
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
            self.values.pop(key, None) is not None,
        )


@pytest.mark.anyio
async def test_opensearch_event_repository_round_trip(
    real_enriched_event: Any,
) -> None:
    client = FakeOpenSearch()
    repository = OpenSearchEventRepository(client)

    await repository.ensure_index()
    await repository.save(real_enriched_event)

    loaded = await repository.get(
        real_enriched_event.event_id,
    )

    assert loaded is not None
    assert (
        loaded.event_id
        == real_enriched_event.event_id
    )
    assert loaded.stage.value == "enriched"

    assert await repository.count() == 1


@pytest.mark.anyio
async def test_opensearch_canonical_event_round_trip(
    real_enriched_event: Any,
) -> None:
    client = FakeOpenSearch()
    repository = OpenSearchEventRepository(client)

    canonical_data = real_enriched_event.model_dump(
        exclude={"enrichment"},
    )

    canonical_data["stage"] = "canonical"

    canonical = CanonicalSecurityEvent.model_validate(
        canonical_data,
    )

    await repository.ensure_index()
    await repository.save(canonical)

    loaded = await repository.get(
        canonical.event_id,
    )

    assert loaded is not None
    assert isinstance(
        loaded,
        CanonicalSecurityEvent,
    )
    assert not isinstance(
        loaded,
        EnrichedEvent,
    )

    assert (
        loaded.event_id
        == canonical.event_id
    )
    assert (
        loaded.source_ip
        == canonical.source_ip
    )
    assert (
        loaded.source_port
        == canonical.source_port
    )
    assert (
        loaded.username
        == canonical.username
    )
    assert loaded.action == canonical.action
    assert loaded.outcome == canonical.outcome
    assert loaded.severity == canonical.severity
    assert loaded.category == canonical.category


@pytest.mark.anyio
async def test_opensearch_get_missing_event_returns_none() -> None:
    repository = OpenSearchEventRepository(
        FakeOpenSearch(),
    )

    missing_id = uuid4()

    assert await repository.get(
        missing_id,
    ) is None


@pytest.mark.anyio
async def test_opensearch_index_definition_contains_required_mapping() -> None:
    definition = OpenSearchEventRepository._index_definition()

    settings = definition["settings"]
    mappings = definition["mappings"]

    assert settings["number_of_shards"] == 1
    assert settings["number_of_replicas"] == 0

    assert mappings["dynamic"] == "strict"

    properties = mappings["properties"]

    assert properties["event_id"]["type"] == "keyword"
    assert properties["timestamp"]["type"] == "date"
    assert properties["source"]["type"] == "keyword"
    assert properties["source_type"]["type"] == "keyword"
    assert properties["source_ip"]["type"] == "ip"
    assert properties["destination_ip"]["type"] == "ip"
    assert properties["source_port"]["type"] == "integer"
    assert properties["destination_port"]["type"] == "integer"
    assert properties["username"]["type"] == "keyword"
    assert properties["action"]["type"] == "keyword"
    assert properties["outcome"]["type"] == "keyword"
    assert properties["severity"]["type"] == "keyword"
    assert properties["category"]["type"] == "keyword"
    assert properties["command"]["type"] == "text"
    assert properties["raw_event"]["type"] == "text"

    assert properties["parsed_data"]["type"] == "object"
    assert properties["parsed_data"]["dynamic"] is False

    assert properties["normalized_data"]["type"] == "object"
    assert properties["normalized_data"]["dynamic"] is False

    assert properties["enrichment"]["type"] == "object"
    assert properties["enrichment"]["dynamic"] is False

    assert properties["metadata"]["type"] == "object"
    assert properties["metadata"]["dynamic"] is False

    assert properties["stage"]["type"] == "keyword"


@pytest.mark.anyio
async def test_opensearch_ensure_index_creates_missing_index() -> None:
    client = FakeOpenSearch()
    repository = OpenSearchEventRepository(client)

    await repository.ensure_index()

    assert client.indices.created is True
    assert client.indices.created_body is not None

    assert (
        client.indices.created_body["settings"][
            "number_of_shards"
        ]
        == 1
    )

    assert (
        client.indices.created_body["settings"][
            "number_of_replicas"
        ]
        == 0
    )


@pytest.mark.anyio
async def test_opensearch_ensure_index_reconciles_existing_index() -> None:
    client = FakeOpenSearch()

    client.indices.created = True

    client.indices.mapping = {
        "siem-events-v1": {
            "mappings": {
                "properties": {},
            },
        },
    }

    repository = OpenSearchEventRepository(client)

    await repository.ensure_index()

    assert len(
        client.indices.put_mapping_calls,
    ) == 1

    assert len(
        client.indices.put_settings_calls,
    ) == 1

    mapping_body = (
        client.indices.put_mapping_calls[0]
    )

    properties = mapping_body["properties"]

    assert "parsed_data" in properties
    assert "normalized_data" in properties
    assert "enrichment" in properties

    assert (
        properties["metadata"]["dynamic"]
        is False
    )

    settings_body = (
        client.indices.put_settings_calls[0]
    )

    assert (
        settings_body["index"][
            "number_of_replicas"
        ]
        == 0
    )


@pytest.mark.anyio
async def test_opensearch_search_builds_filters_and_query(
    real_enriched_event: Any,
) -> None:
    client = FakeOpenSearch()
    repository = OpenSearchEventRepository(client)

    await repository.ensure_index()
    await repository.save(real_enriched_event)

    start_time = datetime(
        2026,
        8,
        14,
        20,
        0,
        0,
        tzinfo=timezone.utc,
    )

    end_time = datetime(
        2026,
        8,
        14,
        21,
        0,
        0,
        tzinfo=timezone.utc,
    )

    result = await repository.search(
        query="failed password",
        source=real_enriched_event.source,
        source_ip=str(
            real_enriched_event.source_ip,
        ),
        severity=(
            real_enriched_event.severity.value
        ),
        category=(
            real_enriched_event.category.value
        ),
        start_time=start_time,
        end_time=end_time,
        offset=0,
        limit=25,
    )

    assert result.total == 1
    assert len(result.events) == 1

    assert (
        result.events[0].event_id
        == real_enriched_event.event_id
    )

    assert client.last_search_from == 0
    assert client.last_search_size == 25
    assert client.last_search_body is not None

    assert (
        client.last_search_body["from"]
        == 0
    )

    body = client.last_search_body
    bool_query = body["query"]["bool"]

    filters = bool_query["filter"]

    assert {
        "term": {
            "source": real_enriched_event.source,
        },
    } in filters

    assert {
        "term": {
            "source_ip": str(
                real_enriched_event.source_ip,
            ),
        },
    } in filters

    assert {
        "term": {
            "severity": (
                real_enriched_event.severity.value
            ),
        },
    } in filters

    assert {
        "term": {
            "category": (
                real_enriched_event.category.value
            ),
        },
    } in filters

    assert {
        "range": {
            "timestamp": {
                "gte": start_time.isoformat(),
                "lte": end_time.isoformat(),
            },
        },
    } in filters

    assert bool_query["must"] == [
        {
            "multi_match": {
                "query": "failed password",
                                "fields": [
                                    "username",
                                    "action",
                                    "command",
                                    "process",
                                    "raw_event",
                                ],
            },
        }
    ]


@pytest.mark.anyio
async def test_opensearch_search_builds_all_event_filters(
    real_enriched_event: Any,
) -> None:
    client = FakeOpenSearch()
    repository = OpenSearchEventRepository(client)

    await repository.ensure_index()
    await repository.save(real_enriched_event)

    result = await repository.search(
        source=real_enriched_event.source,
        source_ip=str(
            real_enriched_event.source_ip,
        ),
        destination_ip=(
            str(real_enriched_event.destination_ip)
            if real_enriched_event.destination_ip
            is not None
            else None
        ),
        username=real_enriched_event.username,
        action=real_enriched_event.action,
        outcome=real_enriched_event.outcome,
        severity=(
            real_enriched_event.severity.value
        ),
        category=(
            real_enriched_event.category.value
        ),
        offset=0,
        limit=25,
    )

    assert result.total == 1
    assert len(result.events) == 1

    assert client.last_search_body is not None

    body = client.last_search_body
    bool_query = body["query"]["bool"]
    filters = bool_query["filter"]

    expected_filters = [
        {
            "term": {
                "source": real_enriched_event.source,
            },
        },
        {
            "term": {
                "source_ip": str(
                    real_enriched_event.source_ip,
                ),
            },
        },
        {
            "term": {
                "username": real_enriched_event.username,
            },
        },
        {
            "term": {
                "action": real_enriched_event.action,
            },
        },
        {
            "term": {
                "outcome": real_enriched_event.outcome,
            },
        },
        {
            "term": {
                "severity": (
                    real_enriched_event.severity.value
                ),
            },
        },
        {
            "term": {
                "category": (
                    real_enriched_event.category.value
                ),
            },
        },
    ]

    for expected_filter in expected_filters:
        assert expected_filter in filters

    if real_enriched_event.destination_ip is not None:
        assert {
            "term": {
                "destination_ip": str(
                    real_enriched_event.destination_ip,
                ),
            },
        } in filters


@pytest.mark.anyio
async def test_opensearch_search_supports_offset_pagination(
    real_enriched_event: Any,
) -> None:
    client = FakeOpenSearch()
    repository = OpenSearchEventRepository(client)

    await repository.ensure_index()

    events = []

    for _ in range(3):
        event_data = real_enriched_event.model_dump(
            mode="json",
        )

        event_data["event_id"] = str(
            uuid4(),
        )

        event = EnrichedEvent.model_validate(
            event_data,
        )

        events.append(event)

        await repository.save(event)

    first_page = await repository.search(
        offset=0,
        limit=2,
    )

    assert first_page.total == 3
    assert len(first_page.events) == 2

    assert client.last_search_from == 0
    assert client.last_search_size == 2

    second_page = await repository.search(
        offset=2,
        limit=2,
    )

    assert second_page.total == 3
    assert len(second_page.events) == 1

    assert (
        second_page.events[0].event_id
        == events[2].event_id
    )

    assert client.last_search_from == 2
    assert client.last_search_size == 2

    assert client.last_search_body is not None

    assert (
        client.last_search_body["from"]
        == 2
    )


@pytest.mark.anyio
async def test_opensearch_search_without_optional_filters() -> None:
    client = FakeOpenSearch()
    repository = OpenSearchEventRepository(client)

    result = await repository.search(
        limit=10,
    )

    assert result.total == 0
    assert result.events == ()

    assert client.last_search_body is not None

    assert (
        client.last_search_body["from"]
        == 0
    )

    bool_query = (
        client.last_search_body["query"]["bool"]
    )

    assert bool_query["filter"] == []
    assert "must" not in bool_query


@pytest.mark.anyio
async def test_opensearch_search_rejects_invalid_offset() -> None:
    repository = OpenSearchEventRepository(
        FakeOpenSearch(),
    )

    with pytest.raises(
        ValueError,
        match="greater than or equal to 0",
    ):
        await repository.search(
            offset=-1,
        )


@pytest.mark.anyio
async def test_opensearch_search_rejects_invalid_limit() -> None:
    repository = OpenSearchEventRepository(
        FakeOpenSearch(),
    )

    with pytest.raises(
        ValueError,
        match="between 1 and 1000",
    ):
        await repository.search(
            limit=0,
        )

    with pytest.raises(
        ValueError,
        match="between 1 and 1000",
    ):
        await repository.search(
            limit=1001,
        )


@pytest.mark.anyio
async def test_redis_repository_round_trip() -> None:
    repository = RedisKeyValueRepository(
        FakeRedis(),
    )

    await repository.set(
        "phase06:test",
        b"value",
        ttl=60,
    )

    assert await repository.get(
        "phase06:test",
    ) == b"value"

    await repository.delete(
        "phase06:test",
    )

    assert await repository.get(
        "phase06:test",
    ) is None


@pytest.mark.anyio
async def test_redis_repository_rejects_invalid_ttl() -> None:
    repository = RedisKeyValueRepository(
        FakeRedis(),
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
