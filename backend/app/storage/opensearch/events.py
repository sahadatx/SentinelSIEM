from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.metrics import REGISTRY, Timer
from app.domain.events.models import CanonicalSecurityEvent, EnrichedEvent
from app.storage.repositories.events import EventSearchResult

_OPENSEARCH_LATENCY_HELP = (
    "OpenSearch repository operation latency in seconds."
)

_OPENSEARCH_FAILURES_HELP = (
    "Total OpenSearch repository operation failures."
)

_EVENT_INDEX_SHARDS = 1
_EVENT_INDEX_REPLICAS = 0


class OpenSearchEventRepository:
    """OpenSearch repository for high-volume security events."""

    def __init__(
        self,
        client: Any,
        *,
        index: str = "siem-events-v1",
    ) -> None:
        if not index.strip():
            raise ValueError("index must not be empty")

        self.client = client
        self.index = index

    async def ensure_index(self) -> None:
        """Create or reconcile the security event index."""
        try:
            with Timer(
                REGISTRY,
                "siem_opensearch_operation_latency_seconds",
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={"operation": "ensure_index"},
            ):
                exists = await self.client.indices.exists(
                    index=self.index,
                )

                if not exists:
                    await self.client.indices.create(
                        index=self.index,
                        body=self._index_definition(),
                    )
                    return

                await self._ensure_required_fields()
                await self._ensure_index_settings()

        except Exception:
            REGISTRY.inc_counter(
                "siem_opensearch_operation_failures_total",
                help_text=_OPENSEARCH_FAILURES_HELP,
                labels={"operation": "ensure_index"},
            )
            raise

    async def _ensure_required_fields(self) -> None:
        """Reconcile required event mappings on an existing index."""
        mapping = await self.client.indices.get_mapping(
            index=self.index,
        )

        index_mapping = mapping.get(self.index, {})
        mappings = index_mapping.get("mappings", {})
        properties = mappings.get("properties", {})

        required_properties: dict[str, Any] = {}

        if "parsed_data" not in properties:
            required_properties["parsed_data"] = {
                "type": "object",
                "enabled": True,
            }

        if "normalized_data" not in properties:
            required_properties["normalized_data"] = {
                "type": "object",
                "enabled": True,
            }

        if "enrichment" not in properties:
            required_properties["enrichment"] = {
                "type": "object",
                "enabled": True,
            }

        metadata_mapping = properties.get("metadata")

        if not isinstance(metadata_mapping, dict):
            required_properties["metadata"] = {
                "type": "object",
                "dynamic": False,
                "enabled": True,
            }
        else:
            metadata_dynamic = metadata_mapping.get("dynamic")

            if metadata_dynamic is not False:
                required_properties["metadata"] = {
                    "type": "object",
                    "dynamic": False,
                    "enabled": True,
                }

        if not required_properties:
            return

        await self.client.indices.put_mapping(
            index=self.index,
            body={
                "properties": required_properties,
            },
        )

    async def _ensure_index_settings(self) -> None:
        """Reconcile shard settings for the current deployment topology."""
        await self.client.indices.put_settings(
            index=self.index,
            body={
                "index": {
                    "number_of_replicas": _EVENT_INDEX_REPLICAS,
                },
            },
        )

    @staticmethod
    def _index_definition() -> dict[str, Any]:
        """Return the canonical security-event index definition."""
        return {
            "settings": {
                "number_of_shards": _EVENT_INDEX_SHARDS,
                "number_of_replicas": _EVENT_INDEX_REPLICAS,
            },
            "mappings": {
                "dynamic": "strict",
                "properties": {
                    "event_id": {
                        "type": "keyword",
                    },
                    "timestamp": {
                        "type": "date",
                    },
                    "ingestion_timestamp": {
                        "type": "date",
                    },
                    "source": {
                        "type": "keyword",
                    },
                    "source_type": {
                        "type": "keyword",
                    },
                    "hostname": {
                        "type": "keyword",
                    },
                    "source_ip": {
                        "type": "ip",
                    },
                    "destination_ip": {
                        "type": "ip",
                    },
                    "source_port": {
                        "type": "integer",
                    },
                    "destination_port": {
                        "type": "integer",
                    },
                    "protocol": {
                        "type": "keyword",
                    },
                    "username": {
                        "type": "keyword",
                    },
                    "process": {
                        "type": "keyword",
                    },
                    "command": {
                        "type": "text",
                    },
                    "action": {
                        "type": "keyword",
                    },
                    "outcome": {
                        "type": "keyword",
                    },
                    "severity": {
                        "type": "keyword",
                    },
                    "category": {
                        "type": "keyword",
                    },
                    "raw_event": {
                        "type": "text",
                    },
                    "parsed_data": {
                        "type": "object",
                        "enabled": True,
                    },
                    "normalized_data": {
                        "type": "object",
                        "enabled": True,
                    },
                    "enrichment": {
                        "type": "object",
                        "enabled": True,
                    },
                    "metadata": {
                        "type": "object",
                        "dynamic": False,
                        "enabled": True,
                    },
                    "stage": {
                        "type": "keyword",
                    },
                },
            },
        }

    async def save(
        self,
        event: CanonicalSecurityEvent | EnrichedEvent,
    ) -> None:
        """Persist a canonical or enriched event."""
        try:
            with Timer(
                REGISTRY,
                "siem_opensearch_operation_latency_seconds",
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={"operation": "index"},
            ):
                await self.client.index(
                    index=self.index,
                    id=str(event.event_id),
                    body=event.model_dump(mode="json"),
                    refresh=False,
                )

        except Exception:
            REGISTRY.inc_counter(
                "siem_opensearch_operation_failures_total",
                help_text=_OPENSEARCH_FAILURES_HELP,
                labels={"operation": "index"},
            )
            raise

    async def get(
        self,
        event_id: UUID,
    ) -> CanonicalSecurityEvent | EnrichedEvent | None:
        """Retrieve an event by its unique event ID."""
        try:
            with Timer(
                REGISTRY,
                "siem_opensearch_operation_latency_seconds",
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={"operation": "get"},
            ):
                response = await self.client.get(
                    index=self.index,
                    id=str(event_id),
                )

        except Exception as exc:
            if getattr(exc, "status_code", None) == 404:
                return None

            REGISTRY.inc_counter(
                "siem_opensearch_operation_failures_total",
                help_text=_OPENSEARCH_FAILURES_HELP,
                labels={"operation": "get"},
            )
            raise

        return self._from_document(response["_source"])

    async def search(
        self,
        *,
        query: str | None = None,
        source: str | None = None,
        source_ip: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
    ) -> EventSearchResult:
        """Search stored security events with optional filters."""
        if not 1 <= limit <= 1000:
            raise ValueError(
                "limit must be between 1 and 1000"
            )

        try:
            with Timer(
                REGISTRY,
                "siem_opensearch_operation_latency_seconds",
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={"operation": "search"},
            ):
                filters: list[dict[str, Any]] = []

                for field, value in (
                    ("source", source),
                    ("source_ip", source_ip),
                    ("severity", severity),
                    ("category", category),
                ):
                    if value is not None:
                        filters.append(
                            {
                                "term": {
                                    field: value,
                                },
                            }
                        )

                if start_time is not None or end_time is not None:
                    range_query: dict[str, str] = {}

                    if start_time is not None:
                        range_query["gte"] = (
                            start_time.isoformat()
                        )

                    if end_time is not None:
                        range_query["lte"] = (
                            end_time.isoformat()
                        )

                    filters.append(
                        {
                            "range": {
                                "timestamp": range_query,
                            },
                        }
                    )

                bool_query: dict[str, Any] = {
                    "filter": filters,
                }

                if query:
                    bool_query["must"] = [
                        {
                            "multi_match": {
                                "query": query,
                                "fields": [
                                    "raw_event",
                                    "command",
                                    "username",
                                ],
                            },
                        }
                    ]

                response = await self.client.search(
                    index=self.index,
                    body={
                        "query": {
                            "bool": bool_query,
                        },
                        "sort": [
                            {
                                "timestamp": "desc",
                            }
                        ],
                    },
                    size=limit,
                )

                hits = response["hits"]

                events = tuple(
                    self._from_document(
                        hit["_source"]
                    )
                    for hit in hits["hits"]
                )

                return EventSearchResult(
                    events=events,
                    total=int(
                        hits["total"]["value"]
                    ),
                )

        except Exception:
            REGISTRY.inc_counter(
                "siem_opensearch_operation_failures_total",
                help_text=_OPENSEARCH_FAILURES_HELP,
                labels={"operation": "search"},
            )
            raise

    async def count(self) -> int:
        """Return the total number of indexed events."""
        try:
            with Timer(
                REGISTRY,
                "siem_opensearch_operation_latency_seconds",
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={"operation": "count"},
            ):
                response = await self.client.count(
                    index=self.index,
                )

        except Exception:
            REGISTRY.inc_counter(
                "siem_opensearch_operation_failures_total",
                help_text=_OPENSEARCH_FAILURES_HELP,
                labels={"operation": "count"},
            )
            raise

        return int(response["count"])

    @staticmethod
    def _from_document(
        document: dict[str, Any],
    ) -> CanonicalSecurityEvent | EnrichedEvent:
        """Convert an OpenSearch document into the appropriate event model."""
        if document.get("stage") == "enriched":
            return EnrichedEvent.model_validate(
                document
            )

        return CanonicalSecurityEvent.model_validate(
            document
        )