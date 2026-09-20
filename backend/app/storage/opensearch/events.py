from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.metrics import REGISTRY, Timer
from app.domain.events.models import (
    CanonicalSecurityEvent,
    EnrichedEvent,
)
from app.storage.repositories.events import (
    EventFilterOptionsResult,
    EventSearchResult,
    EventStatisticsResult,
)


_OPENSEARCH_LATENCY_HELP = (
    "OpenSearch repository operation latency in seconds."
)

_OPENSEARCH_FAILURES_HELP = (
    "Total OpenSearch repository operation failures."
)

_EVENT_INDEX_SHARDS = 1
_EVENT_INDEX_REPLICAS = 0

# Maximum number of unique values returned for a single dropdown.
_FILTER_OPTION_SIZE = 10000

# Maximum number of severity buckets expected by the Events KPI.
_STATISTICS_SEVERITY_BUCKET_SIZE = 16


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
        """
        Reconcile required event mappings on an existing index.

        The top-level event mapping remains strict. Nested parser,
        normalizer, enrichment, and metadata containers remain
        non-dynamic so arbitrary intermediate fields can remain
        available in _source without creating OpenSearch mappings.
        """
        mapping = await self.client.indices.get_mapping(
            index=self.index,
        )

        index_mapping = mapping.get(self.index, {})

        if not isinstance(index_mapping, dict):
            index_mapping = {}

        mappings = index_mapping.get("mappings", {})

        if not isinstance(mappings, dict):
            mappings = {}

        properties = mappings.get("properties", {})

        if not isinstance(properties, dict):
            properties = {}

        required_properties: dict[str, Any] = {}

        nested_object_fields = (
            "parsed_data",
            "normalized_data",
            "enrichment",
        )

        for field_name in nested_object_fields:
            current_mapping = properties.get(field_name)

            if not isinstance(current_mapping, dict):
                required_properties[field_name] = {
                    "type": "object",
                    "dynamic": False,
                    "enabled": True,
                }
                continue

            if current_mapping.get("dynamic") is not False:
                required_properties[field_name] = {
                    "type": "object",
                    "dynamic": False,
                }

        metadata_mapping = properties.get("metadata")

        if not isinstance(metadata_mapping, dict):
            required_properties["metadata"] = {
                "type": "object",
                "dynamic": False,
                "enabled": True,
            }
        elif metadata_mapping.get("dynamic") is not False:
            required_properties["metadata"] = {
                "type": "object",
                "dynamic": False,
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
                        "dynamic": False,
                        "enabled": True,
                    },
                    "normalized_data": {
                        "type": "object",
                        "dynamic": False,
                        "enabled": True,
                    },
                    "enrichment": {
                        "type": "object",
                        "dynamic": False,
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

    @staticmethod
    def _build_filters(
        *,
        query: str | None = None,
        source: str | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        username: str | None = None,
        action: str | None = None,
        outcome: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> dict[str, Any]:
        """
        Build the shared OpenSearch boolean query used by event
        search and event statistics.

        Keeping filter construction centralized ensures that the
        Events table and KPI statistics always operate on the same
        filtered dataset.
        """
        filters: list[dict[str, Any]] = []

        exact_filters = (
            ("source", source),
            ("source_ip", source_ip),
            ("destination_ip", destination_ip),
            ("username", username),
            ("action", action),
            ("outcome", outcome),
            ("severity", severity),
            ("category", category),
        )

        for field, value in exact_filters:
            if value is None:
                continue

            filters.append(
                {
                    "term": {
                        field: value,
                    },
                }
            )

        if start_time is not None or end_time is not None:
            timestamp_range: dict[str, str] = {}

            if start_time is not None:
                timestamp_range["gte"] = (
                    start_time.isoformat()
                )

            if end_time is not None:
                timestamp_range["lte"] = (
                    end_time.isoformat()
                )

            filters.append(
                {
                    "range": {
                        "timestamp": timestamp_range,
                    },
                }
            )

        bool_query: dict[str, Any] = {
            "filter": filters,
        }

        if query is not None and query.strip():
            bool_query["must"] = [
                {
                    "multi_match": {
                        "query": query.strip(),
                        "fields": [
                            "username",
                            "action",
                            "command",
                            "process",
                            "raw_event",
                        ],
                    }
                }
            ]

        return {
            "bool": bool_query,
        }

    async def save(
        self,
        event: CanonicalSecurityEvent | EnrichedEvent,
    ) -> None:
        """Persist a canonical or enriched security event."""
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
        destination_ip: str | None = None,
        username: str | None = None,
        action: str | None = None,
        outcome: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> EventSearchResult:
        """
        Search stored security events with optional filters
        and pagination.

        Args:
            query:
                Free-text search across username, action, command,
                process, and raw_event.

            source:
                Exact event source filter.

            source_ip:
                Exact source IP filter.

            destination_ip:
                Exact destination IP filter.

            username:
                Exact event username filter.

            action:
                Exact event action filter.

            outcome:
                Exact event outcome filter.

            severity:
                Exact event severity filter.

            category:
                Exact event category filter.

            start_time:
                Inclusive lower timestamp boundary.

            end_time:
                Inclusive upper timestamp boundary.

            offset:
                Number of matching events to skip.

            limit:
                Maximum number of events to return.
        """
        if offset < 0:
            raise ValueError(
                "offset must be greater than or equal to 0",
            )

        if not 1 <= limit <= 1000:
            raise ValueError(
                "limit must be between 1 and 1000",
            )

        try:
            with Timer(
                REGISTRY,
                "siem_opensearch_operation_latency_seconds",
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={"operation": "search"},
            ):
                response = await self.client.search(
                    index=self.index,
                    body={
                        "from": offset,
                        "query": self._build_filters(
                            query=query,
                            source=source,
                            source_ip=source_ip,
                            destination_ip=destination_ip,
                            username=username,
                            action=action,
                            outcome=outcome,
                            severity=severity,
                            category=category,
                            start_time=start_time,
                            end_time=end_time,
                        ),
                        "sort": [
                            {
                                "timestamp": "desc",
                            },
                        ],
                    },
                    size=limit,
                )

                hits = response["hits"]

                events = tuple(
                    self._from_document(hit["_source"])
                    for hit in hits["hits"]
                )

                total = hits["total"]

                if isinstance(total, dict):
                    total_value = total.get("value", 0)
                else:
                    total_value = total

                return EventSearchResult(
                    events=events,
                    total=int(total_value),
                )

        except Exception:
            REGISTRY.inc_counter(
                "siem_opensearch_operation_failures_total",
                help_text=_OPENSEARCH_FAILURES_HELP,
                labels={"operation": "search"},
            )
            raise

    async def get_statistics(
        self,
        *,
        query: str | None = None,
        source: str | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        username: str | None = None,
        action: str | None = None,
        outcome: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> EventStatisticsResult:
        """
        Return aggregate event statistics for the complete filtered
        dataset.

        Pagination is intentionally not used here. The returned
        severity counts therefore represent all matching events,
        rather than only the events visible on the current page.
        """
        try:
            with Timer(
                REGISTRY,
                "siem_opensearch_operation_latency_seconds",
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={"operation": "statistics"},
            ):
                response = await self.client.search(
                    index=self.index,
                    body={
                        "size": 0,
                        "track_total_hits": True,
                        "query": self._build_filters(
                            query=query,
                            source=source,
                            source_ip=source_ip,
                            destination_ip=destination_ip,
                            username=username,
                            action=action,
                            outcome=outcome,
                            severity=severity,
                            category=category,
                            start_time=start_time,
                            end_time=end_time,
                        ),
                        "aggs": {
                            "severity_counts": {
                                "terms": {
                                    "field": "severity",
                                    "size": _STATISTICS_SEVERITY_BUCKET_SIZE,
                                    "order": {
                                        "_key": "asc",
                                    },
                                },
                            },
                        },
                    },
                )

                hits = response.get("hits", {})

                total = hits.get("total", 0)

                if isinstance(total, dict):
                    total_value = total.get("value", 0)
                else:
                    total_value = total

                statistics = {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                }

                aggregations = response.get(
                    "aggregations",
                    {},
                )

                if isinstance(aggregations, dict):
                    severity_aggregation = aggregations.get(
                        "severity_counts",
                        {},
                    )

                    if isinstance(
                        severity_aggregation,
                        dict,
                    ):
                        buckets = severity_aggregation.get(
                            "buckets",
                            [],
                        )

                        if isinstance(buckets, list):
                            for bucket in buckets:
                                if not isinstance(bucket, dict):
                                    continue

                                key = bucket.get("key")
                                count = bucket.get("doc_count", 0)

                                if key is None:
                                    continue

                                severity_name = str(key).strip().casefold()

                                if severity_name not in statistics:
                                    continue

                                try:
                                    statistics[severity_name] = int(
                                        count,
                                    )
                                except (TypeError, ValueError):
                                    statistics[severity_name] = 0

                return EventStatisticsResult(
                    total=int(total_value),
                    critical=statistics["critical"],
                    high=statistics["high"],
                    medium=statistics["medium"],
                    low=statistics["low"],
                    info=statistics["info"],
                )

        except Exception:
            REGISTRY.inc_counter(
                "siem_opensearch_operation_failures_total",
                help_text=_OPENSEARCH_FAILURES_HELP,
                labels={"operation": "statistics"},
            )
            raise

    async def get_filter_options(self) -> EventFilterOptionsResult:
        """
        Return unique filter values derived from persisted events.

        OpenSearch terms aggregations are used against keyword fields
        so the frontend can populate its dropdowns dynamically.

        Empty and null values are excluded. Values are returned in
        deterministic case-insensitive alphabetical order.
        """
        try:
            with Timer(
                REGISTRY,
                "siem_opensearch_operation_latency_seconds",
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={"operation": "filter_options"},
            ):
                response = await self.client.search(
                    index=self.index,
                    body={
                        "size": 0,
                        "aggs": {
                            "sources": {
                                "terms": {
                                    "field": "source",
                                    "size": _FILTER_OPTION_SIZE,
                                    "order": {
                                        "_key": "asc",
                                    },
                                },
                            },
                            "users": {
                                "terms": {
                                    "field": "username",
                                    "size": _FILTER_OPTION_SIZE,
                                    "order": {
                                        "_key": "asc",
                                    },
                                },
                            },
                            "actions": {
                                "terms": {
                                    "field": "action",
                                    "size": _FILTER_OPTION_SIZE,
                                    "order": {
                                        "_key": "asc",
                                    },
                                },
                            },
                            "outcomes": {
                                "terms": {
                                    "field": "outcome",
                                    "size": _FILTER_OPTION_SIZE,
                                    "order": {
                                        "_key": "asc",
                                    },
                                },
                            },
                            "severities": {
                                "terms": {
                                    "field": "severity",
                                    "size": _FILTER_OPTION_SIZE,
                                    "order": {
                                        "_key": "asc",
                                    },
                                },
                            },
                            "categories": {
                                "terms": {
                                    "field": "category",
                                    "size": _FILTER_OPTION_SIZE,
                                    "order": {
                                        "_key": "asc",
                                    },
                                },
                            },
                        },
                    },
                )

                aggregations = response.get(
                    "aggregations",
                    {},
                )

                if not isinstance(aggregations, dict):
                    aggregations = {}

                def values_for(
                    aggregation_name: str,
                ) -> tuple[str, ...]:
                    aggregation = aggregations.get(
                        aggregation_name,
                        {},
                    )

                    if not isinstance(aggregation, dict):
                        return ()

                    buckets = aggregation.get(
                        "buckets",
                        [],
                    )

                    if not isinstance(buckets, list):
                        return ()

                    values: set[str] = set()

                    for bucket in buckets:
                        if not isinstance(bucket, dict):
                            continue

                        value = bucket.get("key")

                        if value is None:
                            continue

                        value_string = str(value).strip()

                        if not value_string:
                            continue

                        values.add(value_string)

                    return tuple(
                        sorted(
                            values,
                            key=str.casefold,
                        )
                    )

                return EventFilterOptionsResult(
                    sources=values_for("sources"),
                    users=values_for("users"),
                    actions=values_for("actions"),
                    outcomes=values_for("outcomes"),
                    severities=values_for("severities"),
                    categories=values_for("categories"),
                )

        except Exception:
            REGISTRY.inc_counter(
                "siem_opensearch_operation_failures_total",
                help_text=_OPENSEARCH_FAILURES_HELP,
                labels={"operation": "filter_options"},
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
            return EnrichedEvent.model_validate(document)

        return CanonicalSecurityEvent.model_validate(document)