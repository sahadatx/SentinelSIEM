from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from app.domain.events.models import CanonicalSecurityEvent, EnrichedEvent
from app.storage.repositories.events import EventSearchResult


class OpenSearchEventRepository:
    """OpenSearch repository for high-volume security-event search."""

    def __init__(
        self,
        client: Any,
        *,
        index: str = "siem-events-v1",
    ) -> None:
        self.client = client
        self.index = index

    async def ensure_index(self) -> None:
        """Create the event index when it does not already exist."""
        exists = await self.client.indices.exists(index=self.index)

        if exists:
            return

        await self.client.indices.create(
            index=self.index,
            body={
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 1,
                },
                "mappings": {
                    "dynamic": "strict",
                    "properties": {
                        "event_id": {"type": "keyword"},
                        "timestamp": {"type": "date"},
                        "ingestion_timestamp": {"type": "date"},
                        "source": {"type": "keyword"},
                        "source_type": {"type": "keyword"},
                        "hostname": {"type": "keyword"},
                        "source_ip": {"type": "ip"},
                        "destination_ip": {"type": "ip"},
                        "source_port": {"type": "integer"},
                        "destination_port": {"type": "integer"},
                        "protocol": {"type": "keyword"},
                        "username": {"type": "keyword"},
                        "process": {"type": "keyword"},
                        "command": {"type": "text"},
                        "action": {"type": "keyword"},
                        "outcome": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "category": {"type": "keyword"},
                        "raw_event": {"type": "text"},
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
                            "enabled": True,
                        },
                        "stage": {"type": "keyword"},
                    },
                },
            },
        )

    async def save(
        self,
        event: CanonicalSecurityEvent | EnrichedEvent,
    ) -> None:
        """Persist a canonical or enriched event."""
        await self.client.index(
            index=self.index,
            id=str(event.event_id),
            body=event.model_dump(mode="json"),
            refresh=False,
        )

    async def get(
        self,
        event_id: UUID,
    ) -> CanonicalSecurityEvent | EnrichedEvent | None:
        """Retrieve an event by its unique event ID."""
        try:
            response = await self.client.get(
                index=self.index,
                id=str(event_id),
            )
        except Exception as exc:
            if getattr(exc, "status_code", None) == 404:
                return None
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
            raise ValueError("limit must be between 1 and 1000")

        filters: list[dict[str, Any]] = []

        for field, value in (
            ("source", source),
            ("source_ip", source_ip),
            ("severity", severity),
            ("category", category),
        ):
            if value is not None:
                filters.append({"term": {field: value}})

        if start_time is not None or end_time is not None:
            range_query: dict[str, str] = {}

            if start_time is not None:
                range_query["gte"] = start_time.isoformat()

            if end_time is not None:
                range_query["lte"] = end_time.isoformat()

            filters.append(
                {
                    "range": {
                        "timestamp": range_query,
                    }
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
                    }
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
            self._from_document(hit["_source"])
            for hit in hits["hits"]
        )

        return EventSearchResult(
            events=events,
            total=int(hits["total"]["value"]),
        )

    async def count(self) -> int:
        """Return the total number of indexed events."""
        response = await self.client.count(index=self.index)
        return int(response["count"])

    @staticmethod
    def _from_document(
        document: dict[str, Any],
    ) -> CanonicalSecurityEvent | EnrichedEvent:
        """Convert an OpenSearch document into the appropriate event model."""
        if document.get("stage") == "enriched":
            return EnrichedEvent.model_validate(document)

        return CanonicalSecurityEvent.model_validate(document)
