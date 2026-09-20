from __future__ import annotations

"""
SentinelSIEM — OpenSearch Incident Repository.

Canonical persistence boundary for the Incident domain.

Canonical Incident lifecycle
----------------------------

    open
    investigating
    contained
    resolved
    closed

Canonical Incident severity
---------------------------

    critical
    high
    medium
    low
    informational

Canonical assignment
--------------------

    assigned_to -> User UUID | None

Removed fields
--------------

    priority
    ownership_group

Primary index
-------------

    siem-incidents-v1

Child indexes
-------------

    siem-incidents-v1-audit
    siem-incidents-v1-notes
    siem-incidents-v1-evidence
    siem-incidents-v1-timeline

Repository responsibilities
---------------------------

    - OpenSearch index management
    - Incident persistence
    - Incident retrieval
    - Incident search
    - Incident statistics
    - Incident filter options
    - Alert relationship lookup
    - Investigation note persistence
    - Evidence persistence
    - Timeline persistence
    - Audit persistence
    - Legacy document compatibility

Repository does NOT own
----------------------

    - authorization
    - RBAC
    - User Management validation
    - Incident lifecycle decisions
    - Incident business rules
    - Alert mutation
    - Incident deletion

Historical child records are append-only.
There is intentionally no Incident delete operation.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.metrics import REGISTRY, Timer
from app.incidents.models import (
    EvidenceRecord,
    Incident,
    IncidentAuditEntry,
    InvestigationNote,
    TimelineEntry,
)
from app.storage.opensearch.client import AsyncOpenSearch
from app.storage.repositories.incidents import (
    IncidentRepository,
    IncidentSearchResult,
)


# =============================================================================
# Constants
# =============================================================================

_INCIDENT_INDEX_DEFAULT = "siem-incidents-v1"

_INCIDENT_AUDIT_INDEX_SUFFIX = "-audit"
_INCIDENT_NOTES_INDEX_SUFFIX = "-notes"
_INCIDENT_EVIDENCE_INDEX_SUFFIX = "-evidence"
_INCIDENT_TIMELINE_INDEX_SUFFIX = "-timeline"

_INCIDENT_AUDIT_SIZE = 1000
_INCIDENT_NOTES_SIZE = 1000
_INCIDENT_EVIDENCE_SIZE = 1000
_INCIDENT_TIMELINE_SIZE = 2000

_FILTER_OPTION_SIZE = 1000
_STATS_BUCKET_SIZE = 100

_OPENSEARCH_LATENCY_METRIC = (
    "siem_opensearch_operation_latency_seconds"
)

_OPENSEARCH_FAILURE_METRIC = (
    "siem_opensearch_operation_failures_total"
)

_OPENSEARCH_LATENCY_HELP = (
    "OpenSearch repository operation latency in seconds."
)

_OPENSEARCH_FAILURES_HELP = (
    "Total OpenSearch operation failures."
)


# =============================================================================
# Repository
# =============================================================================


class OpenSearchIncidentRepository(IncidentRepository):
    """
    OpenSearch-backed persistence repository for SentinelSIEM Incidents.

    The AsyncOpenSearch client is owned by the dependency layer.

    This repository never closes the client.
    """

    # =========================================================================
    # Initialization
    # =========================================================================

    def __init__(
        self,
        client: AsyncOpenSearch,
        *,
        index: str = _INCIDENT_INDEX_DEFAULT,
    ) -> None:
        if not index or not index.strip():
            raise ValueError(
                "Incident OpenSearch index must not be empty."
            )

        self.client = client
        self.index = index.strip()

        self.audit_index = (
            f"{self.index}{_INCIDENT_AUDIT_INDEX_SUFFIX}"
        )

        self.notes_index = (
            f"{self.index}{_INCIDENT_NOTES_INDEX_SUFFIX}"
        )

        self.evidence_index = (
            f"{self.index}{_INCIDENT_EVIDENCE_INDEX_SUFFIX}"
        )

        self.timeline_index = (
            f"{self.index}{_INCIDENT_TIMELINE_INDEX_SUFFIX}"
        )

    # =========================================================================
    # Index Management
    # =========================================================================

    async def ensure_index(self) -> None:
        """
        Ensure all Incident indexes exist.

        Existing primary indexes also receive the canonical mapping update.
        """
        await self._ensure_incident_index()
        await self._ensure_audit_index()
        await self._ensure_notes_index()
        await self._ensure_evidence_index()
        await self._ensure_timeline_index()

    async def _ensure_incident_index(self) -> None:
        exists = await self.client.indices.exists(
            index=self.index,
        )

        if not exists:
            await self._ensure_index(
                index=self.index,
                mapping=self._incident_mapping(),
                operation="create_incident_index",
            )
            return

        try:
            await self.client.indices.put_mapping(
                index=self.index,
                body={
                    "properties": self._incident_properties(),
                },
            )
        except Exception:
            self._record_failure(
                "update_incident_mapping",
            )
            raise

    async def _ensure_audit_index(self) -> None:
        await self._ensure_index(
            index=self.audit_index,
            mapping=self._audit_mapping(),
            operation="create_incident_audit_index",
        )

    async def _ensure_notes_index(self) -> None:
        await self._ensure_index(
            index=self.notes_index,
            mapping=self._notes_mapping(),
            operation="create_incident_notes_index",
        )

    async def _ensure_evidence_index(self) -> None:
        await self._ensure_index(
            index=self.evidence_index,
            mapping=self._evidence_mapping(),
            operation="create_incident_evidence_index",
        )

    async def _ensure_timeline_index(self) -> None:
        await self._ensure_index(
            index=self.timeline_index,
            mapping=self._timeline_mapping(),
            operation="create_incident_timeline_index",
        )

    async def _ensure_index(
        self,
        *,
        index: str,
        mapping: dict[str, Any],
        operation: str,
    ) -> None:
        exists = await self.client.indices.exists(
            index=index,
        )

        if exists:
            return

        try:
            await self.client.indices.create(
                index=index,
                body=mapping,
            )
        except Exception as exc:
            status_code = getattr(
                exc,
                "status_code",
                None,
            )

            if status_code == 400:
                exists_after_failure = (
                    await self.client.indices.exists(
                        index=index,
                    )
                )

                if exists_after_failure:
                    return

            self._record_failure(
                operation,
            )
            raise

    @staticmethod
    def _base_index_settings() -> dict[str, Any]:
        return {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
            }
        }

    @classmethod
    def _incident_properties(cls) -> dict[str, Any]:
        """
        Canonical Incident document mapping.

        Obsolete fields are intentionally absent.
        """

        return {
            "incident_id": {
                "type": "keyword",
            },
            "incident_number": {
                "type": "keyword",
            },
            "title": {
                "type": "text",
                "fields": {
                    "keyword": {
                        "type": "keyword",
                        "ignore_above": 512,
                    },
                },
            },
            "description": {
                "type": "text",
            },
            "severity": {
                "type": "keyword",
            },
            "status": {
                "type": "keyword",
            },
            "tags": {
                "type": "keyword",
            },
            "alert_ids": {
                "type": "keyword",
            },
            "evidence_ids": {
                "type": "keyword",
            },
            "related_event_ids": {
                "type": "keyword",
            },
            "related_ioc_ids": {
                "type": "keyword",
            },
            "asset_ids": {
                "type": "keyword",
            },
            "assigned_to": {
                "type": "keyword",
            },
            "created_by": {
                "type": "keyword",
            },
            "created_at": {
                "type": "date",
            },
            "updated_at": {
                "type": "date",
            },
            "resolved_at": {
                "type": "date",
            },
            "closed_at": {
                "type": "date",
            },
        }

    @classmethod
    def _incident_mapping(cls) -> dict[str, Any]:
        return {
            **cls._base_index_settings(),
            "mappings": {
                "dynamic": "strict",
                "properties": cls._incident_properties(),
            },
        }

    @classmethod
    def _audit_mapping(cls) -> dict[str, Any]:
        return {
            **cls._base_index_settings(),
            "mappings": {
                "dynamic": "strict",
                "properties": {
                    "audit_id": {
                        "type": "keyword",
                    },
                    "incident_id": {
                        "type": "keyword",
                    },
                    "action": {
                        "type": "keyword",
                    },
                    "actor": {
                        "type": "keyword",
                    },
                    "field_name": {
                        "type": "keyword",
                    },
                    "from_value": {
                        "type": "keyword",
                    },
                    "to_value": {
                        "type": "keyword",
                    },
                    "from_status": {
                        "type": "keyword",
                    },
                    "to_status": {
                        "type": "keyword",
                    },
                    "from_severity": {
                        "type": "keyword",
                    },
                    "to_severity": {
                        "type": "keyword",
                    },
                    "from_assignee": {
                        "type": "keyword",
                    },
                    "to_assignee": {
                        "type": "keyword",
                    },
                    "reason": {
                        "type": "text",
                    },
                    "created_at": {
                        "type": "date",
                    },
                },
            },
        }

    @classmethod
    def _notes_mapping(cls) -> dict[str, Any]:
        return {
            **cls._base_index_settings(),
            "mappings": {
                "dynamic": "strict",
                "properties": {
                    "note_id": {
                        "type": "keyword",
                    },
                    "incident_id": {
                        "type": "keyword",
                    },
                    "author": {
                        "type": "keyword",
                    },
                    "content": {
                        "type": "text",
                    },
                    "created_at": {
                        "type": "date",
                    },
                },
            },
        }

    @classmethod
    def _evidence_mapping(cls) -> dict[str, Any]:
        return {
            **cls._base_index_settings(),
            "mappings": {
                "dynamic": "strict",
                "properties": {
                    "evidence_id": {
                        "type": "keyword",
                    },
                    "incident_id": {
                        "type": "keyword",
                    },
                    "evidence_type": {
                        "type": "keyword",
                    },
                    "reference": {
                        "type": "text",
                        "fields": {
                            "keyword": {
                                "type": "keyword",
                                "ignore_above": 1024,
                            },
                        },
                    },
                    "collected_by": {
                        "type": "keyword",
                    },
                    "created_at": {
                        "type": "date",
                    },
                },
            },
        }

    @classmethod
    def _timeline_mapping(cls) -> dict[str, Any]:
        return {
            **cls._base_index_settings(),
            "mappings": {
                "dynamic": "strict",
                "properties": {
                    "entry_id": {
                        "type": "keyword",
                    },
                    "incident_id": {
                        "type": "keyword",
                    },
                    "event_type": {
                        "type": "keyword",
                    },
                    "description": {
                        "type": "text",
                    },
                    "actor": {
                        "type": "keyword",
                    },
                    "occurred_at": {
                        "type": "date",
                    },
                },
            },
        }

    # =========================================================================
    # Incident Persistence
    # =========================================================================

    async def save(
        self,
        incident: Incident,
    ) -> None:
        """Create or replace an Incident document."""

        if not isinstance(
            incident,
            Incident,
        ):
            raise TypeError(
                "incident must be an Incident instance."
            )

        try:
            with Timer(
                REGISTRY,
                _OPENSEARCH_LATENCY_METRIC,
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={
                    "operation": "index_incident",
                },
            ):
                await self.client.index(
                    index=self.index,
                    id=str(incident.incident_id),
                    body=incident.model_dump(
                        mode="json",
                    ),
                    refresh=False,
                )
        except Exception:
            self._record_failure(
                "index_incident",
            )
            raise

    async def get(
        self,
        incident_id: UUID,
    ) -> Incident | None:
        """Retrieve an Incident by UUID."""

        self._validate_uuid(
            incident_id,
            "incident_id",
        )

        try:
            with Timer(
                REGISTRY,
                _OPENSEARCH_LATENCY_METRIC,
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={
                    "operation": "get_incident",
                },
            ):
                response = await self.client.get(
                    index=self.index,
                    id=str(incident_id),
                )
        except Exception as exc:
            if self._is_not_found(exc):
                return None

            self._record_failure(
                "get_incident",
            )
            raise

        source = response.get(
            "_source",
        )

        if not isinstance(
            source,
            dict,
        ):
            raise ValueError(
                "OpenSearch incident document has no valid _source."
            )

        return self._from_document(
            source,
        )

    async def get_by_incident_number(
        self,
        incident_number: str,
    ) -> Incident | None:
        """Retrieve an Incident by human-readable incident number."""

        normalized = self._normalize_lookup_value(
            incident_number,
            "incident_number",
        )

        try:
            with Timer(
                REGISTRY,
                _OPENSEARCH_LATENCY_METRIC,
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={
                    "operation": "get_incident_by_number",
                },
            ):
                response = await self.client.search(
                    index=self.index,
                    body={
                        "size": 1,
                        "track_total_hits": False,
                        "query": {
                            "term": {
                                "incident_number": normalized,
                            },
                        },
                    },
                )

            source = self._first_source(
                response,
            )

            if source is None:
                return None

            return self._from_document(
                source,
            )

        except Exception:
            self._record_failure(
                "get_incident_by_number",
            )
            raise

    # =========================================================================
    # Alert Relationship
    # =========================================================================

    async def get_by_alert_id(
        self,
        alert_id: UUID,
    ) -> Incident | None:
        """
        Find an Incident associated with an Alert.

        Used by Alert -> Incident promotion duplicate protection.
        """

        self._validate_uuid(
            alert_id,
            "alert_id",
        )

        try:
            with Timer(
                REGISTRY,
                _OPENSEARCH_LATENCY_METRIC,
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={
                    "operation": "get_incident_by_alert",
                },
            ):
                response = await self.client.search(
                    index=self.index,
                    body={
                        "size": 1,
                        "track_total_hits": False,
                        "query": {
                            "term": {
                                "alert_ids": str(alert_id),
                            },
                        },
                        "sort": [
                            {
                                "updated_at": {
                                    "order": "desc",
                                },
                            },
                            {
                                "incident_id": {
                                    "order": "asc",
                                },
                            },
                        ],
                    },
                )

            source = self._first_source(
                response,
            )

            if source is None:
                return None

            return self._from_document(
                source,
            )

        except Exception:
            self._record_failure(
                "get_incident_by_alert",
            )
            raise

    async def get_related_alert_ids(
        self,
        incident_id: UUID,
    ) -> tuple[UUID, ...]:
        """
        Return Alert UUIDs associated with an Incident.

        Alert documents are owned by the Alert repository.
        """

        incident = await self.get(
            incident_id,
        )

        if incident is None:
            return ()

        result: list[UUID] = []

        for value in incident.alert_ids:
            try:
                parsed = (
                    value
                    if isinstance(
                        value,
                        UUID,
                    )
                    else UUID(
                        str(value),
                    )
                )
            except (
                TypeError,
                ValueError,
            ):
                continue

            if parsed not in result:
                result.append(
                    parsed,
                )

        return tuple(result)

    # =========================================================================
    # Search
    # =========================================================================

    async def search(
        self,
        *,
        query: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        assigned_to: UUID | str | None = None,
        alert_id: UUID | None = None,
        asset_id: str | None = None,
        related_event_id: str | None = None,
        related_ioc_id: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> IncidentSearchResult:
        """
        Search persisted Incidents.

        Canonical filters only.

        Removed:
            priority
            ownership_group
        """

        if offset < 0:
            raise ValueError(
                "offset must be greater than or equal to 0."
            )

        if not 1 <= limit <= 1000:
            raise ValueError(
                "limit must be between 1 and 1000."
            )

        if (
            start_time is not None
            and end_time is not None
            and start_time > end_time
        ):
            raise ValueError(
                "start_time must not be later than end_time."
            )

        filters: list[dict[str, Any]] = []

        normalized_status = self._normalize_optional_status(
            status,
        )

        if normalized_status is not None:
            filters.append(
                {
                    "term": {
                        "status": normalized_status,
                    },
                }
            )

        normalized_severity = (
            self._normalize_optional_severity(
                severity,
            )
        )

        if normalized_severity is not None:
            filters.append(
                {
                    "term": {
                        "severity": normalized_severity,
                    },
                }
            )

        normalized_assignee = (
            self._optional_lookup_value(
                assigned_to,
            )
        )

        if normalized_assignee is not None:
            filters.append(
                {
                    "term": {
                        "assigned_to": normalized_assignee,
                    },
                }
            )

        if alert_id is not None:
            self._validate_uuid(
                alert_id,
                "alert_id",
            )

            filters.append(
                {
                    "term": {
                        "alert_ids": str(alert_id),
                    },
                }
            )

        self._append_relationship_filter(
            filters,
            "asset_ids",
            asset_id,
        )

        self._append_relationship_filter(
            filters,
            "related_event_ids",
            related_event_id,
        )

        self._append_relationship_filter(
            filters,
            "related_ioc_ids",
            related_ioc_id,
        )

        if (
            start_time is not None
            or end_time is not None
        ):
            time_range: dict[str, str] = {}

            if start_time is not None:
                time_range["gte"] = start_time.isoformat()

            if end_time is not None:
                time_range["lte"] = end_time.isoformat()

            filters.append(
                {
                    "range": {
                        "last_updated_at": time_range,
                    },
                }
            )

        bool_query: dict[str, Any] = {
            "filter": filters,
        }

        normalized_query = (
            query.strip()
            if query is not None
            else ""
        )

        if normalized_query:
            bool_query["must"] = [
                {
                    "multi_match": {
                        "query": normalized_query,
                        "fields": [
                            "incident_number",
                            "incident_id",
                            "title",
                            "title.keyword",
                            "description",
                        ],
                        "type": "best_fields",
                    },
                }
            ]

        try:
            with Timer(
                REGISTRY,
                _OPENSEARCH_LATENCY_METRIC,
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={
                    "operation": "search_incidents",
                },
            ):
                response = await self.client.search(
                    index=self.index,
                    body={
                        "from": offset,
                        "size": limit,
                        "track_total_hits": True,
                        "query": {
                            "bool": bool_query,
                        },
                        "sort": [
                            {
                                "last_updated_at": {
                                    "order": "desc",
                                },
                            },
                            {
                                "incident_id": {
                                    "order": "asc",
                                },
                            },
                        ],
                    },
                )

            raw_hits = (
                response
                .get("hits", {})
                .get("hits", [])
            )

            incidents: list[Incident] = []

            for hit in raw_hits:
                if not isinstance(
                    hit,
                    dict,
                ):
                    continue

                source = hit.get(
                    "_source",
                )

                if not isinstance(
                    source,
                    dict,
                ):
                    continue

                incidents.append(
                    self._from_document(
                        source,
                    )
                )

            return IncidentSearchResult(
                incidents=tuple(incidents),
                total=self._total_hits(
                    response,
                ),
            )

        except Exception:
            self._record_failure(
                "search_incidents",
            )
            raise

    # =========================================================================
    # Count
    # =========================================================================

    async def count(
        self,
        *,
        status: str | None = None,
        severity: str | None = None,
    ) -> int:
        """Count persisted Incidents with optional filters."""

        filters: list[dict[str, Any]] = []

        normalized_status = self._normalize_optional_status(
            status,
        )

        if normalized_status is not None:
            filters.append(
                {
                    "term": {
                        "status": normalized_status,
                    },
                }
            )

        normalized_severity = (
            self._normalize_optional_severity(
                severity,
            )
        )

        if normalized_severity is not None:
            filters.append(
                {
                    "term": {
                        "severity": normalized_severity,
                    },
                }
            )

        if filters:
            query: dict[str, Any] = {
                "bool": {
                    "filter": filters,
                },
            }
        else:
            query = {
                "match_all": {},
            }

        try:
            with Timer(
                REGISTRY,
                _OPENSEARCH_LATENCY_METRIC,
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={
                    "operation": "count_incidents",
                },
            ):
                response = await self.client.count(
                    index=self.index,
                    body={
                        "query": query,
                    },
                )

            return int(
                response.get(
                    "count",
                    0,
                )
            )

        except Exception:
            self._record_failure(
                "count_incidents",
            )
            raise

    # =========================================================================
    # Statistics
    # =========================================================================

    async def statistics(
        self,
    ) -> dict[str, int]:
        """
        Return backend-authoritative Incident KPIs.

        Canonical response:

            total
            open
            investigating
            critical
            high
            resolved

        KPIs are obtained from OpenSearch aggregations.
        """

        try:
            with Timer(
                REGISTRY,
                _OPENSEARCH_LATENCY_METRIC,
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={
                    "operation": "incident_statistics",
                },
            ):
                response = await self.client.search(
                    index=self.index,
                    body={
                        "size": 0,
                        "track_total_hits": True,
                        "aggs": {
                            "status_counts": {
                                "terms": {
                                    "field": "status",
                                    "size": _STATS_BUCKET_SIZE,
                                    "order": {
                                        "_key": "asc",
                                    },
                                },
                            },
                            "severity_counts": {
                                "terms": {
                                    "field": "severity",
                                    "size": _STATS_BUCKET_SIZE,
                                    "order": {
                                        "_key": "asc",
                                    },
                                },
                            },
                        },
                    },
                )

            status_counts = self._aggregation_counts(
                response,
                "status_counts",
            )

            severity_counts = self._aggregation_counts(
                response,
                "severity_counts",
            )

            return {
                "total": self._total_hits(
                    response,
                ),
                "open": status_counts.get(
                    "open",
                    0,
                ),
                "investigating": status_counts.get(
                    "investigating",
                    0,
                ),
                "critical": severity_counts.get(
                    "critical",
                    0,
                ),
                "high": severity_counts.get(
                    "high",
                    0,
                ),
                "resolved": status_counts.get(
                    "resolved",
                    0,
                ),
            }

        except Exception:
            self._record_failure(
                "incident_statistics",
            )
            raise

    async def summary(
        self,
    ) -> dict[str, int]:
        """
        Backward-compatible alias.

        New API code should use statistics().
        """

        return await self.statistics()

    async def count_by_status(
        self,
    ) -> dict[str, int]:
        """Return Incident counts grouped by status."""

        return await self._count_terms(
            field="status",
            operation="incident_status_stats",
            aggregation_name="statuses",
        )

    async def count_by_severity(
        self,
    ) -> dict[str, int]:
        """Return Incident counts grouped by severity."""

        return await self._count_terms(
            field="severity",
            operation="incident_severity_stats",
            aggregation_name="severities",
        )

    async def _count_terms(
        self,
        *,
        field: str,
        operation: str,
        aggregation_name: str,
    ) -> dict[str, int]:
        try:
            with Timer(
                REGISTRY,
                _OPENSEARCH_LATENCY_METRIC,
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={
                    "operation": operation,
                },
            ):
                response = await self.client.search(
                    index=self.index,
                    body={
                        "size": 0,
                        "track_total_hits": False,
                        "aggs": {
                            aggregation_name: {
                                "terms": {
                                    "field": field,
                                    "size": _STATS_BUCKET_SIZE,
                                    "order": {
                                        "_key": "asc",
                                    },
                                },
                            },
                        },
                    },
                )

            return self._aggregation_counts(
                response,
                aggregation_name,
            )

        except Exception:
            self._record_failure(
                operation,
            )
            raise

    # =========================================================================
    # Filter Options
    # =========================================================================

    async def get_filter_options(
        self,
    ) -> dict[str, tuple[str, ...]]:
        """
        Return backend-authoritative Incident filter values.

        Canonical filters:

            statuses
            severities
            assignees
        """

        try:
            with Timer(
                REGISTRY,
                _OPENSEARCH_LATENCY_METRIC,
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={
                    "operation": "incident_filter_options",
                },
            ):
                response = await self.client.search(
                    index=self.index,
                    body={
                        "size": 0,
                        "track_total_hits": False,
                        "aggs": {
                            "statuses": {
                                "terms": {
                                    "field": "status",
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
                            "assignees": {
                                "terms": {
                                    "field": "assigned_to",
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

            if not isinstance(
                aggregations,
                dict,
            ):
                return self._empty_filter_options()

            return {
                "statuses": self._canonicalize_status_values(
                    self._aggregation_values(
                        aggregations,
                        "statuses",
                    ),
                ),
                "severities": self._canonicalize_severity_values(
                    self._aggregation_values(
                        aggregations,
                        "severities",
                    ),
                ),
                "assignees": self._aggregation_values(
                    aggregations,
                    "assignees",
                ),
            }

        except Exception:
            self._record_failure(
                "incident_filter_options",
            )
            raise

    # =========================================================================
    # Investigation Notes
    # =========================================================================

    async def save_note(
        self,
        note: InvestigationNote,
    ) -> None:
        """Persist one immutable investigation note."""

        if not isinstance(
            note,
            InvestigationNote,
        ):
            raise TypeError(
                "note must be an InvestigationNote instance."
            )

        try:
            with Timer(
                REGISTRY,
                _OPENSEARCH_LATENCY_METRIC,
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={
                    "operation": "index_incident_note",
                },
            ):
                await self.client.index(
                    index=self.notes_index,
                    id=str(note.note_id),
                    body=note.model_dump(
                        mode="json",
                    ),
                    refresh=False,
                )

        except Exception:
            self._record_failure(
                "index_incident_note",
            )
            raise

    async def get_notes(
        self,
        incident_id: UUID,
    ) -> tuple[InvestigationNote, ...]:
        """Retrieve Incident notes chronologically."""

        self._validate_uuid(
            incident_id,
            "incident_id",
        )

        try:
            response = await self.client.search(
                index=self.notes_index,
                body={
                    "size": _INCIDENT_NOTES_SIZE,
                    "track_total_hits": False,
                    "query": {
                        "term": {
                            "incident_id": str(incident_id),
                        },
                    },
                    "sort": [
                        {
                            "created_at": {
                                "order": "asc",
                            },
                        },
                        {
                            "note_id": {
                                "order": "asc",
                            },
                        },
                    ],
                },
            )

            return self._notes_from_response(
                response,
            )

        except Exception:
            self._record_failure(
                "search_incident_notes",
            )
            raise

    # =========================================================================
    # Evidence
    # =========================================================================

    async def save_evidence(
        self,
        evidence: EvidenceRecord,
    ) -> None:
        """Persist one immutable Incident evidence record."""

        if not isinstance(
            evidence,
            EvidenceRecord,
        ):
            raise TypeError(
                "evidence must be an EvidenceRecord instance."
            )

        document_id = self._evidence_document_id(
            evidence,
        )

        try:
            with Timer(
                REGISTRY,
                _OPENSEARCH_LATENCY_METRIC,
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={
                    "operation": "index_incident_evidence",
                },
            ):
                await self.client.index(
                    index=self.evidence_index,
                    id=document_id,
                    body=evidence.model_dump(
                        mode="json",
                    ),
                    refresh=False,
                )

        except Exception:
            self._record_failure(
                "index_incident_evidence",
            )
            raise

    async def get_evidence(
        self,
        incident_id: UUID,
    ) -> tuple[EvidenceRecord, ...]:
        """Retrieve Incident evidence chronologically."""

        self._validate_uuid(
            incident_id,
            "incident_id",
        )

        try:
            response = await self.client.search(
                index=self.evidence_index,
                body={
                    "size": _INCIDENT_EVIDENCE_SIZE,
                    "track_total_hits": False,
                    "query": {
                        "term": {
                            "incident_id": str(incident_id),
                        },
                    },
                    "sort": [
                        {
                            "created_at": {
                                "order": "asc",
                            },
                        },
                        {
                            "evidence_id": {
                                "order": "asc",
                            },
                        },
                    ],
                },
            )

            return self._evidence_from_response(
                response,
            )

        except Exception:
            self._record_failure(
                "search_incident_evidence",
            )
            raise

    # =========================================================================
    # Timeline
    # =========================================================================

    async def save_timeline_entry(
        self,
        entry: TimelineEntry,
    ) -> None:
        """Persist one immutable Incident timeline entry."""

        if not isinstance(
            entry,
            TimelineEntry,
        ):
            raise TypeError(
                "entry must be a TimelineEntry instance."
            )

        try:
            with Timer(
                REGISTRY,
                _OPENSEARCH_LATENCY_METRIC,
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={
                    "operation": "index_incident_timeline",
                },
            ):
                await self.client.index(
                    index=self.timeline_index,
                    id=str(entry.entry_id),
                    body=entry.model_dump(
                        mode="json",
                    ),
                    refresh=False,
                )

        except Exception:
            self._record_failure(
                "index_incident_timeline",
            )
            raise

    async def get_timeline(
        self,
        incident_id: UUID,
    ) -> tuple[TimelineEntry, ...]:
        """Retrieve the chronological Incident timeline."""

        self._validate_uuid(
            incident_id,
            "incident_id",
        )

        try:
            response = await self.client.search(
                index=self.timeline_index,
                body={
                    "size": _INCIDENT_TIMELINE_SIZE,
                    "track_total_hits": False,
                    "query": {
                        "term": {
                            "incident_id": str(incident_id),
                        },
                    },
                    "sort": [
                        {
                            "occurred_at": {
                                "order": "asc",
                            },
                        },
                        {
                            "entry_id": {
                                "order": "asc",
                            },
                        },
                    ],
                },
            )

            return self._timeline_from_response(
                response,
            )

        except Exception:
            self._record_failure(
                "search_incident_timeline",
            )
            raise

    # =========================================================================
    # Audit
    # =========================================================================

    async def save_audit_entry(
        self,
        entry: IncidentAuditEntry,
    ) -> None:
        """Persist one immutable Incident audit entry."""

        if not isinstance(
            entry,
            IncidentAuditEntry,
        ):
            raise TypeError(
                "entry must be an IncidentAuditEntry instance."
            )

        try:
            with Timer(
                REGISTRY,
                _OPENSEARCH_LATENCY_METRIC,
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={
                    "operation": "index_incident_audit",
                },
            ):
                await self.client.index(
                    index=self.audit_index,
                    id=str(entry.audit_id),
                    body=entry.model_dump(
                        mode="json",
                    ),
                    refresh=False,
                )

        except Exception:
            self._record_failure(
                "index_incident_audit",
            )
            raise

    async def get_audit_history(
        self,
        incident_id: UUID,
    ) -> tuple[IncidentAuditEntry, ...]:
        """Retrieve immutable Incident audit history."""

        self._validate_uuid(
            incident_id,
            "incident_id",
        )

        try:
            response = await self.client.search(
                index=self.audit_index,
                body={
                    "size": _INCIDENT_AUDIT_SIZE,
                    "track_total_hits": False,
                    "query": {
                        "term": {
                            "incident_id": str(incident_id),
                        },
                    },
                    "sort": [
                        {
                            "created_at": {
                                "order": "asc",
                            },
                        },
                        {
                            "audit_id": {
                                "order": "asc",
                            },
                        },
                    ],
                },
            )

            return self._audit_from_response(
                response,
            )

        except Exception:
            self._record_failure(
                "search_incident_audit",
            )
            raise

    # =========================================================================
    # Response Parsing
    # =========================================================================

    @staticmethod
    def _notes_from_response(
        response: dict[str, Any],
    ) -> tuple[InvestigationNote, ...]:
        raw_hits = (
            response
            .get("hits", {})
            .get("hits", [])
        )

        notes: list[InvestigationNote] = []

        for hit in raw_hits:
            if not isinstance(
                hit,
                dict,
            ):
                continue

            source = hit.get(
                "_source",
            )

            if not isinstance(
                source,
                dict,
            ):
                continue

            notes.append(
                InvestigationNote.model_validate(
                    source,
                )
            )

        return tuple(notes)

    @staticmethod
    def _evidence_from_response(
        response: dict[str, Any],
    ) -> tuple[EvidenceRecord, ...]:
        raw_hits = (
            response
            .get("hits", {})
            .get("hits", [])
        )

        evidence: list[EvidenceRecord] = []

        for hit in raw_hits:
            if not isinstance(
                hit,
                dict,
            ):
                continue

            source = hit.get(
                "_source",
            )

            if not isinstance(
                source,
                dict,
            ):
                continue

            evidence.append(
                EvidenceRecord.model_validate(
                    source,
                )
            )

        return tuple(evidence)

    @staticmethod
    def _timeline_from_response(
        response: dict[str, Any],
    ) -> tuple[TimelineEntry, ...]:
        raw_hits = (
            response
            .get("hits", {})
            .get("hits", [])
        )

        entries: list[TimelineEntry] = []

        for hit in raw_hits:
            if not isinstance(
                hit,
                dict,
            ):
                continue

            source = hit.get(
                "_source",
            )

            if not isinstance(
                source,
                dict,
            ):
                continue

            entries.append(
                TimelineEntry.model_validate(
                    source,
                )
            )

        return tuple(entries)

    @staticmethod
    def _audit_from_response(
        response: dict[str, Any],
    ) -> tuple[IncidentAuditEntry, ...]:
        """
        Convert persisted Incident audit documents into canonical
        IncidentAuditEntry models.

        Legacy Incident data may contain the pre-canonical status
        value ``new``.  The current Incident lifecycle uses
        ``open`` as the initial status, so legacy audit values are
        normalized at the persistence boundary rather than adding
        ``new`` back into the canonical IncidentStatus enum.
        """
        raw_hits = (
            response
            .get("hits", {})
            .get("hits", [])
        )

        entries: list[IncidentAuditEntry] = []

        for hit in raw_hits:
            if not isinstance(
                hit,
                dict,
            ):
                continue

            source = hit.get(
                "_source",
            )

            if not isinstance(
                source,
                dict,
            ):
                continue

            normalized = dict(source)

            # -------------------------------------------------
            # Legacy status compatibility
            # -------------------------------------------------
            for field_name in (
                "from_status",
                "to_status",
            ):
                value = normalized.get(field_name)

                if isinstance(value, str):
                    value = value.strip().lower()

                    if value == "new":
                        normalized[field_name] = "open"
                    else:
                        normalized[field_name] = value

            # Some older audit documents may have stored the
            # status transition only through generic from/to
            # values. Normalize those when the audit field says
            # the changed field is status.
            field_name = normalized.get("field_name")

            if (
                isinstance(field_name, str)
                and field_name.strip().lower() == "status"
            ):
                for value_field in (
                    "from_value",
                    "to_value",
                ):
                    value = normalized.get(value_field)

                    if isinstance(value, str):
                        value = value.strip().lower()

                        if value == "new":
                            normalized[value_field] = "open"
                        else:
                            normalized[value_field] = value

            entries.append(
                IncidentAuditEntry.model_validate(
                    normalized,
                )
            )

        return tuple(entries)

    # =========================================================================
    # Aggregation Helpers
    # =========================================================================

    @staticmethod
    def _aggregation_counts(
        response: dict[str, Any],
        aggregation_name: str,
    ) -> dict[str, int]:
        aggregation = (
            response
            .get("aggregations", {})
            .get(aggregation_name, {})
        )

        if not isinstance(
            aggregation,
            dict,
        ):
            return {}

        buckets = aggregation.get(
            "buckets",
            [],
        )

        if not isinstance(
            buckets,
            list,
        ):
            return {}

        result: dict[str, int] = {}

        for bucket in buckets:
            if not isinstance(
                bucket,
                dict,
            ):
                continue

            key = bucket.get(
                "key",
            )

            if key is None:
                continue

            result[str(key)] = int(
                bucket.get(
                    "doc_count",
                    0,
                )
            )

        return result

    @staticmethod
    def _aggregation_values(
        aggregations: dict[str, Any],
        aggregation_name: str,
    ) -> tuple[str, ...]:
        aggregation = aggregations.get(
            aggregation_name,
            {},
        )

        if not isinstance(
            aggregation,
            dict,
        ):
            return ()

        buckets = aggregation.get(
            "buckets",
            [],
        )

        if not isinstance(
            buckets,
            list,
        ):
            return ()

        values: set[str] = set()

        for bucket in buckets:
            if not isinstance(
                bucket,
                dict,
            ):
                continue

            key = bucket.get(
                "key",
            )

            if key is None:
                continue

            normalized = str(
                key,
            ).strip()

            if normalized:
                values.add(
                    normalized,
                )

        return tuple(
            sorted(
                values,
                key=str.casefold,
            )
        )

    @staticmethod
    def _total_hits(
        response: dict[str, Any],
    ) -> int:
        total = (
            response
            .get("hits", {})
            .get("total", 0)
        )

        if isinstance(
            total,
            dict,
        ):
            total = total.get(
                "value",
                0,
            )

        return int(total)

    @staticmethod
    def _first_source(
        response: dict[str, Any],
    ) -> dict[str, Any] | None:
        hits = (
            response
            .get("hits", {})
            .get("hits", [])
        )

        if not isinstance(
            hits,
            list,
        ):
            return None

        for hit in hits:
            if not isinstance(
                hit,
                dict,
            ):
                continue

            source = hit.get(
                "_source",
            )

            if isinstance(
                source,
                dict,
            ):
                return source

        return None

    # =========================================================================
    # Incident Document Compatibility
    # =========================================================================

    @staticmethod
    def _from_document(
        document: dict[str, Any],
    ) -> Incident:
        """
        Convert a persisted OpenSearch document into canonical Incident.

        Legacy compatibility:

            status:
                new -> open

            severity:
                info -> informational

            updated_at:
                last_updated_at fallback

            created_at:
                first_seen_at fallback
                updated_at fallback

            incident_number:
                deterministic fallback

            collections:
                missing/null -> ()

            assigned_to:
                empty string -> None

            created_by:
                missing -> system

        Obsolete fields are discarded before Pydantic validation.
        """

        if not isinstance(
            document,
            dict,
        ):
            raise TypeError(
                "Incident OpenSearch document must be a dictionary."
            )

        normalized = dict(
            document,
        )

        # ---------------------------------------------------------------------
        # Legacy status
        # ---------------------------------------------------------------------

        persisted_status = normalized.get(
            "status",
        )

        if (
            isinstance(
                persisted_status,
                str,
            )
            and persisted_status.strip().lower() == "new"
        ):
            normalized["status"] = "open"

        # ---------------------------------------------------------------------
        # Legacy severity
        # ---------------------------------------------------------------------

        persisted_severity = normalized.get(
            "severity",
        )

        if (
            isinstance(
                persisted_severity,
                str,
            )
            and persisted_severity.strip().lower() == "info"
        ):
            normalized["severity"] = "informational"

        # ---------------------------------------------------------------------
        # Timestamp compatibility
        # ---------------------------------------------------------------------

        if not normalized.get(
            "updated_at",
        ):
            legacy_updated = normalized.get(
                "last_updated_at",
            )

            if legacy_updated:
                normalized["updated_at"] = legacy_updated

        if not normalized.get(
            "created_at",
        ):
            first_seen = normalized.get(
                "first_seen_at",
            )

            if first_seen:
                normalized["created_at"] = first_seen

            elif normalized.get(
                "updated_at",
            ):
                normalized["created_at"] = normalized[
                    "updated_at"
                ]

        # ---------------------------------------------------------------------
        # Incident number compatibility
        # ---------------------------------------------------------------------

        if not normalized.get(
            "incident_number",
        ):
            normalized["incident_number"] = (
                OpenSearchIncidentRepository._legacy_incident_number(
                    normalized.get(
                        "incident_id",
                    )
                )
            )

        # ---------------------------------------------------------------------
        # Collection compatibility
        # ---------------------------------------------------------------------

        for field in (
            "tags",
            "alert_ids",
            "evidence_ids",
            "related_event_ids",
            "related_ioc_ids",
            "asset_ids",
        ):
            if (
                field not in normalized
                or normalized[field] is None
            ):
                normalized[field] = ()

        # ---------------------------------------------------------------------
        # Assignment compatibility
        # ---------------------------------------------------------------------

        assigned_to = normalized.get("assigned_to")

        if assigned_to in ("", None):
            normalized["assigned_to"] = None
        else:
            try:
                normalized["assigned_to"] = (
                    assigned_to
                    if isinstance(assigned_to, UUID)
                    else UUID(str(assigned_to))
                )
            except (TypeError, ValueError, AttributeError):
                # Legacy documents may contain usernames instead of User UUIDs.
                # Never guess a UUID from a username.
                normalized["assigned_to"] = None

        # ---------------------------------------------------------------------
        # Creator compatibility
        # ---------------------------------------------------------------------

        if not normalized.get(
            "created_by",
        ):
            normalized["created_by"] = "system"

        # ---------------------------------------------------------------------
        # Obsolete fields
        # ---------------------------------------------------------------------

        normalized.pop(
            "priority",
            None,
        )

        normalized.pop(
            "ownership_group",
            None,
        )

        normalized.pop(
            "first_seen_at",
            None,
        )

        normalized.pop(
            "last_updated_at",
            None,
        )

        description = normalized.get("description")

        if description is None or not str(description).strip():
            title = normalized.get("title")
            normalized["description"] = (
                str(title).strip()
                if title is not None and str(title).strip()
                else "Incident generated from legacy data."
            )
        else:
            normalized["description"] = str(description).strip()

        return Incident.model_validate(
            normalized,
        )

    @staticmethod
    def _legacy_incident_number(
        incident_id: object,
    ) -> str:
        """Generate a deterministic readable number for legacy records."""

        try:
            parsed = (
                incident_id
                if isinstance(
                    incident_id,
                    UUID,
                )
                else UUID(
                    str(incident_id),
                )
            )

            suffix = parsed.int % 100000

            return f"INC-LEGACY-{suffix:05d}"

        except (
            ValueError,
            AttributeError,
            TypeError,
        ):
            return "INC-LEGACY-00000"

    # =========================================================================
    # Canonical Value Normalization
    # =========================================================================

    @staticmethod
    def _normalize_optional_status(
        value: Any,
    ) -> str | None:
        """
        Normalize an optional status.

        Legacy:
            new -> open
        """

        normalized = (
            OpenSearchIncidentRepository._optional_lookup_value(
                value,
            )
        )

        if normalized is None:
            return None

        normalized = normalized.lower()

        if normalized == "new":
            return "open"

        return normalized

    @staticmethod
    def _normalize_optional_severity(
        value: Any,
    ) -> str | None:
        """
        Normalize an optional severity.

        Legacy:
            info -> informational
        """

        normalized = (
            OpenSearchIncidentRepository._optional_lookup_value(
                value,
            )
        )

        if normalized is None:
            return None

        normalized = normalized.lower()

        if normalized == "info":
            return "informational"

        return normalized

    @staticmethod
    def _canonicalize_status_values(
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        """
        Convert persisted legacy status values into canonical values.
        """

        normalized: set[str] = set()

        for value in values:
            item = value.strip().lower()

            if not item:
                continue

            if item == "new":
                item = "open"

            normalized.add(
                item,
            )

        return tuple(
            sorted(
                normalized,
                key=str.casefold,
            )
        )

    @staticmethod
    def _canonicalize_severity_values(
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        """
        Convert persisted legacy severity values into canonical values.
        """

        normalized: set[str] = set()

        for value in values:
            item = value.strip().lower()

            if not item:
                continue

            if item == "info":
                item = "informational"

            normalized.add(
                item,
            )

        return tuple(
            sorted(
                normalized,
                key=str.casefold,
            )
        )

    # =========================================================================
    # Query Helpers
    # =========================================================================

    @staticmethod
    def _append_relationship_filter(
        filters: list[dict[str, Any]],
        field: str,
        value: str | None,
    ) -> None:
        normalized = (
            OpenSearchIncidentRepository._optional_lookup_value(
                value,
            )
        )

        if normalized is None:
            return

        filters.append(
            {
                "term": {
                    field: normalized,
                },
            }
        )

    @staticmethod
    def _normalize_lookup_value(
        value: str,
        field_name: str,
    ) -> str:
        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                f"{field_name} must be a string."
            )

        normalized = value.strip()

        if not normalized:
            raise ValueError(
                f"{field_name} must not be empty."
            )

        return normalized

    @staticmethod
    def _optional_lookup_value(
        value: Any,
    ) -> str | None:
        if value is None:
            return None

        if isinstance(
            value,
            UUID,
        ):
            return str(value)

        if not isinstance(
            value,
            str,
        ):
            value = str(value)

        normalized = value.strip()

        return normalized or None

    # =========================================================================
    # Evidence ID
    # =========================================================================

    @staticmethod
    def _evidence_document_id(
        evidence: EvidenceRecord,
    ) -> str:
        """Generate deterministic child document ID."""

        return (
            f"{evidence.incident_id}:"
            f"{evidence.evidence_id}"
        )

    # =========================================================================
    # Empty Defaults
    # =========================================================================

    @staticmethod
    def _empty_filter_options() -> dict[str, tuple[str, ...]]:
        return {
            "statuses": (),
            "severities": (),
            "assignees": (),
        }

    # =========================================================================
    # Validation / Errors
    # =========================================================================

    @staticmethod
    def _validate_uuid(
        value: UUID,
        field_name: str,
    ) -> None:
        if not isinstance(
            value,
            UUID,
        ):
            raise TypeError(
                f"{field_name} must be a UUID."
            )

    @staticmethod
    def _is_not_found(
        exc: Exception,
    ) -> bool:
        return (
            getattr(
                exc,
                "status_code",
                None,
            )
            == 404
        )

    @staticmethod
    def _record_failure(
        operation: str,
    ) -> None:
        REGISTRY.inc_counter(
            _OPENSEARCH_FAILURE_METRIC,
            help_text=_OPENSEARCH_FAILURES_HELP,
            labels={
                "operation": operation,
            },
        )


# =============================================================================
# Public API
# =============================================================================

__all__ = [
    "OpenSearchIncidentRepository",
]