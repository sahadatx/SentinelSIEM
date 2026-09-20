from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from app.alerts.models import Alert, AlertAuditEntry
from app.core.metrics import REGISTRY, Timer
from app.storage.opensearch.client import AsyncOpenSearch

_ALERT_INDEX_DEFAULT = "siem-alerts-v1"
_FILTER_OPTION_SIZE = 1000

_OPENSEARCH_LATENCY_HELP = (
    "OpenSearch repository operation latency in seconds."
)
_OPENSEARCH_FAILURES_HELP = (
    "Total OpenSearch operation failures."
)


class AlertSearchResult:
    """
    Result returned by AlertRepository.search().
    """

    __slots__ = (
        "alerts",
        "total",
    )

    def __init__(
        self,
        alerts: tuple[Alert, ...],
        total: int,
    ) -> None:
        self.alerts = alerts
        self.total = total


class AlertRepository:
    """
    Protocol-like base contract for alert persistence.

    Concrete persistence is implemented by OpenSearchAlertRepository.
    """

    async def ensure_index(self) -> None:
        raise NotImplementedError

    async def save(self, alert: Alert) -> None:
        raise NotImplementedError

    async def get(self, alert_id: UUID) -> Alert | None:
        raise NotImplementedError

    async def search(
        self,
        *,
        query: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        priority: str | None = None,
        source_type: str | None = None,
        source_id: str | None = None,
        rule_id: str | None = None,
        assigned_to: str | None = None,
        ownership_group: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> AlertSearchResult:
        raise NotImplementedError

    async def save_audit_entry(
        self,
        entry: AlertAuditEntry,
    ) -> None:
        raise NotImplementedError

    async def get_audit_history(
        self,
        alert_id: UUID,
    ) -> tuple[AlertAuditEntry, ...]:
        raise NotImplementedError


class OpenSearchAlertRepository(AlertRepository):
    """
    OpenSearch-backed persistence repository for SentinelSIEM alerts.

    Alert documents are stored independently from security event
    documents in the dedicated alert index.

    Default index:
        siem-alerts-v1
    """

    def __init__(
        self,
        client: AsyncOpenSearch,
        *,
        index: str = _ALERT_INDEX_DEFAULT,
    ) -> None:
        if not index.strip():
            raise ValueError(
                "Alert OpenSearch index must not be empty.",
            )

        self.client = client
        self.index = index

        self.audit_index = f"{index}-audit"

    # =====================================================
    # Index Management
    # =====================================================

    async def ensure_index(self) -> None:
        """
        Ensure alert and alert-audit indices exist with the
        required mappings.
        """

        await self._ensure_alert_index()
        await self._ensure_audit_index()

    async def _ensure_alert_index(self) -> None:
        exists = await self.client.indices.exists(
            index=self.index,
        )

        if exists:
            return

        mapping = {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
            },
            "mappings": {
                "dynamic": "strict",
                "properties": {
                    "alert_id": {
                        "type": "keyword",
                    },
                    "source_type": {
                        "type": "keyword",
                    },
                    "source_id": {
                        "type": "keyword",
                    },
                    "rule_id": {
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
                    "risk_score": {
                        "type": "float",
                    },
                    "priority": {
                        "type": "keyword",
                    },
                    "status": {
                        "type": "keyword",
                    },
                    "evidence_ids": {
                        "type": "keyword",
                    },
                    "asset_id": {
                        "type": "keyword",
                    },
                    "user_id": {
                        "type": "keyword",
                    },
                    "assigned_to": {
                        "type": "keyword",
                    },
                    "ownership_group": {
                        "type": "keyword",
                    },
                    "deduplication_key": {
                        "type": "keyword",
                        "ignore_above": 1024,
                    },
                    "occurrence_count": {
                        "type": "integer",
                    },
                    "first_seen_at": {
                        "type": "date",
                    },
                    "last_seen_at": {
                        "type": "date",
                    },
                    "acknowledged_at": {
                        "type": "date",
                    },
                    "investigating_at": {
                        "type": "date",
                    },
                    "escalated_at": {
                        "type": "date",
                    },
                    "resolved_at": {
                        "type": "date",
                    },
                    "closed_at": {
                        "type": "date",
                    },
                    "suppressed_at": {
                        "type": "date",
                    },
                    "sla_due_at": {
                        "type": "date",
                    },
                    "updated_at": {
                        "type": "date",
                    },
                },
            },
        }

        try:
            await self.client.indices.create(
                index=self.index,
                body=mapping,
            )

        except Exception as exc:
            # Another worker/process may have created the index
            # between exists() and create().
            if getattr(exc, "status_code", None) == 400:
                exists_after_failure = (
                    await self.client.indices.exists(
                        index=self.index,
                    )
                )

                if exists_after_failure:
                    return

            REGISTRY.inc_counter(
                "siem_opensearch_operation_failures_total",
                help_text=_OPENSEARCH_FAILURES_HELP,
                labels={"operation": "create_alert_index"},
            )
            raise

    async def _ensure_audit_index(self) -> None:
        exists = await self.client.indices.exists(
            index=self.audit_index,
        )

        if exists:
            return

        mapping = {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
            },
            "mappings": {
                "dynamic": "strict",
                "properties": {
                    "audit_id": {
                        "type": "keyword",
                    },
                    "alert_id": {
                        "type": "keyword",
                    },
                    "action": {
                        "type": "keyword",
                    },
                    "actor": {
                        "type": "keyword",
                    },
                    "from_status": {
                        "type": "keyword",
                    },
                    "to_status": {
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

        try:
            await self.client.indices.create(
                index=self.audit_index,
                body=mapping,
            )

        except Exception as exc:
            if getattr(exc, "status_code", None) == 400:
                exists_after_failure = (
                    await self.client.indices.exists(
                        index=self.audit_index,
                    )
                )

                if exists_after_failure:
                    return

            REGISTRY.inc_counter(
                "siem_opensearch_operation_failures_total",
                help_text=_OPENSEARCH_FAILURES_HELP,
                labels={"operation": "create_alert_audit_index"},
            )
            raise

    # =====================================================
    # Save Alert
    # =====================================================

    async def save(
        self,
        alert: Alert,
    ) -> None:
        """
        Persist an alert using alert_id as the OpenSearch document ID.
        """

        try:
            with Timer(
                REGISTRY,
                "siem_opensearch_operation_latency_seconds",
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={"operation": "index_alert"},
            ):
                await self.client.index(
                    index=self.index,
                    id=str(alert.alert_id),
                    body=alert.model_dump(mode="json"),
                    refresh=False,
                )

        except Exception:
            REGISTRY.inc_counter(
                "siem_opensearch_operation_failures_total",
                help_text=_OPENSEARCH_FAILURES_HELP,
                labels={"operation": "index_alert"},
            )
            raise

    # =====================================================
    # Get Alert
    # =====================================================

    async def get(
        self,
        alert_id: UUID,
    ) -> Alert | None:
        """
        Retrieve an alert by UUID.
        """

        try:
            with Timer(
                REGISTRY,
                "siem_opensearch_operation_latency_seconds",
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={"operation": "get_alert"},
            ):
                response = await self.client.get(
                    index=self.index,
                    id=str(alert_id),
                )

        except Exception as exc:
            if getattr(exc, "status_code", None) == 404:
                return None

            REGISTRY.inc_counter(
                "siem_opensearch_operation_failures_total",
                help_text=_OPENSEARCH_FAILURES_HELP,
                labels={"operation": "get_alert"},
            )
            raise

        return self._from_document(
            response["_source"],
        )

    # =====================================================
    # Search Alerts
    # =====================================================

    async def search(
        self,
        *,
        query: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        priority: str | None = None,
        source_type: str | None = None,
        source_id: str | None = None,
        rule_id: str | None = None,
        assigned_to: str | None = None,
        ownership_group: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> AlertSearchResult:
        """
        Search alerts with exact filters, free-text search,
        time filtering, and pagination.
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
                labels={"operation": "search_alerts"},
            ):
                filters: list[dict[str, Any]] = []

                exact_filters = (
                    ("status", status),
                    ("severity", severity),
                    ("priority", priority),
                    ("source_type", source_type),
                    ("source_id", source_id),
                    ("rule_id", rule_id),
                    ("assigned_to", assigned_to),
                    ("ownership_group", ownership_group),
                )

                for field, value in exact_filters:
                    if value is None:
                        continue

                    filters.append(
                        {
                            "term": {
                                field: value,
                            },
                        },
                    )

                if (
                    start_time is not None
                    or end_time is not None
                ):
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
                                "last_seen_at": timestamp_range,
                            },
                        },
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
                                    "title",
                                    "title.keyword",
                                    "description",
                                    "rule_id",
                                    "source_id",
                                    "asset_id",
                                    "user_id",
                                    "assigned_to",
                                    "ownership_group",
                                ],
                            },
                        },
                    ]

                response = await self.client.search(
                    index=self.index,
                    body={
                        "from": offset,
                        "query": {
                            "bool": bool_query,
                        },
                        "sort": [
                            {
                                "last_seen_at": "desc",
                            },
                        ],
                    },
                    size=limit,
                )

                hits = response["hits"]

                alerts = tuple(
                    self._from_document(
                        hit["_source"],
                    )
                    for hit in hits["hits"]
                )

                total = hits["total"]

                if isinstance(total, dict):
                    total_value = total.get(
                        "value",
                        0,
                    )
                else:
                    total_value = total

                return AlertSearchResult(
                    alerts=alerts,
                    total=int(total_value),
                )

        except Exception:
            REGISTRY.inc_counter(
                "siem_opensearch_operation_failures_total",
                help_text=_OPENSEARCH_FAILURES_HELP,
                labels={"operation": "search_alerts"},
            )
            raise

    # =====================================================
    # Save Audit Entry
    # =====================================================

    async def save_audit_entry(
        self,
        entry: AlertAuditEntry,
    ) -> None:
        """
        Persist one immutable alert audit entry.
        """

        try:
            with Timer(
                REGISTRY,
                "siem_opensearch_operation_latency_seconds",
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={"operation": "index_alert_audit"},
            ):
                await self.client.index(
                    index=self.audit_index,
                    id=str(entry.audit_id),
                    body=entry.model_dump(mode="json"),
                    refresh=False,
                )

        except Exception:
            REGISTRY.inc_counter(
                "siem_opensearch_operation_failures_total",
                help_text=_OPENSEARCH_FAILURES_HELP,
                labels={"operation": "index_alert_audit"},
            )
            raise

    # =====================================================
    # Alert Audit History
    # =====================================================

    async def get_audit_history(
        self,
        alert_id: UUID,
    ) -> tuple[AlertAuditEntry, ...]:
        """
        Retrieve immutable audit history for one alert.
        """

        try:
            with Timer(
                REGISTRY,
                "siem_opensearch_operation_latency_seconds",
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={"operation": "search_alert_audit"},
            ):
                response = await self.client.search(
                    index=self.audit_index,
                    body={
                        "query": {
                            "term": {
                                "alert_id": str(alert_id),
                            },
                        },
                        "sort": [
                            {
                                "created_at": "asc",
                            },
                        ],
                    },
                    size=1000,
                )

                return tuple(
                    self._audit_from_document(
                        hit["_source"],
                    )
                    for hit in response["hits"]["hits"]
                )

        except Exception:
            REGISTRY.inc_counter(
                "siem_opensearch_operation_failures_total",
                help_text=_OPENSEARCH_FAILURES_HELP,
                labels={"operation": "search_alert_audit"},
            )
            raise

    # =====================================================
    # Statistics
    # =====================================================

    async def count_by_status(self) -> dict[str, int]:
        """
        Return alert counts grouped by lifecycle status.
        """

        try:
            with Timer(
                REGISTRY,
                "siem_opensearch_operation_latency_seconds",
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={"operation": "alert_status_stats"},
            ):
                response = await self.client.search(
                    index=self.index,
                    body={
                        "size": 0,
                        "aggs": {
                            "statuses": {
                                "terms": {
                                    "field": "status",
                                    "size": 100,
                                    "order": {
                                        "_key": "asc",
                                    },
                                },
                            },
                        },
                    },
                )

                buckets = (
                    response
                    .get("aggregations", {})
                    .get("statuses", {})
                    .get("buckets", [])
                )

                return {
                    str(bucket["key"]): int(
                        bucket["doc_count"],
                    )
                    for bucket in buckets
                    if isinstance(bucket, dict)
                    and "key" in bucket
                }

        except Exception:
            REGISTRY.inc_counter(
                "siem_opensearch_operation_failures_total",
                help_text=_OPENSEARCH_FAILURES_HELP,
                labels={"operation": "alert_status_stats"},
            )
            raise

    async def count_by_severity(self) -> dict[str, int]:
        """
        Return alert counts grouped by severity.
        """

        try:
            response = await self.client.search(
                index=self.index,
                body={
                    "size": 0,
                    "aggs": {
                        "severities": {
                            "terms": {
                                "field": "severity",
                                "size": 100,
                                "order": {
                                    "_key": "asc",
                                },
                            },
                        },
                    },
                },
            )

            buckets = (
                response
                .get("aggregations", {})
                .get("severities", {})
                .get("buckets", [])
            )

            return {
                str(bucket["key"]): int(
                    bucket["doc_count"],
                )
                for bucket in buckets
                if isinstance(bucket, dict)
                and "key" in bucket
            }

        except Exception:
            REGISTRY.inc_counter(
                "siem_opensearch_operation_failures_total",
                help_text=_OPENSEARCH_FAILURES_HELP,
                labels={"operation": "alert_severity_stats"},
            )
            raise

    async def get_filter_options(
        self,
    ) -> dict[str, tuple[str, ...]]:
        """
        Return dynamic values used by the Alerts frontend filters.
        """

        try:
            response = await self.client.search(
                index=self.index,
                body={
                    "size": 0,
                    "aggs": {
                        "statuses": {
                            "terms": {
                                "field": "status",
                                "size": _FILTER_OPTION_SIZE,
                            },
                        },
                        "severities": {
                            "terms": {
                                "field": "severity",
                                "size": _FILTER_OPTION_SIZE,
                            },
                        },
                        "priorities": {
                            "terms": {
                                "field": "priority",
                                "size": _FILTER_OPTION_SIZE,
                            },
                        },
                        "sources": {
                            "terms": {
                                "field": "source_type",
                                "size": _FILTER_OPTION_SIZE,
                            },
                        },
                        "rules": {
                            "terms": {
                                "field": "rule_id",
                                "size": _FILTER_OPTION_SIZE,
                            },
                        },
                        "assignees": {
                            "terms": {
                                "field": "assigned_to",
                                "size": _FILTER_OPTION_SIZE,
                            },
                        },
                    },
                },
            )

            aggregations = response.get(
                "aggregations",
                {},
            )

            def values_for(
                name: str,
            ) -> tuple[str, ...]:
                aggregation = aggregations.get(
                    name,
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

                    value = bucket.get("key")

                    if value is None:
                        continue

                    value_string = str(value).strip()

                    if value_string:
                        values.add(value_string)

                return tuple(
                    sorted(
                        values,
                        key=str.casefold,
                    ),
                )

            return {
                "statuses": values_for("statuses"),
                "severities": values_for("severities"),
                "priorities": values_for("priorities"),
                "sources": values_for("sources"),
                "rules": values_for("rules"),
                "assignees": values_for("assignees"),
            }

        except Exception:
            REGISTRY.inc_counter(
                "siem_opensearch_operation_failures_total",
                help_text=_OPENSEARCH_FAILURES_HELP,
                labels={"operation": "alert_filter_options"},
            )
            raise

    # =====================================================
    # Document Conversion
    # =====================================================

    @staticmethod
    def _from_document(
        document: dict[str, Any],
    ) -> Alert:
        """
        Convert an OpenSearch alert document into an Alert model.
        """

        return Alert.model_validate(document)

    @staticmethod
    def _audit_from_document(
        document: dict[str, Any],
    ) -> AlertAuditEntry:
        """
        Convert an OpenSearch audit document into an audit model.
        """

        return AlertAuditEntry.model_validate(document)


__all__ = [
    "AlertRepository",
    "AlertSearchResult",
    "OpenSearchAlertRepository",
]
