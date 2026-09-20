from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from opensearchpy import AsyncOpenSearch

from app.core.metrics import REGISTRY, Timer
from app.detection.result import DetectionResult
from app.storage.repositories.detections import (
    DetectionRuleStatistics,
    DetectionSearchResult,
)


DETECTION_REPOSITORY_LATENCY_METRIC = (
    "siem_detection_repository_operation_latency_seconds"
)

_DETECTION_REPOSITORY_LATENCY_HELP = (
    "Detection repository operation latency in seconds."
)

_DETECTION_INDEX = "siem-detection-results-v1"


class OpenSearchDetectionRepository:
    """
    OpenSearch-backed repository for persisted DetectionResult objects.

    This repository is responsible only for DetectionResult persistence,
    retrieval, searching, counting, and per-rule statistics.

    It does not:
        - evaluate detection rules
        - manage detection rules
        - create alerts
        - manage incidents
        - perform RBAC
        - perform suppression
    """

    def __init__(
        self,
        client: AsyncOpenSearch,
        *,
        index: str = _DETECTION_INDEX,
    ) -> None:
        if not index or not index.strip():
            raise ValueError("index must not be empty")

        self.client = client
        self.index = index.strip()

    async def ensure_index(self) -> None:
        """
        Ensure the DetectionResult index exists.

        The operation is idempotent when the index already exists.
        """
        with Timer(
            REGISTRY,
            DETECTION_REPOSITORY_LATENCY_METRIC,
            help_text=_DETECTION_REPOSITORY_LATENCY_HELP,
            labels={"operation": "ensure_index"},
        ):
            exists = await self.client.indices.exists(
                index=self.index,
            )

            if exists:
                return

            await self.client.indices.create(
                index=self.index,
                body=self._index_definition(),
            )

    async def save(
        self,
        result: DetectionResult,
    ) -> None:
        """
        Persist one validated DetectionResult.

        Both normal and suppressed detection results are persisted.
        """
        if not isinstance(result, DetectionResult):
            raise TypeError(
                "detection repository expects DetectionResult"
            )

        document = self._to_document(result)

        with Timer(
            REGISTRY,
            DETECTION_REPOSITORY_LATENCY_METRIC,
            help_text=_DETECTION_REPOSITORY_LATENCY_HELP,
            labels={"operation": "save"},
        ):
            await self.client.index(
                index=self.index,
                id=str(result.detection_id),
                body=document,
                refresh=False,
            )

    async def get(
        self,
        detection_id: UUID,
    ) -> DetectionResult | None:
        """
        Retrieve a DetectionResult by its unique detection ID.

        Returns None when the result does not exist.
        """
        if not isinstance(detection_id, UUID):
            raise TypeError("detection_id must be UUID")

        with Timer(
            REGISTRY,
            DETECTION_REPOSITORY_LATENCY_METRIC,
            help_text=_DETECTION_REPOSITORY_LATENCY_HELP,
            labels={"operation": "get"},
        ):
            response = await self.client.get(
                index=self.index,
                id=str(detection_id),
                ignore=[404],
            )

        if not response or not response.get("found", False):
            return None

        source = response.get("_source")

        if not isinstance(source, dict):
            return None

        return self._from_document(source)

    async def search(
        self,
        *,
        query: str | None = None,
        rule_id: str | None = None,
        event_id: UUID | None = None,
        severity: str | None = None,
        category: str | None = None,
        suppressed: bool | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> DetectionSearchResult:
        """
        Search persisted DetectionResult objects.

        Results are ordered by:
            1. matched_at descending
            2. detection_id descending

        Pagination uses zero-based offset and limit.
        """
        self._validate_pagination(offset, limit)
        self._validate_time_range(start_time, end_time)

        body = self._build_search_body(
            query=query,
            rule_id=rule_id,
            event_id=event_id,
            severity=severity,
            category=category,
            suppressed=suppressed,
            start_time=start_time,
            end_time=end_time,
            offset=offset,
            limit=limit,
        )

        with Timer(
            REGISTRY,
            DETECTION_REPOSITORY_LATENCY_METRIC,
            help_text=_DETECTION_REPOSITORY_LATENCY_HELP,
            labels={"operation": "search"},
        ):
            response = await self.client.search(
                index=self.index,
                body=body,
            )

        hits = response.get("hits", {})

        if not isinstance(hits, dict):
            return DetectionSearchResult(
                results=(),
                total=0,
            )

        raw_hits = hits.get("hits", [])

        results: list[DetectionResult] = []

        if isinstance(raw_hits, list):
            for hit in raw_hits:
                if not isinstance(hit, dict):
                    continue

                source = hit.get("_source")

                if not isinstance(source, dict):
                    continue

                results.append(
                    self._from_document(source)
                )

        total = self._extract_total(
            hits.get("total", 0)
        )

        return DetectionSearchResult(
            results=tuple(results),
            total=total,
        )

    async def count(
        self,
        *,
        rule_id: str | None = None,
        suppressed: bool | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> int:
        """
        Count persisted DetectionResult objects matching filters.
        """
        self._validate_time_range(start_time, end_time)

        query = self._build_filter_query(
            rule_id=rule_id,
            suppressed=suppressed,
            start_time=start_time,
            end_time=end_time,
        )

        with Timer(
            REGISTRY,
            DETECTION_REPOSITORY_LATENCY_METRIC,
            help_text=_DETECTION_REPOSITORY_LATENCY_HELP,
            labels={"operation": "count"},
        ):
            response = await self.client.count(
                index=self.index,
                body={
                    "query": query,
                },
            )

        return max(
            0,
            int(response.get("count", 0)),
        )

    async def get_rule_statistics(
        self,
        *,
        rule_ids: Sequence[str] | None = None,
    ) -> tuple[DetectionRuleStatistics, ...]:
        """
        Aggregate persisted DetectionResults by rule ID.

        A single OpenSearch aggregation is used to avoid an N+1 query
        pattern when statistics are requested for multiple rules.
        """
        normalized_rule_ids = self._normalize_rule_ids(
            rule_ids
        )

        query = self._build_rule_statistics_query(
            normalized_rule_ids
        )

        aggregation_size = (
            len(normalized_rule_ids)
            if normalized_rule_ids
            else 1000
        )

        body = {
            "size": 0,
            "track_total_hits": False,
            "query": query,
            "aggs": {
                "rules": {
                    "terms": {
                        "field": "rule_id",
                        "size": aggregation_size,
                    },
                    "aggs": {
                        "suppressed": {
                            "filter": {
                                "term": {
                                    "suppressed": True,
                                },
                            },
                        },
                        "last_match": {
                            "max": {
                                "field": "matched_at",
                            },
                        },
                    },
                },
            },
        }

        with Timer(
            REGISTRY,
            DETECTION_REPOSITORY_LATENCY_METRIC,
            help_text=_DETECTION_REPOSITORY_LATENCY_HELP,
            labels={"operation": "get_rule_statistics"},
        ):
            response = await self.client.search(
                index=self.index,
                body=body,
            )

        aggregations = response.get(
            "aggregations",
            {},
        )

        if not isinstance(aggregations, dict):
            return ()

        rules_aggregation = aggregations.get(
            "rules",
            {},
        )

        if not isinstance(rules_aggregation, dict):
            return ()

        buckets = rules_aggregation.get(
            "buckets",
            [],
        )

        if not isinstance(buckets, list):
            return ()

        statistics: list[DetectionRuleStatistics] = []

        for bucket in buckets:
            if not isinstance(bucket, dict):
                continue

            current_rule_id = bucket.get("key")

            if not isinstance(current_rule_id, str):
                continue

            matches = max(
                0,
                int(bucket.get("doc_count", 0)),
            )

            suppressed_bucket = bucket.get(
                "suppressed",
                {},
            )

            suppressed = 0

            if isinstance(
                suppressed_bucket,
                dict,
            ):
                suppressed = max(
                    0,
                    int(
                        suppressed_bucket.get(
                            "doc_count",
                            0,
                        )
                    ),
                )

            last_match = bucket.get(
                "last_match",
                {},
            )

            last_match_at: datetime | None = None

            if isinstance(last_match, dict):
                raw_timestamp = last_match.get(
                    "value_as_string"
                )

                if isinstance(raw_timestamp, str):
                    last_match_at = self._parse_datetime(
                        raw_timestamp
                    )

            statistics.append(
                DetectionRuleStatistics(
                    rule_id=current_rule_id,
                    matches=matches,
                    suppressed=suppressed,
                    last_match_at=last_match_at,
                )
            )

        statistics.sort(
            key=lambda item: item.rule_id
        )

        return tuple(statistics)

    @staticmethod
    def _index_definition() -> dict[str, Any]:
        """
        Return the strict OpenSearch mapping for DetectionResult documents.
        """
        return {
            "mappings": {
                "dynamic": "strict",
                "properties": {
                    "detection_id": {
                        "type": "keyword",
                    },
                    "rule_id": {
                        "type": "keyword",
                    },
                    "rule_name": {
                        "type": "keyword",
                    },
                    "event_id": {
                        "type": "keyword",
                    },
                    "severity": {
                        "type": "keyword",
                    },
                    "category": {
                        "type": "keyword",
                    },
                    "description": {
                        "type": "text",
                    },
                    "matched_at": {
                        "type": "date",
                    },
                    "tags": {
                        "type": "keyword",
                    },
                    "suppressed": {
                        "type": "boolean",
                    },
                },
            },
        }

    @classmethod
    def _build_search_body(
        cls,
        *,
        query: str | None,
        rule_id: str | None,
        event_id: UUID | None,
        severity: str | None,
        category: str | None,
        suppressed: bool | None,
        start_time: datetime | None,
        end_time: datetime | None,
        offset: int,
        limit: int,
    ) -> dict[str, Any]:
        filters = cls._build_filters(
            rule_id=rule_id,
            event_id=event_id,
            severity=severity,
            category=category,
            suppressed=suppressed,
            start_time=start_time,
            end_time=end_time,
        )

        bool_query: dict[str, Any] = {
            "filter": filters,
        }

        normalized_query = (
            query.strip()
            if isinstance(query, str)
            else ""
        )

        if normalized_query:
            bool_query["must"] = [
                {
                    "multi_match": {
                        "query": normalized_query,
                        "fields": [
                            "rule_id",
                            "rule_name",
                            "description",
                            "severity",
                            "category",
                            "tags",
                        ],
                    },
                },
            ]
        else:
            bool_query["must"] = [
                {
                    "match_all": {},
                },
            ]

        return {
            "track_total_hits": True,
            "from": offset,
            "size": limit,
            "query": {
                "bool": bool_query,
            },
            "sort": [
                {
                    "matched_at": {
                        "order": "desc",
                    },
                },
                {
                    "detection_id": {
                        "order": "desc",
                    },
                },
            ],
        }

    @classmethod
    def _build_filter_query(
        cls,
        *,
        rule_id: str | None,
        suppressed: bool | None,
        start_time: datetime | None,
        end_time: datetime | None,
    ) -> dict[str, Any]:
        filters = cls._build_filters(
            rule_id=rule_id,
            suppressed=suppressed,
            start_time=start_time,
            end_time=end_time,
        )

        if not filters:
            return {
                "match_all": {},
            }

        return {
            "bool": {
                "filter": filters,
            },
        }

    @classmethod
    def _build_rule_statistics_query(
        cls,
        rule_ids: Sequence[str],
    ) -> dict[str, Any]:
        if not rule_ids:
            return {
                "match_all": {},
            }

        return {
            "bool": {
                "filter": [
                    {
                        "terms": {
                            "rule_id": list(rule_ids),
                        },
                    },
                ],
            },
        }

    @staticmethod
    def _build_filters(
        *,
        rule_id: str | None = None,
        event_id: UUID | None = None,
        severity: str | None = None,
        category: str | None = None,
        suppressed: bool | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[dict[str, Any]]:
        filters: list[dict[str, Any]] = []

        normalized_rule_id = (
            rule_id.strip()
            if isinstance(rule_id, str)
            else ""
        )

        if normalized_rule_id:
            filters.append(
                {
                    "term": {
                        "rule_id": normalized_rule_id,
                    },
                }
            )

        if event_id is not None:
            if not isinstance(event_id, UUID):
                raise TypeError(
                    "event_id must be UUID"
                )

            filters.append(
                {
                    "term": {
                        "event_id": str(event_id),
                    },
                }
            )

        normalized_severity = (
            severity.strip()
            if isinstance(severity, str)
            else ""
        )

        if normalized_severity:
            filters.append(
                {
                    "term": {
                        "severity": normalized_severity,
                    },
                }
            )

        normalized_category = (
            category.strip()
            if isinstance(category, str)
            else ""
        )

        if normalized_category:
            filters.append(
                {
                    "term": {
                        "category": normalized_category,
                    },
                }
            )

        if suppressed is not None:
            filters.append(
                {
                    "term": {
                        "suppressed": bool(suppressed),
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
                        "matched_at": range_query,
                    },
                }
            )

        return filters

    @staticmethod
    def _to_document(
        result: DetectionResult,
    ) -> dict[str, Any]:
        """
        Convert a validated DetectionResult into an OpenSearch document.
        """
        return {
            "detection_id": str(
                result.detection_id
            ),
            "rule_id": result.rule_id,
            "rule_name": result.rule_name,
            "event_id": str(
                result.event_id
            ),
            "severity": result.severity,
            "category": result.category,
            "description": result.description,
            "matched_at": result.matched_at.isoformat(),
            "tags": list(result.tags),
            "suppressed": result.suppressed,
        }

    @classmethod
    def _from_document(
        cls,
        source: dict[str, Any],
    ) -> DetectionResult:
        """
        Convert an OpenSearch document into a validated DetectionResult.
        """
        try:
            detection_id = UUID(
                str(source["detection_id"])
            )

            event_id = UUID(
                str(source["event_id"])
            )

            matched_at = cls._parse_datetime(
                str(source["matched_at"])
            )

            raw_tags = source.get(
                "tags",
                (),
            )

            if not isinstance(
                raw_tags,
                (list, tuple),
            ):
                raw_tags = ()

            tags = tuple(
                str(tag)
                for tag in raw_tags
            )

            return DetectionResult(
                detection_id=detection_id,
                rule_id=str(
                    source["rule_id"]
                ),
                rule_name=str(
                    source["rule_name"]
                ),
                event_id=event_id,
                severity=str(
                    source["severity"]
                ),
                category=str(
                    source["category"]
                ),
                description=str(
                    source.get(
                        "description",
                        "",
                    )
                ),
                matched_at=matched_at,
                tags=tags,
                suppressed=bool(
                    source.get(
                        "suppressed",
                        False,
                    )
                ),
            )

        except KeyError as exc:
            raise ValueError(
                f"invalid detection document; missing field: {exc}"
            ) from exc

    @staticmethod
    def _parse_datetime(
        value: str,
    ) -> datetime:
        """
        Parse an ISO-8601 timestamp and normalize naive timestamps to UTC.
        """
        parsed = datetime.fromisoformat(
            value.replace(
                "Z",
                "+00:00",
            )
        )

        if parsed.tzinfo is None:
            return parsed.replace(
                tzinfo=UTC
            )

        return parsed.astimezone(UTC)

    @staticmethod
    def _extract_total(
        total: Any,
    ) -> int:
        """
        Normalize OpenSearch total-hit formats.

        OpenSearch may return either:
            123

        or:
            {"value": 123, "relation": "eq"}
        """
        if isinstance(total, dict):
            return max(
                0,
                int(
                    total.get(
                        "value",
                        0,
                    )
                ),
            )

        return max(
            0,
            int(total),
        )

    @staticmethod
    def _normalize_rule_ids(
        rule_ids: Sequence[str] | None,
    ) -> tuple[str, ...]:
        """
        Normalize rule IDs while preserving input order and uniqueness.
        """
        if not rule_ids:
            return ()

        normalized: list[str] = []
        seen: set[str] = set()

        for rule_id in rule_ids:
            if not isinstance(
                rule_id,
                str,
            ):
                continue

            value = rule_id.strip()

            if not value or value in seen:
                continue

            seen.add(value)
            normalized.append(value)

        return tuple(normalized)

    @staticmethod
    def _validate_pagination(
        offset: int,
        limit: int,
    ) -> None:
        if offset < 0:
            raise ValueError(
                "offset must be >= 0"
            )

        if limit <= 0:
            raise ValueError(
                "limit must be > 0"
            )

    @staticmethod
    def _validate_time_range(
        start_time: datetime | None,
        end_time: datetime | None,
    ) -> None:
        if (
            start_time is not None
            and end_time is not None
            and start_time > end_time
        ):
            raise ValueError(
                "start_time must be less than or equal to end_time"
            )


__all__ = [
    "OpenSearchDetectionRepository",
]