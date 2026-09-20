"""OpenSearch persistence for SentinelSIEM Detection → MITRE mappings.

This repository owns only SentinelSIEM's runtime intelligence mappings:

    Detection Rule
        ↓
    MITRE Technique / Sub-Technique

MITRE ATT&CK knowledge itself is NOT stored here.

MITRE knowledge is dataset-owned and belongs to the PostgreSQL repository:

    backend/app/mitre/repository.py

This separation is intentional:

    MITRE ATT&CK Dataset
            ↓
    PostgreSQL MITRE Knowledge
            ↓
    Read-only MITRE API/UI

    SentinelSIEM Detections
            ↓
    Detection → MITRE Mapping
            ↓
    OpenSearch Mapping Index
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from opensearchpy import AsyncOpenSearch

from app.mitre.models import DetectionMapping


class MitreMappingRepository:
    """Persist and retrieve SentinelSIEM Detection → MITRE mappings."""

    INDEX_NAME = "siem-mitre-mappings-v1"

    INDEX_MAPPING: dict[str, Any] = {
        "dynamic": "strict",
        "properties": {
            "mapping_id": {
                "type": "keyword",
            },
            "detection_id": {
                "type": "keyword",
            },
            "technique_id": {
                "type": "keyword",
            },
            "subtechnique_id": {
                "type": "keyword",
            },
            "tactic_ids": {
                "type": "keyword",
            },
            "confidence": {
                "type": "float",
            },
            "source": {
                "type": "keyword",
            },
            "description": {
                "type": "text",
            },
            "created_at": {
                "type": "date",
            },
        },
    }

    MAX_RESULTS = 10_000

    def __init__(
        self,
        client: AsyncOpenSearch,
    ) -> None:
        self.client = client

    # ========================================================================
    # Index Management
    # ========================================================================

    async def ensure_index(self) -> None:
        """Create the mapping index if it does not already exist."""

        exists = await self.client.indices.exists(
            index=self.INDEX_NAME,
        )

        if exists:
            return

        await self.client.indices.create(
            index=self.INDEX_NAME,
            body={
                "mappings": self.INDEX_MAPPING,
            },
        )

    async def index_exists(self) -> bool:
        """Return whether the mapping index currently exists."""

        return bool(
            await self.client.indices.exists(
                index=self.INDEX_NAME,
            ),
        )

    # ========================================================================
    # Serialization
    # ========================================================================

    @staticmethod
    def _serialize(
        mapping: DetectionMapping,
    ) -> dict[str, Any]:
        """Convert a DetectionMapping into an OpenSearch document."""

        return {
            "mapping_id": str(mapping.mapping_id),
            "detection_id": str(mapping.detection_id),
            "technique_id": str(mapping.technique_id),
            "subtechnique_id": (
                str(mapping.subtechnique_id)
                if mapping.subtechnique_id is not None
                else None
            ),
            "tactic_ids": [
                str(tactic_id)
                for tactic_id in mapping.tactic_ids
            ],
            "confidence": float(mapping.confidence),
            "source": str(mapping.source),
            "description": str(mapping.description),
            "created_at": (
                mapping.created_at.astimezone(
                    timezone.utc,
                ).isoformat()
                if mapping.created_at.tzinfo is not None
                else mapping.created_at.replace(
                    tzinfo=timezone.utc,
                ).isoformat()
            ),
        }

    @staticmethod
    def _deserialize(
        source: dict[str, Any],
    ) -> DetectionMapping:
        """Convert an OpenSearch document into a DetectionMapping."""

        created_at = source.get("created_at")

        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(
                created_at.replace(
                    "Z",
                    "+00:00",
                ),
            )

        if not isinstance(created_at, datetime):
            created_at = datetime.now(
                timezone.utc,
            )

        if created_at.tzinfo is None:
            created_at = created_at.replace(
                tzinfo=timezone.utc,
            )

        return DetectionMapping(
            mapping_id=UUID(
                str(
                    source["mapping_id"],
                ),
            ),
            detection_id=str(
                source["detection_id"],
            ),
            technique_id=str(
                source["technique_id"],
            ),
            subtechnique_id=(
                str(
                    source["subtechnique_id"],
                )
                if source.get("subtechnique_id") is not None
                else None
            ),
            tactic_ids=tuple(
                str(item)
                for item in source.get(
                    "tactic_ids",
                    [],
                )
            ),
            confidence=float(
                source.get(
                    "confidence",
                    0.0,
                ),
            ),
            source=str(
                source.get(
                    "source",
                    "sentinelsiem",
                ),
            ),
            description=str(
                source.get(
                    "description",
                    "",
                ),
            ),
            created_at=created_at,
        )

    @classmethod
    def _deserialize_hit(
        cls,
        hit: dict[str, Any],
    ) -> DetectionMapping | None:
        """Deserialize one OpenSearch search hit safely."""

        source = hit.get("_source")

        if not isinstance(source, dict):
            return None

        return cls._deserialize(
            source,
        )

    # ========================================================================
    # Create / Upsert
    # ========================================================================

    async def save(
        self,
        mapping: DetectionMapping,
    ) -> DetectionMapping:
        """
        Persist a Detection → MITRE mapping.

        mapping_id is the OpenSearch document ID, making repeated writes
        idempotent.
        """

        await self.ensure_index()

        await self.client.index(
            index=self.INDEX_NAME,
            id=str(
                mapping.mapping_id,
            ),
            body=self._serialize(
                mapping,
            ),
            refresh="wait_for",
        )

        return mapping

    async def upsert(
        self,
        mapping: DetectionMapping,
    ) -> DetectionMapping:
        """Create or replace a mapping using its mapping ID."""

        return await self.save(
            mapping,
        )

    # ========================================================================
    # Get
    # ========================================================================

    async def get(
        self,
        mapping_id: UUID | str,
    ) -> DetectionMapping | None:
        """Return one mapping by mapping ID."""

        await self.ensure_index()

        try:
            response = await self.client.get(
                index=self.INDEX_NAME,
                id=str(
                    mapping_id,
                ),
            )
        except Exception as exc:
            if self._is_not_found(
                exc,
            ):
                return None

            raise

        source = response.get(
            "_source",
        )

        if not isinstance(source, dict):
            return None

        return self._deserialize(
            source,
        )

    # ========================================================================
    # List All
    # ========================================================================

    async def all(
        self,
    ) -> tuple[DetectionMapping, ...]:
        """Return all persisted Detection → MITRE mappings."""

        await self.ensure_index()

        response = await self.client.search(
            index=self.INDEX_NAME,
            body={
                "size": self.MAX_RESULTS,
                "track_total_hits": True,
                "query": {
                    "match_all": {},
                },
                "sort": [
                    {
                        "created_at": {
                            "order": "asc",
                        },
                    },
                    {
                        "mapping_id": {
                            "order": "asc",
                        },
                    },
                ],
            },
        )

        return self._deserialize_hits(
            response,
        )

    # ========================================================================
    # Detection Relationships
    # ========================================================================

    async def for_detection(
        self,
        detection_id: str,
    ) -> tuple[DetectionMapping, ...]:
        """Return all mappings belonging to one detection rule."""

        await self.ensure_index()

        response = await self.client.search(
            index=self.INDEX_NAME,
            body={
                "size": self.MAX_RESULTS,
                "track_total_hits": True,
                "query": {
                    "term": {
                        "detection_id": str(
                            detection_id,
                        ),
                    },
                },
                "sort": [
                    {
                        "technique_id": {
                            "order": "asc",
                        },
                    },
                    {
                        "subtechnique_id": {
                            "order": "asc",
                            "missing": "_last",
                        },
                    },
                    {
                        "mapping_id": {
                            "order": "asc",
                        },
                    },
                ],
            },
        )

        return self._deserialize_hits(
            response,
        )

    # ========================================================================
    # Technique Relationships
    # ========================================================================

    async def for_technique(
        self,
        technique_id: str,
    ) -> tuple[DetectionMapping, ...]:
        """
        Return all mappings for a top-level MITRE technique.

        The technique_id field represents the parent/top-level technique.
        Therefore mappings for its sub-techniques are included when their
        parent technique_id matches.
        """

        await self.ensure_index()

        response = await self.client.search(
            index=self.INDEX_NAME,
            body={
                "size": self.MAX_RESULTS,
                "track_total_hits": True,
                "query": {
                    "term": {
                        "technique_id": str(
                            technique_id,
                        ),
                    },
                },
                "sort": [
                    {
                        "subtechnique_id": {
                            "order": "asc",
                            "missing": "_last",
                        },
                    },
                    {
                        "mapping_id": {
                            "order": "asc",
                        },
                    },
                ],
            },
        )

        return self._deserialize_hits(
            response,
        )

    async def for_subtechnique(
        self,
        subtechnique_id: str,
    ) -> tuple[DetectionMapping, ...]:
        """Return mappings for one specific sub-technique."""

        await self.ensure_index()

        response = await self.client.search(
            index=self.INDEX_NAME,
            body={
                "size": self.MAX_RESULTS,
                "track_total_hits": True,
                "query": {
                    "term": {
                        "subtechnique_id": str(
                            subtechnique_id,
                        ),
                    },
                },
                "sort": [
                    {
                        "mapping_id": {
                            "order": "asc",
                        },
                    },
                ],
            },
        )

        return self._deserialize_hits(
            response,
        )

    # ========================================================================
    # Tactic Relationships
    # ========================================================================

    async def for_tactic(
        self,
        tactic_id: str,
    ) -> tuple[DetectionMapping, ...]:
        """Return mappings associated with one MITRE tactic."""

        await self.ensure_index()

        response = await self.client.search(
            index=self.INDEX_NAME,
            body={
                "size": self.MAX_RESULTS,
                "track_total_hits": True,
                "query": {
                    "term": {
                        "tactic_ids": str(
                            tactic_id,
                        ),
                    },
                },
                "sort": [
                    {
                        "technique_id": {
                            "order": "asc",
                        },
                    },
                    {
                        "subtechnique_id": {
                            "order": "asc",
                            "missing": "_last",
                        },
                    },
                    {
                        "mapping_id": {
                            "order": "asc",
                        },
                    },
                ],
            },
        )

        return self._deserialize_hits(
            response,
        )

    # ========================================================================
    # Existence / Duplicate Checks
    # ========================================================================

    async def exists(
        self,
        mapping_id: UUID | str,
    ) -> bool:
        """Return whether a mapping exists."""

        await self.ensure_index()

        try:
            response = await self.client.exists(
                index=self.INDEX_NAME,
                id=str(
                    mapping_id,
                ),
            )
        except Exception as exc:
            if self._is_not_found(
                exc,
            ):
                return False

            raise

        return bool(
            response,
        )

    async def exists_for_detection_and_technique(
        self,
        *,
        detection_id: str,
        technique_id: str,
        subtechnique_id: str | None = None,
    ) -> bool:
        """
        Return whether an equivalent Detection → MITRE mapping exists.

        mapping_id is not considered here. This is useful when preventing
        duplicate semantic mappings.
        """

        await self.ensure_index()

        must: list[dict[str, Any]] = [
            {
                "term": {
                    "detection_id": str(
                        detection_id,
                    ),
                },
            },
            {
                "term": {
                    "technique_id": str(
                        technique_id,
                    ),
                },
            },
        ]

        if subtechnique_id is None:
            must.append(
                {
                    "bool": {
                        "must_not": {
                            "exists": {
                                "field": "subtechnique_id",
                            },
                        },
                    },
                },
            )
        else:
            must.append(
                {
                    "term": {
                        "subtechnique_id": str(
                            subtechnique_id,
                        ),
                    },
                },
            )

        response = await self.client.search(
            index=self.INDEX_NAME,
            body={
                "size": 0,
                "track_total_hits": True,
                "query": {
                    "bool": {
                        "must": must,
                    },
                },
            },
        )

        total = (
            response
            .get("hits", {})
            .get("total", 0)
        )

        if isinstance(total, dict):
            total = total.get(
                "value",
                0,
            )

        return int(
            total,
        ) > 0

    # ========================================================================
    # Delete
    # ========================================================================

    async def delete(
        self,
        mapping_id: UUID | str,
    ) -> bool:
        """Delete one persisted Detection → MITRE mapping."""

        await self.ensure_index()

        try:
            response = await self.client.delete(
                index=self.INDEX_NAME,
                id=str(
                    mapping_id,
                ),
                refresh="wait_for",
            )
        except Exception as exc:
            if self._is_not_found(
                exc,
            ):
                return False

            raise

        return response.get(
            "result",
        ) in {
            "deleted",
            "noop",
        }

    async def delete_for_detection(
        self,
        detection_id: str,
    ) -> int:
        """
        Delete all MITRE mappings belonging to one detection.

        Returns the number of deleted documents.
        """

        await self.ensure_index()

        response = await self.client.delete_by_query(
            index=self.INDEX_NAME,
            body={
                "query": {
                    "term": {
                        "detection_id": str(
                            detection_id,
                        ),
                    },
                },
            },
            refresh=True,
            conflicts="proceed",
        )

        return int(
            response.get(
                "deleted",
                0,
            ),
        )

    # ========================================================================
    # Bulk Hydration
    # ========================================================================

    async def hydrate_registry(
        self,
    ) -> tuple[DetectionMapping, ...]:
        """
        Load persisted mappings for runtime hydration.

        The returned tuple is directly consumable by MappingRegistry.
        """

        return await self.all()

    # ========================================================================
    # Internal Search Helpers
    # ========================================================================

    @classmethod
    def _deserialize_hits(
        cls,
        response: dict[str, Any],
    ) -> tuple[DetectionMapping, ...]:
        """Deserialize OpenSearch hits into domain mappings."""

        hits = (
            response
            .get("hits", {})
            .get("hits", [])
        )

        mappings: list[DetectionMapping] = []

        for hit in hits:
            if not isinstance(
                hit,
                dict,
            ):
                continue

            mapping = cls._deserialize_hit(
                hit,
            )

            if mapping is not None:
                mappings.append(
                    mapping,
                )

        return tuple(
            mappings,
        )

    # ========================================================================
    # Error Helpers
    # ========================================================================

    @staticmethod
    def _is_not_found(
        exc: Exception,
    ) -> bool:
        """
        Detect OpenSearch 404 errors without depending on one concrete
        exception class.
        """

        status_code = getattr(
            exc,
            "status_code",
            None,
        )

        if status_code == 404:
            return True

        info = getattr(
            exc,
            "info",
            None,
        )

        if not isinstance(
            info,
            dict,
        ):
            return False

        if info.get(
            "status",
        ) == 404:
            return True

        error = info.get(
            "error",
        )

        if not isinstance(
            error,
            dict,
        ):
            return False

        return error.get(
            "type",
        ) in {
            "index_not_found_exception",
            "document_missing_exception",
        }


__all__ = [
    "MitreMappingRepository",
]