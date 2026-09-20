"""Runtime registry for SentinelSIEM Detection → MITRE ATT&CK mappings.

Architecture
------------

This registry represents SentinelSIEM's runtime mapping state.

It does NOT own the MITRE ATT&CK knowledge base.

MITRE knowledge:

    enterprise-attack.json
            ↓
       MitreImporter
            ↓
        PostgreSQL
            ↓
       MitreRepository

Detection mappings:

    Detection Rule
            ↓
    MappingRegistry
            ↓
    MitreMappingRepository
            ↓
        OpenSearch

A logical mapping is uniquely identified by:

    detection_id
    technique_id
    subtechnique_id

This allows one detection to map to multiple ATT&CK techniques while
preventing two conflicting mapping records for the same logical relationship.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Final
from uuid import UUID

from .models import DetectionMapping, NavigatorTechnique


# ============================================================================
# Types
# ============================================================================

MappingKey = tuple[
    str,
    str,
    str | None,
]


# ============================================================================
# Mapping Registry
# ============================================================================


class MappingRegistry:
    """In-memory registry for Detection → MITRE ATT&CK mappings.

    The registry is intentionally persistence-agnostic.

    Persistence is handled by ``MitreMappingRepository``. The registry is
    hydrated during application startup and updated when mapping operations
    occur.

    Uniqueness is based on the logical relationship:

        detection_id + technique_id + subtechnique_id

    ``mapping_id`` remains the stable identity of the individual persisted
    mapping record.
    """

    def __init__(
        self,
        mappings: Iterable[DetectionMapping] = (),
    ) -> None:
        self._items: dict[
            MappingKey,
            DetectionMapping,
        ] = {}

        self.hydrate(
            mappings,
        )

    # ========================================================================
    # Registration
    # ========================================================================

    def register(
        self,
        mapping: DetectionMapping,
    ) -> DetectionMapping:
        """
        Register a Detection → MITRE mapping.

        Identical existing mappings are idempotent.

        A mapping with the same logical key but different content is rejected.
        """

        self._validate_mapping(
            mapping,
        )

        key = self._key(
            mapping,
        )

        existing = self._items.get(
            key,
        )

        if existing is not None:
            if existing != mapping:
                raise ValueError(
                    "conflicting MITRE mapping: "
                    f"{key}",
                )

            return existing

        self._items[
            key
        ] = mapping

        return mapping

    def register_many(
        self,
        mappings: Iterable[DetectionMapping],
    ) -> int:
        """
        Register multiple mappings.

        Returns the number of newly registered mappings.

        The operation is atomic from the registry's perspective: if a
        conflicting mapping is encountered, the registry is restored to the
        state it had before this call.
        """

        incoming = tuple(
            mappings,
        )

        snapshot = dict(
            self._items,
        )

        added = 0

        try:
            for mapping in incoming:
                key = self._key(
                    mapping,
                )

                existing = self._items.get(
                    key,
                )

                if existing is None:
                    self.register(
                        mapping,
                    )
                    added += 1
                    continue

                if existing != mapping:
                    raise ValueError(
                        "conflicting MITRE mapping: "
                        f"{key}",
                    )

        except Exception:
            self._items = snapshot
            raise

        return added

    # ========================================================================
    # Retrieval
    # ========================================================================

    def all(
        self,
    ) -> tuple[DetectionMapping, ...]:
        """Return all mappings in deterministic logical-key order."""

        return tuple(
            self._items[key]
            for key in sorted(
                self._items,
                key=self._sort_key,
            )
        )

    def get(
        self,
        mapping_id: UUID | str,
    ) -> DetectionMapping:
        """
        Return a mapping by its stable UUID.

        Raises:
            KeyError:
                When the mapping does not exist.
        """

        normalized_id = str(
            mapping_id,
        )

        for mapping in self._items.values():
            if str(
                mapping.mapping_id,
            ) == normalized_id:
                return mapping

        raise KeyError(
            f"unknown MITRE mapping: {normalized_id}",
        )

    def find(
        self,
        mapping_id: UUID | str,
    ) -> DetectionMapping | None:
        """Return a mapping by UUID or ``None``."""

        normalized_id = str(
            mapping_id,
        )

        for mapping in self._items.values():
            if str(
                mapping.mapping_id,
            ) == normalized_id:
                return mapping

        return None

    def contains(
        self,
        mapping_id: UUID | str,
    ) -> bool:
        """Return whether a mapping UUID exists."""

        return (
            self.find(
                mapping_id,
            )
            is not None
        )

    # ========================================================================
    # Logical Lookup
    # ========================================================================

    def find_logical(
        self,
        *,
        detection_id: str,
        technique_id: str,
        subtechnique_id: str | None = None,
    ) -> DetectionMapping | None:
        """Return a mapping by its logical relationship key."""

        key = (
            str(
                detection_id,
            ),
            str(
                technique_id,
            ),
            (
                str(
                    subtechnique_id,
                )
                if subtechnique_id is not None
                else None
            ),
        )

        return self._items.get(
            key,
        )

    def exists_logical(
        self,
        *,
        detection_id: str,
        technique_id: str,
        subtechnique_id: str | None = None,
    ) -> bool:
        """Return whether a logical Detection → MITRE mapping exists."""

        return (
            self.find_logical(
                detection_id=detection_id,
                technique_id=technique_id,
                subtechnique_id=subtechnique_id,
            )
            is not None
        )

    # ========================================================================
    # Detection Relationships
    # ========================================================================

    def for_detection(
        self,
        detection_id: str,
    ) -> tuple[DetectionMapping, ...]:
        """Return all mappings belonging to one detection rule."""

        normalized_detection_id = str(
            detection_id,
        )

        return tuple(
            self._items[key]
            for key in sorted(
                self._items,
                key=self._sort_key,
            )
            if key[0]
            == normalized_detection_id
        )

    def detection_ids(
        self,
    ) -> frozenset[str]:
        """Return all detection IDs represented by the registry."""

        return frozenset(
            mapping.detection_id
            for mapping in self._items.values()
        )

    # ========================================================================
    # Technique Relationships
    # ========================================================================

    def for_technique(
        self,
        technique_id: str,
    ) -> tuple[DetectionMapping, ...]:
        """
        Return all mappings belonging to a top-level technique.

        Sub-technique mappings are included when their
        ``DetectionMapping.technique_id`` references the parent technique.
        """

        normalized_technique_id = str(
            technique_id,
        )

        return tuple(
            self._items[key]
            for key in sorted(
                self._items,
                key=self._sort_key,
            )
            if key[1]
            == normalized_technique_id
        )

    def for_subtechnique(
        self,
        subtechnique_id: str,
    ) -> tuple[DetectionMapping, ...]:
        """Return all mappings for one specific sub-technique."""

        normalized_subtechnique_id = str(
            subtechnique_id,
        )

        return tuple(
            self._items[key]
            for key in sorted(
                self._items,
                key=self._sort_key,
            )
            if key[2]
            == normalized_subtechnique_id
        )

    def mapped_technique_ids(
        self,
    ) -> frozenset[str]:
        """
        Return top-level technique IDs referenced by mappings.

        A mapping to ``T1059.001`` still contributes ``T1059`` here because
        ``technique_id`` is the parent/top-level technique field.
        """

        return frozenset(
            mapping.technique_id
            for mapping in self._items.values()
        )

    def mapped_subtechnique_ids(
        self,
    ) -> frozenset[str]:
        """Return explicitly mapped sub-technique IDs."""

        return frozenset(
            mapping.subtechnique_id
            for mapping in self._items.values()
            if mapping.subtechnique_id
            is not None
        )

    def mapped_technique_count(
        self,
    ) -> int:
        """Return the number of unique mapped top-level techniques."""

        return len(
            self.mapped_technique_ids(),
        )

    def mapped_subtechnique_count(
        self,
    ) -> int:
        """Return the number of unique mapped sub-techniques."""

        return len(
            self.mapped_subtechnique_ids(),
        )

    # ========================================================================
    # Tactic Relationships
    # ========================================================================

    def for_tactic(
        self,
        tactic_id: str,
    ) -> tuple[DetectionMapping, ...]:
        """Return mappings associated with a MITRE tactic."""

        normalized_tactic_id = str(
            tactic_id,
        )

        return tuple(
            self._items[key]
            for key in sorted(
                self._items,
                key=self._sort_key,
            )
            if normalized_tactic_id
            in mapping_tactic_ids(
                self._items[key],
            )
        )

    # ========================================================================
    # Coverage
    # ========================================================================

    def coverage_technique_ids(
        self,
    ) -> frozenset[str]:
        """
        Return the technique IDs considered covered by mappings.

        Coverage is represented at the top-level technique level.
        """

        return self.mapped_technique_ids()

    def coverage_subtechnique_ids(
        self,
    ) -> frozenset[str]:
        """Return explicitly covered sub-technique IDs."""

        return self.mapped_subtechnique_ids()

    # ========================================================================
    # ATT&CK Navigator
    # ========================================================================

    def navigator_techniques(
        self,
    ) -> list[NavigatorTechnique]:
        """
        Build ATT&CK Navigator technique entries.

        Multiple mappings for the same technique/sub-technique are merged.
        The highest confidence value is retained.

        Sub-techniques are represented by their explicit sub-technique IDs;
        otherwise the top-level technique ID is used.
        """

        scores: dict[str, float] = {}

        for mapping in self._items.values():
            navigator_id = (
                mapping.subtechnique_id
                or mapping.technique_id
            )

            confidence = float(
                mapping.confidence,
            )

            previous = scores.get(
                navigator_id,
                0.0,
            )

            scores[
                navigator_id
            ] = max(
                previous,
                confidence,
            )

        return [
            NavigatorTechnique(
                techniqueID=technique_id,
                score=score,
            )
            for technique_id, score in sorted(
                scores.items(),
            )
        ]

    # ========================================================================
    # Removal
    # ========================================================================

    def remove(
        self,
        mapping_id: UUID | str,
    ) -> DetectionMapping:
        """
        Remove a mapping by UUID.

        Raises:
            KeyError:
                When the mapping does not exist.
        """

        normalized_id = str(
            mapping_id,
        )

        for key, mapping in tuple(
            self._items.items(),
        ):
            if str(
                mapping.mapping_id,
            ) != normalized_id:
                continue

            del self._items[
                key
            ]

            return mapping

        raise KeyError(
            f"unknown MITRE mapping: {normalized_id}",
        )

    def remove_if_present(
        self,
        mapping_id: UUID | str,
    ) -> DetectionMapping | None:
        """Remove a mapping when present, otherwise return ``None``."""

        try:
            return self.remove(
                mapping_id,
            )
        except KeyError:
            return None

    def remove_for_detection(
        self,
        detection_id: str,
    ) -> tuple[DetectionMapping, ...]:
        """Remove all mappings belonging to one detection."""

        normalized_detection_id = str(
            detection_id,
        )

        removed: list[
            DetectionMapping
        ] = []

        for key in tuple(
            self._items,
        ):
            if key[0] != normalized_detection_id:
                continue

            removed.append(
                self._items.pop(
                    key,
                ),
            )

        return tuple(
            removed,
        )

    # ========================================================================
    # Registry State
    # ========================================================================

    def count(
        self,
    ) -> int:
        """Return the number of registered mappings."""

        return len(
            self._items,
        )

    def is_empty(
        self,
    ) -> bool:
        """Return whether the registry contains no mappings."""

        return not self._items

    def clear(
        self,
    ) -> None:
        """Remove all runtime mappings."""

        self._items.clear()

    # ========================================================================
    # Persistence Hydration
    # ========================================================================

    def hydrate(
        self,
        mappings: Iterable[DetectionMapping],
    ) -> int:
        """
        Load persisted mappings into the runtime registry.

        Existing identical mappings are ignored.

        Conflicting mappings are rejected.

        Returns:
            Number of mappings newly added by this hydration call.
        """

        incoming = tuple(
            mappings,
        )

        snapshot = dict(
            self._items,
        )

        added = 0

        try:
            for mapping in incoming:
                self._validate_mapping(
                    mapping,
                )

                key = self._key(
                    mapping,
                )

                existing = self._items.get(
                    key,
                )

                if existing is None:
                    self._items[
                        key
                    ] = mapping

                    added += 1
                    continue

                if existing != mapping:
                    raise ValueError(
                        "conflicting MITRE mapping "
                        f"during hydration: {key}",
                    )

        except Exception:
            self._items = snapshot
            raise

        return added

    # ========================================================================
    # Snapshot
    # ========================================================================

    def snapshot(
        self,
    ) -> tuple[DetectionMapping, ...]:
        """Return a deterministic immutable snapshot of registry state."""

        return self.all()

    # ========================================================================
    # Internal Helpers
    # ========================================================================

    @staticmethod
    def _key(
        mapping: DetectionMapping,
    ) -> MappingKey:
        """Build the logical uniqueness key."""

        return (
            str(
                mapping.detection_id,
            ),
            str(
                mapping.technique_id,
            ),
            (
                str(
                    mapping.subtechnique_id,
                )
                if mapping.subtechnique_id is not None
                else None
            ),
        )

    @staticmethod
    def _sort_key(
        key: MappingKey,
    ) -> tuple[str, str, str]:
        """Build a stable sorting key."""

        return (
            key[0],
            key[1],
            key[2] or "",
        )

    @staticmethod
    def _validate_mapping(
        mapping: DetectionMapping,
    ) -> None:
        """Validate minimum registry invariants."""

        if not isinstance(
            mapping,
            DetectionMapping,
        ):
            raise TypeError(
                "mapping must be a DetectionMapping instance",
            )

        if not str(
            mapping.detection_id,
        ).strip():
            raise ValueError(
                "MITRE mapping detection_id cannot be empty",
            )

        if not str(
            mapping.technique_id,
        ).strip():
            raise ValueError(
                "MITRE mapping technique_id cannot be empty",
            )

        if (
            mapping.subtechnique_id is not None
            and not str(
                mapping.subtechnique_id,
            ).strip()
        ):
            raise ValueError(
                "MITRE mapping subtechnique_id cannot be empty",
            )


# ============================================================================
# Module Helpers
# ============================================================================


def mapping_tactic_ids(
    mapping: DetectionMapping,
) -> frozenset[str]:
    """Return normalized tactic IDs from a mapping."""

    return frozenset(
        str(tactic_id).strip().upper()
        for tactic_id in mapping.tactic_ids
        if str(tactic_id).strip()
    )


# ============================================================================
# Default Registry
# ============================================================================


DEFAULT_MAPPING_REGISTRY: Final[
    MappingRegistry
] = MappingRegistry()


# ============================================================================
# Public API
# ============================================================================


__all__ = [
    "DEFAULT_MAPPING_REGISTRY",
    "MappingKey",
    "MappingRegistry",
    "mapping_tactic_ids",
]