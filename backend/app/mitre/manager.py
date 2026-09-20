"""MITRE ATT&CK orchestration layer.

Architecture
------------

The MITRE subsystem has two deliberately separate concerns.

1. MITRE ATT&CK knowledge

       enterprise-attack.json
                ↓
          MitreImporter
                ↓
            PostgreSQL
                ↓
         MitreRepository
                ↓
          MitreService/API

2. SentinelSIEM Detection → MITRE mappings

       Detection Rule
                ↓
         MitreManager
                ↓
        MappingRegistry
                ↓
     MitreMappingRepository
                ↓
           OpenSearch

``MitreManager`` owns the runtime mapping lifecycle.

It does NOT own the authoritative MITRE ATT&CK knowledge database.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from uuid import UUID

from .coverage import CoverageAnalyzer
from .mappings import MappingRegistry
from .models import DetectionMapping
from .tactics import TacticCatalog
from .techniques import TechniqueCatalog


class MitreManager:
    """Central orchestration layer for Detection → MITRE mappings.

    Responsibilities:

    - maintain the runtime mapping registry;
    - hydrate mappings from persistence;
    - validate mapping taxonomy relationships;
    - synchronize runtime mappings with persistence;
    - expose mapping queries;
    - calculate detection coverage;
    - generate ATT&CK Navigator layers.

    MITRE knowledge itself is intentionally not managed here. The
    dataset-backed MITRE knowledge layer is handled by the PostgreSQL
    repository/service stack.
    """

    def __init__(
        self,
        tactics: TacticCatalog | None = None,
        techniques: TechniqueCatalog | None = None,
        mappings: Iterable[DetectionMapping] = (),
        repository: object | None = None,
    ) -> None:
        self.tactics = (
            tactics
            if tactics is not None
            else TacticCatalog()
        )

        self.techniques = (
            techniques
            if techniques is not None
            else TechniqueCatalog()
        )

        self.mappings = MappingRegistry(
            mappings,
        )

        self.coverage = CoverageAnalyzer(
            catalog=self.techniques,
            mappings=self.mappings,
        )

        self.repository = repository

        self._hydrated = False

    # ========================================================================
    # Persistence / Hydration
    # ========================================================================

    async def hydrate(
        self,
    ) -> int:
        """
        Load persisted Detection → MITRE mappings into runtime state.

        Returns:
            Number of mappings newly added to the runtime registry.

        If no persistence repository is configured, hydration simply marks
        the manager as hydrated.
        """

        if self._hydrated:
            return 0

        if self.repository is None:
            self._hydrated = True
            return 0

        hydrate_registry = getattr(
            self.repository,
            "hydrate_registry",
            None,
        )

        if not callable(
            hydrate_registry,
        ):
            raise TypeError(
                "MITRE mapping repository must provide "
                "hydrate_registry()",
            )

        persisted = await hydrate_registry()

        if persisted is None:
            persisted = ()

        added = self.mappings.hydrate(
            persisted,
        )

        self._hydrated = True

        return added

    @property
    def hydrated(
        self,
    ) -> bool:
        """Return whether runtime mappings have been hydrated."""

        return self._hydrated

    async def ensure_hydrated(
        self,
    ) -> None:
        """Ensure persisted mappings are loaded exactly once."""

        if self._hydrated:
            return

        await self.hydrate()

    async def refresh_from_persistence(
        self,
    ) -> int:
        """
        Replace runtime mapping state with persisted mappings.

        This is intended for controlled re-synchronization after external
        persistence changes.

        Returns:
            Number of mappings hydrated into the refreshed registry.
        """

        if self.repository is None:
            self.mappings.clear()
            self._hydrated = True
            return 0

        hydrate_registry = getattr(
            self.repository,
            "hydrate_registry",
            None,
        )

        if not callable(
            hydrate_registry,
        ):
            raise TypeError(
                "MITRE mapping repository must provide "
                "hydrate_registry()",
            )

        persisted = await hydrate_registry()

        if persisted is None:
            persisted = ()

        self.mappings.clear()

        added = self.mappings.hydrate(
            persisted,
        )

        self._hydrated = True

        return added

    # ========================================================================
    # Mapping Creation
    # ========================================================================

    async def map_detection(
        self,
        mapping: DetectionMapping,
    ) -> DetectionMapping:
        """
        Validate, register, and persist a Detection → MITRE mapping.

        Runtime state is updated only after persistence succeeds.

        This prevents the runtime registry from becoming inconsistent with
        OpenSearch when persistence fails.
        """

        await self.ensure_hydrated()

        self._validate_mapping(
            mapping,
        )

        logical_existing = (
            self.mappings.find_logical(
                detection_id=mapping.detection_id,
                technique_id=mapping.technique_id,
                subtechnique_id=mapping.subtechnique_id,
            )
        )

        if logical_existing is not None:
            if logical_existing != mapping:
                raise ValueError(
                    "conflicting MITRE mapping: "
                    f"{self.mappings._key(mapping)}",
                )

            return logical_existing

        if self.repository is not None:
            save = getattr(
                self.repository,
                "save",
                None,
            )

            if not callable(
                save,
            ):
                raise TypeError(
                    "MITRE mapping repository must provide save()",
                )

            persisted = await save(
                mapping,
            )

            # The repository may return the persisted domain object. If it
            # does, prefer it; otherwise retain the submitted mapping.
            registered_mapping = (
                persisted
                if isinstance(
                    persisted,
                    DetectionMapping,
                )
                else mapping
            )

            self._validate_mapping(
                registered_mapping,
            )

            self.mappings.register(
                registered_mapping,
            )

            return registered_mapping

        return self.mappings.register(
            mapping,
        )

    async def map_detection_many(
        self,
        mappings: Iterable[DetectionMapping],
    ) -> int:
        """
        Persist and register multiple mappings.

        Persistence is performed one mapping at a time because the existing
        mapping repository exposes individual ``save()`` operations.

        Returns:
            Number of newly registered mappings.
        """

        incoming = tuple(
            mappings,
        )

        # Validate the complete input before modifying runtime state.
        for mapping in incoming:
            self._validate_mapping(
                mapping,
            )

        added = 0

        for mapping in incoming:
            before = self.mappings.find_logical(
                detection_id=mapping.detection_id,
                technique_id=mapping.technique_id,
                subtechnique_id=mapping.subtechnique_id,
            )

            await self.map_detection(
                mapping,
            )

            if before is None:
                added += 1

        return added

    # ========================================================================
    # Mapping Retrieval
    # ========================================================================

    async def get_mapping(
        self,
        mapping_id: UUID | str,
    ) -> DetectionMapping:
        """Return one runtime mapping by stable mapping UUID."""

        await self.ensure_hydrated()

        return self.mappings.get(
            mapping_id,
        )

    async def find_mapping(
        self,
        mapping_id: UUID | str,
    ) -> DetectionMapping | None:
        """Return one mapping by UUID or ``None``."""

        await self.ensure_hydrated()

        return self.mappings.find(
            mapping_id,
        )

    async def all_mappings(
        self,
    ) -> tuple[DetectionMapping, ...]:
        """Return all hydrated runtime mappings."""

        await self.ensure_hydrated()

        return self.mappings.all()

    # ========================================================================
    # Detection Relationships
    # ========================================================================

    async def mappings_for_detection(
        self,
        detection_id: str,
    ) -> tuple[DetectionMapping, ...]:
        """Return mappings associated with one detection rule."""

        await self.ensure_hydrated()

        return self.mappings.for_detection(
            detection_id,
        )

    async def remove_mappings_for_detection(
        self,
        detection_id: str,
    ) -> tuple[DetectionMapping, ...]:
        """
        Remove all mappings belonging to one detection.

        Persistence is deleted first. Runtime state is changed only after
        persistence succeeds.
        """

        await self.ensure_hydrated()

        mappings = self.mappings.for_detection(
            detection_id,
        )

        if not mappings:
            return ()

        if self.repository is not None:
            delete_for_detection = getattr(
                self.repository,
                "delete_for_detection",
                None,
            )

            if callable(
                delete_for_detection,
            ):
                await delete_for_detection(
                    detection_id,
                )
            else:
                delete = getattr(
                    self.repository,
                    "delete",
                    None,
                )

                if not callable(
                    delete,
                ):
                    raise TypeError(
                        "MITRE mapping repository must provide "
                        "delete_for_detection() or delete()",
                    )

                for mapping in mappings:
                    deleted = await delete(
                        mapping.mapping_id,
                    )

                    if not deleted:
                        raise KeyError(
                            "MITRE mapping not found in persistence: "
                            f"{mapping.mapping_id}",
                        )

        return self.mappings.remove_for_detection(
            detection_id,
        )

    # ========================================================================
    # Technique Relationships
    # ========================================================================

    async def mappings_for_technique(
        self,
        technique_id: str,
    ) -> tuple[DetectionMapping, ...]:
        """Return mappings associated with a top-level technique.

        MITRE knowledge is authoritative in PostgreSQL.
        This method only queries the SentinelSIEM Detection → MITRE
        mapping registry and therefore must not depend on the legacy
        static TechniqueCatalog.
        """

        await self.ensure_hydrated()

        normalized_id = str(
            technique_id,
        ).strip().upper()

        if not normalized_id:
            raise ValueError(
                "MITRE technique_id cannot be empty",
            )

        return self.mappings.for_technique(
            normalized_id,
        )

    async def mappings_for_subtechnique(
        self,
        subtechnique_id: str,
    ) -> tuple[DetectionMapping, ...]:
        """Return mappings associated with a specific sub-technique."""

        await self.ensure_hydrated()

        self.techniques.get_subtechnique(
            subtechnique_id,
        )

        return self.mappings.for_subtechnique(
            subtechnique_id,
        )

    async def mappings_for_tactic(
        self,
        tactic_id: str,
    ) -> tuple[DetectionMapping, ...]:
        """Return mappings associated with a MITRE tactic."""

        await self.ensure_hydrated()

        self.tactics.get(
            tactic_id,
        )

        return self.mappings.for_tactic(
            tactic_id,
        )

    # ========================================================================
    # Mapping Removal
    # ========================================================================

    async def remove_mapping(
        self,
        mapping_id: UUID | str,
    ) -> DetectionMapping:
        """
        Remove one mapping from persistence and runtime.

        Persistence is changed first. Runtime state is removed only after
        successful persistence deletion.
        """

        await self.ensure_hydrated()

        mapping = self.mappings.get(
            mapping_id,
        )

        if self.repository is not None:
            delete = getattr(
                self.repository,
                "delete",
                None,
            )

            if not callable(
                delete,
            ):
                raise TypeError(
                    "MITRE mapping repository must provide delete()",
                )

            deleted = await delete(
                mapping_id,
            )

            if not deleted:
                raise KeyError(
                    "MITRE mapping not found in persistence: "
                    f"{mapping_id}",
                )

        self.mappings.remove(
            mapping_id,
        )

        return mapping

    # ========================================================================
    # Coverage
    # ========================================================================

    async def calculate_coverage(
        self,
    ) -> Any:
        """Calculate current MITRE detection coverage."""

        await self.ensure_hydrated()

        return self.coverage.calculate()

    async def coverage_analytics(
        self,
    ) -> Any:
        """Calculate detailed MITRE coverage analytics."""

        await self.ensure_hydrated()

        return self.coverage.analytics()

    async def technique_coverage(
        self,
        technique_id: str,
    ) -> Any:
        """Calculate detailed coverage for one top-level technique."""

        await self.ensure_hydrated()

        return self.coverage.technique_coverage(
            technique_id,
        )

    async def all_technique_coverage(
        self,
    ) -> tuple[Any, ...]:
        """Calculate coverage for all top-level techniques."""

        await self.ensure_hydrated()

        return self.coverage.all_technique_coverage()

    # ========================================================================
    # ATT&CK Navigator
    # ========================================================================

    async def navigator_layer(
        self,
        *,
        name: str = "SentinelSIEM MITRE Coverage",
        description: str = "MITRE ATT&CK detection coverage",
    ) -> Any:
        """Build an ATT&CK Navigator layer from current mappings."""

        await self.ensure_hydrated()

        return self.coverage.navigator_layer(
            name=name,
            description=description,
        )

    # ========================================================================
    # Validation
    # ========================================================================

    def validate_mapping(
        self,
        mapping: DetectionMapping,
    ) -> None:
        """Public mapping validation entry point."""

        self._validate_mapping(
            mapping,
        )

    def _validate_mapping(
        self,
        mapping: DetectionMapping,
    ) -> None:
        """
        Validate the taxonomy relationships of a DetectionMapping.

        Validation rules:

        - parent technique must exist;
        - sub-technique must exist when supplied;
        - supplied sub-technique must belong to the supplied parent;
        - every supplied tactic must exist.
        """

        if not isinstance(
            mapping,
            DetectionMapping,
        ):
            raise TypeError(
                "mapping must be a DetectionMapping instance",
            )

        detection_id = str(
            mapping.detection_id,
        ).strip()

        technique_id = str(
            mapping.technique_id,
        ).strip().upper()

        if not detection_id:
            raise ValueError(
                "MITRE mapping detection_id cannot be empty",
            )

        if not technique_id:
            raise ValueError(
                "MITRE mapping technique_id cannot be empty",
            )

        # ---------------------------------------------------------------
        # Parent technique
        # ---------------------------------------------------------------

        parent = self.techniques.get(
            technique_id,
        )

        # ---------------------------------------------------------------
        # Sub-technique
        # ---------------------------------------------------------------

        if mapping.subtechnique_id is not None:
            subtechnique_id = str(
                mapping.subtechnique_id,
            ).strip().upper()

            if not subtechnique_id:
                raise ValueError(
                    "MITRE mapping subtechnique_id cannot be empty",
                )

            subtechnique = (
                self.techniques.get_subtechnique(
                    subtechnique_id,
                )
            )

            expected_parent = str(
                subtechnique.parent_id,
            ).strip().upper()

            if expected_parent != technique_id:
                raise ValueError(
                    f"{subtechnique_id} is not a child of "
                    f"{technique_id}",
                )

        # ---------------------------------------------------------------
        # Tactics
        # ---------------------------------------------------------------

        unknown_tactics = (
            set(
                str(tactic_id).strip().upper()
                for tactic_id in mapping.tactic_ids
                if str(tactic_id).strip()
            )
            - set(
                self.tactics.ids(),
            )
        )

        if unknown_tactics:
            raise ValueError(
                "unknown MITRE tactics: "
                f"{sorted(unknown_tactics)}",
            )

        # Keep this variable intentionally referenced so static analyzers
        # understand that successful parent lookup is part of validation.
        _ = parent

    # ========================================================================
    # Runtime State
    # ========================================================================

    def reset_runtime_mappings(
        self,
    ) -> None:
        """
        Clear runtime mappings without touching persistence.

        This is primarily intended for:

        - tests;
        - controlled runtime rehydration;
        - application lifecycle management.
        """

        self.mappings.clear()

        self._hydrated = False

    def runtime_mapping_count(
        self,
    ) -> int:
        """Return the current runtime mapping count."""

        return self.mappings.count()

    def runtime_is_empty(
        self,
    ) -> bool:
        """Return whether the runtime registry is empty."""

        return self.mappings.is_empty()


__all__ = [
    "MitreManager",
]