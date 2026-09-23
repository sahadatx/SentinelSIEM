"""
Application-facing MITRE ATT&CK service.

SentinelSIEM MITRE service boundary.

Architecture
------------

The MITRE subsystem has two deliberately separate data concerns.

1. MITRE ATT&CK Knowledge
-------------------------

    enterprise-attack.json
            │
            ▼
       MitreImporter
            │
            ▼
        PostgreSQL
            │
            ▼
      MitreRepository
            │
            ▼
        MitreService
            │
            ▼
          API/UI


2. SentinelSIEM Intelligence
----------------------------

    Detections / Events / Alerts / Incidents / IOCs
                │
                ▼
        Detection → MITRE mappings
                │
                ▼
           MitreManager
                │
                ▼
        Coverage / Navigator

Important architectural rules
------------------------------

- MITRE ATT&CK knowledge is dataset-backed.
- PostgreSQL is the authoritative source for imported MITRE knowledge.
- MITRE knowledge is read-only through this service.
- MITRE knowledge mutation is performed only by MitreImporter.
- Detection → MITRE mappings are NOT stored in the MITRE knowledge repository.
- MitreManager remains responsible for Detection → MITRE mappings,
  coverage, hydration, and Navigator functionality.
- API routes should depend on MitreService rather than directly reaching
  into MitreRepository, MitreManager, catalogs, or registries.

This service therefore acts as the application-facing composition boundary
between the authoritative MITRE knowledge repository and the existing
SentinelSIEM intelligence/mapping subsystem.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .manager import MitreManager
from .models import (
    CoverageAnalytics,
    DetectionMapping,
    MitreSubTechnique,
    MitreTactic,
    MitreTechnique,
    TechniqueCoverage,
    TechniqueDetail,
)
from .repository import (
    MitreRepository,
)


class MitreService:
    """
    Application-facing MITRE ATT&CK service.

    Two dependencies are intentionally maintained:

    ``repository``
        PostgreSQL-backed authoritative MITRE ATT&CK knowledge.

    ``manager``
        Existing SentinelSIEM Detection → MITRE mapping and coverage
        subsystem.

    The service never treats the runtime mapping registry as the source of
    truth for ATT&CK knowledge.
    """

    def __init__(
        self,
        repository: MitreRepository,
        manager: MitreManager | None = None,
    ) -> None:
        self.repository = repository

        self.manager = (
            manager
            if manager is not None
            else MitreManager()
        )

    # ========================================================================
    # MITRE ATT&CK Knowledge
    # ========================================================================

    # ------------------------------------------------------------------------
    # Tactics
    # ------------------------------------------------------------------------

    async def tactic(
        self,
        tactic_id: str,
    ) -> MitreTactic:
        """
        Return one MITRE ATT&CK tactic from PostgreSQL.
        """

        return await self.repository.get_tactic(
            tactic_id,
        )

    async def tactics(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[MitreTactic, ...]:
        """
        Return MITRE ATT&CK tactics from PostgreSQL.
        """

        return await self.repository.list_tactics(
            limit=limit,
            offset=offset,
        )

    async def tactic_count(
        self,
    ) -> int:
        """
        Return the number of imported MITRE tactics.
        """

        return await self.repository.count_tactics()

    # ------------------------------------------------------------------------
    # Platforms
    # ------------------------------------------------------------------------

    async def platforms(
        self,
    ) -> tuple[str, ...]:
        """
        Return imported MITRE ATT&CK platforms.

        Platform information is extracted from the authoritative ATT&CK
        dataset by the importer and stored in PostgreSQL.
        """

        return await self.repository.list_platforms()

    async def platform_count(
        self,
    ) -> int:
        """
        Return the number of imported MITRE platforms.
        """

        return await self.repository.count_platforms()

    # ------------------------------------------------------------------------
    # Techniques
    # ------------------------------------------------------------------------

    async def technique(
        self,
        technique_id: str,
    ) -> MitreTechnique:
        """
        Return one MITRE ATT&CK technique from PostgreSQL.
        """

        return await self.repository.get_technique(
            technique_id,
        )

    async def techniques(
        self,
        *,
        search: str | None = None,
        tactic: str | None = None,
        platform: str | None = None,
        technique_type: str | None = None,
        page: int = 1,
        page_size: int = 30,
    ) -> tuple[tuple[MitreTechnique, ...], int]:
        """
        Return MITRE ATT&CK techniques from PostgreSQL.

        The returned tuple contains:
            - the requested page of techniques;
            - the total number of techniques matching the filters.

        Supported filters:

        - search
        - tactic
        - platform
        - technique type
        - page
        - page size
        """

        techniques, total = await self.repository.list_techniques(
            search=search,
            tactic=tactic,
            platform=platform,
            technique_type=technique_type,
            page=page,
            page_size=page_size,
        )

        return tuple(techniques), total

    async def technique_count(
        self,
        *,
        top_level_only: bool = False,
    ) -> int:
        """
        Return the number of imported MITRE techniques.

        ``top_level_only=True`` excludes sub-techniques.
        """

        return await self.repository.count_techniques(
            top_level_only=top_level_only,
        )

    # ------------------------------------------------------------------------
    # Sub-techniques
    # ------------------------------------------------------------------------

    async def subtechnique(
        self,
        subtechnique_id: str,
    ) -> MitreSubTechnique:
        """
        Return one MITRE ATT&CK sub-technique.

        The repository-backed technique model is authoritative.
        """

        technique = await self.repository.get_technique(
            subtechnique_id,
        )

        if getattr(
            technique,
            "type",
            None,
        ) == "SUB_TECHNIQUE":
            return technique  # type: ignore[return-value]

        raise ValueError(
            f"MITRE object '{subtechnique_id}' is not a sub-technique.",
        )

    async def subtechniques(
        self,
        *,
        page: int = 1,
        page_size: int = 30,
    ) -> tuple[MitreSubTechnique, ...]:
        """
        Return imported MITRE sub-techniques.

        The repository's technique listing is used so the PostgreSQL
        knowledge base remains the single source of truth.
        """

        techniques = await self.repository.list_techniques(
            technique_type="SUB_TECHNIQUE",
            page=page,
            page_size=page_size,
        )

        return tuple(
            technique
            for technique in techniques
            if getattr(
                technique,
                "type",
                None,
            ) == "SUB_TECHNIQUE"
        )  # type: ignore[return-value]

    async def subtechnique_count(
        self,
    ) -> int:
        """
        Return the number of imported MITRE sub-techniques.
        """

        return await self.repository.count_subtechniques()

    async def subtechniques_for_parent(
        self,
        technique_id: str,
    ) -> tuple[MitreSubTechnique, ...]:
        """
        Return sub-techniques belonging to one parent technique.

        The parent and children are resolved from PostgreSQL rather than the
        old static TechniqueCatalog.
        """

        parent = await self.repository.get_technique(
            technique_id,
        )

        parent_uuid = getattr(
            parent,
            "id",
            None,
        )

        if parent_uuid is None:
            raise ValueError(
                f"MITRE technique '{technique_id}' has no database ID.",
            )

        return await self.repository.list_subtechniques(
            parent_uuid,
        )

    async def subtechnique_count_for_parent(
        self,
        technique_id: str,
    ) -> int:
        """
        Return the number of sub-techniques for one parent technique.
        """

        parent = await self.repository.get_technique(
            technique_id,
        )

        parent_uuid = getattr(
            parent,
            "id",
            None,
        )

        if parent_uuid is None:
            raise ValueError(
                f"MITRE technique '{technique_id}' has no database ID.",
            )

        return await self.repository.count_subtechniques_for_parent(
            parent_uuid,
        )

    # ------------------------------------------------------------------------
    # References
    # ------------------------------------------------------------------------

    async def references(
        self,
        technique_id: str,
    ) -> tuple[Any, ...]:
        """
        Return external references associated with a MITRE technique.
        """

        return await self.repository.list_references(
            technique_id,
        )

    # ------------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------------

    async def knowledge_relationships(
        self,
        *,
        technique_id: str | None = None,
        relationship_type: str | None = None,
    ) -> tuple[Any, ...]:
        """
        Return dataset-backed MITRE STIX relationships.

        This method concerns ATT&CK knowledge relationships only.

        It does NOT return SentinelSIEM Detection → MITRE mappings.
        """

        source_id = technique_id
        target_id = technique_id

        return await self.repository.list_relationships(
            source_id=source_id,
            target_id=target_id,
            relationship_type=relationship_type,
        )

    # ------------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------------

    async def statistics(
        self,
    ) -> dict[str, int]:
        """
        Return statistics for the PostgreSQL-backed MITRE knowledge base.
        """

        return await self.repository.statistics()

    # ========================================================================
    # Detection → MITRE Mapping
    # ========================================================================

    async def map_detection(
        self,
        *,
        detection_id: str,
        technique_id: str,
        subtechnique_id: str | None = None,
        tactic_ids: Iterable[str] = (),
        confidence: float = 1.0,
        source: str = "sentinelsiem",
        description: str = "",
    ) -> DetectionMapping:
        """
        Create a SentinelSIEM Detection → MITRE mapping.

        This operation deliberately remains under MitreManager.

        It does NOT mutate the PostgreSQL ATT&CK knowledge base.
        """

        mapping = DetectionMapping(
            detection_id=detection_id,
            technique_id=technique_id,
            subtechnique_id=subtechnique_id,
            tactic_ids=tuple(tactic_ids),
            confidence=confidence,
            source=source,
            description=description,
        )

        return await self.manager.map_detection(
            mapping,
        )

    async def mappings(
        self,
    ) -> tuple[DetectionMapping, ...]:
        """
        Return all SentinelSIEM Detection → MITRE mappings.
        """

        return await self.manager.all_mappings()

    async def mapping(
        self,
        mapping_id: str,
    ) -> DetectionMapping:
        """
        Return one SentinelSIEM Detection → MITRE mapping.
        """

        return await self.manager.get_mapping(
            mapping_id,
        )

    async def mappings_for_detection(
        self,
        detection_id: str,
    ) -> tuple[DetectionMapping, ...]:
        """
        Return mappings associated with one detection rule.
        """

        return await self.manager.mappings_for_detection(
            detection_id,
        )

    async def mappings_for_technique(
        self,
        technique_id: str,
    ) -> tuple[DetectionMapping, ...]:
        """
        Return Detection → MITRE mappings for one technique.
        """

        return await self.manager.mappings_for_technique(
            technique_id,
        )

    async def mappings_for_subtechnique(
        self,
        subtechnique_id: str,
    ) -> tuple[DetectionMapping, ...]:
        """
        Return Detection → MITRE mappings for one sub-technique.
        """

        return await self.manager.mappings_for_subtechnique(
            subtechnique_id,
        )

    async def remove_mapping(
        self,
        mapping_id: str,
    ) -> DetectionMapping:
        """
        Remove one Detection → MITRE mapping.
        """

        return await self.manager.remove_mapping(
            mapping_id,
        )

    # ========================================================================
    # Coverage
    # ========================================================================

    async def coverage(
        self,
    ) -> Any:
        """
        Calculate current SentinelSIEM MITRE detection coverage.

        Coverage is based on Detection → MITRE mappings and therefore
        remains owned by MitreManager.
        """

        return await self.manager.calculate_coverage()

    async def analytics(
        self,
    ) -> CoverageAnalytics:
        """
        Return coverage analytics for the PostgreSQL-backed
        MITRE ATT&CK knowledge universe.

        PostgreSQL is authoritative for the ATT&CK knowledge
        universe. MitreManager remains authoritative for
        Detection → MITRE mappings.
        """

        from .models import CoverageState

        page = 1
        page_size = 30
        all_techniques: list[MitreTechnique] = []

        # Load the complete PostgreSQL ATT&CK technique universe.
        while True:
            techniques, total = await self.repository.list_techniques(
                technique_type="TECHNIQUE",
                page=page,
                page_size=page_size,
            )

            all_techniques.extend(techniques)

            if len(all_techniques) >= total:
                break

            page += 1

        # Calculate coverage against the PostgreSQL universe.
        coverage_items: list[TechniqueCoverage] = []

        for technique in all_techniques:
            technique_id = str(
                getattr(
                    technique,
                    "external_id",
                    technique.id,
                ),
            ).strip().upper()

            coverage_items.append(
                await self._postgresql_technique_coverage(
                    technique_id,
                ),
            )

        coverage_tuple = tuple(coverage_items)

        full_count = sum(
            1
            for item in coverage_tuple
            if item.state is CoverageState.FULL
        )

        partial_count = sum(
            1
            for item in coverage_tuple
            if item.state is CoverageState.PARTIAL
        )

        unmapped_count = sum(
            1
            for item in coverage_tuple
            if item.state is CoverageState.UNMAPPED
        )

        total_techniques = len(all_techniques)

        coverage_percent = (
            round(
                (full_count / total_techniques) * 100.0,
                2,
            )
            if total_techniques
            else 0.0
        )

        # PostgreSQL-backed tactic coverage.
        by_tactic_counts: dict[str, dict[str, int]] = {}

        for technique, coverage in zip(
            all_techniques,
            coverage_tuple,
        ):
            for tactic_id in getattr(
                technique,
                "tactic_ids",
                (),
            ):
                normalized_tactic_id = str(
                    tactic_id,
                ).strip().upper()

                if not normalized_tactic_id:
                    continue

                bucket = by_tactic_counts.setdefault(
                    normalized_tactic_id,
                    {
                        "total": 0,
                        "full": 0,
                    },
                )

                bucket["total"] += 1

                if coverage.state is CoverageState.FULL:
                    bucket["full"] += 1

        by_tactic: dict[str, float] = {}

        for tactic_id, counts in by_tactic_counts.items():
            total = counts["total"]
            full = counts["full"]

            by_tactic[tactic_id] = (
                round(
                    (full / total) * 100.0,
                    2,
                )
                if total
                else 0.0
            )

        # Detection counts remain mapping-subsystem data.
        technique_detection_counts: dict[str, int] = {}

        for technique in all_techniques:
            technique_id = str(
                getattr(
                    technique,
                    "external_id",
                    technique.id,
                ),
            ).strip().upper()

            mappings = await self.manager.mappings_for_technique(
                technique_id,
            )

            detection_ids = {
                str(mapping.detection_id)
                for mapping in mappings
            }

            if detection_ids:
                technique_detection_counts[
                    technique_id
                ] = len(detection_ids)

        top_detected = tuple(
            technique_id
            for technique_id, _count in sorted(
                technique_detection_counts.items(),
                key=lambda item: (
                    -item[1],
                    item[0],
                ),
            )[:10]
        )

        return CoverageAnalytics(
            total_techniques=total_techniques,
            full_techniques=full_count,
            partial_techniques=partial_count,
            unmapped_techniques=unmapped_count,
            coverage_percent=coverage_percent,
            by_tactic=by_tactic,
            technique_detection_counts=(
                technique_detection_counts
            ),
            top_detected_technique_ids=top_detected,
        )

    async def technique_coverage(
        self,
        technique_id: str,
    ) -> TechniqueCoverage:
        """
        Return SentinelSIEM coverage state for one technique.
        """

        return await self.manager.technique_coverage(
            technique_id,
        )

    async def all_technique_coverage(
        self,
    ) -> tuple[TechniqueCoverage, ...]:
        """
        Return SentinelSIEM coverage states for all techniques known by the
        mapping subsystem.

        The mapping subsystem remains responsible for coverage calculation.
        """

        result = await self.manager.all_technique_coverage()

        return tuple(
            result,
        )

    # ========================================================================
    # ATT&CK Matrix
    # ========================================================================

    async def _postgresql_technique_coverage(
        self,
        technique_id: str,
    ) -> "TechniqueCoverage":
        """Calculate coverage for a PostgreSQL-backed ATT&CK technique.

        MITRE ATT&CK knowledge comes from PostgreSQL.
        Detection → MITRE mappings come from MitreManager.

        This intentionally does not consult the legacy TechniqueCatalog.
        """

        from .models import CoverageState, TechniqueCoverage

        normalized_id = str(
            technique_id,
        ).strip().upper()

        technique = await self.repository.get_technique(
            normalized_id,
        )

        if technique is None:
            raise KeyError(
                f"unknown MITRE technique: {normalized_id}",
            )

        technique_type = getattr(
            technique,
            "type",
            None,
        )

        if technique_type == "SUB_TECHNIQUE":
            raise ValueError(
                f"MITRE coverage requires a top-level technique: "
                f"{normalized_id}",
            )

        subtechniques = await self.subtechniques_for_parent(
            normalized_id,
        )

        mappings = await self.manager.mappings_for_technique(
            normalized_id,
        )

        parent_mapped = any(
            mapping.subtechnique_id is None
            for mapping in mappings
        )

        mapped_subtechnique_ids = {
            str(mapping.subtechnique_id).strip().upper()
            for mapping in mappings
            if mapping.subtechnique_id is not None
        }

        mapped_subtechnique_count = sum(
            1
            for subtechnique in subtechniques
            if str(subtechnique.id).strip().upper()
            in mapped_subtechnique_ids
        )

        mapping_count = len(
            mappings,
        )

        detection_count = len(
            {
                str(mapping.detection_id)
                for mapping in mappings
            },
        )

        subtechnique_count = len(
            subtechniques,
        )

        if parent_mapped:
            state = CoverageState.FULL
        elif subtechnique_count == 0:
            state = CoverageState.UNMAPPED
        elif mapped_subtechnique_count == 0:
            state = CoverageState.UNMAPPED
        elif mapped_subtechnique_count == subtechnique_count:
            state = CoverageState.FULL
        else:
            state = CoverageState.PARTIAL

        confidence_values = [
            float(mapping.confidence)
            for mapping in mappings
            if getattr(mapping, "confidence", None) is not None
        ]

        confidence = (
            sum(confidence_values) / len(confidence_values)
            if confidence_values
            else 0.0
        )

        return TechniqueCoverage(
            technique_id=normalized_id,
            state=state,
            mapping_count=mapping_count,
            detection_count=detection_count,
            subtechnique_count=subtechnique_count,
            mapped_subtechnique_count=mapped_subtechnique_count,
            confidence=confidence,
        )

    async def matrix(
        self,
    ) -> tuple[dict[str, object], ...]:
        """Build the complete MITRE matrix from PostgreSQL-backed knowledge.

        Each row contains:
            - technique;
            - coverage;
            - subtechniques;
            - mappings.

        The matrix intentionally loads all top-level techniques through
        repository pagination instead of depending on the legacy static
        TechniqueCatalog.
        """

        page = 1
        page_size = 30
        all_techniques = []

        while True:
            techniques, total = await self.repository.list_techniques(
                technique_type="TECHNIQUE",
                page=page,
                page_size=page_size,
            )

            all_techniques.extend(
                techniques,
            )

            if len(all_techniques) >= total:
                break

            page += 1

        rows: list[dict[str, object]] = []

        for technique in all_techniques:
            technique_id = str(
                getattr(
                    technique,
                    "external_id",
                    None,
                ) or technique.id,
            ).strip().upper()

            coverage = (
                await self._postgresql_technique_coverage(
                    technique_id,
                )
            )

            subtechniques = (
                await self.subtechniques_for_parent(
                    technique_id,
                )
            )

            mappings = (
                await self.manager.mappings_for_technique(
                    technique_id,
                )
            )

            rows.append(
                {
                    "technique": technique,
                    "coverage": coverage,
                    "subtechniques": subtechniques,
                    "mappings": mappings,
                }
            )

        return tuple(
            rows,
        )

    # ========================================================================
    # Technique Details
    # ========================================================================

    async def technique_detail(
        self,
        technique_id: str,
    ) -> TechniqueDetail:
        """
        Build the complete application-facing detail model for one MITRE
        ATT&CK technique or sub-technique.

        ATT&CK knowledge comes from PostgreSQL.

        Detection mappings and coverage come from MitreManager.

        TechniqueCoverage represents coverage for a top-level technique.
        Therefore a sub-technique such as T1001.001 uses the coverage
        identity of its parent technique T1001.
        """

        normalized_id = technique_id.strip().upper()

        if not normalized_id:
            raise ValueError(
                "MITRE technique ID cannot be empty."
            )

        # ---------------------------------------------------------------
        # Resolve ATT&CK knowledge from PostgreSQL.
        #
        # Supports both top-level techniques and sub-techniques.
        # ---------------------------------------------------------------

        technique = await self.repository.get_technique_any(
            normalized_id,
        )

        if technique is None:
            raise ValueError(
                f"unknown MITRE technique: {normalized_id}",
            )

        # ---------------------------------------------------------------
        # TechniqueCoverage only accepts top-level technique IDs.
        #
        # T1001       -> T1001
        # T1001.001   -> T1001
        # ---------------------------------------------------------------

        if isinstance(technique, MitreSubTechnique):
            coverage_technique_id = (
                technique.parent_id.strip().upper()
            )
        else:
            coverage_technique_id = normalized_id

        # ---------------------------------------------------------------
        # Resolve SentinelSIEM coverage.
        #
        # The ATT&CK PostgreSQL catalog is authoritative for knowledge.
        # If the operational mapping catalog has no entry for a valid
        # ATT&CK technique, expose an unmapped coverage state instead of
        # making the knowledge-detail endpoint fail.
        # ---------------------------------------------------------------

        try:
            coverage = await self.manager.technique_coverage(
                coverage_technique_id,
            )
        except KeyError:
            from .models import CoverageState, TechniqueCoverage

            coverage = TechniqueCoverage(
                technique_id=coverage_technique_id,
                state=CoverageState.UNMAPPED,
                mapping_count=0,
                detection_count=0,
                subtechnique_count=0,
                mapped_subtechnique_count=0,
                confidence=0.0,
            )

        # ---------------------------------------------------------------
        # Return children only when the requested object is a
        # top-level technique.
        # ---------------------------------------------------------------

        if isinstance(technique, MitreSubTechnique):
            subtechniques = ()
        else:
            subtechniques = (
                await self.subtechniques_for_parent(
                    normalized_id,
                )
            )

        # ---------------------------------------------------------------
        # Detection mappings belong to the operational mapping layer.
        # Use the same top-level coverage identity.
        # ---------------------------------------------------------------

        try:
            mappings = (
                await self.manager.mappings_for_technique(
                    coverage_technique_id,
                )
            )
        except KeyError:
            mappings = ()

        detection_ids = tuple(
            sorted(
                {
                    str(mapping.detection_id)
                    for mapping in mappings
                }
            )
        )

        # ---------------------------------------------------------------
        # Cross-module operational relationships remain empty until the
        # respective SentinelSIEM modules provide their relationship
        # providers.
        # ---------------------------------------------------------------

        return TechniqueDetail(
            technique=technique,
            coverage=coverage,
            subtechniques=subtechniques,
            mappings=mappings,
            detection_ids=detection_ids,
            event_ids=(),
            alert_ids=(),
            incident_ids=(),
            ioc_ids=(),
            asset_ids=(),
        )

    async def relationships_for_technique(
        self,
        technique_id: str,
    ) -> dict[str, object]:
        """
        Return currently available SentinelSIEM relationships for a
        technique.

        The response combines two distinct sources:

        ATT&CK knowledge:
            - sub-techniques

        SentinelSIEM intelligence:
            - detection IDs
            - mapping IDs

        Event, alert, incident, IOC, and asset relationships remain empty
        until those providers are integrated.
        """

        detail = await self.technique_detail(
            technique_id,
        )

        return {
            "technique_id": detail.technique.id,
            "detection_ids": detail.detection_ids,
            "event_ids": detail.event_ids,
            "alert_ids": detail.alert_ids,
            "incident_ids": detail.incident_ids,
            "ioc_ids": detail.ioc_ids,
            "asset_ids": detail.asset_ids,
            "mapping_ids": tuple(
                str(
                    mapping.mapping_id,
                )
                for mapping in detail.mappings
            ),
            "subtechnique_ids": tuple(
                subtechnique.id
                for subtechnique in detail.subtechniques
            ),
        }

    # ========================================================================
    # Navigator
    # ========================================================================

    async def navigator_layer(
        self,
        name: str = "SentinelSIEM MITRE Coverage",
        description: str = "MITRE ATT&CK detection coverage",
    ) -> Any:
        """
        Generate an ATT&CK Navigator layer for current SentinelSIEM
        Detection → MITRE coverage.
        """

        return await self.manager.navigator_layer(
            name=name,
            description=description,
        )

    # ========================================================================
    # Runtime Mapping State
    # ========================================================================

    async def hydrate(
        self,
    ) -> int:
        """
        Hydrate SentinelSIEM Detection → MITRE mappings.

        This does not import or mutate ATT&CK knowledge.
        """

        return await self.manager.hydrate()

    async def ensure_hydrated(
        self,
    ) -> None:
        """
        Ensure SentinelSIEM Detection → MITRE mappings are hydrated.
        """

        await self.manager.ensure_hydrated()

    @property
    def hydrated(
        self,
    ) -> bool:
        """
        Return whether SentinelSIEM runtime Detection → MITRE mappings
        have been hydrated.
        """

        return self.manager.hydrated


__all__ = [
    "MitreService",
]