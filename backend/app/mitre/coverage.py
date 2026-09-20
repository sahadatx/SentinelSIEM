"""MITRE ATT&CK coverage analysis and Navigator representation.

Architecture
------------

MITRE ATT&CK knowledge:

    enterprise-attack.json
            ↓
       MitreImporter
            ↓
        PostgreSQL
            ↓
      MitreRepository

SentinelSIEM intelligence:

    Detection Rules
            ↓
    Detection → MITRE mappings
            ↓
      MappingRegistry
            ↓
       CoverageAnalyzer

This module calculates coverage from the current runtime mapping registry.
It does not modify MITRE knowledge or detection mappings.

Coverage is evaluated at the top-level technique level while explicit
sub-technique mappings are considered when determining the state of a
parent technique.

Coverage states:

    FULL
    PARTIAL
    UNMAPPED
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from .mappings import MappingRegistry
from .models import (
    CoverageAnalytics,
    CoverageResult,
    CoverageState,
    NavigatorLayer,
    TechniqueCoverage,
)
from .techniques import TechniqueCatalog


class CoverageAnalyzer:
    """Calculate SentinelSIEM coverage of the MITRE ATT&CK taxonomy."""

    def __init__(
        self,
        catalog: TechniqueCatalog,
        mappings: MappingRegistry,
    ) -> None:
        self.catalog = catalog
        self.mappings = mappings

    # ========================================================================
    # Legacy / Aggregate Coverage
    # ========================================================================

    def calculate(self) -> CoverageResult:
        """
        Calculate aggregate MITRE coverage.

        A top-level technique is considered mapped when:

        1. The parent technique itself has a mapping, OR
        2. At least one of its sub-techniques has a mapping.

        The returned object preserves the existing aggregate coverage API.
        """

        all_technique_ids = self.catalog.ids()

        mapped_ids = set(
            self.mappings.mapped_technique_ids()
        ) & set(
            all_technique_ids,
        )

        # A parent technique receives coverage when at least one of its
        # sub-techniques is explicitly mapped.
        for technique in self.catalog.all():
            if technique.id in mapped_ids:
                continue

            children = (
                self.catalog.subtechniques_for_parent(
                    technique.id,
                )
            )

            if any(
                self.mappings.for_subtechnique(
                    child.id,
                )
                for child in children
            ):
                mapped_ids.add(
                    technique.id,
                )

        total = len(
            all_technique_ids,
        )

        mapped = len(
            mapped_ids,
        )

        coverage_percent = (
            round(
                (mapped / total) * 100.0,
                2,
            )
            if total
            else 0.0
        )

        unmapped_ids = (
            set(all_technique_ids)
            - mapped_ids
        )

        return CoverageResult(
            total_techniques=total,
            mapped_techniques=mapped,
            coverage_percent=coverage_percent,
            mapped_technique_ids=tuple(
                sorted(
                    mapped_ids,
                ),
            ),
            unmapped_technique_ids=tuple(
                sorted(
                    unmapped_ids,
                ),
            ),
        )

    # ========================================================================
    # Single Technique Coverage
    # ========================================================================

    def technique_coverage(
        self,
        technique_id: str,
    ) -> TechniqueCoverage:
        """
        Calculate detailed coverage for one top-level technique.

        Rules
        -----

        Parent directly mapped:
            FULL

        No sub-techniques + no parent mapping:
            UNMAPPED

        Has sub-techniques + none mapped:
            UNMAPPED

        Has sub-techniques + some mapped:
            PARTIAL

        Has sub-techniques + every sub-technique mapped:
            FULL
        """

        technique = self.catalog.get(
            technique_id,
        )

        mappings = self.mappings.for_technique(
            technique.id,
        )

        subtechniques = (
            self.catalog.subtechniques_for_parent(
                technique.id,
            )
        )

        mapped_subtechniques = tuple(
            subtechnique
            for subtechnique in subtechniques
            if self.mappings.for_subtechnique(
                subtechnique.id,
            )
        )

        parent_mapped = any(
            mapping.subtechnique_id is None
            for mapping in mappings
        )

        mapping_count = len(
            mappings,
        )

        detection_ids = {
            mapping.detection_id
            for mapping in mappings
        }

        detection_count = len(
            detection_ids,
        )

        subtechnique_count = len(
            subtechniques,
        )

        mapped_subtechnique_count = len(
            mapped_subtechniques,
        )

        confidence = self._average_confidence(
            mappings,
        )

        state = self._calculate_state(
            parent_mapped=parent_mapped,
            subtechnique_count=subtechnique_count,
            mapped_subtechnique_count=(
                mapped_subtechnique_count
            ),
        )

        return TechniqueCoverage(
            technique_id=technique.id,
            state=state,
            mapping_count=mapping_count,
            detection_count=detection_count,
            subtechnique_count=subtechnique_count,
            mapped_subtechnique_count=(
                mapped_subtechnique_count
            ),
            confidence=confidence,
        )

    def all_technique_coverage(
        self,
    ) -> tuple[TechniqueCoverage, ...]:
        """Calculate coverage for every top-level technique."""

        return tuple(
            self.technique_coverage(
                technique.id,
            )
            for technique in self.catalog.all()
        )

    # ========================================================================
    # Coverage State
    # ========================================================================

    @staticmethod
    def _calculate_state(
        *,
        parent_mapped: bool,
        subtechnique_count: int,
        mapped_subtechnique_count: int,
    ) -> CoverageState:
        """Calculate the coverage state for one parent technique."""

        if parent_mapped:
            return CoverageState.FULL

        if subtechnique_count == 0:
            return CoverageState.UNMAPPED

        if mapped_subtechnique_count == 0:
            return CoverageState.UNMAPPED

        if (
            mapped_subtechnique_count
            == subtechnique_count
        ):
            return CoverageState.FULL

        return CoverageState.PARTIAL

    # ========================================================================
    # Coverage Analytics
    # ========================================================================

    def analytics(
        self,
    ) -> CoverageAnalytics:
        """Build coverage analytics for the MITRE workspace."""

        techniques = self.catalog.all()

        coverage_items = (
            self.all_technique_coverage()
        )

        full = tuple(
            item
            for item in coverage_items
            if item.state
            is CoverageState.FULL
        )

        partial = tuple(
            item
            for item in coverage_items
            if item.state
            is CoverageState.PARTIAL
        )

        unmapped = tuple(
            item
            for item in coverage_items
            if item.state
            is CoverageState.UNMAPPED
        )

        total = len(
            techniques,
        )

        full_count = len(
            full,
        )

        coverage_percent = (
            round(
                (full_count / total) * 100.0,
                2,
            )
            if total
            else 0.0
        )

        by_tactic = self._coverage_by_tactic(
            coverage_items,
        )

        technique_detection_counts = (
            self._technique_detection_counts()
        )

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
            total_techniques=total,
            full_techniques=full_count,
            partial_techniques=len(
                partial,
            ),
            unmapped_techniques=len(
                unmapped,
            ),
            coverage_percent=coverage_percent,
            by_tactic=by_tactic,
            technique_detection_counts=(
                technique_detection_counts
            ),
            top_detected_technique_ids=top_detected,
        )

    # ========================================================================
    # Tactic Analytics
    # ========================================================================

    def _coverage_by_tactic(
        self,
        coverage_items: tuple[
            TechniqueCoverage,
            ...,
        ],
    ) -> dict[str, float]:
        """
        Calculate full-coverage percentage by tactic.

        A technique assigned to multiple tactics contributes to each of its
        assigned tactics.
        """

        states = {
            item.technique_id: item.state
            for item in coverage_items
        }

        tactic_total: dict[
            str,
            int,
        ] = defaultdict(int)

        tactic_full: dict[
            str,
            int,
        ] = defaultdict(int)

        for technique in self.catalog.all():
            for tactic_id in technique.tactic_ids:
                tactic_total[
                    tactic_id
                ] += 1

                if (
                    states.get(
                        technique.id,
                    )
                    is CoverageState.FULL
                ):
                    tactic_full[
                        tactic_id
                    ] += 1

        result: dict[
            str,
            float,
        ] = {}

        for tactic_id in sorted(
            tactic_total,
        ):
            total = tactic_total[
                tactic_id
            ]

            full = tactic_full[
                tactic_id
            ]

            result[
                tactic_id
            ] = (
                round(
                    (full / total) * 100.0,
                    2,
                )
                if total
                else 0.0
            )

        return result

    def coverage_for_tactic(
        self,
        tactic_id: str,
    ) -> float:
        """
        Return full-coverage percentage for one tactic.

        The tactic is evaluated against the techniques represented in the
        current catalog.
        """

        coverage_items = (
            self.all_technique_coverage()
        )

        technique_states = {
            item.technique_id: item.state
            for item in coverage_items
        }

        techniques = (
            technique
            for technique in self.catalog.all()
            if tactic_id in technique.tactic_ids
        )

        total = 0
        full = 0

        for technique in techniques:
            total += 1

            if (
                technique_states.get(
                    technique.id,
                )
                is CoverageState.FULL
            ):
                full += 1

        if total == 0:
            return 0.0

        return round(
            (full / total) * 100.0,
            2,
        )

    # ========================================================================
    # Detection Analytics
    # ========================================================================

    def _technique_detection_counts(
        self,
    ) -> dict[str, int]:
        """
        Return unique detection-rule counts by top-level technique.

        Techniques without mappings are omitted.
        """

        counts: dict[
            str,
            set[str],
        ] = defaultdict(
            set,
        )

        for mapping in self.mappings.all():
            counts[
                mapping.technique_id
            ].add(
                mapping.detection_id,
            )

        return {
            technique_id: len(
                detection_ids,
            )
            for technique_id, detection_ids
            in sorted(
                counts.items(),
            )
        }

    def detection_count_for_technique(
        self,
        technique_id: str,
    ) -> int:
        """Return the unique detection count for one technique."""

        mappings = self.mappings.for_technique(
            technique_id,
        )

        return len(
            {
                mapping.detection_id
                for mapping in mappings
            },
        )

    # ========================================================================
    # Navigator
    # ========================================================================

    def navigator_layer(
        self,
        name: str = "SentinelSIEM MITRE Coverage",
        description: str = "",
    ) -> NavigatorLayer:
        """
        Build an ATT&CK Navigator layer from current mappings.

        Navigator entries are generated by MappingRegistry, with duplicate
        technique references consolidated using the highest confidence score.
        """

        return NavigatorLayer(
            name=name,
            description=description,
            techniques=(
                self.mappings.navigator_techniques()
            ),
        )

    # ========================================================================
    # Technique IDs
    # ========================================================================

    def fully_covered_technique_ids(
        self,
    ) -> frozenset[str]:
        """Return IDs of fully covered top-level techniques."""

        return frozenset(
            item.technique_id
            for item in self.all_technique_coverage()
            if item.state
            is CoverageState.FULL
        )

    def partially_covered_technique_ids(
        self,
    ) -> frozenset[str]:
        """Return IDs of partially covered techniques."""

        return frozenset(
            item.technique_id
            for item in self.all_technique_coverage()
            if item.state
            is CoverageState.PARTIAL
        )

    def unmapped_technique_ids(
        self,
    ) -> frozenset[str]:
        """Return IDs of unmapped techniques."""

        return frozenset(
            item.technique_id
            for item in self.all_technique_coverage()
            if item.state
            is CoverageState.UNMAPPED
        )

    # ========================================================================
    # Helpers
    # ========================================================================

    @staticmethod
    def _average_confidence(
        mappings: Iterable,
    ) -> float:
        """Return average mapping confidence.

        Returns:
            ``0.0`` when there are no mappings.
        """

        values = tuple(
            float(
                mapping.confidence,
            )
            for mapping in mappings
        )

        if not values:
            return 0.0

        return round(
            sum(values) / len(values),
            4,
        )


__all__ = [
    "CoverageAnalyzer",
]