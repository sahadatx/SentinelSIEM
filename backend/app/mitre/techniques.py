"""MITRE ATT&CK technique domain catalog for SentinelSIEM.

Architecture
------------

The authoritative MITRE ATT&CK knowledge source is the official dataset:

    backend/data/mitre/enterprise-attack.json

The dataset is imported into PostgreSQL by ``MitreImporter``.

This module is therefore NOT the authoritative production knowledge store.
It provides a compatibility/domain catalog for:

- technique ID validation;
- sub-technique parent validation;
- deterministic taxonomy traversal;
- matrix-oriented consumers;
- existing runtime mapping validation;
- tests and backward-compatible callers.

Detection → MITRE mappings remain separate from this taxonomy.
They are persisted by the OpenSearch mapping repository.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Final

from .models import MitreSubTechnique, MitreTechnique


# ============================================================================
# Compatibility Technique Catalog
# ============================================================================
#
# NOTE:
# These entries preserve the existing SentinelSIEM domain catalog.
#
# They are NOT intended to replace the official ATT&CK dataset. Once the
# PostgreSQL-backed MITRE service is used by the API, dataset-backed data
# should be preferred over this compatibility catalog.
# ============================================================================


DEFAULT_TECHNIQUES: Final[tuple[MitreTechnique, ...]] = (
    MitreTechnique(
        id="T1059",
        name="Command and Scripting Interpreter",
        tactic_ids=("TA0002",),
    ),
    MitreTechnique(
        id="T1078",
        name="Valid Accounts",
        tactic_ids=(
            "TA0001",
            "TA0003",
            "TA0004",
            "TA0005",
        ),
    ),
    MitreTechnique(
        id="T1110",
        name="Brute Force",
        tactic_ids=("TA0006",),
    ),
    MitreTechnique(
        id="T1021",
        name="Remote Services",
        tactic_ids=("TA0008",),
    ),
    MitreTechnique(
        id="T1046",
        name="Network Service Scanning",
        tactic_ids=("TA0007",),
    ),
    MitreTechnique(
        id="T1087",
        name="Account Discovery",
        tactic_ids=("TA0007",),
    ),
    MitreTechnique(
        id="T1053",
        name="Scheduled Task/Job",
        tactic_ids=(
            "TA0003",
            "TA0004",
        ),
    ),
    MitreTechnique(
        id="T1548",
        name="Abuse Elevation Control Mechanism",
        tactic_ids=(
            "TA0004",
            "TA0005",
        ),
    ),
    MitreTechnique(
        id="T1562",
        name="Impair Defenses",
        tactic_ids=("TA0005",),
    ),
    MitreTechnique(
        id="T1003",
        name="OS Credential Dumping",
        tactic_ids=("TA0006",),
    ),
    MitreTechnique(
        id="T1555",
        name="Credentials from Password Stores",
        tactic_ids=("TA0006",),
    ),
    MitreTechnique(
        id="T1082",
        name="System Information Discovery",
        tactic_ids=("TA0007",),
    ),
    MitreTechnique(
        id="T1057",
        name="Process Discovery",
        tactic_ids=("TA0007",),
    ),
    MitreTechnique(
        id="T1105",
        name="Ingress Tool Transfer",
        tactic_ids=("TA0011",),
    ),
    MitreTechnique(
        id="T1071",
        name="Application Layer Protocol",
        tactic_ids=("TA0011",),
    ),
)


DEFAULT_SUBTECHNIQUES: Final[
    tuple[MitreSubTechnique, ...]
] = (
    MitreSubTechnique(
        id="T1059.001",
        name="PowerShell",
        parent_id="T1059",
        tactic_ids=("TA0002",),
    ),
    MitreSubTechnique(
        id="T1059.004",
        name="Unix Shell",
        parent_id="T1059",
        tactic_ids=("TA0002",),
    ),
    MitreSubTechnique(
        id="T1110.001",
        name="Password Guessing",
        parent_id="T1110",
        tactic_ids=("TA0006",),
    ),
    MitreSubTechnique(
        id="T1110.003",
        name="Password Spraying",
        parent_id="T1110",
        tactic_ids=("TA0006",),
    ),
    MitreSubTechnique(
        id="T1021.004",
        name="SSH",
        parent_id="T1021",
        tactic_ids=("TA0008",),
    ),
    MitreSubTechnique(
        id="T1078.004",
        name="Cloud Accounts",
        parent_id="T1078",
        tactic_ids=(
            "TA0001",
            "TA0003",
            "TA0004",
            "TA0005",
        ),
    ),
    MitreSubTechnique(
        id="T1003.001",
        name="LSASS Memory",
        parent_id="T1003",
        tactic_ids=("TA0006",),
    ),
    MitreSubTechnique(
        id="T1071.001",
        name="Web Protocols",
        parent_id="T1071",
        tactic_ids=("TA0011",),
    ),
)


# ============================================================================
# Lookup Constants
# ============================================================================


TECHNIQUE_IDS: Final[frozenset[str]] = frozenset(
    technique.id
    for technique in DEFAULT_TECHNIQUES
)

SUBTECHNIQUE_IDS: Final[frozenset[str]] = frozenset(
    subtechnique.id
    for subtechnique in DEFAULT_SUBTECHNIQUES
)

ALL_TECHNIQUE_IDS: Final[frozenset[str]] = (
    TECHNIQUE_IDS | SUBTECHNIQUE_IDS
)


# ============================================================================
# Technique Catalog
# ============================================================================


class TechniqueCatalog:
    """In-memory MITRE ATT&CK technique compatibility catalog.

    Top-level techniques and sub-techniques are indexed separately while
    retaining the ATT&CK parent → child relationship.

    The catalog validates:

    - duplicate technique IDs;
    - duplicate sub-technique IDs;
    - cross-category ID collisions;
    - valid sub-technique parents;
    - valid non-empty identifiers.
    """

    def __init__(
        self,
        techniques: Iterable[MitreTechnique] = DEFAULT_TECHNIQUES,
        subtechniques: Iterable[
            MitreSubTechnique
        ] = DEFAULT_SUBTECHNIQUES,
    ) -> None:
        technique_items = tuple(
            techniques,
        )

        subtechnique_items = tuple(
            subtechniques,
        )

        self._tech: dict[
            str,
            MitreTechnique,
        ] = {}

        self._sub: dict[
            str,
            MitreSubTechnique,
        ] = {}

        # --------------------------------------------------------------------
        # Top-level technique validation
        # --------------------------------------------------------------------

        for technique in technique_items:
            technique_id = self._normalize_id(
                technique.id,
            )

            if technique_id in self._tech:
                raise ValueError(
                    "duplicate MITRE technique ID: "
                    f"{technique_id}",
                )

            self._tech[
                technique_id
            ] = technique

        # --------------------------------------------------------------------
        # Sub-technique validation
        # --------------------------------------------------------------------

        for subtechnique in subtechnique_items:
            subtechnique_id = self._normalize_id(
                subtechnique.id,
            )

            if subtechnique_id in self._sub:
                raise ValueError(
                    "duplicate MITRE sub-technique ID: "
                    f"{subtechnique_id}",
                )

            self._sub[
                subtechnique_id
            ] = subtechnique

        # --------------------------------------------------------------------
        # Cross-category validation
        # --------------------------------------------------------------------

        collision_ids = (
            set(self._tech)
            & set(self._sub)
        )

        if collision_ids:
            collision = sorted(
                collision_ids,
            )[0]

            raise ValueError(
                "MITRE technique ID is registered as both "
                f"technique and sub-technique: {collision}",
            )

        # --------------------------------------------------------------------
        # Parent validation
        # --------------------------------------------------------------------

        for subtechnique in self._sub.values():
            parent_id = self._normalize_id(
                subtechnique.parent_id,
            )

            if parent_id not in self._tech:
                raise ValueError(
                    "unknown parent technique for "
                    f"{subtechnique.id}: {parent_id}",
                )

    # ========================================================================
    # Single-item Retrieval
    # ========================================================================

    def get(
        self,
        technique_id: str,
    ) -> MitreTechnique:
        """Return one top-level MITRE technique."""

        normalized_id = self._normalize_id(
            technique_id,
        )

        try:
            return self._tech[
                normalized_id
            ]
        except KeyError as exc:
            raise KeyError(
                f"unknown MITRE technique: {normalized_id}",
            ) from exc

    def get_optional(
        self,
        technique_id: str,
    ) -> MitreTechnique | None:
        """Return a top-level technique or ``None``."""

        normalized_id = self._normalize_id(
            technique_id,
        )

        return self._tech.get(
            normalized_id,
        )

    def get_subtechnique(
        self,
        subtechnique_id: str,
    ) -> MitreSubTechnique:
        """Return one MITRE sub-technique."""

        normalized_id = self._normalize_id(
            subtechnique_id,
        )

        try:
            return self._sub[
                normalized_id
            ]
        except KeyError as exc:
            raise KeyError(
                "unknown MITRE sub-technique: "
                f"{normalized_id}",
            ) from exc

    def get_subtechnique_optional(
        self,
        subtechnique_id: str,
    ) -> MitreSubTechnique | None:
        """Return a sub-technique or ``None``."""

        normalized_id = self._normalize_id(
            subtechnique_id,
        )

        return self._sub.get(
            normalized_id,
        )

    def get_any(
        self,
        technique_id: str,
    ) -> MitreTechnique | MitreSubTechnique:
        """Return either a top-level technique or sub-technique."""

        normalized_id = self._normalize_id(
            technique_id,
        )

        if normalized_id in self._tech:
            return self._tech[
                normalized_id
            ]

        if normalized_id in self._sub:
            return self._sub[
                normalized_id
            ]

        raise KeyError(
            f"unknown MITRE technique: {normalized_id}",
        )

    # ========================================================================
    # Top-level Techniques
    # ========================================================================

    def all(
        self,
    ) -> tuple[MitreTechnique, ...]:
        """Return top-level techniques in deterministic ID order."""

        return tuple(
            self._tech[technique_id]
            for technique_id in sorted(
                self._tech,
            )
        )

    def ids(
        self,
    ) -> frozenset[str]:
        """Return top-level technique IDs."""

        return frozenset(
            self._tech,
        )

    def values(
        self,
    ) -> tuple[MitreTechnique, ...]:
        """Alias for ``all()``."""

        return self.all()

    def count(
        self,
    ) -> int:
        """Return the number of top-level techniques."""

        return len(
            self._tech,
        )

    # ========================================================================
    # Sub-techniques
    # ========================================================================

    def all_subtechniques(
        self,
    ) -> tuple[MitreSubTechnique, ...]:
        """Return sub-techniques in deterministic ID order."""

        return tuple(
            self._sub[subtechnique_id]
            for subtechnique_id in sorted(
                self._sub,
            )
        )

    def subtechnique_ids(
        self,
    ) -> frozenset[str]:
        """Return all sub-technique IDs."""

        return frozenset(
            self._sub,
        )

    def subtechnique_count(
        self,
    ) -> int:
        """Return the number of sub-techniques."""

        return len(
            self._sub,
        )

    def subtechniques_for_parent(
        self,
        technique_id: str,
    ) -> tuple[MitreSubTechnique, ...]:
        """Return direct sub-techniques belonging to a technique."""

        parent_id = self._normalize_id(
            technique_id,
        )

        self.get(
            parent_id,
        )

        return tuple(
            subtechnique
            for subtechnique in self.all_subtechniques()
            if subtechnique.parent_id
            == parent_id
        )

    def children(
        self,
        technique_id: str,
    ) -> tuple[MitreSubTechnique, ...]:
        """Alias for ``subtechniques_for_parent()``."""

        return self.subtechniques_for_parent(
            technique_id,
        )

    # ========================================================================
    # Combined Taxonomy
    # ========================================================================

    def all_ids(
        self,
    ) -> frozenset[str]:
        """Return all technique and sub-technique IDs."""

        return frozenset(
            set(self._tech)
            | set(self._sub)
        )

    def total_count(
        self,
    ) -> int:
        """Return combined technique and sub-technique count."""

        return (
            len(self._tech)
            + len(self._sub)
        )

    # ========================================================================
    # Relationship Helpers
    # ========================================================================

    def has(
        self,
        technique_id: str,
    ) -> bool:
        """Return whether an ID is a top-level technique."""

        try:
            normalized_id = self._normalize_id(
                technique_id,
            )
        except (
            TypeError,
            ValueError,
        ):
            return False

        return normalized_id in self._tech

    def has_subtechnique(
        self,
        subtechnique_id: str,
    ) -> bool:
        """Return whether an ID is a sub-technique."""

        try:
            normalized_id = self._normalize_id(
                subtechnique_id,
            )
        except (
            TypeError,
            ValueError,
        ):
            return False

        return normalized_id in self._sub

    def contains(
        self,
        technique_id: str,
    ) -> bool:
        """Return whether an ID belongs to the taxonomy."""

        try:
            normalized_id = self._normalize_id(
                technique_id,
            )
        except (
            TypeError,
            ValueError,
        ):
            return False

        return (
            normalized_id in self._tech
            or normalized_id in self._sub
        )

    def is_subtechnique(
        self,
        technique_id: str,
    ) -> bool:
        """Return whether the supplied ID is a sub-technique."""

        try:
            normalized_id = self._normalize_id(
                technique_id,
            )
        except (
            TypeError,
            ValueError,
        ):
            return False

        return normalized_id in self._sub

    def parent_id_for(
        self,
        subtechnique_id: str,
    ) -> str:
        """Return the parent technique ID for a sub-technique."""

        subtechnique = self.get_subtechnique(
            subtechnique_id,
        )

        return self._normalize_id(
            subtechnique.parent_id,
        )

    def parent_for(
        self,
        subtechnique_id: str,
    ) -> MitreTechnique:
        """Return the parent technique object."""

        parent_id = self.parent_id_for(
            subtechnique_id,
        )

        return self.get(
            parent_id,
        )

    # ========================================================================
    # Tactic Helpers
    # ========================================================================

    def techniques_for_tactic(
        self,
        tactic_id: str,
    ) -> tuple[MitreTechnique, ...]:
        """Return top-level techniques associated with a tactic."""

        normalized_tactic_id = (
            self._normalize_id(
                tactic_id,
            )
        )

        return tuple(
            technique
            for technique in self.all()
            if normalized_tactic_id
            in technique.tactic_ids
        )

    def subtechniques_for_tactic(
        self,
        tactic_id: str,
    ) -> tuple[MitreSubTechnique, ...]:
        """Return sub-techniques associated with a tactic."""

        normalized_tactic_id = (
            self._normalize_id(
                tactic_id,
            )
        )

        return tuple(
            subtechnique
            for subtechnique in self.all_subtechniques()
            if normalized_tactic_id
            in subtechnique.tactic_ids
        )

    def ids_for_tactic(
        self,
        tactic_id: str,
    ) -> frozenset[str]:
        """Return all technique IDs associated with a tactic."""

        return frozenset(
            technique.id
            for technique in self.techniques_for_tactic(
                tactic_id,
            )
        ) | frozenset(
            subtechnique.id
            for subtechnique in self.subtechniques_for_tactic(
                tactic_id,
            )
        )

    # ========================================================================
    # Matrix Helpers
    # ========================================================================

    def technique_tree(
        self,
    ) -> tuple[
        tuple[
            MitreTechnique,
            tuple[MitreSubTechnique, ...],
        ],
        ...,
    ]:
        """
        Return the complete technique → sub-technique tree.

        Each top-level technique appears once, followed by its direct
        sub-techniques.
        """

        return tuple(
            (
                technique,
                self.subtechniques_for_parent(
                    technique.id,
                ),
            )
            for technique in self.all()
        )

    def matrix(
        self,
    ) -> tuple[
        tuple[
            MitreTechnique,
            tuple[MitreSubTechnique, ...],
        ],
        ...,
    ]:
        """Alias for ``technique_tree()`` for matrix consumers."""

        return self.technique_tree()

    # ========================================================================
    # Validation
    # ========================================================================

    def validate(
        self,
        technique_id: str,
    ) -> str:
        """Validate any technique/sub-technique ID and return normalized ID."""

        normalized_id = self._normalize_id(
            technique_id,
        )

        if normalized_id not in self._tech:
            if normalized_id not in self._sub:
                raise KeyError(
                    "unknown MITRE technique: "
                    f"{normalized_id}",
                )

        return normalized_id

    def validate_technique(
        self,
        technique_id: str,
    ) -> str:
        """Validate a top-level technique ID."""

        normalized_id = self._normalize_id(
            technique_id,
        )

        if normalized_id not in self._tech:
            raise KeyError(
                "unknown MITRE technique: "
                f"{normalized_id}",
            )

        return normalized_id

    def validate_subtechnique(
        self,
        subtechnique_id: str,
    ) -> str:
        """Validate a sub-technique ID."""

        normalized_id = self._normalize_id(
            subtechnique_id,
        )

        if normalized_id not in self._sub:
            raise KeyError(
                "unknown MITRE sub-technique: "
                f"{normalized_id}",
            )

        return normalized_id

    # ========================================================================
    # Python Protocols
    # ========================================================================

    def __contains__(
        self,
        technique_id: object,
    ) -> bool:
        """Support ``technique_id in catalog``."""

        if not isinstance(
            technique_id,
            str,
        ):
            return False

        return self.contains(
            technique_id,
        )

    def __iter__(
        self,
    ) -> Iterator[MitreTechnique]:
        """Iterate through top-level techniques."""

        return iter(
            self.all(),
        )

    def __len__(
        self,
    ) -> int:
        """Return top-level technique count."""

        return self.count()

    # ========================================================================
    # Internal Helpers
    # ========================================================================

    @staticmethod
    def _normalize_id(
        technique_id: str,
    ) -> str:
        """Normalize an ATT&CK technique identifier."""

        if not isinstance(
            technique_id,
            str,
        ):
            raise TypeError(
                "MITRE technique ID must be a string",
            )

        normalized = technique_id.strip().upper()

        if not normalized:
            raise ValueError(
                "MITRE technique ID cannot be empty",
            )

        return normalized


# ============================================================================
# Default Compatibility Catalog
# ============================================================================


DEFAULT_TECHNIQUE_CATALOG: Final[
    TechniqueCatalog
] = TechniqueCatalog(
    DEFAULT_TECHNIQUES,
    DEFAULT_SUBTECHNIQUES,
)


# ============================================================================
# Public Convenience Functions
# ============================================================================


def get_technique(
    technique_id: str,
) -> MitreTechnique:
    """Return a top-level technique from the default catalog."""

    return DEFAULT_TECHNIQUE_CATALOG.get(
        technique_id,
    )


def get_subtechnique(
    subtechnique_id: str,
) -> MitreSubTechnique:
    """Return a sub-technique from the default catalog."""

    return DEFAULT_TECHNIQUE_CATALOG.get_subtechnique(
        subtechnique_id,
    )


def get_parent_technique(
    subtechnique_id: str,
) -> MitreTechnique:
    """Return the parent technique for a sub-technique."""

    return DEFAULT_TECHNIQUE_CATALOG.parent_for(
        subtechnique_id,
    )


def is_valid_technique(
    technique_id: str,
) -> bool:
    """Return whether an ID exists in the compatibility taxonomy."""

    return DEFAULT_TECHNIQUE_CATALOG.contains(
        technique_id,
    )


def is_subtechnique(
    technique_id: str,
) -> bool:
    """Return whether an ID is a registered sub-technique."""

    return DEFAULT_TECHNIQUE_CATALOG.is_subtechnique(
        technique_id,
    )


# ============================================================================
# Public Exports
# ============================================================================


__all__ = [
    "ALL_TECHNIQUE_IDS",
    "DEFAULT_SUBTECHNIQUES",
    "DEFAULT_TECHNIQUES",
    "DEFAULT_TECHNIQUE_CATALOG",
    "SUBTECHNIQUE_IDS",
    "TECHNIQUE_IDS",
    "TechniqueCatalog",
    "get_parent_technique",
    "get_subtechnique",
    "get_technique",
    "is_subtechnique",
    "is_valid_technique",
]