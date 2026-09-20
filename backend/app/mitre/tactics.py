"""MITRE ATT&CK Enterprise tactic definitions.

This module provides the static identity of Enterprise ATT&CK tactics
used by SentinelSIEM's MITRE domain layer.

Important architecture rule
----------------------------

The authoritative MITRE ATT&CK knowledge source is:

    backend/data/mitre/enterprise-attack.json

The dataset importer is responsible for loading/updating MITRE knowledge
in PostgreSQL.

This module therefore does NOT act as the authoritative MITRE database
and must NOT be used to populate the production MITRE knowledge store.

It remains useful as a small domain-level catalog for:

- validating tactic identifiers;
- compatibility with existing runtime code;
- deterministic tactic ordering;
- tests;
- fallback/domain contracts where a database lookup is not required.

Detection → MITRE mappings are handled separately and are not managed
by this catalog.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Final

from .models import MitreTactic


# ============================================================================
# Enterprise ATT&CK Tactics
# ============================================================================

DEFAULT_TACTICS: Final[tuple[MitreTactic, ...]] = (
    MitreTactic(
        id="TA0043",
        name="Reconnaissance",
    ),
    MitreTactic(
        id="TA0042",
        name="Resource Development",
    ),
    MitreTactic(
        id="TA0001",
        name="Initial Access",
    ),
    MitreTactic(
        id="TA0002",
        name="Execution",
    ),
    MitreTactic(
        id="TA0003",
        name="Persistence",
    ),
    MitreTactic(
        id="TA0004",
        name="Privilege Escalation",
    ),
    MitreTactic(
        id="TA0005",
        name="Defense Evasion",
    ),
    MitreTactic(
        id="TA0006",
        name="Credential Access",
    ),
    MitreTactic(
        id="TA0007",
        name="Discovery",
    ),
    MitreTactic(
        id="TA0008",
        name="Lateral Movement",
    ),
    MitreTactic(
        id="TA0009",
        name="Collection",
    ),
    MitreTactic(
        id="TA0011",
        name="Command and Control",
    ),
    MitreTactic(
        id="TA0010",
        name="Exfiltration",
    ),
    MitreTactic(
        id="TA0040",
        name="Impact",
    ),
)


# ============================================================================
# Lookup Constants
# ============================================================================

TACTIC_IDS: Final[frozenset[str]] = frozenset(
    tactic.id
    for tactic in DEFAULT_TACTICS
)

TACTIC_NAMES: Final[frozenset[str]] = frozenset(
    tactic.name
    for tactic in DEFAULT_TACTICS
)


# ============================================================================
# Tactic Catalog
# ============================================================================


class TacticCatalog:
    """Immutable-style lookup catalog for Enterprise ATT&CK tactics.

    The catalog accepts an iterable of ``MitreTactic`` objects so tests and
    compatibility callers can provide their own catalog.

    The default catalog contains the Enterprise ATT&CK tactic identities
    currently represented by SentinelSIEM.
    """

    def __init__(
        self,
        tactics: Iterable[MitreTactic] = DEFAULT_TACTICS,
    ) -> None:
        items = tuple(tactics)

        if not items:
            raise ValueError(
                "MITRE tactic catalog cannot be empty",
            )

        by_id: dict[str, MitreTactic] = {}

        for tactic in items:
            tactic_id = self._normalize_id(
                tactic.id,
            )

            if tactic_id in by_id:
                raise ValueError(
                    f"duplicate MITRE tactic ID: {tactic_id}",
                )

            by_id[tactic_id] = tactic

        self._items: dict[str, MitreTactic] = by_id

    # ========================================================================
    # Lookup
    # ========================================================================

    def get(
        self,
        tactic_id: str,
    ) -> MitreTactic:
        """Return a tactic by external ATT&CK ID.

        Raises:
            KeyError: if the tactic does not exist in this catalog.
        """

        normalized_id = self._normalize_id(
            tactic_id,
        )

        try:
            return self._items[
                normalized_id
            ]
        except KeyError as exc:
            raise KeyError(
                f"unknown MITRE tactic: {normalized_id}",
            ) from exc

    def get_optional(
        self,
        tactic_id: str,
    ) -> MitreTactic | None:
        """Return a tactic or ``None`` when it does not exist."""

        normalized_id = self._normalize_id(
            tactic_id,
        )

        return self._items.get(
            normalized_id,
        )

    def contains(
        self,
        tactic_id: str,
    ) -> bool:
        """Return whether a tactic ID exists."""

        normalized_id = self._normalize_id(
            tactic_id,
        )

        return normalized_id in self._items

    # ========================================================================
    # Collection Access
    # ========================================================================

    def all(
        self,
    ) -> tuple[MitreTactic, ...]:
        """Return all tactics in deterministic ATT&CK ID order."""

        return tuple(
            self._items[tactic_id]
            for tactic_id in sorted(
                self._items,
            )
        )

    def ids(
        self,
    ) -> frozenset[str]:
        """Return all tactic IDs."""

        return frozenset(
            self._items,
        )

    def names(
        self,
    ) -> frozenset[str]:
        """Return all tactic names."""

        return frozenset(
            tactic.name
            for tactic in self._items.values()
        )

    def values(
        self,
    ) -> tuple[MitreTactic, ...]:
        """Alias for ``all()``."""

        return self.all()

    def __iter__(
        self,
    ) -> Iterator[MitreTactic]:
        """Iterate through tactics in deterministic order."""

        return iter(
            self.all(),
        )

    def __len__(
        self,
    ) -> int:
        """Return number of tactics."""

        return len(
            self._items,
        )

    # ========================================================================
    # Validation
    # ========================================================================

    def validate(
        self,
        tactic_id: str,
    ) -> str:
        """Validate and return a normalized tactic ID.

        Raises:
            ValueError: if the identifier is empty.
            KeyError: if the identifier is unknown.
        """

        normalized_id = self._normalize_id(
            tactic_id,
        )

        if normalized_id not in self._items:
            raise KeyError(
                f"unknown MITRE tactic: {normalized_id}",
            )

        return normalized_id

    # ========================================================================
    # Helpers
    # ========================================================================

    @staticmethod
    def _normalize_id(
        tactic_id: str,
    ) -> str:
        """Normalize a tactic identifier."""

        if not isinstance(
            tactic_id,
            str,
        ):
            raise TypeError(
                "MITRE tactic ID must be a string",
            )

        normalized = tactic_id.strip().upper()

        if not normalized:
            raise ValueError(
                "MITRE tactic ID cannot be empty",
            )

        return normalized


# ============================================================================
# Default Catalog
# ============================================================================

DEFAULT_TACTIC_CATALOG: Final[TacticCatalog] = TacticCatalog(
    DEFAULT_TACTICS,
)


# ============================================================================
# Compatibility Helpers
# ============================================================================


def get_tactic(
    tactic_id: str,
) -> MitreTactic:
    """Return a tactic from the default catalog."""

    return DEFAULT_TACTIC_CATALOG.get(
        tactic_id,
    )


def get_all_tactics() -> tuple[MitreTactic, ...]:
    """Return all default Enterprise ATT&CK tactics."""

    return DEFAULT_TACTIC_CATALOG.all()


def is_valid_tactic(
    tactic_id: str,
) -> bool:
    """Return whether an Enterprise ATT&CK tactic ID is known."""

    try:
        return DEFAULT_TACTIC_CATALOG.contains(
            tactic_id,
        )
    except (TypeError, ValueError):
        return False


__all__ = [
    "DEFAULT_TACTICS",
    "DEFAULT_TACTIC_CATALOG",
    "TACTIC_IDS",
    "TACTIC_NAMES",
    "TacticCatalog",
    "get_all_tactics",
    "get_tactic",
    "is_valid_tactic",
]