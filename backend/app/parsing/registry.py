from __future__ import annotations

from collections.abc import Callable
from typing import Generic, TypeVar

from app.domain.events.models import (
    CanonicalSecurityEvent,
    EnrichedEvent,
    NormalizedEvent,
    ParsedEvent,
    RawEvent,
)


# =========================================================
# Type Contracts
# =========================================================

Parser = Callable[[RawEvent], ParsedEvent]
Normalizer = Callable[[ParsedEvent], NormalizedEvent]
Enricher = Callable[[CanonicalSecurityEvent], EnrichedEvent]

T = TypeVar("T")


# =========================================================
# Base Registry
# =========================================================


class _Registry(Generic[T]):
    """
    Deterministic name-based component registry.

    Responsibilities:
        - Validate component names.
        - Register components.
        - Prevent duplicate registrations.
        - Resolve components by name.
        - Expose deterministic component names.

    The registry owns runtime registration state only.
    It does not create, initialize, or execute components.
    """

    def __init__(self) -> None:
        self._items: dict[str, T] = {}

    # -----------------------------------------------------
    # Registration
    # -----------------------------------------------------

    def register(
        self,
        name: str,
        item: T,
    ) -> None:
        """
        Register a component under a validated name.

        Raises:
            ValueError:
                If the component name is empty or already
                registered.
        """

        normalized_name = self._validate_name(name)

        if normalized_name in self._items:
            raise ValueError(
                f"component already registered: {normalized_name}",
            )

        self._items[normalized_name] = item

    # -----------------------------------------------------
    # Resolution
    # -----------------------------------------------------

    def get(
        self,
        name: str,
    ) -> T:
        """
        Resolve a registered component by name.

        Raises:
            ValueError:
                If the requested name is empty.

            KeyError:
                If no component is registered under the
                requested name.
        """

        normalized_name = self._validate_name(name)

        try:
            return self._items[normalized_name]
        except KeyError as exc:
            raise KeyError(
                f"component not registered: {normalized_name}",
            ) from exc

    # -----------------------------------------------------
    # Inspection
    # -----------------------------------------------------

    def names(self) -> tuple[str, ...]:
        """
        Return registered component names in deterministic
        sorted order.
        """

        return tuple(sorted(self._items))

    def contains(
        self,
        name: str,
    ) -> bool:
        """
        Return True when a component is registered.

        Empty names are treated as invalid input and therefore
        raise ValueError rather than silently returning False.
        """

        normalized_name = self._validate_name(name)

        return normalized_name in self._items

    def count(self) -> int:
        """
        Return the number of registered components.
        """

        return len(self._items)

    def clear(self) -> None:
        """
        Remove all registered components.

        Primarily useful for controlled lifecycle management
        and isolated tests.
        """

        self._items.clear()

    # -----------------------------------------------------
    # Validation
    # -----------------------------------------------------

    @staticmethod
    def _validate_name(
        name: str,
    ) -> str:
        """
        Normalize and validate a component name.

        Leading and trailing whitespace is removed.

        Empty names are rejected.
        """

        if not isinstance(name, str):
            raise TypeError(
                "component name must be a string",
            )

        normalized_name = name.strip()

        if not normalized_name:
            raise ValueError(
                "component name must not be empty",
            )

        return normalized_name


# =========================================================
# Parser Registry
# =========================================================


class ParserRegistry(_Registry[Parser]):
    """
    Registry for raw-event parsers.

    Parser contract:

        RawEvent
            ↓
        Parser
            ↓
        ParsedEvent

    A parser must preserve the event identity and return a
    ParsedEvent representation.
    """

    def register(
        self,
        name: str,
        parser: Parser,
    ) -> None:
        """
        Register a raw-event parser.
        """

        if not callable(parser):
            raise TypeError(
                "parser must be callable",
            )

        super().register(name, parser)


# =========================================================
# Normalizer Registry
# =========================================================


class NormalizerRegistry(_Registry[Normalizer]):
    """
    Registry for parsed-event normalizers.

    Normalizer contract:

        ParsedEvent
            ↓
        Normalizer
            ↓
        NormalizedEvent

    A normalizer must preserve the event identity and convert
    parser-specific data into the normalized representation.
    """

    def register(
        self,
        name: str,
        normalizer: Normalizer,
    ) -> None:
        """
        Register a parsed-event normalizer.
        """

        if not callable(normalizer):
            raise TypeError(
                "normalizer must be callable",
            )

        super().register(name, normalizer)


# =========================================================
# Enricher Registry
# =========================================================


class EnricherRegistry(_Registry[Enricher]):
    """
    Registry for canonical-event enrichers.

    Enricher contract:

        CanonicalSecurityEvent
            ↓
        Enricher
            ↓
        EnrichedEvent

    An enricher must preserve the event identity and attach
    additional security context without changing the event
    identity.
    """

    def register(
        self,
        name: str,
        enricher: Enricher,
    ) -> None:
        """
        Register a canonical-event enricher.
        """

        if not callable(enricher):
            raise TypeError(
                "enricher must be callable",
            )

        super().register(name, enricher)


# =========================================================
# Public API
# =========================================================

__all__ = [
    "Enricher",
    "EnricherRegistry",
    "Normalizer",
    "NormalizerRegistry",
    "Parser",
    "ParserRegistry",
]