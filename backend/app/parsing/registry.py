from __future__ import annotations

from collections.abc import Callable

from app.domain.events.models import (
    CanonicalSecurityEvent,
    EnrichedEvent,
    NormalizedEvent,
    ParsedEvent,
    RawEvent,
)

type Parser = Callable[[RawEvent], ParsedEvent]
type Normalizer = Callable[[ParsedEvent], NormalizedEvent]
type Enricher = Callable[[CanonicalSecurityEvent], EnrichedEvent]


class _Registry[T]:
    """Deterministic name-based registry with duplicate protection."""

    def __init__(self) -> None:
        self._items: dict[str, T] = {}

    def register(self, name: str, item: T) -> None:
        normalized_name = self._validate_name(name)
        if normalized_name in self._items:
            raise ValueError(f"component already registered: {normalized_name}")
        self._items[normalized_name] = item

    def get(self, name: str) -> T:
        normalized_name = self._validate_name(name)
        try:
            return self._items[normalized_name]
        except KeyError as exc:
            raise KeyError(f"component not registered: {normalized_name}") from exc

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._items))

    @staticmethod
    def _validate_name(name: str) -> str:
        normalized_name = name.strip()
        if not normalized_name:
            raise ValueError("component name must not be empty")
        return normalized_name


class ParserRegistry(_Registry[Parser]):
    """Registry for raw-event parsers."""


class NormalizerRegistry(_Registry[Normalizer]):
    """Registry for parsed-event normalizers."""


class EnricherRegistry(_Registry[Enricher]):
    """Registry for canonical-event enrichers."""
