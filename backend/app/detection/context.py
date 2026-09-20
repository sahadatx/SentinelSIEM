from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.domain.events.models import CanonicalSecurityEvent, EnrichedEvent


class DetectionContext:
    """
    Read-only context exposed to the detection evaluator.

    The context provides controlled field resolution over a canonical
    security event without modifying the underlying event.

    Supported field forms
    ---------------------
    Top-level field:
        severity
        username
        source_ip

    Nested field:
        metadata.hostname
        parsed_data.process.name

    Mapping values:
        metadata.hostname

    Object attributes:
        event.severity
        event.source_ip

    Enum-like values:
        severity.value

    Responsibilities
    ----------------
    - Provide deterministic read-only event field access.
    - Resolve dotted/nested field paths.
    - Safely handle mappings and object attributes.
    - Normalize enum-like values to their underlying value.

    Non-responsibilities
    --------------------
    - Does not evaluate operators.
    - Does not execute detection rules.
    - Does not create alerts.
    - Does not perform suppression.
    - Does not perform RBAC.
    - Does not mutate the event.
    """

    def __init__(
        self,
        event: CanonicalSecurityEvent | EnrichedEvent,
    ) -> None:
        self._event = event

    @property
    def event(self) -> CanonicalSecurityEvent | EnrichedEvent:
        """
        Return the underlying event.

        The returned event is exposed for read access only. DetectionContext
        itself never mutates it.
        """
        return self._event

    def get(self, field: str) -> Any:
        """
        Resolve a field from the event using a dotted path.

        Examples
        --------
        ``severity``
            Resolves the event severity.

        ``source_ip``
            Resolves the source IP.

        ``metadata.hostname``
            Resolves a nested mapping/object value.

        Missing or invalid paths return ``None``.
        """
        if not isinstance(field, str):
            return None

        field = field.strip()

        if not field:
            return None

        current: Any = self._event

        for part in field.split("."):
            part = part.strip()

            if not part:
                return None

            current = self._resolve_part(current, part)

            if current is _MISSING:
                return None

        return self._normalize_value(current)

    @classmethod
    def _resolve_part(
        cls,
        current: Any,
        part: str,
    ) -> Any:
        """
        Resolve one path component from a mapping or object.

        Mapping lookup is preferred over object attribute lookup so that
        dictionary-backed event data behaves predictably.
        """
        if isinstance(current, Mapping):
            if part not in current:
                return _MISSING

            return current[part]

        try:
            return getattr(current, part)
        except AttributeError:
            return _MISSING

    @classmethod
    def _normalize_value(
        cls,
        value: Any,
    ) -> Any:
        """
        Normalize enum-like values to their underlying value.

        For example:

            Severity.HIGH.value -> "high"

        Nested enum-like values are intentionally not recursively modified;
        only the final resolved field value is normalized.
        """
        if value is None:
            return None

        enum_value = getattr(value, "value", _MISSING)

        if enum_value is not _MISSING:
            return enum_value

        return value


class _MissingValue:
    """Internal sentinel used to distinguish missing fields from None."""

    __slots__ = ()


_MISSING = _MissingValue()