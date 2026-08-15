from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.domain.events.models import CanonicalSecurityEvent, EnrichedEvent

CorrelationEvent = CanonicalSecurityEvent | EnrichedEvent


def get_field(event: CorrelationEvent, path: str) -> Any:
    """Safely resolve a dotted field from an event model or mapping."""
    current: Any = event

    for part in path.split("."):
        if isinstance(current, Mapping):
            if part not in current:
                return None
            current = current[part]
            continue

        if not hasattr(current, part):
            return None

        current = getattr(current, part)

    return current


def matches(
    event: CorrelationEvent,
    condition_field: str,
    expected: Any,
) -> bool:
    """Return whether an event field exactly matches the expected value."""
    actual = get_field(event, condition_field)
    return bool(actual == expected)


def group_key(
    event: CorrelationEvent,
    fields: tuple[str, ...],
) -> tuple[Any, ...]:
    """Build a deterministic correlation grouping key."""
    return tuple(get_field(event, field) for field in fields)
