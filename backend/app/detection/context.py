from __future__ import annotations

from typing import Any

from app.domain.events.models import CanonicalSecurityEvent, EnrichedEvent


class DetectionContext:
    """Read-only context exposed to detection evaluation."""

    def __init__(self, event: CanonicalSecurityEvent | EnrichedEvent) -> None:
        self.event = event

    def get(self, field: str) -> Any:
        """Resolve a rule field from the event model or safe nested data."""
        current: Any = self.event
        for part in field.split("."):
            if isinstance(current, dict):
                current = current.get(part)
            else:
                current = getattr(current, part, None)
            if current is None:
                return None

        value = getattr(current, "value", current)
        return value
