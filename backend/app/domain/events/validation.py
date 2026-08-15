from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def require_utc_datetime(value: datetime) -> datetime:
    """Normalize an aware datetime to UTC and reject naive timestamps."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("event timestamps must be timezone-aware")
    return value.astimezone(UTC)


def require_non_empty_text(value: str, *, field_name: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must not be empty")
    return normalized


def validate_metadata(value: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy so callers cannot mutate the model through input references."""
    return dict(value)
