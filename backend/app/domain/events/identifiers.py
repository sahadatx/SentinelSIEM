from __future__ import annotations

from uuid import UUID, uuid4


def new_event_id() -> UUID:
    """Create a globally unique event identifier."""
    return uuid4()
