from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from app.correlation.context import CorrelationEvent


@dataclass(slots=True)
class CorrelationState:
    """Ephemeral state for one rule/group/window."""

    started_at: datetime
    events: list[CorrelationEvent] = field(default_factory=list)
    matched_steps: set[int] = field(default_factory=set)

    def add(self, event: CorrelationEvent) -> None:
        self.events.append(event)
