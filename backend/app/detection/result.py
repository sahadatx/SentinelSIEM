from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class DetectionResult(BaseModel):
    """Immutable result emitted when a detection rule matches an event."""

    model_config = ConfigDict(extra="forbid")

    detection_id: UUID = Field(default_factory=uuid4)
    rule_id: str
    rule_name: str
    event_id: UUID
    severity: str
    category: str
    description: str
    matched_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tags: tuple[str, ...] = ()
    suppressed: bool = False
