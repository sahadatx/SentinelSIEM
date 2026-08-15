from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CorrelationResult(BaseModel):
    """Immutable output emitted when a multi-event pattern is satisfied."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    correlation_id: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    event_ids: tuple[str, ...] = Field(min_length=1)
    severity: str
    description: str
    detected_at: datetime
    group_key: tuple[Any, ...] = ()
    evidence_count: int = Field(gt=0)
