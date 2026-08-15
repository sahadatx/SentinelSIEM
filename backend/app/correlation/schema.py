from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CorrelationMode(StrEnum):
    SEQUENCE = "sequence"
    THRESHOLD = "threshold"


class CorrelationCondition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    field: str = Field(min_length=1, max_length=128)
    equals: Any | None = None
    exists: bool | None = None


class CorrelationRule(BaseModel):
    """External, declarative multi-event correlation rule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=256)
    description: str = Field(min_length=1, max_length=1024)
    mode: CorrelationMode
    window_seconds: int = Field(gt=0, le=86_400)
    group_by: tuple[str, ...] = ()
    threshold: int | None = Field(default=None, gt=0)
    conditions: tuple[CorrelationCondition, ...] = ()
    enabled: bool = True
    severity: str = "medium"

    def __post_init__(self) -> None:
        if self.mode is CorrelationMode.THRESHOLD and self.threshold is None:
            raise ValueError("threshold mode requires threshold")
        if self.mode is CorrelationMode.SEQUENCE and not self.conditions:
            raise ValueError("sequence mode requires conditions")
