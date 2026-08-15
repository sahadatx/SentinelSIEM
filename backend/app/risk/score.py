from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class RiskScore(BaseModel):
    """Bounded numeric risk score."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    value: float = Field(ge=0.0, le=100.0)
    priority: str
    rationale: tuple[str, ...] = ()
