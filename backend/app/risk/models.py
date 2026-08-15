from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RiskInput(BaseModel):
    """Normalized evidence used by the risk engine."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str = Field(min_length=1, max_length=256)
    severity: str = "medium"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    asset_criticality: float = Field(default=0.5, ge=0.0, le=1.0)
    user_risk: float = Field(default=0.0, ge=0.0, le=1.0)
    ioc_reputation: float = Field(default=0.0, ge=0.0, le=1.0)
    threat_intelligence: float = Field(default=0.0, ge=0.0, le=1.0)
    frequency: float = Field(default=0.0, ge=0.0, le=1.0)
    correlation_strength: float = Field(default=0.0, ge=0.0, le=1.0)
    mitre_technique: float = Field(default=0.0, ge=0.0, le=1.0)
    historical_context: float = Field(default=0.0, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RiskAssessment(BaseModel):
    """Explainable and auditable risk assessment."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    assessment_id: str = Field(min_length=1)
    source_id: str = Field(min_length=1)
    score: float = Field(ge=0.0, le=100.0)
    priority: str
    factors: dict[str, float]
    explanation: tuple[str, ...]
    assessed_at: datetime
