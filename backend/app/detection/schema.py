from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ConditionOperator = Literal[
    "equals",
    "not_equals",
    "in",
    "not_in",
    "contains",
    "exists",
]


class RuleCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str = Field(min_length=1, max_length=128)
    operator: ConditionOperator
    value: object | None = None


class DetectionRule(BaseModel):
    """External, declarative rule consumed by the Phase 07 engine."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{2,127}$")
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2000)
    enabled: bool = True
    severity: str = Field(min_length=1, max_length=32)
    category: str = Field(min_length=1, max_length=64)
    conditions: list[RuleCondition] = Field(min_length=1, max_length=50)
    match: Literal["all", "any"] = "all"
    tags: list[str] = Field(default_factory=list, max_length=50)
