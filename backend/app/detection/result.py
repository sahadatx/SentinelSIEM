from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class DetectionResult(BaseModel):
    """
    Immutable result emitted when a detection rule matches an event.

    A DetectionResult represents the output of the detection layer.
    It contains the rule/event relationship and the classification
    information required by downstream consumers such as the Alert
    subsystem.

    Responsibilities
    ----------------
    - Represent a validated detection result.
    - Preserve the rule and event identifiers.
    - Preserve severity, category, description, and tags.
    - Record when the detection matched.
    - Record whether the result was suppressed.

    Non-responsibilities
    --------------------
    - Does not create alerts.
    - Does not persist itself.
    - Does not perform suppression.
    - Does not evaluate detection rules.
    - Does not perform RBAC.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_assignment=True,
    )

    detection_id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier of this detection result.",
    )

    rule_id: str = Field(
        min_length=1,
        max_length=128,
        description="Identifier of the detection rule that matched.",
    )

    rule_name: str = Field(
        min_length=1,
        max_length=200,
        description="Human-readable name of the detection rule.",
    )

    event_id: UUID = Field(
        description="Identifier of the event evaluated by the rule.",
    )

    severity: str = Field(
        min_length=1,
        max_length=32,
        description="Severity assigned by the detection rule.",
    )

    category: str = Field(
        min_length=1,
        max_length=64,
        description="Detection category assigned by the rule.",
    )

    description: str = Field(
        min_length=1,
        max_length=2000,
        description="Human-readable explanation of the detection.",
    )

    matched_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when the detection result was generated.",
    )

    tags: tuple[str, ...] = Field(
        default=(),
        description="Tags associated with the detection rule/result.",
    )

    suppressed: bool = Field(
        default=False,
        description="Whether this detection result was suppressed.",
    )