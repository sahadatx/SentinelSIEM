from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
)

from app.detection.result import DetectionResult
from app.detection.schema import (
    ConditionOperator,
    DetectionRule,
    RuleCondition,
)


# ============================================================================
# Shared API Configuration
# ============================================================================


class DetectionAPIModel(BaseModel):
    """
    Base model for all Detection API schemas.

    Unknown fields are rejected intentionally so the public Detection
    API contract remains explicit, strict, and predictable.
    """

    model_config = ConfigDict(
        extra="forbid",
    )


# ============================================================================
# Rule Conditions
# ============================================================================


class DetectionRuleConditionResponse(
    DetectionAPIModel,
):
    """
    API representation of a Detection rule condition.

    Used by:
        - rule responses
        - rule creation
        - rule updates
    """

    field: str = Field(
        min_length=1,
        max_length=128,
    )

    operator: ConditionOperator

    value: object | None = None

    @classmethod
    def from_domain(
        cls,
        condition: RuleCondition,
    ) -> DetectionRuleConditionResponse:
        """
        Convert a domain RuleCondition into its API representation.
        """

        return cls(
            field=condition.field,
            operator=condition.operator,
            value=condition.value,
        )

    def to_domain(
        self,
    ) -> RuleCondition:
        """
        Convert the API representation into the domain representation.

        Final validation remains owned by the domain model.
        """

        return RuleCondition.model_validate(
            self.model_dump(),
        )


# ============================================================================
# Detection Rule Response
# ============================================================================


class DetectionRuleResponse(
    DetectionAPIModel,
):
    """
    Public API representation of a Detection rule.

    Rule definition fields originate from DetectionRule.

    Read-side statistics:
        - matches
        - alerts
        - suppressed
        - last_match

    These statistics are not part of the DetectionRule domain model.
    """

    # ------------------------------------------------------------------------
    # Rule Identity
    # ------------------------------------------------------------------------

    id: str = Field(
        min_length=1,
        max_length=128,
    )

    name: str = Field(
        min_length=1,
        max_length=200,
    )

    description: str = Field(
        min_length=1,
        max_length=2000,
    )

    # ------------------------------------------------------------------------
    # Rule Configuration
    # ------------------------------------------------------------------------

    enabled: bool

    severity: str = Field(
        min_length=1,
        max_length=32,
    )

    category: str = Field(
        min_length=1,
        max_length=64,
    )

    conditions: list[
        DetectionRuleConditionResponse
    ] = Field(
        min_length=1,
        max_length=50,
    )

    match: Literal["all", "any"]

    tags: list[str] = Field(
        max_length=50,
    )

    # ------------------------------------------------------------------------
    # Persisted Detection Statistics
    # ------------------------------------------------------------------------

    matches: int = Field(
        default=0,
        ge=0,
    )

    alerts: int = Field(
        default=0,
        ge=0,
    )

    suppressed: int = Field(
        default=0,
        ge=0,
    )

    last_match: datetime | None = None

    # ------------------------------------------------------------------------
    # Domain Conversion
    # ------------------------------------------------------------------------

    @classmethod
    def from_domain(
        cls,
        rule: DetectionRule,
        *,
        matches: int = 0,
        alerts: int = 0,
        suppressed: int = 0,
        last_match: datetime | None = None,
    ) -> DetectionRuleResponse:
        """
        Build an API response from a DetectionRule domain object.

        Statistics are normalized defensively to non-negative values.
        """

        return cls(
            id=rule.id,
            name=rule.name,
            description=rule.description,
            enabled=rule.enabled,
            severity=rule.severity,
            category=rule.category,
            conditions=[
                DetectionRuleConditionResponse.from_domain(
                    condition,
                )
                for condition in rule.conditions
            ],
            match=rule.match,
            tags=list(rule.tags),
            matches=max(
                0,
                matches,
            ),
            alerts=max(
                0,
                alerts,
            ),
            suppressed=max(
                0,
                suppressed,
            ),
            last_match=last_match,
        )


# ============================================================================
# Detection Rule Create Request
# ============================================================================


class DetectionRuleCreateRequest(
    DetectionAPIModel,
):
    """
    Request body for creating a Detection rule.

    The client explicitly supplies the rule ID.
    """

    id: str = Field(
        pattern=r"^[a-z0-9][a-z0-9_-]{2,127}$",
    )

    name: str = Field(
        min_length=1,
        max_length=200,
    )

    description: str = Field(
        min_length=1,
        max_length=2000,
    )

    enabled: bool = True

    severity: str = Field(
        min_length=1,
        max_length=32,
    )

    category: str = Field(
        min_length=1,
        max_length=64,
    )

    conditions: list[
        DetectionRuleConditionResponse
    ] = Field(
        min_length=1,
        max_length=50,
    )

    match: Literal["all", "any"] = "all"

    tags: list[str] = Field(
        default_factory=list,
        max_length=50,
    )

    def to_domain(
        self,
    ) -> DetectionRule:
        """
        Convert the validated API request into DetectionRule.

        The domain model remains the final validation boundary.
        """

        return DetectionRule.model_validate(
            {
                "id": self.id,
                "name": self.name,
                "description": self.description,
                "enabled": self.enabled,
                "severity": self.severity,
                "category": self.category,
                "conditions": [
                    condition.model_dump()
                    for condition in self.conditions
                ],
                "match": self.match,
                "tags": list(self.tags),
            },
        )


# ============================================================================
# Detection Rule Update Request
# ============================================================================


class DetectionRuleUpdateRequest(
    DetectionAPIModel,
):
    """
    Partial update request for an existing Detection rule.

    Rule ID is intentionally excluded.

    The rule ID comes from the URL path.

    None means:
        "do not update this field"
    """

    name: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
    )

    description: str | None = Field(
        default=None,
        min_length=1,
        max_length=2000,
    )

    enabled: bool | None = None

    severity: str | None = Field(
        default=None,
        min_length=1,
        max_length=32,
    )

    category: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
    )

    conditions: list[
        DetectionRuleConditionResponse
    ] | None = Field(
        default=None,
        min_length=1,
        max_length=50,
    )

    match: Literal["all", "any"] | None = None

    tags: list[str] | None = Field(
        default=None,
        max_length=50,
    )


# ============================================================================
# Detection Result Response
# ============================================================================


class DetectionResultResponse(
    DetectionAPIModel,
):
    """
    Public API representation of a persisted DetectionResult.

    DetectionResult represents the output of the Detection layer.

    It remains independent from DetectionRule configuration.
    """

    detection_id: UUID

    rule_id: str = Field(
        min_length=1,
        max_length=128,
    )

    rule_name: str = Field(
        min_length=1,
        max_length=200,
    )

    event_id: UUID

    severity: str = Field(
        min_length=1,
        max_length=32,
    )

    category: str = Field(
        min_length=1,
        max_length=64,
    )

    description: str = Field(
        min_length=1,
        max_length=2000,
    )

    matched_at: datetime

    tags: list[str] = Field(
        max_length=50,
    )

    suppressed: bool

    @classmethod
    def from_domain(
        cls,
        result: DetectionResult,
    ) -> DetectionResultResponse:
        """
        Convert a domain DetectionResult into its API representation.
        """

        return cls(
            detection_id=result.detection_id,
            rule_id=result.rule_id,
            rule_name=result.rule_name,
            event_id=result.event_id,
            severity=result.severity,
            category=result.category,
            description=result.description,
            matched_at=result.matched_at,
            tags=list(result.tags),
            suppressed=result.suppressed,
        )


# ============================================================================
# Detection Summary / Statistics
# ============================================================================


class DetectionSummaryResponse(
    DetectionAPIModel,
):
    """
    High-level Detection subsystem statistics.

    Runtime registry:
        - total_rules
        - enabled_rules
        - disabled_rules
        - total_plugins
        - enabled_plugins

    Persisted DetectionResult history:
        - detection_matches
        - suppressed_matches

    Current-process runtime metrics:
        - total_evaluations
        - evaluation_failures
        - plugin_evaluations
        - plugin_failures

    The schema performs validation only.
    Values are supplied by the backend application layer.
    """

    # ------------------------------------------------------------------------
    # Rule Registry
    # ------------------------------------------------------------------------

    total_rules: int = Field(
        default=0,
        ge=0,
    )

    enabled_rules: int = Field(
        default=0,
        ge=0,
    )

    disabled_rules: int = Field(
        default=0,
        ge=0,
    )

    # ------------------------------------------------------------------------
    # Plugin Registry
    # ------------------------------------------------------------------------

    total_plugins: int = Field(
        default=0,
        ge=0,
    )

    enabled_plugins: int = Field(
        default=0,
        ge=0,
    )

    # ------------------------------------------------------------------------
    # Detection Activity
    # ------------------------------------------------------------------------

    total_evaluations: int = Field(
        default=0,
        ge=0,
    )

    detection_matches: int = Field(
        default=0,
        ge=0,
    )

    suppressed_matches: int = Field(
        default=0,
        ge=0,
    )

    evaluation_failures: int = Field(
        default=0,
        ge=0,
    )

    # ------------------------------------------------------------------------
    # Plugin Activity
    # ------------------------------------------------------------------------

    plugin_evaluations: int = Field(
        default=0,
        ge=0,
    )

    plugin_failures: int = Field(
        default=0,
        ge=0,
    )


# ============================================================================
# Detection Filter Options
# ============================================================================


class DetectionFilterOptionsResponse(
    DetectionAPIModel,
):
    """
    Backend-owned Detection filter options.

    Frontend must consume these values from the API instead of maintaining
    authoritative hardcoded option lists.
    """

    status: list[str] = Field(
        default_factory=list,
    )

    severity: list[str] = Field(
        default_factory=list,
    )

    category: list[str] = Field(
        default_factory=list,
    )

    tags: list[str] = Field(
        default_factory=list,
    )


# ============================================================================
# Detection Capability
# ============================================================================


class DetectionCapabilityResponse(
    DetectionAPIModel,
):
    """
    Describes currently available Detection capabilities.
    """

    resource: str = Field(
        default="detections",
        min_length=1,
        max_length=64,
    )

    status: str = Field(
        min_length=1,
        max_length=32,
    )

    message: str = Field(
        min_length=1,
        max_length=500,
    )

    rules_api: bool = False

    results_api: bool = False

    plugins_api: bool = False


# ============================================================================
# Detection Rule List
# ============================================================================


class DetectionRuleListResponse(
    DetectionAPIModel,
):
    """
    Paginated Detection rule response.

    Pagination is backend-owned.

    Example:

        page=1
        page_size=30
        total=42
        total_pages=2

    The frontend should use these fields directly for pagination UI.
    """

    items: list[
        DetectionRuleResponse
    ] = Field(
        default_factory=list,
    )

    total: int = Field(
        ge=0,
    )

    page: int = Field(
        ge=1,
    )

    page_size: int = Field(
        ge=1,
        le=100,
    )

    total_pages: int = Field(
        ge=0,
    )


# ============================================================================
# Detection Result List
# ============================================================================


class DetectionResultListResponse(
    DetectionAPIModel,
):
    """
    Paginated persisted DetectionResult response.

    Pagination metadata is supplied by the backend.
    """

    items: list[
        DetectionResultResponse
    ] = Field(
        default_factory=list,
    )

    total: int = Field(
        ge=0,
    )

    page: int = Field(
        ge=1,
    )

    page_size: int = Field(
        ge=1,
        le=100,
    )

    total_pages: int = Field(
        ge=0,
    )


# ============================================================================
# Public API
# ============================================================================

__all__ = [
    "DetectionAPIModel",
    "DetectionCapabilityResponse",
    "DetectionFilterOptionsResponse",
    "DetectionResultListResponse",
    "DetectionResultResponse",
    "DetectionRuleConditionResponse",
    "DetectionRuleCreateRequest",
    "DetectionRuleListResponse",
    "DetectionRuleResponse",
    "DetectionRuleUpdateRequest",
    "DetectionSummaryResponse",
]