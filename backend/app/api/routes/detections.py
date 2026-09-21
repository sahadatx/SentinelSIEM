from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
)

from app.api.dependencies import (
    get_detection_engine,
    get_detection_repository,
    get_detection_service,
    require_permission,
)
from app.api.schemas.detections import (
    DetectionCapabilityResponse,
    DetectionResultListResponse,
    DetectionResultResponse,
    DetectionRuleCreateRequest,
    DetectionRuleListResponse,
    DetectionRuleResponse,
    DetectionRuleUpdateRequest,
    DetectionSummaryResponse,
)
from app.auth.permissions import Permission
from app.detection.engine import DetectionEngine
from app.detection.schema import DetectionRule
from app.detection.service import DetectionService
from app.storage.opensearch.detections import (
    OpenSearchDetectionRepository,
)


# ============================================================================
# Router
# ============================================================================

router = APIRouter(
    prefix="/detections",
    tags=["detections"],
)


# ============================================================================
# Permission Dependencies
# ============================================================================

_detection_read_permission = require_permission(
    Permission.DETECTIONS_READ,
)

_detection_manage_permission = require_permission(
    Permission.DETECTIONS_MANAGE,
)


# ============================================================================
# Backend-owned Detection option catalogues
# ============================================================================

# These are backend-owned UI/domain options.
#
# IMPORTANT:
#   - Frontend must NOT hardcode these values.
#   - Create/Edit receives these values from /filter-options.
#   - Table filters receive the same values from /filter-options.
#   - Existing custom severity values are merged into this catalogue below.
#
# The DetectionRule schema intentionally keeps `severity` as a string.
# Therefore the catalogue controls the standard selectable values without
# changing the underlying DetectionRule contract.
DETECTION_SEVERITY_OPTIONS: tuple[str, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "informational",
)


# ============================================================================
# Internal Dependency Helpers
# ============================================================================


def _require_detection_service(
    detection_service: DetectionService | None,
) -> DetectionService:
    """Require the application-scoped DetectionService."""

    if detection_service is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detection service is not configured.",
        )

    return detection_service


def _require_detection_engine(
    detection_engine: DetectionEngine | None,
) -> DetectionEngine:
    """Require the application-scoped DetectionEngine."""

    if detection_engine is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detection engine is not configured.",
        )

    return detection_engine


def _require_detection_repository(
    detection_repository: OpenSearchDetectionRepository | None,
) -> OpenSearchDetectionRepository:
    """Require the persisted DetectionResult repository."""

    if detection_repository is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detection result repository is not configured.",
        )

    return detection_repository


# ============================================================================
# Internal Normalization Helpers
# ============================================================================


def _normalize_rule_id(
    rule_id: str,
) -> str:
    """Normalize and validate a Detection rule ID."""

    normalized = rule_id.strip()

    if not normalized:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Detection rule ID must not be empty.",
        )

    return normalized


def _normalize_optional_text(
    value: str | None,
) -> str | None:
    """Normalize optional query text."""

    if value is None:
        return None

    normalized = value.strip()

    return normalized or None


# ============================================================================
# Pagination Helpers
# ============================================================================


def _calculate_total_pages(
    *,
    total: int,
    page_size: int,
) -> int:
    """
    Calculate total page count for API pagination metadata.

    This is pagination metadata, not a security metric.
    """

    if total <= 0:
        return 0

    return (
        total + page_size - 1
    ) // page_size


def _validate_requested_page(
    *,
    page: int,
    total: int,
    page_size: int,
) -> None:
    """
    Validate a requested one-based page.

    Empty result sets are allowed on page 1.

    For non-empty datasets, requesting a page beyond the last page
    returns 404 rather than silently returning an empty page.
    """

    total_pages = _calculate_total_pages(
        total=total,
        page_size=page_size,
    )

    if total_pages > 0 and page > total_pages:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Detection rule page {page} "
                f"does not exist. Total pages: {total_pages}."
            ),
        )


def _paginate_rules(
    rules: tuple[DetectionRule, ...],
    *,
    page: int,
    page_size: int,
) -> tuple[DetectionRule, ...]:
    """Apply one-based pagination to a rule collection."""

    offset = (
        page - 1
    ) * page_size

    return rules[
        offset:offset + page_size
    ]


# ============================================================================
# Internal Rule Helpers
# ============================================================================


def _build_updated_rule(
    *,
    existing: DetectionRule,
    payload: DetectionRuleUpdateRequest,
) -> DetectionRule:
    """
    Build a new DetectionRule from an existing rule and partial update.

    Rule ID remains immutable.
    """

    updates = payload.model_dump(
        exclude_unset=True,
        exclude_none=True,
    )

    if not updates:
        return existing

    current = existing.model_dump()

    current.update(
        updates,
    )

    current["id"] = existing.id

    return DetectionRule.model_validate(
        current,
    )


async def _get_rule_statistics(
    *,
    detection_repository: OpenSearchDetectionRepository,
    rule_ids: tuple[str, ...],
) -> dict[str, Any]:
    """
    Return persisted DetectionResult statistics keyed by rule ID.
    """

    if not rule_ids:
        return {}

    statistics = (
        await detection_repository.get_rule_statistics(
            rule_ids=rule_ids,
        )
    )

    return {
        item.rule_id: item
        for item in statistics
    }


async def _build_rule_response(
    *,
    rule: DetectionRule,
    detection_repository: OpenSearchDetectionRepository,
) -> DetectionRuleResponse:
    """
    Build the public DetectionRule response.

    Rule definitions come from DetectionService.

    Historical DetectionResult statistics come from OpenSearch.

    Alert lifecycle remains outside Detection.
    """

    statistics_by_rule = (
        await _get_rule_statistics(
            detection_repository=detection_repository,
            rule_ids=(rule.id,),
        )
    )

    item = statistics_by_rule.get(
        rule.id,
    )

    if item is None:
        matches = 0
        suppressed = 0
        last_match = None

    else:
        matches = max(
            0,
            int(item.matches),
        )

        suppressed = max(
            0,
            int(item.suppressed),
        )

        last_match = (
            item.last_match_at
        )

    return DetectionRuleResponse.from_domain(
        rule,
        matches=matches,
        alerts=0,
        suppressed=suppressed,
        last_match=last_match,
    )


def _rule_matches_query(
    *,
    rule: DetectionRule,
    query: str | None,
) -> bool:
    """
    Match a Detection rule against search text.

    Search fields:
        - ID
        - name
        - description
    """

    normalized = (
        _normalize_optional_text(
            query,
        )
    )

    if normalized is None:
        return True

    needle = normalized.casefold()

    searchable = (
        rule.id,
        rule.name,
        rule.description,
    )

    return any(
        needle in value.casefold()
        for value in searchable
    )


def _rule_matches_filters(
    *,
    rule: DetectionRule,
    query: str | None,
    enabled: bool | None,
    severity: str | None,
    category: str | None,
    tag: str | None,
) -> bool:
    """Apply Detection rule list filters."""

    if not _rule_matches_query(
        rule=rule,
        query=query,
    ):
        return False

    if enabled is not None:
        if rule.enabled is not enabled:
            return False

    normalized_severity = (
        _normalize_optional_text(
            severity,
        )
    )

    if (
        normalized_severity is not None
        and rule.severity.casefold()
        != normalized_severity.casefold()
    ):
        return False

    normalized_category = (
        _normalize_optional_text(
            category,
        )
    )

    if (
        normalized_category is not None
        and rule.category.casefold()
        != normalized_category.casefold()
    ):
        return False

    normalized_tag = (
        _normalize_optional_text(
            tag,
        )
    )

    if normalized_tag is not None:
        tag_needle = (
            normalized_tag.casefold()
        )

        if not any(
            item.casefold() == tag_needle
            for item in rule.tags
        ):
            return False

    return True


# ============================================================================
# Internal Persisted Statistics Helpers
# ============================================================================


async def _get_persisted_detection_statistics(
    *,
    detection_repository: OpenSearchDetectionRepository,
) -> tuple[int, int]:
    """
    Return authoritative persisted DetectionResult statistics.

    Returns:
        (
            non_suppressed_matches,
            suppressed_matches,
        )
    """

    try:
        non_suppressed = (
            await detection_repository.search(
                query=None,
                rule_id=None,
                event_id=None,
                severity=None,
                category=None,
                suppressed=False,
                start_time=None,
                end_time=None,
                offset=0,
                limit=1,
            )
        )

        detection_matches = max(
            0,
            int(
                non_suppressed.total,
            ),
        )

        suppressed = (
            await detection_repository.search(
                query=None,
                rule_id=None,
                event_id=None,
                severity=None,
                category=None,
                suppressed=True,
                start_time=None,
                end_time=None,
                offset=0,
                limit=1,
            )
        )

        suppressed_matches = max(
            0,
            int(
                suppressed.total,
            ),
        )

        return (
            detection_matches,
            suppressed_matches,
        )

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Detection result statistics are temporarily "
                "unavailable."
            ),
        ) from exc


# ============================================================================
# GET /detections
# Canonical Detection Rule List
# ============================================================================


@router.get(
    "",
    response_model=DetectionRuleListResponse,
    summary="List Detection rules",
    dependencies=[
        Depends(
            _detection_read_permission,
        ),
    ],
)
async def list_detections(
    query: str | None = Query(
        default=None,
        description=(
            "Case-insensitive search across rule ID, "
            "name, and description."
        ),
    ),
    enabled: bool | None = Query(
        default=None,
        description="Filter rules by enabled state.",
    ),
    severity: str | None = Query(
        default=None,
        description="Filter rules by severity.",
    ),
    category: str | None = Query(
        default=None,
        description="Filter rules by category.",
    ),
    tag: str | None = Query(
        default=None,
        description="Filter rules by tag.",
    ),
    page: int = Query(
        default=1,
        ge=1,
        description="One-based rule page.",
    ),
    page_size: int = Query(
        default=30,
        ge=1,
        le=100,
        description="Number of rules per page.",
    ),
    detection_service: DetectionService | None = Depends(
        get_detection_service,
    ),
    detection_repository: OpenSearchDetectionRepository | None = Depends(
        get_detection_repository,
    ),
) -> DetectionRuleListResponse:
    """
    Return the canonical Detection rule list.

    GET /api/v1/detections
    """

    service = _require_detection_service(
        detection_service,
    )

    repository = _require_detection_repository(
        detection_repository,
    )

    rules = service.list_rules()

    filtered_rules = tuple(
        rule
        for rule in rules
        if _rule_matches_filters(
            rule=rule,
            query=query,
            enabled=enabled,
            severity=severity,
            category=category,
            tag=tag,
        )
    )

    total = len(
        filtered_rules,
    )

    total_pages = (
        _calculate_total_pages(
            total=total,
            page_size=page_size,
        )
    )

    _validate_requested_page(
        page=page,
        total=total,
        page_size=page_size,
    )

    page_rules = _paginate_rules(
        filtered_rules,
        page=page,
        page_size=page_size,
    )

    if not page_rules:
        return DetectionRuleListResponse(
            items=[],
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
        )

    statistics_by_rule = (
        await _get_rule_statistics(
            detection_repository=repository,
            rule_ids=tuple(
                rule.id
                for rule in page_rules
            ),
        )
    )

    items: list[
        DetectionRuleResponse
    ] = []

    for rule in page_rules:
        item = statistics_by_rule.get(
            rule.id,
        )

        if item is None:
            matches = 0
            suppressed = 0
            last_match = None

        else:
            matches = max(
                0,
                int(item.matches),
            )

            suppressed = max(
                0,
                int(item.suppressed),
            )

            last_match = (
                item.last_match_at
            )

        items.append(
            DetectionRuleResponse.from_domain(
                rule,
                matches=matches,
                alerts=0,
                suppressed=suppressed,
                last_match=last_match,
            )
        )

    return DetectionRuleListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


# ============================================================================
# GET /detections/capability
# ============================================================================


@router.get(
    "/capability",
    response_model=DetectionCapabilityResponse,
    summary="Get Detection capability",
    dependencies=[
        Depends(
            _detection_read_permission,
        ),
    ],
)
def get_detection_capability(
    detection_service: DetectionService | None = Depends(
        get_detection_service,
    ),
    detection_engine: DetectionEngine | None = Depends(
        get_detection_engine,
    ),
    detection_repository: OpenSearchDetectionRepository | None = Depends(
        get_detection_repository,
    ),
) -> DetectionCapabilityResponse:
    """Return Detection subsystem capability."""

    service_available = (
        detection_service is not None
    )

    engine_available = (
        detection_engine is not None
    )

    repository_available = (
        detection_repository is not None
    )

    if (
        service_available
        and engine_available
        and repository_available
    ):
        subsystem_status = "available"

        message = (
            "Detection service, Detection engine, "
            "and Detection result repository are available."
        )

    elif service_available:
        subsystem_status = "degraded"

        message = (
            "Detection rule management is available, "
            "but one or more Detection runtime dependencies "
            "are unavailable."
        )

    elif engine_available:
        subsystem_status = "degraded"

        message = (
            "Detection engine is available, "
            "but Detection rule management is unavailable."
        )

    else:
        subsystem_status = "unavailable"

        message = (
            "Detection service and Detection engine "
            "are not configured."
        )

    return DetectionCapabilityResponse(
        resource="detections",
        status=subsystem_status,
        message=message,
        rules_api=service_available,
        results_api=repository_available,
        plugins_api=service_available,
    )


# ============================================================================
# GET /detections/statistics
# ============================================================================


@router.get(
    "/statistics",
    response_model=DetectionSummaryResponse,
    summary="Get Detection statistics",
    dependencies=[
        Depends(
            _detection_read_permission,
        ),
    ],
)
async def get_detection_statistics(
    detection_service: DetectionService | None = Depends(
        get_detection_service,
    ),
    detection_repository: OpenSearchDetectionRepository | None = Depends(
        get_detection_repository,
    ),
) -> DetectionSummaryResponse:
    """Return authoritative Detection statistics."""

    service = _require_detection_service(
        detection_service,
    )

    repository = _require_detection_repository(
        detection_repository,
    )

    runtime_statistics = (
        service.statistics()
    )

    (
        persisted_detection_matches,
        persisted_suppressed_matches,
    ) = await _get_persisted_detection_statistics(
        detection_repository=repository,
    )

    return DetectionSummaryResponse(
        total_rules=(
            runtime_statistics.total_rules
        ),
        enabled_rules=(
            runtime_statistics.enabled_rules
        ),
        disabled_rules=(
            runtime_statistics.disabled_rules
        ),
        total_plugins=(
            runtime_statistics.total_plugins
        ),
        enabled_plugins=(
            runtime_statistics.enabled_plugins
        ),
        detection_matches=(
            persisted_detection_matches
        ),
        suppressed_matches=(
            persisted_suppressed_matches
        ),
        total_evaluations=(
            runtime_statistics.total_evaluations
        ),
        evaluation_failures=(
            runtime_statistics.evaluation_failures
        ),
        plugin_evaluations=(
            runtime_statistics.plugin_evaluations
        ),
        plugin_failures=(
            runtime_statistics.plugin_failures
        ),
    )


# ============================================================================
# GET /detections/summary
# Backward-compatible alias
# ============================================================================


@router.get(
    "/summary",
    response_model=DetectionSummaryResponse,
    summary="Get Detection summary",
    dependencies=[
        Depends(
            _detection_read_permission,
        ),
    ],
)
async def get_detection_summary(
    detection_service: DetectionService | None = Depends(
        get_detection_service,
    ),
    detection_repository: OpenSearchDetectionRepository | None = Depends(
        get_detection_repository,
    ),
) -> DetectionSummaryResponse:
    """Backward-compatible alias for statistics."""

    return await get_detection_statistics(
        detection_service=detection_service,
        detection_repository=detection_repository,
    )


# ============================================================================
# GET /detections/filter-options
# ============================================================================


@router.get(
    "/filter-options",
    response_model=dict[str, Any],
    summary="Get Detection filter options",
    dependencies=[
        Depends(
            _detection_read_permission,
        ),
    ],
)
def get_detection_filter_options(
    detection_service: DetectionService | None = Depends(
        get_detection_service,
    ),
) -> dict[str, Any]:
    """
    Return backend-owned Detection filter options.

    Severity behavior:

        1. Standard backend severity catalogue is always returned.
        2. Existing rule severity values are merged into the catalogue.
        3. Existing custom severity values are therefore preserved.
        4. Frontend does not need to hardcode severity options.

    Example:

        {
            "status": [
                "enabled",
                "disabled"
            ],
            "severity": [
                "critical",
                "high",
                "informational",
                "low",
                "medium"
            ],
            "category": [...],
            "tags": [...]
        }
    """

    service = _require_detection_service(
        detection_service,
    )

    rules = service.list_rules()


    # ----------------------------------------------------------------------
    # Severity
    #
    # Start with the backend-owned standard catalogue.
    # Then merge any severity already used by existing Detection rules.
    # ----------------------------------------------------------------------

    severity_values = {
        value.casefold(): value
        for value in DETECTION_SEVERITY_OPTIONS
    }

    for rule in rules:
        severity = (
            rule.severity.strip()
            if rule.severity
            else ""
        )

        if severity:
            severity_values.setdefault(
                severity.casefold(),
                severity,
            )

    severities = sorted(
        severity_values.values(),
        key=str.casefold,
    )


    # ----------------------------------------------------------------------
    # Category
    # ----------------------------------------------------------------------

    categories = sorted(
        {
            rule.category.strip()
            for rule in rules
            if rule.category
            and rule.category.strip()
        },
        key=str.casefold,
    )


    # ----------------------------------------------------------------------
    # Tags
    # ----------------------------------------------------------------------

    tags = sorted(
        {
            tag.strip()
            for rule in rules
            for tag in rule.tags
            if tag
            and tag.strip()
        },
        key=str.casefold,
    )


    return {
        "status": [
            "enabled",
            "disabled",
        ],
        "severity": severities,
        "category": categories,
        "tags": tags,
    }


# ============================================================================
# GET /detections/results
# ============================================================================


@router.get(
    "/results",
    response_model=DetectionResultListResponse,
    summary="List Detection results",
    dependencies=[
        Depends(
            _detection_read_permission,
        ),
    ],
)
async def list_detection_results(
    query: str | None = Query(
        default=None,
    ),
    rule_id: str | None = Query(
        default=None,
    ),
    event_id: UUID | None = Query(
        default=None,
    ),
    severity: str | None = Query(
        default=None,
    ),
    category: str | None = Query(
        default=None,
    ),
    suppressed: bool | None = Query(
        default=None,
    ),
    start_time: datetime | None = Query(
        default=None,
    ),
    end_time: datetime | None = Query(
        default=None,
    ),
    page: int = Query(
        default=1,
        ge=1,
    ),
    page_size: int = Query(
        default=30,
        ge=1,
        le=100,
    ),
    detection_repository: OpenSearchDetectionRepository | None = Depends(
        get_detection_repository,
    ),
) -> DetectionResultListResponse:
    """List persisted DetectionResult records."""

    repository = _require_detection_repository(
        detection_repository,
    )

    normalized_rule_id = (
        _normalize_optional_text(
            rule_id,
        )
    )

    normalized_query = (
        _normalize_optional_text(
            query,
        )
    )

    normalized_severity = (
        _normalize_optional_text(
            severity,
        )
    )

    normalized_category = (
        _normalize_optional_text(
            category,
        )
    )

    if (
        rule_id is not None
        and normalized_rule_id is None
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="rule_id must not be empty.",
        )

    if (
        start_time is not None
        and end_time is not None
        and start_time > end_time
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "start_time must be earlier than "
                "or equal to end_time."
            ),
        )

    offset = (
        page - 1
    ) * page_size

    result = await repository.search(
        query=normalized_query,
        rule_id=normalized_rule_id,
        event_id=event_id,
        severity=normalized_severity,
        category=normalized_category,
        suppressed=suppressed,
        start_time=start_time,
        end_time=end_time,
        offset=offset,
        limit=page_size,
    )

    total = max(
        0,
        int(result.total),
    )

    total_pages = (
        _calculate_total_pages(
            total=total,
            page_size=page_size,
        )
    )

    if (
        total_pages > 0
        and page > total_pages
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Detection result page {page} "
                f"does not exist. Total pages: "
                f"{total_pages}."
            ),
        )

    return DetectionResultListResponse(
        items=[
            DetectionResultResponse.from_domain(
                item,
            )
            for item in result.results
        ],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


# ============================================================================
# GET /detections/results/{detection_id}
# ============================================================================


@router.get(
    "/results/{detection_id}",
    response_model=DetectionResultResponse,
    summary="Get Detection result",
    dependencies=[
        Depends(
            _detection_read_permission,
        ),
    ],
)
async def get_detection_result(
    detection_id: UUID,
    detection_repository: OpenSearchDetectionRepository | None = Depends(
        get_detection_repository,
    ),
) -> DetectionResultResponse:
    """Get one persisted DetectionResult."""

    repository = _require_detection_repository(
        detection_repository,
    )

    result = await repository.get(
        detection_id,
    )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "Detection result not found: "
                f"{detection_id}"
            ),
        )

    return DetectionResultResponse.from_domain(
        result,
    )


# ============================================================================
# GET /detections/rules
# Compatibility endpoint
# ============================================================================


@router.get(
    "/rules",
    response_model=DetectionRuleListResponse,
    summary="List Detection rules (compatibility)",
    dependencies=[
        Depends(
            _detection_read_permission,
        ),
    ],
)
async def list_detection_rules_compatibility(
    enabled: bool | None = Query(
        default=None,
    ),
    query: str | None = Query(
        default=None,
    ),
    severity: str | None = Query(
        default=None,
    ),
    category: str | None = Query(
        default=None,
    ),
    tag: str | None = Query(
        default=None,
    ),
    page: int = Query(
        default=1,
        ge=1,
    ),
    page_size: int = Query(
        default=30,
        ge=1,
        le=100,
    ),
    detection_service: DetectionService | None = Depends(
        get_detection_service,
    ),
    detection_repository: OpenSearchDetectionRepository | None = Depends(
        get_detection_repository,
    ),
) -> DetectionRuleListResponse:
    """Backward-compatible Detection rule list endpoint."""

    return await list_detections(
        query=query,
        enabled=enabled,
        severity=severity,
        category=category,
        tag=tag,
        page=page,
        page_size=page_size,
        detection_service=detection_service,
        detection_repository=detection_repository,
    )


# ============================================================================
# GET /detections/rules/{rule_id}
# ============================================================================


@router.get(
    "/rules/{rule_id}",
    response_model=DetectionRuleResponse,
    summary="Get Detection rule (compatibility)",
    dependencies=[
        Depends(
            _detection_read_permission,
        ),
    ],
)
async def get_detection_rule_compatibility(
    rule_id: str,
    detection_service: DetectionService | None = Depends(
        get_detection_service,
    ),
    detection_repository: OpenSearchDetectionRepository | None = Depends(
        get_detection_repository,
    ),
) -> DetectionRuleResponse:
    """Backward-compatible Detection rule detail endpoint."""

    return await get_detection(
        rule_id=rule_id,
        detection_service=detection_service,
        detection_repository=detection_repository,
    )


# ============================================================================
# POST /detections
# ============================================================================


@router.post(
    "",
    response_model=DetectionRuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Detection rule",
    dependencies=[
        Depends(
            _detection_manage_permission,
        ),
    ],
)
async def create_detection(
    payload: DetectionRuleCreateRequest,
    detection_service: DetectionService | None = Depends(
        get_detection_service,
    ),
    detection_repository: OpenSearchDetectionRepository | None = Depends(
        get_detection_repository,
    ),
) -> DetectionRuleResponse:
    """Create a Detection rule."""

    service = _require_detection_service(
        detection_service,
    )

    repository = _require_detection_repository(
        detection_repository,
    )

    try:
        rule = payload.to_domain()

        created = service.create_rule(
            rule,
        )

    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    except ValueError as exc:
        message = str(exc)

        if message.startswith(
            "duplicate detection rule:",
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=message,
            ) from exc

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message,
        ) from exc

    return await _build_rule_response(
        rule=created,
        detection_repository=repository,
    )


# ============================================================================
# POST /detections/rules
# Compatibility endpoint
# ============================================================================


@router.post(
    "/rules",
    response_model=DetectionRuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Detection rule (compatibility)",
    dependencies=[
        Depends(
            _detection_manage_permission,
        ),
    ],
)
async def create_detection_rule_compatibility(
    payload: DetectionRuleCreateRequest,
    detection_service: DetectionService | None = Depends(
        get_detection_service,
    ),
    detection_repository: OpenSearchDetectionRepository | None = Depends(
        get_detection_repository,
    ),
) -> DetectionRuleResponse:
    """Backward-compatible rule creation endpoint."""

    return await create_detection(
        payload=payload,
        detection_service=detection_service,
        detection_repository=detection_repository,
    )


# ============================================================================
# GET /detections/{rule_id}
# ============================================================================


@router.get(
    "/{rule_id}",
    response_model=DetectionRuleResponse,
    summary="Get Detection rule",
    dependencies=[
        Depends(
            _detection_read_permission,
        ),
    ],
)
async def get_detection(
    rule_id: str,
    detection_service: DetectionService | None = Depends(
        get_detection_service,
    ),
    detection_repository: OpenSearchDetectionRepository | None = Depends(
        get_detection_repository,
    ),
) -> DetectionRuleResponse:
    """Get one Detection rule."""

    service = _require_detection_service(
        detection_service,
    )

    repository = _require_detection_repository(
        detection_repository,
    )

    normalized_rule_id = _normalize_rule_id(
        rule_id,
    )

    try:
        rule = service.get_rule(
            normalized_rule_id,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "Detection rule not found: "
                f"{normalized_rule_id}"
            ),
        )

    return await _build_rule_response(
        rule=rule,
        detection_repository=repository,
    )


# ============================================================================
# PATCH /detections/{rule_id}
# ============================================================================


@router.patch(
    "/{rule_id}",
    response_model=DetectionRuleResponse,
    summary="Update Detection rule",
    dependencies=[
        Depends(
            _detection_manage_permission,
        ),
    ],
)
async def update_detection(
    rule_id: str,
    payload: DetectionRuleUpdateRequest,
    detection_service: DetectionService | None = Depends(
        get_detection_service,
    ),
    detection_repository: OpenSearchDetectionRepository | None = Depends(
        get_detection_repository,
    ),
) -> DetectionRuleResponse:
    """Update an existing Detection rule."""

    service = _require_detection_service(
        detection_service,
    )

    repository = _require_detection_repository(
        detection_repository,
    )

    normalized_rule_id = _normalize_rule_id(
        rule_id,
    )

    try:
        existing = service.get_rule(
            normalized_rule_id,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "Detection rule not found: "
                f"{normalized_rule_id}"
            ),
        )

    try:
        updated_rule = _build_updated_rule(
            existing=existing,
            payload=payload,
        )

        updated = service.update_rule(
            updated_rule,
        )

    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return await _build_rule_response(
        rule=updated,
        detection_repository=repository,
    )


# ============================================================================
# PATCH /detections/rules/{rule_id}
# Compatibility endpoint
# ============================================================================


@router.patch(
    "/rules/{rule_id}",
    response_model=DetectionRuleResponse,
    summary="Update Detection rule (compatibility)",
    dependencies=[
        Depends(
            _detection_manage_permission,
        ),
    ],
)
async def update_detection_rule_compatibility(
    rule_id: str,
    payload: DetectionRuleUpdateRequest,
    detection_service: DetectionService | None = Depends(
        get_detection_service,
    ),
    detection_repository: OpenSearchDetectionRepository | None = Depends(
        get_detection_repository,
    ),
) -> DetectionRuleResponse:
    """Backward-compatible rule update endpoint."""

    return await update_detection(
        rule_id=rule_id,
        payload=payload,
        detection_service=detection_service,
        detection_repository=detection_repository,
    )


# ============================================================================
# POST /detections/{rule_id}/enable
# ============================================================================


@router.post(
    "/{rule_id}/enable",
    response_model=DetectionRuleResponse,
    summary="Enable Detection rule",
    dependencies=[
        Depends(
            _detection_manage_permission,
        ),
    ],
)
async def enable_detection(
    rule_id: str,
    detection_service: DetectionService | None = Depends(
        get_detection_service,
    ),
    detection_repository: OpenSearchDetectionRepository | None = Depends(
        get_detection_repository,
    ),
) -> DetectionRuleResponse:
    """Enable one Detection rule."""

    service = _require_detection_service(
        detection_service,
    )

    repository = _require_detection_repository(
        detection_repository,
    )

    normalized_rule_id = _normalize_rule_id(
        rule_id,
    )

    try:
        existing = service.get_rule(
            normalized_rule_id,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "Detection rule not found: "
                f"{normalized_rule_id}"
            ),
        )

    try:
        updated = service.enable_rule(
            normalized_rule_id,
        )

    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return await _build_rule_response(
        rule=updated,
        detection_repository=repository,
    )


# ============================================================================
# POST /detections/{rule_id}/disable
# ============================================================================


@router.post(
    "/{rule_id}/disable",
    response_model=DetectionRuleResponse,
    summary="Disable Detection rule",
    dependencies=[
        Depends(
            _detection_manage_permission,
        ),
    ],
)
async def disable_detection(
    rule_id: str,
    detection_service: DetectionService | None = Depends(
        get_detection_service,
    ),
    detection_repository: OpenSearchDetectionRepository | None = Depends(
        get_detection_repository,
    ),
) -> DetectionRuleResponse:
    """Disable one Detection rule."""

    service = _require_detection_service(
        detection_service,
    )

    repository = _require_detection_repository(
        detection_repository,
    )

    normalized_rule_id = _normalize_rule_id(
        rule_id,
    )

    try:
        existing = service.get_rule(
            normalized_rule_id,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "Detection rule not found: "
                f"{normalized_rule_id}"
            ),
        )

    try:
        updated = service.disable_rule(
            normalized_rule_id,
        )

    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return await _build_rule_response(
        rule=updated,
        detection_repository=repository,
    )


# ============================================================================
# DELETE /detections/{rule_id}
# ============================================================================


@router.delete(
    "/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete Detection rule",
    dependencies=[
        Depends(
            _detection_manage_permission,
        ),
    ],
)
def delete_detection(
    rule_id: str,
    detection_service: DetectionService | None = Depends(
        get_detection_service,
    ),
) -> None:
    """
    Delete a Detection rule.

    Historical DetectionResult documents are retained.
    """

    service = _require_detection_service(
        detection_service,
    )

    normalized_rule_id = _normalize_rule_id(
        rule_id,
    )

    try:
        service.delete_rule(
            normalized_rule_id,
        )

    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return None


# ============================================================================
# Public API
# ============================================================================

__all__ = [
    "router",
]