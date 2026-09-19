from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.alerts.manager import AlertManager
from app.alerts.models import (
    AlertSeverity,
    AlertSourceType,
    AlertStatus,
)
from app.api.dependencies import (
    get_alert_repository,
    get_current_principal,
    get_incident_manager,
    get_incident_repository,
    get_user_management_service,
)
from app.api.schemas.alerts import (
    AlertAssignmentRequest,
    AlertAuditResponse,
    AlertResponse,
    AlertTransitionRequest,
)
from app.api.schemas.common import PageResponse, Pagination
from app.api.schemas.incidents import IncidentResponse
from app.auth.authorization import require_permission
from app.auth.models import UserPrincipal
from app.auth.permissions import Permission
from app.auth.user_management import UserManagementService
from app.incidents.manager import IncidentManager
from app.incidents.promotion import (
    IncidentAlreadyExistsError,
    IncidentPromotionError,
    IncidentPromotionService,
    IncidentPromotionValidationError,
)
from app.storage.opensearch.alerts import OpenSearchAlertRepository
from app.storage.opensearch.incidents import OpenSearchIncidentRepository


# ============================================================================
# Router
# ============================================================================

router = APIRouter(
    prefix="/alerts",
    tags=["alerts"],
)


# ============================================================================
# Permissions
# ============================================================================

_alerts_read_permission = require_permission(
    Permission.ALERTS_READ,
)

_alerts_manage_permission = require_permission(
    Permission.ALERTS_MANAGE,
)


# ============================================================================
# Constants
# ============================================================================

_ASSIGNABLE_ALERT_ROLES = frozenset(
    {
        "ADMIN",
        "SECURITY_ANALYST",
        "SOC_ANALYST",
    }
)


_SUPPORTED_TRANSITION_TARGETS = frozenset(
    {
        AlertStatus.ACKNOWLEDGED,
        AlertStatus.INVESTIGATING,
        AlertStatus.ESCALATED,
        AlertStatus.RESOLVED,
    }
)


_STATS_BUCKET_SIZE = 100
_FILTER_OPTION_SIZE = 1000


# ============================================================================
# Response Models
# ============================================================================


class AlertStatisticsResponse(BaseModel):
    """
    Backend-authoritative Alert KPI response.

    KPI values are calculated by the backend from persisted Alert data.
    The frontend must not calculate these values from the current page.
    """

    total: int = Field(
        default=0,
        ge=0,
    )

    new: int = Field(
        default=0,
        ge=0,
    )

    critical: int = Field(
        default=0,
        ge=0,
    )

    escalated: int = Field(
        default=0,
        ge=0,
    )

    acknowledged: int = Field(
        default=0,
        ge=0,
    )

    investigating: int = Field(
        default=0,
        ge=0,
    )

    resolved: int = Field(
        default=0,
        ge=0,
    )


class AlertFilterOptionsResponse(BaseModel):
    """
    Backend-authoritative Alert filter catalogue.

    Values are derived from persisted Alert documents.
    The frontend does not maintain a separate hardcoded catalogue.
    """

    statuses: list[str] = Field(
        default_factory=list,
    )

    severities: list[str] = Field(
        default_factory=list,
    )

    source_types: list[str] = Field(
        default_factory=list,
    )

    sources: list[str] = Field(
        default_factory=list,
    )

    rules: list[str] = Field(
        default_factory=list,
    )

    assignees: list[str] = Field(
        default_factory=list,
    )


# ============================================================================
# Helpers
# ============================================================================


def _load_request_alert_manager(
    repository: OpenSearchAlertRepository,
) -> AlertManager:
    """
    Build a request-local AlertManager backed by the request-scoped
    repository.

    The application-scoped AlertManager is not mutated with a
    request-scoped repository.
    """

    return AlertManager(
        repository=repository,
    )


async def _load_persisted_alert(
    *,
    alert_id: UUID,
    repository: OpenSearchAlertRepository,
):
    """
    Load an Alert from persistent storage.

    Raises HTTP 404 when the Alert does not exist.
    """

    alert = await repository.get(
        alert_id,
    )

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="alert not found",
        )

    return alert


async def _ensure_incident_index(
    repository: OpenSearchIncidentRepository,
) -> None:
    """
    Ensure the Incident OpenSearch index exists before promotion.
    """

    try:
        await repository.ensure_index()

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="failed to initialize incident storage",
        ) from exc


async def _validate_alert_assignee(
    *,
    assignee: str | None,
    user_management: UserManagementService,
) -> None:
    """
    Validate an Alert assignment target.

    Assignment is allowed only for an existing, active, unlocked user
    whose role is eligible for Alert operations.

    The role is always obtained from authoritative User Management data.
    The client cannot provide or override the target user's role.
    """

    # Explicit null means unassign.
    if assignee is None:
        return

    normalized_assignee = assignee.strip()

    if not normalized_assignee:
        raise HTTPException(
            status_code=422,
            detail="assignee must be a valid user ID or null",
        )

    try:
        assignee_id = UUID(
            normalized_assignee,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail="assignee must be a valid user ID",
        ) from exc

    try:
        user = await user_management._require_user(
            assignee_id,
        )

    except HTTPException:
        raise

    except Exception as exc:
        error_name = exc.__class__.__name__

        if error_name == "UserNotFoundError":
            raise HTTPException(
                status_code=404,
                detail="assignee user does not exist",
            ) from exc

        raise HTTPException(
            status_code=500,
            detail="unable to validate assignee",
        ) from exc

    if not user.is_active:
        raise HTTPException(
            status_code=409,
            detail="assignee user is inactive",
        )

    if user.is_locked:
        raise HTTPException(
            status_code=409,
            detail="assignee user is locked",
        )

    user_roles = {
        str(role).upper()
        for role in user.roles
    }

    if not user_roles.intersection(
        _ASSIGNABLE_ALERT_ROLES,
    ):
        raise HTTPException(
            status_code=403,
            detail=(
                "assignee user does not have an eligible "
                "Alert analyst role"
            ),
        )


def _normalize_optional_string(
    value: str | None,
) -> str | None:
    """
    Normalize optional query-string values.
    """

    if value is None:
        return None

    normalized = value.strip()

    return normalized or None


def _build_alert_search_bool_query(
    *,
    query: str | None = None,
    status: AlertStatus | None = None,
    severity: AlertSeverity | None = None,
    source_type: AlertSourceType | None = None,
    source_id: str | None = None,
    rule_id: str | None = None,
    assigned_to: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> dict[str, Any]:
    """
    Build the logical Alert filter query.

    The same filter semantics are used by Alert list and KPI endpoints
    so the backend remains the single source of truth.
    """

    filters: list[dict[str, Any]] = []

    lookup_values = (
        (
            "status",
            status.value
            if status is not None
            else None,
        ),
        (
            "severity",
            severity.value
            if severity is not None
            else None,
        ),
        (
            "source_type",
            source_type.value
            if source_type is not None
            else None,
        ),
        (
            "source_id",
            source_id,
        ),
        (
            "rule_id",
            rule_id,
        ),
        (
            "assigned_to",
            assigned_to,
        ),
    )

    for field, value in lookup_values:
        normalized = _normalize_optional_string(
            value,
        )

        if normalized is None:
            continue

        filters.append(
            {
                "term": {
                    field: normalized,
                },
            }
        )

    if (
        start_time is not None
        or end_time is not None
    ):
        time_range: dict[str, str] = {}

        if start_time is not None:
            time_range["gte"] = (
                start_time.isoformat()
            )

        if end_time is not None:
            time_range["lte"] = (
                end_time.isoformat()
            )

        filters.append(
            {
                "range": {
                    "last_seen_at": time_range,
                },
            }
        )

    bool_query: dict[str, Any] = {
        "filter": filters,
    }

    normalized_query = (
        query.strip()
        if query is not None
        else ""
    )

    if normalized_query:
        bool_query["must"] = [
            {
                "multi_match": {
                    "query": normalized_query,
                    "fields": [
                        "alert_id",
                        "title",
                        "title.keyword",
                        "description",
                        "rule_id",
                        "source_id",
                        "assigned_to",
                    ],
                    "type": "best_fields",
                },
            }
        ]

    return bool_query


def _build_alert_search_query(
    *,
    query: str | None = None,
    status: AlertStatus | None = None,
    severity: AlertSeverity | None = None,
    source_type: AlertSourceType | None = None,
    source_id: str | None = None,
    rule_id: str | None = None,
    assigned_to: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> dict[str, Any]:
    """
    Build the OpenSearch query body for Alert aggregate endpoints.
    """

    bool_query = _build_alert_search_bool_query(
        query=query,
        status=status,
        severity=severity,
        source_type=source_type,
        source_id=source_id,
        rule_id=rule_id,
        assigned_to=assigned_to,
        start_time=start_time,
        end_time=end_time,
    )

    if (
        not bool_query["filter"]
        and "must" not in bool_query
    ):
        return {
            "match_all": {},
        }

    return {
        "bool": bool_query,
    }


def _aggregation_counts(
    response: dict[str, Any],
    aggregation_name: str,
) -> dict[str, int]:
    """
    Convert an OpenSearch terms aggregation into key -> count.
    """

    aggregation = response.get(
        "aggregations",
        {},
    )

    if not isinstance(
        aggregation,
        dict,
    ):
        return {}

    bucket_container = aggregation.get(
        aggregation_name,
        {},
    )

    if not isinstance(
        bucket_container,
        dict,
    ):
        return {}

    buckets = bucket_container.get(
        "buckets",
        [],
    )

    if not isinstance(
        buckets,
        list,
    ):
        return {}

    result: dict[str, int] = {}

    for bucket in buckets:
        if not isinstance(
            bucket,
            dict,
        ):
            continue

        key = bucket.get(
            "key",
        )

        if key is None:
            continue

        try:
            count = int(
                bucket.get(
                    "doc_count",
                    0,
                )
            )

        except (
            TypeError,
            ValueError,
        ):
            count = 0

        result[str(key)] = count

    return result


def _total_hits(
    response: dict[str, Any],
) -> int:
    """
    Read OpenSearch total hits across supported response shapes.
    """

    hits = response.get(
        "hits",
        {},
    )

    if not isinstance(
        hits,
        dict,
    ):
        return 0

    total = hits.get(
        "total",
        0,
    )

    if isinstance(
        total,
        dict,
    ):
        total = total.get(
            "value",
            0,
        )

    try:
        return int(total)

    except (
        TypeError,
        ValueError,
    ):
        return 0


def _validate_time_range(
    *,
    start_time: datetime | None,
    end_time: datetime | None,
) -> None:
    """
    Validate an Alert time range.
    """

    if (
        start_time is not None
        and end_time is not None
        and start_time > end_time
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "'start_time' must be earlier than or equal to "
                "'end_time'"
            ),
        )


# ============================================================================
# Alert List
# ============================================================================


@router.get(
    "",
    response_model=PageResponse[AlertResponse],
    dependencies=[
        Depends(_alerts_read_permission),
    ],
)
async def list_alerts(
    query: str | None = Query(
        default=None,
        description="Free-text alert search.",
    ),
    status: AlertStatus | None = Query(
        default=None,
        description="Alert lifecycle status.",
    ),
    severity: AlertSeverity | None = Query(
        default=None,
        description="Alert severity.",
    ),
    source_type: AlertSourceType | None = Query(
        default=None,
        description="Alert source type.",
    ),
    rule_id: str | None = Query(
        default=None,
        description="Detection or correlation rule ID.",
    ),
    assigned_to: str | None = Query(
        default=None,
        description="Assigned analyst/user UUID.",
    ),
    source_id: str | None = Query(
        default=None,
        description="Detection/correlation source ID.",
    ),
    start_time: datetime | None = Query(
        default=None,
        description="Start of alert time range.",
    ),
    end_time: datetime | None = Query(
        default=None,
        description="End of alert time range.",
    ),
    page: int = Query(
        default=1,
        ge=1,
    ),
    page_size: int = Query(
        default=25,
        ge=1,
        le=100,
    ),
    repository: OpenSearchAlertRepository = Depends(
        get_alert_repository,
    ),
) -> PageResponse[AlertResponse]:
    """
    List persisted Alerts with filtering and pagination.
    """

    _validate_time_range(
        start_time=start_time,
        end_time=end_time,
    )

    offset = (
        page - 1
    ) * page_size

    try:
        result = await repository.search(
            query=query,
            status=(
                status.value
                if status is not None
                else None
            ),
            severity=(
                severity.value
                if severity is not None
                else None
            ),
            source_type=(
                source_type.value
                if source_type is not None
                else None
            ),
            source_id=source_id,
            rule_id=rule_id,
            assigned_to=assigned_to,
            start_time=start_time,
            end_time=end_time,
            offset=offset,
            limit=page_size,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    return PageResponse(
        items=[
            AlertResponse.from_model(
                alert,
            )
            for alert in result.alerts
        ],
        pagination=Pagination(
            page=page,
            page_size=page_size,
            total=result.total,
            total_pages=(
                (result.total + page_size - 1) // page_size
                if result.total > 0
                else 0
            ),
        ),
    )


# ============================================================================
# Alert Statistics / KPI
#
# IMPORTANT:
# Static route is declared before /{alert_id}.
# ============================================================================


@router.get(
    "/statistics",
    response_model=AlertStatisticsResponse,
    dependencies=[
        Depends(_alerts_read_permission),
    ],
)
async def get_alert_statistics(
    query: str | None = Query(
        default=None,
        description="Free-text alert search.",
    ),
    status: AlertStatus | None = Query(
        default=None,
        description="Filter KPI data by lifecycle status.",
    ),
    severity: AlertSeverity | None = Query(
        default=None,
        description="Filter KPI data by severity.",
    ),
    source_type: AlertSourceType | None = Query(
        default=None,
        description="Filter KPI data by source type.",
    ),
    source_id: str | None = Query(
        default=None,
        description="Filter KPI data by source ID.",
    ),
    rule_id: str | None = Query(
        default=None,
        description="Filter KPI data by rule ID.",
    ),
    assigned_to: str | None = Query(
        default=None,
        description="Filter KPI data by assignee.",
    ),
    start_time: datetime | None = Query(
        default=None,
        description="Start of alert time range.",
    ),
    end_time: datetime | None = Query(
        default=None,
        description="End of alert time range.",
    ),
    repository: OpenSearchAlertRepository = Depends(
        get_alert_repository,
    ),
) -> AlertStatisticsResponse:
    """
    Return backend-authoritative Alert KPIs.

    The frontend must consume these values directly instead of calculating
    them from the current Alert table page.
    """

    _validate_time_range(
        start_time=start_time,
        end_time=end_time,
    )

    body = {
        "size": 0,
        "track_total_hits": True,
        "query": _build_alert_search_query(
            query=query,
            status=status,
            severity=severity,
            source_type=source_type,
            source_id=source_id,
            rule_id=rule_id,
            assigned_to=assigned_to,
            start_time=start_time,
            end_time=end_time,
        ),
        "aggs": {
            "status_counts": {
                "terms": {
                    "field": "status",
                    "size": _STATS_BUCKET_SIZE,
                },
            },
            "severity_counts": {
                "terms": {
                    "field": "severity",
                    "size": _STATS_BUCKET_SIZE,
                },
            },
        },
    }

    try:
        response = await repository.client.search(
            index=repository.index,
            body=body,
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="failed to retrieve alert statistics",
        ) from exc

    status_counts = _aggregation_counts(
        response,
        "status_counts",
    )

    severity_counts = _aggregation_counts(
        response,
        "severity_counts",
    )

    return AlertStatisticsResponse(
        total=_total_hits(
            response,
        ),
        new=status_counts.get(
            "new",
            0,
        ),
        critical=severity_counts.get(
            "critical",
            0,
        ),
        escalated=status_counts.get(
            "escalated",
            0,
        ),
        acknowledged=status_counts.get(
            "acknowledged",
            0,
        ),
        investigating=status_counts.get(
            "investigating",
            0,
        ),
        resolved=status_counts.get(
            "resolved",
            0,
        ),
    )


# ============================================================================
# Alert Filter Options
#
# IMPORTANT:
# Static route is declared before /{alert_id}.
# ============================================================================


@router.get(
    "/filter-options",
    response_model=AlertFilterOptionsResponse,
    dependencies=[
        Depends(_alerts_read_permission),
    ],
)
async def get_alert_filter_options(
    repository: OpenSearchAlertRepository = Depends(
        get_alert_repository,
    ),
) -> AlertFilterOptionsResponse:
    """
    Return backend-authoritative distinct Alert filter values.

    All values are derived from persisted Alert documents.
    """

    body = {
        "size": 0,
        "track_total_hits": False,
        "aggs": {
            "statuses": {
                "terms": {
                    "field": "status",
                    "size": _FILTER_OPTION_SIZE,
                },
            },
            "severities": {
                "terms": {
                    "field": "severity",
                    "size": _FILTER_OPTION_SIZE,
                },
            },
            "source_types": {
                "terms": {
                    "field": "source_type",
                    "size": _FILTER_OPTION_SIZE,
                },
            },
            "sources": {
                "terms": {
                    "field": "source_id",
                    "size": _FILTER_OPTION_SIZE,
                },
            },
            "rules": {
                "terms": {
                    "field": "rule_id",
                    "size": _FILTER_OPTION_SIZE,
                },
            },
            "assignees": {
                "terms": {
                    "field": "assigned_to",
                    "size": _FILTER_OPTION_SIZE,
                },
            },
        },
    }

    try:
        response = await repository.client.search(
            index=repository.index,
            body=body,
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="failed to retrieve alert filter options",
        ) from exc

    return AlertFilterOptionsResponse(
        statuses=sorted(
            _aggregation_counts(
                response,
                "statuses",
            ).keys(),
        ),
        severities=sorted(
            _aggregation_counts(
                response,
                "severities",
            ).keys(),
        ),
        source_types=sorted(
            _aggregation_counts(
                response,
                "source_types",
            ).keys(),
        ),
        sources=sorted(
            _aggregation_counts(
                response,
                "sources",
            ).keys(),
        ),
        rules=sorted(
            _aggregation_counts(
                response,
                "rules",
            ).keys(),
        ),
        assignees=sorted(
            _aggregation_counts(
                response,
                "assignees",
            ).keys(),
        ),
    )


# ============================================================================
# Alert Details
# ============================================================================


@router.get(
    "/{alert_id}",
    response_model=AlertResponse,
    dependencies=[
        Depends(_alerts_read_permission),
    ],
)
async def get_alert(
    alert_id: UUID,
    repository: OpenSearchAlertRepository = Depends(
        get_alert_repository,
    ),
) -> AlertResponse:
    """
    Get one persisted Alert.
    """

    alert = await _load_persisted_alert(
        alert_id=alert_id,
        repository=repository,
    )

    return AlertResponse.from_model(
        alert,
    )


# ============================================================================
# Alert Audit History
# ============================================================================


@router.get(
    "/{alert_id}/audit",
    response_model=list[AlertAuditResponse],
    dependencies=[
        Depends(_alerts_read_permission),
    ],
)
async def get_alert_audit(
    alert_id: UUID,
    repository: OpenSearchAlertRepository = Depends(
        get_alert_repository,
    ),
) -> list[AlertAuditResponse]:
    """
    Return persisted Alert audit history.
    """

    await _load_persisted_alert(
        alert_id=alert_id,
        repository=repository,
    )

    entries = await repository.get_audit_history(
        alert_id,
    )

    return [
        AlertAuditResponse.from_model(
            entry,
        )
        for entry in entries
    ]


# ============================================================================
# Alert -> Incident Promotion
# ============================================================================


@router.post(
    "/{alert_id}/incident",
    response_model=IncidentResponse,
    status_code=201,
    dependencies=[
        Depends(_alerts_manage_permission),
    ],
)
async def promote_alert_to_incident(
    alert_id: UUID,
    repository: OpenSearchAlertRepository = Depends(
        get_alert_repository,
    ),
    incident_repository: OpenSearchIncidentRepository = Depends(
        get_incident_repository,
    ),
    incident_manager: IncidentManager = Depends(
        get_incident_manager,
    ),
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
) -> IncidentResponse:
    """
    Promote a persisted Alert into a Security Incident.

    The authenticated principal is used as the audit actor.
    """

    alert = await _load_persisted_alert(
        alert_id=alert_id,
        repository=repository,
    )

    await _ensure_incident_index(
        incident_repository,
    )

    promotion_service = IncidentPromotionService(
        incident_repository=incident_repository,
        manager=incident_manager,
    )

    try:
        incident = (
            await promotion_service.promote_alert_persisted(
                alert,
                actor=str(
                    principal.user_id,
                ),
            )
        )

    except IncidentAlreadyExistsError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "message": (
                    "alert has already been promoted "
                    "to an incident"
                ),
                "alert_id": str(
                    exc.alert_id,
                ),
                "incident_id": str(
                    exc.incident_id,
                ),
            },
        ) from exc

    except IncidentPromotionValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

    except IncidentPromotionError as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        ) from exc

    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="failed to promote alert to incident",
        ) from exc

    return IncidentResponse.from_model(
        incident,
    )


# ============================================================================
# Alert Lifecycle Transition
# ============================================================================


@router.post(
    "/{alert_id}/transition",
    response_model=AlertResponse,
    dependencies=[
        Depends(_alerts_manage_permission),
    ],
)
async def transition_alert(
    alert_id: UUID,
    request: AlertTransitionRequest,
    repository: OpenSearchAlertRepository = Depends(
        get_alert_repository,
    ),
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
) -> AlertResponse:
    """
    Perform a validated Alert lifecycle transition.

    Lifecycle changes require ALERTS_MANAGE.
    """

    persisted_alert = await _load_persisted_alert(
        alert_id=alert_id,
        repository=repository,
    )

    if request.status == persisted_alert.status:
        raise HTTPException(
            status_code=409,
            detail=(
                "alert is already in status "
                f"'{persisted_alert.status.value}'"
            ),
        )

    if request.status not in _SUPPORTED_TRANSITION_TARGETS:
        raise HTTPException(
            status_code=422,
            detail=(
                "unsupported alert transition target: "
                f"'{request.status.value}'"
            ),
        )

    manager = _load_request_alert_manager(
        repository,
    )

    await manager.hydrate(
        [persisted_alert],
    )

    try:
        alert = manager.transition(
            alert_id,
            request.status,
            actor=str(
                principal.user_id,
            ),
            reason=request.reason,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        ) from exc

    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail="alert not found",
        ) from exc

    return AlertResponse.from_model(
        alert,
    )


# ============================================================================
# Alert Assignment
# ============================================================================


@router.patch(
    "/{alert_id}/assignment",
    response_model=AlertResponse,
    dependencies=[
        Depends(_alerts_manage_permission),
    ],
)
async def assign_alert(
    alert_id: UUID,
    request: AlertAssignmentRequest,
    repository: OpenSearchAlertRepository = Depends(
        get_alert_repository,
    ),
    user_management: UserManagementService = Depends(
        get_user_management_service,
    ),
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
) -> AlertResponse:
    """
    Assign, reassign, or explicitly unassign an Alert.

    Assignment rules:

    - ALERTS_MANAGE permission is required.
    - Target user must exist.
    - Target user must be active.
    - Target user must not be locked.
    - Target user must have an eligible Alert analyst role.
    - Role is read from authoritative User Management data.
    - Client-provided role information is never trusted.
    - null explicitly unassigns the Alert.
    - Authenticated principal is recorded as audit actor.
    """

    persisted_alert = await _load_persisted_alert(
        alert_id=alert_id,
        repository=repository,
    )

    await _validate_alert_assignee(
        assignee=request.assignee,
        user_management=user_management,
    )

    manager = _load_request_alert_manager(
        repository,
    )

    await manager.hydrate(
        [persisted_alert],
    )

    normalized_assignee = (
        request.assignee.strip()
        if request.assignee is not None
        else None
    )

    try:
        alert = manager.assign(
            alert_id,
            assignee=normalized_assignee,
            actor=str(
                principal.user_id,
            ),
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        ) from exc

    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail="alert not found",
        ) from exc

    return AlertResponse.from_model(
        alert,
    )


# ============================================================================
# Public API
# ============================================================================

__all__ = [
    "router",
]