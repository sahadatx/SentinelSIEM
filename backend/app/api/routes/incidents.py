"""
SentinelSIEM — Incident API Routes.

Final Incident HTTP boundary.

Canonical Incident contract
----------------------------

Lifecycle:
    open
    investigating
    contained
    resolved
    closed

Severity:
    critical
    high
    medium
    low
    informational

Supported API workflow
----------------------

Read:
    GET    /incidents
    GET    /incidents/statistics
    GET    /incidents/filter-options
    GET    /incidents/{incident_id}
    GET    /incidents/{incident_id}/alerts
    GET    /incidents/{incident_id}/notes
    GET    /incidents/{incident_id}/evidence
    GET    /incidents/{incident_id}/timeline
    GET    /incidents/{incident_id}/audit

Manage:
    POST   /incidents
    PATCH  /incidents/{incident_id}
    PATCH  /incidents/{incident_id}/assignment
    POST   /incidents/{incident_id}/transition
    POST   /incidents/{incident_id}/notes
    POST   /incidents/{incident_id}/evidence

The route layer owns:
    - HTTP validation
    - RBAC enforcement
    - dependency wiring
    - persistence orchestration
    - response serialization
    - detail enrichment orchestration

The route layer does NOT own:
    - Incident lifecycle rules
    - Incident domain mutation rules
    - Alert promotion business logic
    - OpenSearch query construction
    - investigation domain logic
    - filter aggregation logic
    - User Management business rules
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.dependencies import (
    get_alert_repository,
    get_current_principal,
    get_incident_repository,
    require_permission,
)
from app.api.schemas.common import PageResponse, Pagination
from app.api.schemas.incidents import (
    IncidentAssignmentRequest,
    IncidentAuditResponse,
    IncidentCreateRequest,
    IncidentDetailResponse,
    IncidentEvidenceCreateRequest,
    IncidentEvidenceResponse,
    IncidentFilterOptionsResponse,
    IncidentListResponse,
    IncidentNoteCreateRequest,
    IncidentNoteResponse,
    IncidentResponse,
    IncidentStatisticsResponse,
    IncidentTimelineResponse,
    IncidentTransitionRequest,
    IncidentUpdateRequest,
    RelatedAlertResponse,
)
from app.auth.models import UserPrincipal
from app.incidents.lifecycle import IncidentLifecycle
from app.incidents.manager import IncidentManager
from app.storage.opensearch.alerts import OpenSearchAlertRepository
from app.incidents.models import (
    Incident,
    IncidentAuditEntry,
    IncidentSeverity,
    IncidentStatus,
)
from app.storage.opensearch.incidents import (
    OpenSearchIncidentRepository,
)


# =============================================================================
# Router
# =============================================================================

router = APIRouter(
    prefix="/incidents",
    tags=["incidents"],
)


# =============================================================================
# RBAC
# =============================================================================

_incidents_read = require_permission(
    "incidents:read",
)

_incidents_manage = require_permission(
    "incidents:manage",
)


# =============================================================================
# Authentication / Actor Helpers
# =============================================================================


def _get_actor(
    principal: UserPrincipal,
) -> str:
    """
    Resolve the authenticated principal into a domain actor identifier.
    """

    user_id = getattr(
        principal,
        "user_id",
        None,
    )

    if user_id is not None:
        return str(user_id)

    username = getattr(
        principal,
        "username",
        None,
    )

    if username:
        return str(username)

    return "api"


# =============================================================================
# Manager / Persistence Wiring
# =============================================================================


def _build_manager(
    repository: OpenSearchIncidentRepository,
) -> IncidentManager:
    """
    Build a request-scoped IncidentManager.

    The manager remains responsible for domain mutation and lifecycle rules.
    The API route supplies only persistence callbacks.
    """

    async def persist_incident(
        incident: Incident,
    ) -> None:
        await repository.ensure_index()
        await repository.save(
            incident,
        )

    async def persist_audit(
        audit: IncidentAuditEntry,
    ) -> None:
        await repository.save_audit_entry(
            audit,
        )

    async def persist_note(
        note,
    ) -> None:
        await repository.save_note(
            note,
        )

    async def persist_evidence(
        evidence,
    ) -> None:
        await repository.save_evidence(
            evidence,
        )

    async def persist_timeline(
        entry,
    ) -> None:
        await repository.save_timeline_entry(
            entry,
        )

    return IncidentManager(
        lifecycle=IncidentLifecycle(),
        incident_persister=persist_incident,
        audit_persister=persist_audit,
        note_persister=persist_note,
        evidence_persister=persist_evidence,
        timeline_persister=persist_timeline,
    )


# =============================================================================
# Validation Helpers
# =============================================================================


def _validate_time_range(
    start_time: datetime | None,
    end_time: datetime | None,
) -> None:
    """Validate a query time range."""

    if (
        start_time is not None
        and end_time is not None
        and start_time > end_time
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "'start_time' must be earlier than or equal to "
                "'end_time'"
            ),
        )


def _clean_optional_string(
    value: str | None,
) -> str | None:
    """Trim optional strings and convert empty strings to None."""

    if value is None:
        return None

    normalized = value.strip()

    return normalized or None


def _require_actor(
    principal: UserPrincipal,
) -> str:
    """Resolve and validate an authenticated actor."""

    actor = _get_actor(
        principal,
    )

    if not actor.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authenticated actor could not be resolved",
        )

    return actor


# =============================================================================
# Incident Serialization
# =============================================================================


def _incident_response(
    incident: Incident,
) -> IncidentResponse:
    """Convert a domain Incident into its API representation."""

    return IncidentResponse.from_model(
        incident,
    )


# =============================================================================
# Filter Options
# =============================================================================


def _filter_options_response(
    options: Any,
) -> IncidentFilterOptionsResponse:
    """
    Normalize repository filter options into the canonical API response.

    Repository contract:

        statuses
        severities
        assignees
    """

    if not isinstance(
        options,
        dict,
    ):
        raise ValueError(
            "invalid incident filter options response",
        )

    # Status is a canonical backend catalogue.
    # Do not derive Create/Edit options from existing incidents.
    statuses = [
        status.value
        for status in IncidentStatus
    ]

    # Severity is a canonical backend catalogue.
    # Always expose all five values, even when no incident
    # currently uses one of them.
    severities = [
        severity.value
        for severity in IncidentSeverity
    ]

    assignees = _normalize_uuid_values(
        options.get("assignees"),
    )

    return IncidentFilterOptionsResponse(
        statuses=tuple(statuses),
        severities=tuple(severities),
        assignees=tuple(assignees),
    )


def _normalize_filter_values(
    values: Any,
) -> list[str]:
    """Normalize arbitrary repository string values."""

    if values is None:
        return []

    if isinstance(
        values,
        dict,
    ):
        iterable = values.keys()

    elif isinstance(
        values,
        (list, tuple, set, frozenset),
    ):
        iterable = values

    else:
        iterable = [values]

    normalized: set[str] = set()

    for value in iterable:
        if value is None:
            continue

        item = str(
            value,
        ).strip()

        if item:
            normalized.add(item)

    return sorted(
        normalized,
        key=str.casefold,
    )


def _normalize_uuid_values(
    values: Any,
) -> list[UUID]:
    """Normalize repository assignee values into UUIDs."""

    if values is None:
        return []

    if isinstance(
        values,
        dict,
    ):
        iterable = values.keys()

    elif isinstance(
        values,
        (list, tuple, set, frozenset),
    ):
        iterable = values

    else:
        iterable = [values]

    normalized: set[UUID] = set()

    for value in iterable:
        if value is None:
            continue

        if isinstance(
            value,
            UUID,
        ):
            normalized.add(value)
            continue

        try:
            normalized.add(
                UUID(
                    str(value).strip(),
                )
            )
        except (
            TypeError,
            ValueError,
        ):
            # Invalid persisted filter values are not exposed as
            # fake User UUIDs through the API.
            continue

    return sorted(
        normalized,
        key=str,
    )


# =============================================================================
# Incident Detail
# =============================================================================


async def _load_persisted_incident(
    *,
    incident_id: UUID,
    repository: OpenSearchIncidentRepository,
) -> Incident:
    """Load an Incident from persistent OpenSearch storage."""

    try:
        incident = await repository.get(
            incident_id,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="failed to load incident",
        ) from exc

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="incident not found",
        )

    return incident


async def _load_incident_owned_details(
    *,
    incident_id: UUID,
    repository: OpenSearchIncidentRepository,
) -> dict[str, list[Any]]:
    """
    Load investigation data directly owned by the Incident repository.
    """

    try:
        notes = await repository.get_notes(
            incident_id,
        )
        evidence = await repository.get_evidence(
            incident_id,
        )
        timeline = await repository.get_timeline(
            incident_id,
        )
        audit_history = await repository.get_audit_history(
            incident_id,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="failed to load incident investigation data",
        ) from exc

    return {
        "notes": [
            IncidentNoteResponse.from_model(
                item,
            )
            for item in notes
        ],
        "evidence": [
            IncidentEvidenceResponse.from_model(
                item,
            )
            for item in evidence
        ],
        "timeline": [
            IncidentTimelineResponse.from_model(
                item,
            )
            for item in timeline
        ],
        "audit_history": [
            IncidentAuditResponse.from_model(
                item,
            )
            for item in audit_history
        ],
    }


async def _load_related_alerts(
    *,
    incident_id: UUID,
    repository: OpenSearchIncidentRepository,
    alert_repository: OpenSearchAlertRepository,
) -> list[RelatedAlertResponse]:
    """
    Return fully hydrated Alerts associated with an Incident.

    Incident storage owns only the relationship between the
    Incident and Alert IDs. Alert data itself remains owned by
    the Alert repository.
    """

    try:
        alert_ids = await repository.get_related_alert_ids(
            incident_id,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="failed to load incident related alerts",
        ) from exc

    related_alerts: list[RelatedAlertResponse] = []

    for alert_id in alert_ids:
        try:
            alert = await alert_repository.get(alert_id)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="failed to load related alert",
            ) from exc

        # Relationship may point to an Alert that no longer exists.
        # Do not fabricate Alert data.
        if alert is None:
            continue

        related_alerts.append(
            RelatedAlertResponse(
                alert_id=alert.alert_id,
                title=alert.title,
                description=alert.description,
                severity=alert.severity.value,
                status=alert.status.value,
                source_type=alert.source_type.value,
                rule_id=alert.rule_id,
                rule_name=None,
                event_ids=tuple(alert.evidence_ids),
                first_seen_at=alert.first_seen_at,
                last_seen_at=alert.last_seen_at,
            )
        )

    return related_alerts


async def _build_incident_detail(
    *,
    incident: Incident,
    repository: OpenSearchIncidentRepository,
    alert_repository: OpenSearchAlertRepository,
) -> IncidentDetailResponse:
    """Build the complete Incident detail response."""

    base = IncidentResponse.from_model(
        incident,
    )

    owned_details = await _load_incident_owned_details(
        incident_id=incident.incident_id,
        repository=repository,
    )

    related_alerts = await _load_related_alerts(
        incident_id=incident.incident_id,
        repository=repository,
        alert_repository=alert_repository,
    )

    return IncidentDetailResponse(
        **base.model_dump(
            mode="python",
        ),
        related_alerts=related_alerts,
        related_events=[],
        related_iocs=[],
        affected_assets=[],
        notes=owned_details["notes"],
        evidence=owned_details["evidence"],
        timeline=owned_details["timeline"],
        audit_history=owned_details["audit_history"],
    )


# =============================================================================
# GET /incidents
# =============================================================================


@router.get(
    "",
    response_model=PageResponse[IncidentResponse],
    dependencies=[
        Depends(_incidents_read),
    ],
)
async def list_incidents(
    query: str | None = Query(
        default=None,
        description=(
            "Free-text search across Incident identity and content."
        ),
    ),
    status_filter: IncidentStatus | None = Query(
        default=None,
        alias="status",
        description="Incident lifecycle status.",
    ),
    severity: str | None = Query(
        default=None,
        description="Incident severity.",
    ),
    assigned_to: UUID | None = Query(
        default=None,
        description="Assigned User UUID.",
    ),
    alert_id: UUID | None = Query(
        default=None,
        description="Related Alert UUID.",
    ),
    asset_id: str | None = Query(
        default=None,
        description="Affected Asset identifier.",
    ),
    related_event_id: str | None = Query(
        default=None,
        description="Related Event identifier.",
    ),
    related_ioc_id: str | None = Query(
        default=None,
        description="Related IOC identifier.",
    ),
    start_time: datetime | None = Query(
        default=None,
        description="Beginning of Incident update time range.",
    ),
    end_time: datetime | None = Query(
        default=None,
        description="End of Incident update time range.",
    ),
    page: int = Query(
        default=1,
        ge=1,
    ),
    page_size: int = Query(
        default=50,
        ge=1,
        le=200,
    ),
    repository: OpenSearchIncidentRepository = Depends(
        get_incident_repository,
    ),
) -> PageResponse[IncidentResponse]:
    """Return persisted Incidents using backend-authoritative filters."""

    _validate_time_range(
        start_time,
        end_time,
    )

    offset = (
        page - 1
    ) * page_size

    try:
        result = await repository.search(
            query=_clean_optional_string(
                query,
            ),
            status=(
                status_filter.value
                if status_filter is not None
                else None
            ),
            severity=_clean_optional_string(
                severity,
            ),
            assigned_to=assigned_to,
            alert_id=alert_id,
            asset_id=_clean_optional_string(
                asset_id,
            ),
            related_event_id=_clean_optional_string(
                related_event_id,
            ),
            related_ioc_id=_clean_optional_string(
                related_ioc_id,
            ),
            start_time=start_time,
            end_time=end_time,
            offset=offset,
            limit=page_size,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"failed to query incidents: {type(exc).__name__}: {exc}",
        ) from exc

    return PageResponse(
        items=[
            _incident_response(
                incident,
            )
            for incident in result.incidents
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


# =============================================================================
# GET /incidents/statistics
# =============================================================================


@router.get(
    "/statistics",
    response_model=IncidentStatisticsResponse,
    dependencies=[
        Depends(_incidents_read),
    ],
)
async def get_incident_statistics(
    repository: OpenSearchIncidentRepository = Depends(
        get_incident_repository,
    ),
) -> IncidentStatisticsResponse:
    """Return backend-authoritative Incident KPI statistics."""

    try:
        statistics = await repository.statistics()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="failed to query incident statistics",
        ) from exc

    try:
        return IncidentStatisticsResponse.model_validate(
            statistics,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="invalid incident statistics response",
        ) from exc


# =============================================================================
# GET /incidents/summary
# =============================================================================


@router.get(
    "/summary",
    response_model=IncidentStatisticsResponse,
    dependencies=[
        Depends(_incidents_read),
    ],
)
async def get_incident_summary(
    repository: OpenSearchIncidentRepository = Depends(
        get_incident_repository,
    ),
) -> IncidentStatisticsResponse:
    """
    Backward-compatible summary endpoint.

    New frontend code should use /statistics.
    """

    try:
        statistics = await repository.statistics()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="failed to query incident summary",
        ) from exc

    try:
        return IncidentStatisticsResponse.model_validate(
            statistics,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="invalid incident summary response",
        ) from exc


# =============================================================================
# GET /incidents/filter-options
# =============================================================================


@router.get(
    "/filter-options",
    response_model=IncidentFilterOptionsResponse,
    dependencies=[
        Depends(_incidents_read),
    ],
)
async def get_incident_filter_options(
    repository: OpenSearchIncidentRepository = Depends(
        get_incident_repository,
    ),
) -> IncidentFilterOptionsResponse:
    """Return backend-authoritative Incident filter options."""

    try:
        options = await repository.get_filter_options()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="failed to query incident filter options",
        ) from exc

    try:
        return _filter_options_response(
            options,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc


# =============================================================================
# POST /incidents
# =============================================================================


@router.post(
    "",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(_incidents_manage),
    ],
)
async def create_incident(
    request: IncidentCreateRequest,
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    repository: OpenSearchIncidentRepository = Depends(
        get_incident_repository,
    ),
) -> IncidentResponse:
    """Create and persist a new Incident."""

    actor = _require_actor(
        principal,
    )

    manager = _build_manager(
        repository,
    )

    try:
        incident = await manager.create_persisted(
            request.to_domain(),
            actor=actor,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="failed to create incident",
        ) from exc

    return _incident_response(
        incident,
    )


# =============================================================================
# GET /incidents/{incident_id}
# =============================================================================


@router.get(
    "/{incident_id}",
    response_model=IncidentDetailResponse,
    dependencies=[
        Depends(_incidents_read),
    ],
)
async def get_incident(
    incident_id: UUID,
    repository: OpenSearchIncidentRepository = Depends(
        get_incident_repository,
    ),
    alert_repository: OpenSearchAlertRepository = Depends(
        get_alert_repository,
    ),
) -> IncidentDetailResponse:
    """Return complete persisted Incident detail."""

    incident = await _load_persisted_incident(
        incident_id=incident_id,
        repository=repository,
    )

    return await _build_incident_detail(
        incident=incident,
        repository=repository,
        alert_repository=alert_repository,
    )


# =============================================================================
# PATCH /incidents/{incident_id}
# =============================================================================


@router.patch(
    "/{incident_id}",
    response_model=IncidentResponse,
    dependencies=[
        Depends(_incidents_manage),
    ],
)
async def update_incident(
    incident_id: UUID,
    request: IncidentUpdateRequest,
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    repository: OpenSearchIncidentRepository = Depends(
        get_incident_repository,
    ),
) -> IncidentResponse:
    """
    Edit mutable Incident fields.

    Supported:
        title
        description
        severity
        assigned_to
        status

    All supplied fields are applied through one manager operation.

    Status changes are validated by IncidentManager /
    IncidentLifecycle using the canonical lifecycle:

        OPEN
          ↓
        INVESTIGATING
          ↓
        CONTAINED
          ↓
        RESOLVED
          ↓
        CLOSED
    """

    actor = _require_actor(
        principal,
    )

    incident = await _load_persisted_incident(
        incident_id=incident_id,
        repository=repository,
    )

    payload = request.model_dump(
        mode="python",
        exclude_unset=True,
    )

    if not payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="at least one Incident field must be provided",
        )

    manager = _build_manager(
        repository,
    )

    manager.hydrate(
        [incident],
    )

    # ---------------------------------------------------------
    # Only pass fields that were actually supplied.
    #
    # This is important because:
    #   omitted field != explicit field value
    #
    # In particular, assigned_to=None means explicit
    # unassignment when the field is present in the request.
    # ---------------------------------------------------------

    update_kwargs: dict[str, object] = {
        "actor": actor,
    }

    if "title" in payload:
        update_kwargs["title"] = payload["title"]

    if "description" in payload:
        update_kwargs["description"] = payload["description"]

    if "severity" in payload:
        try:
            update_kwargs["severity"] = IncidentSeverity(
                str(payload["severity"]).strip().lower(),
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="invalid Incident severity",
            ) from exc

    if "assigned_to" in payload:
        update_kwargs["assignee"] = payload["assigned_to"]

    if "status" in payload:
        try:
            update_kwargs["status"] = IncidentStatus(
                str(payload["status"]).strip().lower(),
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="invalid Incident lifecycle status",
            ) from exc

    try:
        # -----------------------------------------------------
        # ONE atomic domain update.
        #
        # Do NOT call transition_persisted() separately here.
        # update_persisted() already sends status through
        # IncidentLifecycle.
        # -----------------------------------------------------

        updated = await manager.update_persisted(
            incident_id,
            **update_kwargs,
        )

    except ValueError as exc:
        # Lifecycle conflicts and domain validation failures
        # are exposed as HTTP 409.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="incident not found",
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="failed to update incident",
        ) from exc

    return _incident_response(
        updated,
    )


# =============================================================================
# PATCH /incidents/{incident_id}/assignment
# =============================================================================


@router.patch(
    "/{incident_id}/assignment",
    response_model=IncidentResponse,
    dependencies=[
        Depends(_incidents_manage),
    ],
)
async def assign_incident(
    incident_id: UUID,
    request: IncidentAssignmentRequest,
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    repository: OpenSearchIncidentRepository = Depends(
        get_incident_repository,
    ),
) -> IncidentResponse:
    """Assign, reassign or unassign an Incident."""

    actor = _require_actor(
        principal,
    )

    incident = await _load_persisted_incident(
        incident_id=incident_id,
        repository=repository,
    )

    manager = _build_manager(
        repository,
    )

    manager.hydrate(
        [incident],
    )

    try:
        updated = await manager.assign_persisted(
            incident_id,
            assignee=request.assignee,
            actor=actor,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="incident not found",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="failed to assign incident",
        ) from exc

    return _incident_response(
        updated,
    )


# =============================================================================
# POST /incidents/{incident_id}/transition
# =============================================================================


@router.post(
    "/{incident_id}/transition",
    response_model=IncidentResponse,
    dependencies=[
        Depends(_incidents_manage),
    ],
)
async def transition_incident(
    incident_id: UUID,
    request: IncidentTransitionRequest,
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    repository: OpenSearchIncidentRepository = Depends(
        get_incident_repository,
    ),
) -> IncidentResponse:
    """Transition an Incident through its canonical lifecycle."""

    actor = _require_actor(
        principal,
    )

    incident = await _load_persisted_incident(
        incident_id=incident_id,
        repository=repository,
    )

    try:
        target = IncidentStatus(
            request.status,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="invalid Incident lifecycle status",
        ) from exc

    if target == incident.status:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "incident is already in status "
                f"'{incident.status.value}'"
            ),
        )

    manager = _build_manager(
        repository,
    )

    manager.hydrate(
        [incident],
    )

    try:
        updated = await manager.transition_persisted(
            incident_id,
            target,
            actor=actor,
            reason=request.reason.strip(),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="incident not found",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="failed to transition incident",
        ) from exc

    return _incident_response(
        updated,
    )


# =============================================================================
# GET /incidents/{incident_id}/alerts
# =============================================================================


@router.get(
    "/{incident_id}/alerts",
    response_model=list[RelatedAlertResponse],
    dependencies=[
        Depends(_incidents_read),
    ],
)
async def get_incident_alerts(
    incident_id: UUID,
    repository: OpenSearchIncidentRepository = Depends(
        get_incident_repository,
    ),
    alert_repository: OpenSearchAlertRepository = Depends(
        get_alert_repository,
    ),
) -> list[RelatedAlertResponse]:
    """
    Return Alert relationships associated with an Incident.

    The Incident repository owns the relationship IDs. Full Alert
    enrichment is intentionally delegated to the Alert application layer.
    """

    await _load_persisted_incident(
        incident_id=incident_id,
        repository=repository,
    )

    return await _load_related_alerts(
        incident_id=incident_id,
        repository=repository,
        alert_repository=alert_repository,
    )


# =============================================================================
# POST /incidents/{incident_id}/notes
# =============================================================================


@router.post(
    "/{incident_id}/notes",
    response_model=IncidentNoteResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(_incidents_manage),
    ],
)
async def add_incident_note(
    incident_id: UUID,
    request: IncidentNoteCreateRequest,
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    repository: OpenSearchIncidentRepository = Depends(
        get_incident_repository,
    ),
) -> IncidentNoteResponse:
    """Add an immutable investigation note."""

    actor = _require_actor(
        principal,
    )

    incident = await _load_persisted_incident(
        incident_id=incident_id,
        repository=repository,
    )

    manager = _build_manager(
        repository,
    )

    manager.hydrate(
        [incident],
    )

    author = (
        request.author.strip()
        or actor
    )

    try:
        note = await manager.add_note_persisted(
            incident_id,
            author=author,
            content=request.content.strip(),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="incident not found",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="failed to add investigation note",
        ) from exc

    return IncidentNoteResponse.from_model(
        note,
    )


# =============================================================================
# GET /incidents/{incident_id}/notes
# =============================================================================


@router.get(
    "/{incident_id}/notes",
    response_model=list[IncidentNoteResponse],
    dependencies=[
        Depends(_incidents_read),
    ],
)
async def get_incident_notes(
    incident_id: UUID,
    repository: OpenSearchIncidentRepository = Depends(
        get_incident_repository,
    ),
) -> list[IncidentNoteResponse]:
    """Return immutable investigation notes."""

    await _load_persisted_incident(
        incident_id=incident_id,
        repository=repository,
    )

    try:
        notes = await repository.get_notes(
            incident_id,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="failed to query investigation notes",
        ) from exc

    return [
        IncidentNoteResponse.from_model(
            note,
        )
        for note in notes
    ]


# =============================================================================
# POST /incidents/{incident_id}/evidence
# =============================================================================


@router.post(
    "/{incident_id}/evidence",
    response_model=IncidentEvidenceResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(_incidents_manage),
    ],
)
async def add_incident_evidence(
    incident_id: UUID,
    request: IncidentEvidenceCreateRequest,
    repository: OpenSearchIncidentRepository = Depends(
        get_incident_repository,
    ),
) -> IncidentEvidenceResponse:
    """Attach an immutable evidence record to an Incident."""

    incident = await _load_persisted_incident(
        incident_id=incident_id,
        repository=repository,
    )

    manager = _build_manager(
        repository,
    )

    manager.hydrate(
        [incident],
    )

    try:
        evidence = await manager.add_evidence_persisted(
            incident_id,
            evidence_id=request.evidence_id,
            evidence_type=request.evidence_type,
            reference=request.reference,
            collected_by=request.collected_by,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="incident not found",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="failed to add incident evidence",
        ) from exc

    return IncidentEvidenceResponse.from_model(
        evidence,
    )


# =============================================================================
# GET /incidents/{incident_id}/evidence
# =============================================================================


@router.get(
    "/{incident_id}/evidence",
    response_model=list[IncidentEvidenceResponse],
    dependencies=[
        Depends(_incidents_read),
    ],
)
async def get_incident_evidence(
    incident_id: UUID,
    repository: OpenSearchIncidentRepository = Depends(
        get_incident_repository,
    ),
) -> list[IncidentEvidenceResponse]:
    """Return immutable Incident evidence."""

    await _load_persisted_incident(
        incident_id=incident_id,
        repository=repository,
    )

    try:
        records = await repository.get_evidence(
            incident_id,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="failed to query incident evidence",
        ) from exc

    return [
        IncidentEvidenceResponse.from_model(
            record,
        )
        for record in records
    ]


# =============================================================================
# GET /incidents/{incident_id}/timeline
# =============================================================================


@router.get(
    "/{incident_id}/timeline",
    response_model=list[IncidentTimelineResponse],
    dependencies=[
        Depends(_incidents_read),
    ],
)
async def get_incident_timeline(
    incident_id: UUID,
    repository: OpenSearchIncidentRepository = Depends(
        get_incident_repository,
    ),
) -> list[IncidentTimelineResponse]:
    """Return the chronological Incident timeline."""

    await _load_persisted_incident(
        incident_id=incident_id,
        repository=repository,
    )

    try:
        entries = await repository.get_timeline(
            incident_id,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="failed to query incident timeline",
        ) from exc

    return [
        IncidentTimelineResponse.from_model(
            entry,
        )
        for entry in entries
    ]


# =============================================================================
# GET /incidents/{incident_id}/audit
# =============================================================================


@router.get(
    "/{incident_id}/audit",
    response_model=list[IncidentAuditResponse],
    dependencies=[
        Depends(_incidents_read),
    ],
)
async def get_incident_audit(
    incident_id: UUID,
    repository: OpenSearchIncidentRepository = Depends(
        get_incident_repository,
    ),
) -> list[IncidentAuditResponse]:
    """Return immutable Incident audit history."""

    await _load_persisted_incident(
        incident_id=incident_id,
        repository=repository,
    )

    try:
        entries = await repository.get_audit_history(
            incident_id,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="failed to query incident audit history",
        ) from exc

    return [
        IncidentAuditResponse.from_model(
            entry,
        )
        for entry in entries
    ]


# =============================================================================
# Public API
# =============================================================================

__all__ = [
    "router",
]
