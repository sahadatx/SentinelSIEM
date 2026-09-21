"""
SentinelSIEM — Global Audit API Routes
======================================

Canonical HTTP boundary for Global Audit.

Architecture
------------

    HTTP
      |
      v
    Audit Router
      |
      v
    AuditService
      |
      v
    AuditRepository
      |
      v
    AuditEvent
      |
      v
    siem_auth_audit


Global Audit endpoints
----------------------

    GET /audit
    GET /audit/export
    GET /audit/{audit_id}/related
    GET /audit/{audit_id}


RBAC
----

Global Audit uses the existing locked permission:

    users:read

No audit-specific permission is introduced.


Router responsibilities
-----------------------

    - HTTP parameter validation
    - authentication dependency resolution
    - centralized RBAC dependency
    - service invocation
    - service-error -> HTTP-error mapping
    - explicit response serialization
    - JSON export
    - CSV export


Router does NOT
---------------

    - access the database directly
    - create database sessions
    - create repositories
    - create audit records
    - update audit records
    - delete audit records
    - perform RBAC decisions directly
    - expose credential material
    - manage transactions
    - perform identity enrichment
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Response,
    status,
)

from app.api.dependencies import (
    get_audit_service,
    get_current_principal,
    require_permission,
)
from app.audit.schemas import (
    AuditListResponse,
    AuditResponse,
)
from app.audit.service import (
    AuditService,
    AuditServiceError,
    AuditValidationError,
)
from app.auth.models import UserPrincipal


# ============================================================================
# Router
# ============================================================================

router = APIRouter(
    prefix="/audit",
    tags=["Audit"],
)


# ============================================================================
# Locked RBAC
# ============================================================================

# SentinelSIEM locked RBAC matrix:
#
#     Global Audit -> users:read
#
# Do NOT introduce:
#
#     audit:read
#     audit:export
#
# unless the central RBAC matrix is explicitly changed.

audit_read_permission = require_permission(
    "users:read",
)


# ============================================================================
# Pagination / Query Limits
# ============================================================================

DEFAULT_PAGE = 1
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

DEFAULT_RELATED_LIMIT = 100
MAX_RELATED_LIMIT = 200

DEFAULT_EXPORT_LIMIT = 10_000
MAX_EXPORT_LIMIT = 10_000


# ============================================================================
# Query Validation Limits
# ============================================================================

MAX_ACTION_LENGTH = 150
MAX_CATEGORY_LENGTH = 100
MAX_OUTCOME_LENGTH = 50
MAX_SOURCE_IP_LENGTH = 100
MAX_SEARCH_LENGTH = 500
MAX_REQUEST_ID_LENGTH = 100


# ============================================================================
# Serialization
# ============================================================================


def _serialize_audit_event(
    event: Any,
) -> AuditResponse:
    """
    Convert one AuditEvent into the public AuditResponse schema.

    Explicit allow-list serialization is intentional.

    The ORM object is never returned directly.
    """

    if event is None:
        raise ValueError(
            "Cannot serialize a null audit event."
        )

    metadata = getattr(
        event,
        "metadata_json",
        None,
    )

    if metadata is not None:
        try:
            serialized_metadata = dict(metadata)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "Audit event metadata is invalid."
            ) from exc
    else:
        serialized_metadata = None

    return AuditResponse(
        audit_id=event.audit_id,
        actor_user_id=event.actor_user_id,
        target_user_id=event.target_user_id,
        session_id=event.session_id,
        request_id=event.request_id,
        source_ip=event.source_ip,
        action=event.action,
        outcome=event.outcome,
        metadata_json=serialized_metadata,
        created_at=event.created_at,
    )


def _serialize_audit_events(
    events: list[Any],
) -> list[AuditResponse]:
    """
    Serialize multiple AuditEvent instances.
    """

    return [
        _serialize_audit_event(event)
        for event in events
    ]


# ============================================================================
# Query Normalization
# ============================================================================


def _normalize_text(
    value: str | None,
) -> str | None:
    """
    Normalize optional query text.

    Empty and whitespace-only values become None.
    """

    if value is None:
        return None

    normalized = value.strip()

    return normalized or None


# ============================================================================
# Date Validation
# ============================================================================


def _validate_date_range(
    date_from: datetime | None,
    date_to: datetime | None,
) -> None:
    """
    Validate HTTP date-range semantics.

    Canonical timezone validation remains the responsibility
    of the AuditService.
    """

    if (
        date_from is not None
        and date_to is not None
        and date_from > date_to
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "date_from cannot be later than date_to."
            ),
        )


# ============================================================================
# Service Error Mapping
# ============================================================================


def _raise_audit_http_error(
    exc: Exception,
) -> None:
    """
    Convert audit-layer exceptions into stable HTTP errors.

    Internal repository/database implementation details
    are never exposed through the HTTP boundary.
    """

    if isinstance(
        exc,
        AuditValidationError,
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    if isinstance(
        exc,
        AuditServiceError,
    ):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "Unable to complete audit operation."
            ),
        ) from exc

    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=(
            "Unable to complete audit operation."
        ),
    ) from exc


# ============================================================================
# Export Serialization
# ============================================================================


def _audit_event_to_export_row(
    event: AuditResponse,
) -> dict[str, Any]:
    """
    Convert an AuditResponse into an export-safe dictionary.

    UUID values are converted to strings so the exported
    representation is JSON/CSV friendly.
    """

    return {
        "audit_id": str(event.audit_id),
        "actor_user_id": (
            str(event.actor_user_id)
            if event.actor_user_id is not None
            else None
        ),
        "target_user_id": (
            str(event.target_user_id)
            if event.target_user_id is not None
            else None
        ),
        "session_id": (
            str(event.session_id)
            if event.session_id is not None
            else None
        ),
        "request_id": event.request_id,
        "source_ip": event.source_ip,
        "action": event.action,
        "outcome": event.outcome,
        "metadata_json": event.metadata_json,
        "created_at": (
            event.created_at.isoformat()
            if event.created_at is not None
            else None
        ),
    }


def _serialize_metadata_for_csv(
    metadata: dict[str, Any] | None,
) -> str:
    """
    Serialize metadata safely for CSV.

    JSON encoding is preferred over Python repr so the
    exported value remains machine-readable.
    """

    if metadata is None:
        return ""

    return json.dumps(
        metadata,
        ensure_ascii=False,
        separators=(
            ",",
            ":",
        ),
        default=str,
    )


# ============================================================================
# Shared Filter Normalization
# ============================================================================


def _normalize_audit_filters(
    *,
    action: str | None,
    category: str | None,
    result: str | None,
    source: str | None,
    search: str | None,
    request_id: str | None,
) -> tuple[
    str | None,
    str | None,
    str | None,
    str | None,
    str | None,
    str | None,
]:
    """
    Normalize all textual Global Audit filters.

    UUID/date filters are already parsed and validated by FastAPI.
    """

    return (
        _normalize_text(action),
        _normalize_text(category),
        _normalize_text(result),
        _normalize_text(source),
        _normalize_text(search),
        _normalize_text(request_id),
    )


# ============================================================================
# GET /audit
# ============================================================================


@router.get(
    "",
    response_model=AuditListResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(audit_read_permission),
    ],
)
async def list_audit_events(
    service: AuditService = Depends(
        get_audit_service,
    ),
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    page: int = Query(
        default=DEFAULT_PAGE,
        ge=1,
        description="One-based page number.",
    ),
    page_size: int = Query(
        default=DEFAULT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
        description="Number of audit events per page.",
    ),
    actor: UUID | None = Query(
        default=None,
        description="Filter by actor user ID.",
    ),
    target: UUID | None = Query(
        default=None,
        description="Filter by target user ID.",
    ),
    action: str | None = Query(
        default=None,
        min_length=1,
        max_length=MAX_ACTION_LENGTH,
        description="Filter by canonical audit action.",
    ),
    category: str | None = Query(
        default=None,
        max_length=MAX_CATEGORY_LENGTH,
        description="Filter by audit category.",
    ),
    result: str | None = Query(
        default=None,
        max_length=MAX_OUTCOME_LENGTH,
        description="Filter by audit outcome.",
    ),
    source: str | None = Query(
        default=None,
        max_length=MAX_SOURCE_IP_LENGTH,
        description="Filter by source IP.",
    ),
    date_from: datetime | None = Query(
        default=None,
        description=(
            "Events created at or after this timestamp."
        ),
    ),
    date_to: datetime | None = Query(
        default=None,
        description=(
            "Events created at or before this timestamp."
        ),
    ),
    search: str | None = Query(
        default=None,
        max_length=MAX_SEARCH_LENGTH,
        description="Audit investigation search term.",
    ),
    session_id: UUID | None = Query(
        default=None,
        description="Filter by session ID.",
    ),
    request_id: str | None = Query(
        default=None,
        max_length=MAX_REQUEST_ID_LENGTH,
        description="Filter by request correlation ID.",
    ),
) -> AuditListResponse:
    """
    List centralized Global Audit events.

    Locked permission:

        users:read

    Public HTTP query names:

        actor
        target
        action
        category
        result
        source
        date_from
        date_to
        search
        session_id
        request_id

    These names are translated into canonical AuditService
    arguments before the service is called.
    """

    # ------------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------------

    # Authentication is resolved centrally by the dependency.
    #
    # Authorization is resolved centrally by audit_read_permission.
    #
    # The authenticated principal is intentionally not used for
    # filtering because this is a Global Audit administrative endpoint.

    _ = principal

    # ------------------------------------------------------------------------
    # Date validation
    # ------------------------------------------------------------------------

    _validate_date_range(
        date_from,
        date_to,
    )

    # ------------------------------------------------------------------------
    # Filter normalization
    # ------------------------------------------------------------------------

    (
        action,
        category,
        result,
        source,
        search,
        request_id,
    ) = _normalize_audit_filters(
        action=action,
        category=category,
        result=result,
        source=source,
        search=search,
        request_id=request_id,
    )

    # ------------------------------------------------------------------------
    # Service invocation
    # ------------------------------------------------------------------------

    try:
        result_data = await service.list_events(
            page=page,
            page_size=page_size,
            actor_user_id=actor,
            target_user_id=target,
            action=action,
            category=category,
            outcome=result,
            source_ip=source,
            date_from=date_from,
            date_to=date_to,
            search=search,
            session_id=session_id,
            request_id=request_id,
        )

    except HTTPException:
        raise

    except Exception as exc:
        _raise_audit_http_error(
            exc,
        )

    # ------------------------------------------------------------------------
    # Service response validation
    #
    # Canonical service contract:
    #
    #     (events, total)
    # ------------------------------------------------------------------------

    try:
        events, total = result_data

    except (
        TypeError,
        ValueError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Invalid audit list response.",
        ) from exc

    # ------------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------------

    serialized_events = _serialize_audit_events(
        events,
    )

    return AuditListResponse(
        items=serialized_events,
        total=total,
        page=page,
        page_size=page_size,
    )


# ============================================================================
# GET /audit/export
# ============================================================================


@router.get(
    "/export",
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(audit_read_permission),
    ],
)
async def export_audit_events(
    service: AuditService = Depends(
        get_audit_service,
    ),
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    actor: UUID | None = Query(
        default=None,
        description="Filter by actor user ID.",
    ),
    target: UUID | None = Query(
        default=None,
        description="Filter by target user ID.",
    ),
    action: str | None = Query(
        default=None,
        min_length=1,
        max_length=MAX_ACTION_LENGTH,
        description="Filter by canonical audit action.",
    ),
    category: str | None = Query(
        default=None,
        max_length=MAX_CATEGORY_LENGTH,
        description="Filter by audit category.",
    ),
    result: str | None = Query(
        default=None,
        max_length=MAX_OUTCOME_LENGTH,
        description="Filter by audit outcome.",
    ),
    source: str | None = Query(
        default=None,
        max_length=MAX_SOURCE_IP_LENGTH,
        description="Filter by source IP.",
    ),
    date_from: datetime | None = Query(
        default=None,
        description=(
            "Events created at or after this timestamp."
        ),
    ),
    date_to: datetime | None = Query(
        default=None,
        description=(
            "Events created at or before this timestamp."
        ),
    ),
    search: str | None = Query(
        default=None,
        max_length=MAX_SEARCH_LENGTH,
        description="Audit investigation search term.",
    ),
    session_id: UUID | None = Query(
        default=None,
        description="Filter by session ID.",
    ),
    request_id: str | None = Query(
        default=None,
        max_length=MAX_REQUEST_ID_LENGTH,
        description="Filter by request correlation ID.",
    ),
    limit: int = Query(
        default=DEFAULT_EXPORT_LIMIT,
        ge=1,
        le=MAX_EXPORT_LIMIT,
        description="Maximum number of events to export.",
    ),
    format: str = Query(
        default="json",
        pattern="^(json|csv)$",
        description="Export format.",
    ),
):
    """
    Export Global Audit events.

    Locked permission:

        users:read

    Supported formats:

        json
        csv

    Export is strictly read-only.
    """

    _ = principal

    # ------------------------------------------------------------------------
    # Date validation
    # ------------------------------------------------------------------------

    _validate_date_range(
        date_from,
        date_to,
    )

    # ------------------------------------------------------------------------
    # Filter normalization
    # ------------------------------------------------------------------------

    (
        action,
        category,
        result,
        source,
        search,
        request_id,
    ) = _normalize_audit_filters(
        action=action,
        category=category,
        result=result,
        source=source,
        search=search,
        request_id=request_id,
    )

    # ------------------------------------------------------------------------
    # Service invocation
    # ------------------------------------------------------------------------

    try:
        events = await service.get_export_events(
            actor_user_id=actor,
            target_user_id=target,
            action=action,
            category=category,
            outcome=result,
            source_ip=source,
            date_from=date_from,
            date_to=date_to,
            search=search,
            session_id=session_id,
            request_id=request_id,
            limit=limit,
        )

    except HTTPException:
        raise

    except Exception as exc:
        _raise_audit_http_error(
            exc,
        )

    # ------------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------------

    serialized_events = _serialize_audit_events(
        events,
    )

    # ------------------------------------------------------------------------
    # JSON export
    # ------------------------------------------------------------------------

    if format == "json":
        return {
            "format": "json",
            "total": len(
                serialized_events,
            ),
            "events": [
                _audit_event_to_export_row(
                    event,
                )
                for event in serialized_events
            ],
        }

    # ------------------------------------------------------------------------
    # CSV export
    # ------------------------------------------------------------------------

    output = io.StringIO(
        newline="",
    )

    writer = csv.writer(
        output,
    )

    writer.writerow(
        [
            "audit_id",
            "actor_user_id",
            "target_user_id",
            "session_id",
            "request_id",
            "source_ip",
            "action",
            "outcome",
            "metadata_json",
            "created_at",
        ]
    )

    for event in serialized_events:
        writer.writerow(
            [
                str(event.audit_id),
                (
                    str(event.actor_user_id)
                    if event.actor_user_id is not None
                    else ""
                ),
                (
                    str(event.target_user_id)
                    if event.target_user_id is not None
                    else ""
                ),
                (
                    str(event.session_id)
                    if event.session_id is not None
                    else ""
                ),
                event.request_id or "",
                event.source_ip or "",
                event.action,
                event.outcome,
                _serialize_metadata_for_csv(
                    event.metadata_json,
                ),
                (
                    event.created_at.isoformat()
                    if event.created_at is not None
                    else ""
                ),
            ]
        )

    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                'attachment; filename="audit-export.csv"'
            ),
        },
    )


# ============================================================================
# GET /audit/{audit_id}/related
# ============================================================================


@router.get(
    "/{audit_id}/related",
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(audit_read_permission),
    ],
)
async def get_related_audit_events(
    audit_id: UUID,
    service: AuditService = Depends(
        get_audit_service,
    ),
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    limit: int = Query(
        default=DEFAULT_RELATED_LIMIT,
        ge=1,
        le=MAX_RELATED_LIMIT,
        description="Maximum number of related events.",
    ),
):
    """
    Retrieve events related to one audit event.

    Locked permission:

        users:read

    The parent audit event must exist before related events
    are requested.
    """

    _ = principal

    # ------------------------------------------------------------------------
    # Retrieve parent event
    # ------------------------------------------------------------------------

    try:
        parent_event = await service.get_event(
            audit_id,
        )

    except HTTPException:
        raise

    except Exception as exc:
        _raise_audit_http_error(
            exc,
        )

    if parent_event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit event not found.",
        )

    # ------------------------------------------------------------------------
    # Retrieve related events
    # ------------------------------------------------------------------------

    try:
        events = await service.get_related_events(
            audit_id,
            limit=limit,
        )

    except HTTPException:
        raise

    except Exception as exc:
        _raise_audit_http_error(
            exc,
        )

    # ------------------------------------------------------------------------
    # Serialize response
    # ------------------------------------------------------------------------

    serialized_events = _serialize_audit_events(
        events,
    )

    return {
        "audit_id": audit_id,
        "events": [
            _audit_event_to_export_row(
                event,
            )
            for event in serialized_events
        ],
        "total": len(
            serialized_events,
        ),
    }


# ============================================================================
# GET /audit/{audit_id}
# ============================================================================


@router.get(
    "/{audit_id}",
    response_model=AuditResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(audit_read_permission),
    ],
)
async def get_audit_event(
    audit_id: UUID,
    service: AuditService = Depends(
        get_audit_service,
    ),
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
) -> AuditResponse:
    """
    Retrieve one immutable audit event.

    Locked permission:

        users:read
    """

    _ = principal

    # ------------------------------------------------------------------------
    # Service invocation
    # ------------------------------------------------------------------------

    try:
        event = await service.get_event(
            audit_id,
        )

    except HTTPException:
        raise

    except Exception as exc:
        _raise_audit_http_error(
            exc,
        )

    # ------------------------------------------------------------------------
    # Not found
    # ------------------------------------------------------------------------

    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit event not found.",
        )

    # ------------------------------------------------------------------------
    # Explicit serialization
    # ------------------------------------------------------------------------

    return _serialize_audit_event(
        event,
    )


# ============================================================================
# Public Exports
# ============================================================================

__all__ = [
    "router",
    "audit_read_permission",
    "list_audit_events",
    "export_audit_events",
    "get_related_audit_events",
    "get_audit_event",
]