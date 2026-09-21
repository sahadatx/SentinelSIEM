"""
SentinelSIEM — Canonical Global Audit API Routes
================================================

HTTP boundary for the centralized SentinelSIEM audit subsystem.

Canonical endpoints
-------------------

    GET /audit
    GET /audit/statistics
    GET /audit/export
    GET /audit/{audit_id}/related
    GET /audit/{audit_id}


Authorization
-------------

Global Audit requires:

    users:read


Locked RBAC boundary
--------------------

    ADMIN            -> ALLOWED
    SECURITY_ANALYST -> DENIED
    SOC_ANALYST      -> DENIED
    INVESTIGATOR     -> DENIED
    VIEWER           -> DENIED


Read-only
---------

This router exposes no:

    POST
    PUT
    PATCH
    DELETE


Architecture
------------

    HTTP Request
         |
         v
    Authentication
         |
         v
    users:read
         |
         v
    AuditRouter
         |
         v
    AuditService
         |
         v
    AuditRepository
         |
         v
    siem_auth_audit


Important
---------

The database stores canonical UUID references:

    actor_user_id
    target_user_id

The service layer is responsible for identity enrichment.

The router MUST NOT:

    - query the user table directly
    - create an AuditRepository directly
    - resolve usernames
    - resolve roles
    - perform RBAC decisions
    - commit
    - rollback
    - create transactions


Target Display Contract
-----------------------

The router preserves canonical target semantics.

If:

    target_user_id is NULL

then the response MUST preserve:

    target = None

The presentation layer may render this as:

    No target

The router MUST NOT invent:

    User
    Unknown User
    —
    None-as-user


Transaction
-----------

The router never owns transaction lifecycle.

The normal request session is managed by:

    app.api.dependencies.get_db_session


Security
--------

The router never intentionally exposes:

    - passwords
    - password hashes
    - access tokens
    - refresh tokens
    - JWTs
    - session tokens
    - API keys
    - private keys
    - secrets
    - authorization headers
    - cookies
"""

from __future__ import annotations


# =============================================================================
# Standard Library
# =============================================================================

from datetime import datetime
from typing import Any
from uuid import UUID


# =============================================================================
# Third-Party
# =============================================================================

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
)


# =============================================================================
# SentinelSIEM
# =============================================================================

from app.api.dependencies import (
    get_audit_service,
    get_current_principal,
    require_permission,
)

from app.audit.schemas import (
    AuditExportResponse,
    AuditListResponse,
    AuditRelatedEventListResponse,
    AuditResponse,
    AuditStatisticsResponse,
)

from app.audit.service import (
    AuditService,
    AuditServiceError,
    AuditValidationError,
)

from app.auth.models import UserPrincipal


# =============================================================================
# Router
# =============================================================================

router = APIRouter(
    prefix="/audit",
    tags=["Audit"],
)


# =============================================================================
# Constants
# =============================================================================

DEFAULT_PAGE = 1
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

DEFAULT_RELATED_LIMIT = 100
MAX_RELATED_LIMIT = 200

DEFAULT_EXPORT_LIMIT = 10_000
MAX_EXPORT_LIMIT = 10_000

MAX_ACTION_LENGTH = 150
MAX_CATEGORY_LENGTH = 100
MAX_OUTCOME_LENGTH = 50
MAX_SOURCE_IP_LENGTH = 45
MAX_SEARCH_LENGTH = 500


# =============================================================================
# Locked Authorization Boundary
# =============================================================================

"""
Global Audit has NO dedicated audit permission.

Canonical permission:

    users:read

Do NOT use:

    audit:read
    audit:view
    audit:export

unless the global RBAC contract is explicitly changed.
"""

audit_read_permission = require_permission(
    "users:read",
)


# =============================================================================
# Query Normalization
# =============================================================================


def _normalize_text(
    value: str | None,
) -> str | None:
    """
    Normalize optional text input.

    Examples:

        None
            -> None

        ""
            -> None

        "   "
            -> None

        " value "
            -> "value"
    """

    if value is None:
        return None

    normalized = value.strip()

    if not normalized:
        return None

    return normalized


def _validate_date_range(
    date_from: datetime | None,
    date_to: datetime | None,
) -> None:
    """
    Validate chronological ordering of the audit date range.
    """

    if (
        date_from is not None
        and date_to is not None
        and date_from > date_to
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="date_from cannot be later than date_to.",
        )


# =============================================================================
# Metadata Serialization
# =============================================================================


def _serialize_metadata(
    metadata: Any,
) -> dict[str, Any] | None:
    """
    Serialize canonical metadata_json.

    Only dictionary metadata is considered valid for the public
    audit representation.

    Sensitive metadata should already have been rejected/sanitized
    by the audit service/repository boundary.
    """

    if metadata is None:
        return None

    if not isinstance(
        metadata,
        dict,
    ):
        raise ValueError(
            "Audit event metadata_json must be a dictionary."
        )

    return dict(
        metadata,
    )


# =============================================================================
# Source IP Serialization
# =============================================================================


def _serialize_source_ip(
    source_ip: Any,
) -> str | None:
    """
    Convert PostgreSQL INET or equivalent value to string.
    """

    if source_ip is None:
        return None

    normalized = str(
        source_ip,
    ).strip()

    return normalized or None


# =============================================================================
# Identity Serialization
# =============================================================================


def _serialize_identity(
    identity: Any,
) -> Any:
    """
    Preserve service-resolved identity.

    Identity resolution belongs to AuditService.

    This function intentionally does not invent fallback identities.
    """

    if identity is None:
        return None

    return identity


# =============================================================================
# Single Audit Event Serialization
# =============================================================================


def _serialize_audit_event(
    event: Any,
) -> AuditResponse:
    """
    Convert a canonical service-level audit event to AuditResponse.

    Only public canonical audit fields are serialized.
    """

    if event is None:
        raise ValueError(
            "Cannot serialize a null audit event."
        )

    # -------------------------------------------------------------------------
    # Required fields
    # -------------------------------------------------------------------------

    audit_id = getattr(
        event,
        "audit_id",
        None,
    )

    action = getattr(
        event,
        "action",
        None,
    )

    outcome = getattr(
        event,
        "outcome",
        None,
    )

    created_at = getattr(
        event,
        "created_at",
        None,
    )

    if audit_id is None:
        raise ValueError(
            "Audit event is missing audit_id."
        )

    if action is None:
        raise ValueError(
            "Audit event is missing action."
        )

    if outcome is None:
        raise ValueError(
            "Audit event is missing outcome."
        )

    if created_at is None:
        raise ValueError(
            "Audit event is missing created_at."
        )

    # -------------------------------------------------------------------------
    # Canonical UUID references
    # -------------------------------------------------------------------------

    actor_user_id = getattr(
        event,
        "actor_user_id",
        None,
    )

    target_user_id = getattr(
        event,
        "target_user_id",
        None,
    )

    session_id = getattr(
        event,
        "session_id",
        None,
    )

    # -------------------------------------------------------------------------
    # Correlation
    # -------------------------------------------------------------------------

    request_id = getattr(
        event,
        "request_id",
        None,
    )

    # -------------------------------------------------------------------------
    # Network
    # -------------------------------------------------------------------------

    source_ip = _serialize_source_ip(
        getattr(
            event,
            "source_ip",
            None,
        ),
    )

    # -------------------------------------------------------------------------
    # Metadata
    # -------------------------------------------------------------------------

    metadata_json = _serialize_metadata(
        getattr(
            event,
            "metadata_json",
            None,
        ),
    )

    # -------------------------------------------------------------------------
    # Service-resolved identities
    # -------------------------------------------------------------------------

    actor = _serialize_identity(
        getattr(
            event,
            "actor",
            None,
        ),
    )

    target = _serialize_identity(
        getattr(
            event,
            "target",
            None,
        ),
    )

    # -------------------------------------------------------------------------
    # Preserve NULL target semantics
    # -------------------------------------------------------------------------

    if target_user_id is None:
        target = None

    # -------------------------------------------------------------------------
    # Response
    # -------------------------------------------------------------------------

    return AuditResponse(
        audit_id=audit_id,
        actor_user_id=actor_user_id,
        target_user_id=target_user_id,
        session_id=session_id,
        actor=actor,
        target=target,
        request_id=request_id,
        source_ip=source_ip,
        action=action,
        outcome=outcome,
        metadata_json=metadata_json,
        created_at=created_at,
    )


# =============================================================================
# Multiple Audit Event Serialization
# =============================================================================


def _serialize_audit_events(
    events: Any,
) -> list[AuditResponse]:
    """
    Serialize a collection of audit events.
    """

    if events is None:
        return []

    return [
        _serialize_audit_event(
            event,
        )
        for event in events
    ]


# =============================================================================
# Service Error Mapping
# =============================================================================


def _raise_audit_http_error(
    exc: Exception,
) -> None:
    """
    Convert internal AuditService exceptions into stable HTTP errors.

    AuditValidationError:

        -> HTTP 422

    AuditServiceError:

        -> HTTP 500

    Unexpected exception:

        -> HTTP 500
    """

    if isinstance(
        exc,
        HTTPException,
    ):
        raise exc

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
            detail="Unable to complete audit operation.",
        ) from exc

    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Unable to complete audit operation.",
    ) from exc


# =============================================================================
# GET /audit
# =============================================================================


@router.get(
    "",
    response_model=AuditListResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            audit_read_permission,
        ),
    ],
)
async def list_audit_events(
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    service: AuditService = Depends(
        get_audit_service,
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
        max_length=MAX_ACTION_LENGTH,
        description="Filter by canonical audit action.",
    ),
    category: str | None = Query(
        default=None,
        max_length=MAX_CATEGORY_LENGTH,
        description="Filter by audit action category.",
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
        description="Return events at or after this timestamp.",
    ),
    date_to: datetime | None = Query(
        default=None,
        description="Return events at or before this timestamp.",
    ),
    search: str | None = Query(
        default=None,
        max_length=MAX_SEARCH_LENGTH,
        description="Search non-secret audit fields.",
    ),
) -> AuditListResponse:
    """
    Return paginated Global Audit events.

    Authorization:

        users:read
    """

    # Explicitly retain dependency for authentication context.
    _ = principal

    _validate_date_range(
        date_from,
        date_to,
    )

    try:
        events, total = await service.list_events(
            page=page,
            page_size=page_size,
            actor_user_id=actor,
            target_user_id=target,
            action=_normalize_text(
                action,
            ),
            category=_normalize_text(
                category,
            ),
            outcome=_normalize_text(
                result,
            ),
            source_ip=_normalize_text(
                source,
            ),
            date_from=date_from,
            date_to=date_to,
            search=_normalize_text(
                search,
            ),
        )

        serialized_events = _serialize_audit_events(
            events,
        )

        pages = (
            (total + page_size - 1) // page_size
            if total > 0
            else 0
        )

        return AuditListResponse(
            events=serialized_events,
            total=total,
            page=page,
            page_size=page_size,
            pages=pages,
        )

    except HTTPException:
        raise

    except (
        AuditValidationError,
        AuditServiceError,
    ) as exc:
        _raise_audit_http_error(
            exc,
        )

    except Exception as exc:
        _raise_audit_http_error(
            exc,
        )


# =============================================================================
# GET /audit/statistics
# =============================================================================


@router.get(
    "/statistics",
    response_model=AuditStatisticsResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            audit_read_permission,
        ),
    ],
)
async def get_audit_statistics(
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    service: AuditService = Depends(
        get_audit_service,
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
        max_length=MAX_ACTION_LENGTH,
    ),
    category: str | None = Query(
        default=None,
        max_length=MAX_CATEGORY_LENGTH,
    ),
    result: str | None = Query(
        default=None,
        max_length=MAX_OUTCOME_LENGTH,
    ),
    source: str | None = Query(
        default=None,
        max_length=MAX_SOURCE_IP_LENGTH,
    ),
    date_from: datetime | None = Query(
        default=None,
    ),
    date_to: datetime | None = Query(
        default=None,
    ),
    search: str | None = Query(
        default=None,
        max_length=MAX_SEARCH_LENGTH,
    ),
) -> AuditStatisticsResponse:
    """
    Return Global Audit statistics.
    """

    _ = principal

    _validate_date_range(
        date_from,
        date_to,
    )

    try:
        statistics = await service.get_statistics(
            actor_user_id=actor,
            target_user_id=target,
            action=_normalize_text(
                action,
            ),
            category=_normalize_text(
                category,
            ),
            outcome=_normalize_text(
                result,
            ),
            source_ip=_normalize_text(
                source,
            ),
            date_from=date_from,
            date_to=date_to,
            search=_normalize_text(
                search,
            ),
        )

        if not isinstance(
            statistics,
            dict,
        ):
            raise AuditServiceError(
                "Invalid audit statistics response."
            )

        return AuditStatisticsResponse(
            total=int(
                statistics.get(
                    "total",
                    0,
                )
            ),
            success=int(
                statistics.get(
                    "success",
                    0,
                )
            ),
            failure=int(
                statistics.get(
                    "failure",
                    0,
                )
            ),
            denied=int(
                statistics.get(
                    "denied",
                    0,
                )
            ),
            unique_actors=int(
                statistics.get(
                    "unique_actors",
                    0,
                )
            ),
            unique_targets=int(
                statistics.get(
                    "unique_targets",
                    0,
                )
            ),
        )

    except HTTPException:
        raise

    except (
        AuditValidationError,
        AuditServiceError,
    ) as exc:
        _raise_audit_http_error(
            exc,
        )

    except Exception as exc:
        _raise_audit_http_error(
            exc,
        )


# =============================================================================
# GET /audit/export
# =============================================================================


@router.get(
    "/export",
    response_model=AuditExportResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            audit_read_permission,
        ),
    ],
)
async def export_audit_events(
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    service: AuditService = Depends(
        get_audit_service,
    ),
    actor: UUID | None = Query(
        default=None,
        description="Filter export by actor user ID.",
    ),
    target: UUID | None = Query(
        default=None,
        description="Filter export by target user ID.",
    ),
    action: str | None = Query(
        default=None,
        max_length=MAX_ACTION_LENGTH,
    ),
    category: str | None = Query(
        default=None,
        max_length=MAX_CATEGORY_LENGTH,
    ),
    result: str | None = Query(
        default=None,
        max_length=MAX_OUTCOME_LENGTH,
    ),
    source: str | None = Query(
        default=None,
        max_length=MAX_SOURCE_IP_LENGTH,
    ),
    date_from: datetime | None = Query(
        default=None,
    ),
    date_to: datetime | None = Query(
        default=None,
    ),
    search: str | None = Query(
        default=None,
        max_length=MAX_SEARCH_LENGTH,
    ),
    limit: int = Query(
        default=DEFAULT_EXPORT_LIMIT,
        ge=1,
        le=MAX_EXPORT_LIMIT,
        description="Maximum number of events to export.",
    ),
) -> AuditExportResponse:
    """
    Return bounded read-only audit export data.

    Export does not modify the database.
    """

    _ = principal

    _validate_date_range(
        date_from,
        date_to,
    )

    try:
        events = await service.get_export_events(
            actor_user_id=actor,
            target_user_id=target,
            action=_normalize_text(
                action,
            ),
            category=_normalize_text(
                category,
            ),
            outcome=_normalize_text(
                result,
            ),
            source_ip=_normalize_text(
                source,
            ),
            date_from=date_from,
            date_to=date_to,
            search=_normalize_text(
                search,
            ),
            limit=limit,
        )

        serialized_events = _serialize_audit_events(
            events,
        )

        return AuditExportResponse(
            format="json",
            total=len(
                serialized_events,
            ),
            events=serialized_events,
        )

    except HTTPException:
        raise

    except (
        AuditValidationError,
        AuditServiceError,
    ) as exc:
        _raise_audit_http_error(
            exc,
        )

    except Exception as exc:
        _raise_audit_http_error(
            exc,
        )


# =============================================================================
# GET /audit/{audit_id}/related
# =============================================================================


@router.get(
    "/{audit_id}/related",
    response_model=AuditRelatedEventListResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            audit_read_permission,
        ),
    ],
)
async def get_related_audit_events(
    audit_id: UUID,
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    service: AuditService = Depends(
        get_audit_service,
    ),
    limit: int = Query(
        default=DEFAULT_RELATED_LIMIT,
        ge=1,
        le=MAX_RELATED_LIMIT,
        description="Maximum number of related events.",
    ),
) -> AuditRelatedEventListResponse:
    """
    Return events correlated with one audit event.
    """

    _ = principal

    try:
        source_event = await service.get_event(
            audit_id,
        )

        if source_event is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Audit event not found.",
            )

        related_events = await service.get_related_events(
            audit_id,
            limit=limit,
        )

        serialized_events = _serialize_audit_events(
            related_events,
        )

        return AuditRelatedEventListResponse(
            audit_id=audit_id,
            events=serialized_events,
            total=len(
                serialized_events,
            ),
        )

    except HTTPException:
        raise

    except (
        AuditValidationError,
        AuditServiceError,
    ) as exc:
        _raise_audit_http_error(
            exc,
        )

    except Exception as exc:
        _raise_audit_http_error(
            exc,
        )


# =============================================================================
# GET /audit/{audit_id}
# =============================================================================


@router.get(
    "/{audit_id}",
    response_model=AuditResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            audit_read_permission,
        ),
    ],
)
async def get_audit_event(
    audit_id: UUID,
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    service: AuditService = Depends(
        get_audit_service,
    ),
) -> AuditResponse:
    """
    Return one immutable audit event.
    """

    _ = principal

    try:
        event = await service.get_event(
            audit_id,
        )

        if event is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Audit event not found.",
            )

        return _serialize_audit_event(
            event,
        )

    except HTTPException:
        raise

    except (
        AuditValidationError,
        AuditServiceError,
    ) as exc:
        _raise_audit_http_error(
            exc,
        )

    except Exception as exc:
        _raise_audit_http_error(
            exc,
        )


# =============================================================================
# Public API
# =============================================================================

__all__ = [
    "router",
    "audit_read_permission",
    "list_audit_events",
    "get_audit_statistics",
    "export_audit_events",
    "get_related_audit_events",
    "get_audit_event",
]