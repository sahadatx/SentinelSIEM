"""
SentinelSIEM User Management API Routes
=======================================

HTTP/API boundary for the SentinelSIEM User Management subsystem.

Architecture
------------

    HTTP Request
         |
         v
    FastAPI Route
         |
         +--> Authentication / Principal
         |
         +--> Permission Dependency
         |
         v
    UserManagementService
         |
         +--> UserRepository
         |
         +--> SessionRepository
         |
         +--> AuditService
                    |
                    v
              AuditRepository
                    |
                    v
              siem_auth_audit


Responsibilities
----------------

Routes are responsible ONLY for:

    - HTTP request parsing
    - authentication dependency wiring
    - permission dependency wiring
    - request schema validation
    - service invocation
    - HTTP exception mapping
    - safe response serialization
    - pagination response metadata

Routes MUST NOT:

    - query repositories directly
    - implement RBAC policy
    - implement last-admin protection
    - implement self-action protection
    - implement password policy
    - hash passwords
    - revoke sessions directly
    - construct audit records
    - decide audit authorization
    - expose internal security fields
    - implement user-management business logic


Authorization
-------------

User Management read operations:

    users:read

User Management mutations:

    users:manage

Role changes:

    users:manage
    roles:manage

Individual User Audit:

    users:read

There is intentionally no:

    audit:read
    audit:export

for the User Management audit endpoint.


Canonical Audit Architecture
----------------------------

    User Route
         |
         v
    AuditService
         |
         v
    AuditRepository


There is no secondary User Audit repository/table.


Audit Semantics
---------------

Individual User Audit includes events where the requested user is either:

    actor_user_id
        OR
    target_user_id

The route does not broaden this scope itself.

Global Audit remains a separate API surface.


Individual Audit Filter Contract
--------------------------------

The Individual User Audit UI may send only:

    action
    outcome
    target_user_id
    source_ip
    date_from
    date_to
    page
    page_size

The route accepts exactly those audit filters.

The requested user scope remains:

    actor_user_id = user_id
    OR
    target_user_id = user_id

The frontend does NOT provide an actor filter.

The frontend does NOT provide category/search filters.

Global Audit remains a separate API surface.


Individual Audit Statistics Contract
------------------------------------

The Individual User Audit endpoint returns:

    activities
    total
    limit
    offset
    statistics

Statistics are calculated by AuditService against the COMPLETE
filtered Individual Audit dataset, not against the current page.

Statistics:

    total
    success
    failure
    denied

Example:

    {
        "statistics": {
            "total": 143,
            "success": 30,
            "failure": 113,
            "denied": 0
        }
    }

The same filters are applied to:

    get_user_events()
    get_user_statistics()

Therefore:

    page 1 + filter
    page 2 + same filter

must have identical statistics.

Changing:

    action
    outcome
    target_user_id
    source_ip
    date_from
    date_to

causes both the event list and statistics to change.


Global Audit Display Contract
-----------------------------

The backend preserves technical identity references.

The presentation layer may render:

Actor:

    existing actor:
        👤 Name
        Role

    system actor:
        🛡 System
        System

Target:

    target_user_id exists:
        👤 Name
        Role

    all-users target:
        👥 All Users

    target_user_id is NULL:
        —
        No target

IMPORTANT:

    NULL target_user_id remains NULL.

The route MUST NOT replace NULL with a fake user,
fake UUID, or synthetic target.


Security
--------

Never expose:

    password
    password_hash
    access_token
    refresh_token
    session_token
    JWT
    JTI
    token_id
    API key
    secret
    private key
    authorization header
    cookies
    credential material

Password requests are forwarded to the service and never returned.

Session token/JTI values remain internal to the authentication/session layer.


Pagination Contract
-------------------

User Management pagination is backend-driven.

Canonical page size:

    30 users per page

The backend returns:

    users
    total
    total_pages
    limit
    offset

Individual User Audit pagination is also backend-driven.

The Individual Audit frontend requests:

    page_size = 30

The backend returns:

    activities
    total
    limit
    offset
    statistics

The frontend may calculate the number of audit pages from
the backend total and the fixed requested page size.

Statistics MUST NOT be calculated from the current page
in the frontend.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    status,
)

from app.api.dependencies import (
    get_audit_service,
    get_current_principal,
    get_user_management_service,
    require_permission,
)

from app.api.schemas.users import (
    ChangeRoleRequest,
    CreateUserRequest,
    DeleteUserResponse,
    ResetPasswordRequest,
    ResetPasswordResponse,
    RevokeSessionsResponse,
    SetActiveRequest,
    SetLockedRequest,
    UpdateUserRequest,
    UserActivityListResponse,
    UserActivityResponse,
    UserDetailResponse,
    UserListResponse,
    UserResponse,
    UserStatisticsResponse,
)

from app.audit.service import (
    AuditService,
    AuditServiceError,
    AuditValidationError,
)

from app.auth.models import UserPrincipal

from app.auth.user_management import (
    InvalidRoleError,
    LastAdminProtectionError,
    SelfServiceDeniedError,
    UserAlreadyExistsError,
    UserManagementError,
    UserManagementService,
    UserManagementValidationError,
    UserNotFoundError,
)


# =============================================================================
# Router
# =============================================================================


router = APIRouter(
    prefix="/users",
    tags=["Users"],
)


# =============================================================================
# Permission Dependencies
# =============================================================================


users_read_permission = require_permission(
    "users:read",
)

users_manage_permission = require_permission(
    "users:manage",
)

roles_manage_permission = require_permission(
    "roles:manage",
)


# =============================================================================
# Constants
# =============================================================================


# ---------------------------------------------------------------------------
# User pagination
# ---------------------------------------------------------------------------

DEFAULT_USER_PAGE_SIZE = 30
MAX_USER_PAGE_SIZE = 200


# ---------------------------------------------------------------------------
# Audit pagination
# ---------------------------------------------------------------------------

DEFAULT_AUDIT_PAGE = 1
DEFAULT_AUDIT_PAGE_SIZE = 30
MAX_AUDIT_PAGE_SIZE = 200


# ---------------------------------------------------------------------------
# Request validation limits
# ---------------------------------------------------------------------------

MAX_REQUEST_ID_LENGTH = 200
MAX_SOURCE_IP_LENGTH = 45

MAX_SEARCH_LENGTH = 200
MAX_ACTION_LENGTH = 200
MAX_OUTCOME_LENGTH = 100


# =============================================================================
# Request Metadata
# =============================================================================


def _get_request_id(
    request: Request,
) -> str | None:
    """
    Resolve the request correlation ID.

    Preferred source:

        request.state.request_id

    Fallback:

        X-Request-ID

    Request IDs are correlation metadata only.
    """

    value = getattr(
        request.state,
        "request_id",
        None,
    )

    if value is None:
        value = request.headers.get(
            "X-Request-ID",
        )

    if value is None:
        return None

    value = str(
        value,
    ).strip()

    if not value:
        return None

    return value[:MAX_REQUEST_ID_LENGTH]


def _get_source_ip(
    request: Request,
) -> str | None:
    """
    Resolve the direct client IP.

    X-Forwarded-For is intentionally NOT trusted here.
    """

    client = request.client

    if client is None:
        return None

    host = getattr(
        client,
        "host",
        None,
    )

    if host is None:
        return None

    value = str(
        host,
    ).strip()

    if not value:
        return None

    return value[:MAX_SOURCE_IP_LENGTH]


# =============================================================================
# Date Validation
# =============================================================================


def _validate_date_range(
    date_from: datetime | None,
    date_to: datetime | None,
) -> None:
    """
    Validate an optional inclusive date range.
    """

    if (
        date_from is not None
        and date_to is not None
        and date_from > date_to
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="date_from cannot be later than date_to.",
        )


# =============================================================================
# User Pagination
# =============================================================================


def _calculate_total_pages(
    total: int,
    limit: int,
) -> int:
    """
    Calculate total User Management pages.

    Pagination is based on the backend total.
    """

    if total <= 0:
        return 0

    return (
        total + limit - 1
    ) // limit


# =============================================================================
# Safe User Serialization
# =============================================================================


def _serialize_user(
    user: Any,
) -> UserResponse:
    """
    Serialize an internal user object through an explicit allow-list.

    Sensitive/internal attributes are deliberately excluded.
    """

    return UserResponse(
        user_id=user.user_id,
        username=user.username,
        email=user.email,
        roles=sorted(
            user.roles,
        ),
        is_active=user.is_active,
        is_locked=user.is_locked,
        failed_login_count=user.failed_login_count,
        display_name=getattr(
            user,
            "display_name",
            None,
        ),
        force_password_change=getattr(
            user,
            "force_password_change",
            False,
        ),
        password_changed_at=getattr(
            user,
            "password_changed_at",
            None,
        ),
        last_login_at=getattr(
            user,
            "last_login_at",
            None,
        ),
        created_at=getattr(
            user,
            "created_at",
            None,
        ),
        updated_at=getattr(
            user,
            "updated_at",
            None,
        ),
    )


def _serialize_user_detail(
    user: Any,
) -> UserDetailResponse:
    """
    Serialize a detailed user response.

    Credential/session information is never exposed.
    """

    return UserDetailResponse(
        user_id=user.user_id,
        username=user.username,
        email=user.email,
        roles=sorted(
            user.roles,
        ),
        is_active=user.is_active,
        is_locked=user.is_locked,
        failed_login_count=user.failed_login_count,
        display_name=getattr(
            user,
            "display_name",
            None,
        ),
        force_password_change=getattr(
            user,
            "force_password_change",
            False,
        ),
        password_changed_at=getattr(
            user,
            "password_changed_at",
            None,
        ),
        last_login_at=getattr(
            user,
            "last_login_at",
            None,
        ),
        created_at=getattr(
            user,
            "created_at",
            None,
        ),
        updated_at=getattr(
            user,
            "updated_at",
            None,
        ),
    )


# =============================================================================
# Safe Audit Serialization
# =============================================================================


def _serialize_audit_metadata(
    event: Any,
) -> dict[str, Any]:
    """
    Convert internal audit metadata to a plain JSON-safe dictionary.

    The database/repository boundary may expose SQLAlchemy-specific
    mapping objects. The public API contract must expose a plain dict.

    metadata_json is preferred because it is the canonical persisted
    audit metadata field.
    """

    metadata_json = getattr(
        event,
        "metadata_json",
        None,
    )

    if isinstance(
        metadata_json,
        Mapping,
    ):
        return dict(
            metadata_json,
        )

    metadata = getattr(
        event,
        "metadata",
        None,
    )

    if isinstance(
        metadata,
        Mapping,
    ):
        return dict(
            metadata,
        )

    return {}


def _serialize_audit_source_ip(
    event: Any,
) -> str | None:
    """
    Normalize PostgreSQL/SQLAlchemy IP address values.

    PostgreSQL INET values may arrive as IPv4Address/IPv6Address
    objects rather than strings.
    """

    value = getattr(
        event,
        "source_ip",
        None,
    )

    if value is None:
        return None

    return str(
        value,
    )


def _serialize_audit_event(
    event: Any,
) -> UserActivityResponse:
    """
    Convert an internal audit record to the public User Activity contract.

    IMPORTANT:

        target_user_id=None

    remains:

        None

    It is never converted into a synthetic target identity.

    Technical UUIDs remain available to the details view.

    Presentation-layer identity resolution belongs outside this route.
    """

    timestamp = (
        getattr(
            event,
            "timestamp",
            None,
        )
        or getattr(
            event,
            "created_at",
            None,
        )
    )

    if timestamp is None:
        raise ValueError(
            "Audit event is missing its timestamp.",
        )

    return UserActivityResponse(
        audit_id=getattr(
            event,
            "audit_id",
            None,
        ),
        action=getattr(
            event,
            "action",
        ),
        outcome=getattr(
            event,
            "outcome",
        ),
        category=getattr(
            event,
            "category",
            None,
        ),
        actor_user_id=getattr(
            event,
            "actor_user_id",
            None,
        ),
        target_user_id=getattr(
            event,
            "target_user_id",
            None,
        ),
        session_id=getattr(
            event,
            "session_id",
            None,
        ),
        request_id=getattr(
            event,
            "request_id",
            None,
        ),
        source_ip=_serialize_audit_source_ip(
            event,
        ),
        metadata=_serialize_audit_metadata(
            event,
        ),
        timestamp=timestamp,
    )


def _serialize_audit_events(
    events: list[Any],
) -> list[UserActivityResponse]:
    """
    Serialize audit events through the safe public contract.
    """

    return [
        _serialize_audit_event(
            event,
        )
        for event in events
    ]


# =============================================================================
# Safe Audit Statistics Serialization
# =============================================================================


def _serialize_user_audit_statistics(
    statistics: Any,
) -> dict[str, int]:
    """
    Serialize backend-authoritative Individual User Audit statistics.

    Only the four Individual Audit counters are exposed.

    Expected repository/service contract:

        total
        success
        failure
        denied

    The statistics represent the complete filtered dataset,
    not the current pagination page.
    """

    if not isinstance(
        statistics,
        Mapping,
    ):
        raise AuditServiceError(
            "Invalid individual user audit statistics.",
        )

    result: dict[str, int] = {}

    for key in (
        "total",
        "success",
        "failure",
        "denied",
    ):
        try:
            value = int(
                statistics.get(
                    key,
                    0,
                ),
            )
        except (
            TypeError,
            ValueError,
        ) as exc:
            raise AuditServiceError(
                "Invalid individual user audit statistic: "
                f"{key}.",
            ) from exc

        if value < 0:
            raise AuditServiceError(
                "Individual user audit statistic cannot "
                f"be negative: {key}.",
            )

        result[key] = value

    return result


# =============================================================================
# User Management Exception Mapping
# =============================================================================


def _raise_user_management_error(
    exc: Exception,
) -> None:
    """
    Translate service-layer exceptions to safe HTTP responses.

    Internal exception/database details are never exposed.
    """

    if isinstance(
        exc,
        UserNotFoundError,
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        ) from exc

    if isinstance(
        exc,
        UserAlreadyExistsError,
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    if isinstance(
        exc,
        LastAdminProtectionError,
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    if isinstance(
        exc,
        SelfServiceDeniedError,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        ) from exc

    if isinstance(
        exc,
        InvalidRoleError,
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    if isinstance(
        exc,
        UserManagementValidationError,
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    if isinstance(
        exc,
        UserManagementError,
    ):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to complete user-management operation.",
        ) from exc

    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Unable to complete user-management operation.",
    ) from exc


# =============================================================================
# Audit Exception Mapping
# =============================================================================


def _raise_audit_error(
    exc: Exception,
) -> None:
    """
    Translate AuditService exceptions to safe HTTP responses.
    """

    if isinstance(
        exc,
        AuditValidationError,
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    if isinstance(
        exc,
        AuditServiceError,
    ):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to retrieve user audit history.",
        ) from exc

    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Unable to retrieve user audit history.",
    ) from exc


# =============================================================================
# GET /users
# =============================================================================


@router.get(
    "",
    response_model=UserListResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(users_read_permission),
    ],
)
async def list_users(
    request: Request,
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    service: UserManagementService = Depends(
        get_user_management_service,
    ),
    search: str | None = Query(
        default=None,
        max_length=MAX_SEARCH_LENGTH,
    ),
    role: str | None = Query(
        default=None,
    ),
    is_active: bool | None = Query(
        default=None,
    ),
    is_locked: bool | None = Query(
        default=None,
    ),
    force_password_change: bool | None = Query(
        default=None,
    ),
    created_from: datetime | None = Query(
        default=None,
    ),
    created_to: datetime | None = Query(
        default=None,
    ),
    last_login_from: datetime | None = Query(
        default=None,
    ),
    last_login_to: datetime | None = Query(
        default=None,
    ),
    limit: int = Query(
        default=DEFAULT_USER_PAGE_SIZE,
        ge=1,
        le=MAX_USER_PAGE_SIZE,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
) -> UserListResponse:

    _validate_date_range(
        created_from,
        created_to,
    )

    _validate_date_range(
        last_login_from,
        last_login_to,
    )

    try:
        result = await service.list_users(
            actor_user_id=principal.user_id,
            search=search,
            role=role,
            is_active=is_active,
            is_locked=is_locked,
            force_password_change=force_password_change,
            created_from=created_from,
            created_to=created_to,
            last_login_from=last_login_from,
            last_login_to=last_login_to,
            limit=limit,
            offset=offset,
            request_id=_get_request_id(request),
            source_ip=_get_source_ip(request),
        )

    except Exception as exc:
        _raise_user_management_error(
            exc,
        )

    users = getattr(
        result,
        "users",
        result,
    )

    total = int(
        getattr(
            result,
            "total",
            len(users),
        ),
    )

    result_limit = int(
        getattr(
            result,
            "limit",
            limit,
        ),
    )

    result_offset = int(
        getattr(
            result,
            "offset",
            offset,
        ),
    )

    total_pages = _calculate_total_pages(
        total=total,
        limit=result_limit,
    )

    return UserListResponse(
        users=[
            _serialize_user(user)
            for user in users
        ],
        total=total,
        total_pages=total_pages,
        limit=result_limit,
        offset=result_offset,
    )


# =============================================================================
# GET /users/statistics
# =============================================================================


@router.get(
    "/statistics",
    response_model=UserStatisticsResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(users_read_permission),
    ],
)
async def get_user_statistics(
    request: Request,
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    service: UserManagementService = Depends(
        get_user_management_service,
    ),
) -> UserStatisticsResponse:

    try:
        result = await service.statistics(
            actor_user_id=principal.user_id,
            request_id=_get_request_id(request),
            source_ip=_get_source_ip(request),
        )

    except Exception as exc:
        _raise_user_management_error(
            exc,
        )

    return UserStatisticsResponse(
        total=result.total,
        active=result.active,
        disabled=result.disabled,
        locked=result.locked,
    )


# =============================================================================
# GET /users/{user_id}
# =============================================================================


@router.get(
    "/{user_id}",
    response_model=UserDetailResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(users_read_permission),
    ],
)
async def get_user(
    user_id: UUID,
    request: Request,
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    service: UserManagementService = Depends(
        get_user_management_service,
    ),
) -> UserDetailResponse:

    try:
        user = await service.get_user(
            actor_user_id=principal.user_id,
            user_id=user_id,
            request_id=_get_request_id(request),
            source_ip=_get_source_ip(request),
        )

    except Exception as exc:
        _raise_user_management_error(
            exc,
        )

    return _serialize_user_detail(
        user,
    )


# =============================================================================
# POST /users
# =============================================================================


@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(users_manage_permission),
    ],
)
async def create_user(
    payload: CreateUserRequest,
    request: Request,
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    service: UserManagementService = Depends(
        get_user_management_service,
    ),
) -> UserResponse:

    try:
        user = await service.create_user(
            actor_user_id=principal.user_id,
            username=payload.username,
            email=str(payload.email),
            password=payload.password,
            role=payload.role,
            is_active=payload.is_active,
            display_name=payload.display_name,
            request_id=_get_request_id(request),
            source_ip=_get_source_ip(request),
        )

    except Exception as exc:
        _raise_user_management_error(
            exc,
        )

    return _serialize_user(
        user,
    )


# =============================================================================
# PATCH /users/{user_id}
# =============================================================================


@router.patch(
    "/{user_id}",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(users_manage_permission),
    ],
)
async def update_user(
    user_id: UUID,
    payload: UpdateUserRequest,
    request: Request,
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    service: UserManagementService = Depends(
        get_user_management_service,
    ),
) -> UserResponse:

    try:
        user = await service.update_profile(
            actor_user_id=principal.user_id,
            user_id=user_id,
            username=payload.username,
            email=str(payload.email),
            display_name=payload.display_name,
            request_id=_get_request_id(request),
            source_ip=_get_source_ip(request),
        )

    except Exception as exc:
        _raise_user_management_error(
            exc,
        )

    return _serialize_user(
        user,
    )


# =============================================================================
# PATCH /users/{user_id}/role
# =============================================================================


@router.patch(
    "/{user_id}/role",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(users_manage_permission),
        Depends(roles_manage_permission),
    ],
)
async def change_user_role(
    user_id: UUID,
    payload: ChangeRoleRequest,
    request: Request,
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    service: UserManagementService = Depends(
        get_user_management_service,
    ),
) -> UserResponse:

    try:
        user = await service.change_role(
            actor_user_id=principal.user_id,
            user_id=user_id,
            role=payload.role,
            request_id=_get_request_id(request),
            source_ip=_get_source_ip(request),
        )

    except Exception as exc:
        _raise_user_management_error(
            exc,
        )

    return _serialize_user(
        user,
    )


# =============================================================================
# PATCH /users/{user_id}/active
# =============================================================================


@router.patch(
    "/{user_id}/active",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(users_manage_permission),
    ],
)
async def set_user_active(
    user_id: UUID,
    payload: SetActiveRequest,
    request: Request,
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    service: UserManagementService = Depends(
        get_user_management_service,
    ),
) -> UserResponse:

    try:
        user = await service.set_active(
            actor_user_id=principal.user_id,
            user_id=user_id,
            is_active=payload.is_active,
            request_id=_get_request_id(request),
            source_ip=_get_source_ip(request),
        )

    except Exception as exc:
        _raise_user_management_error(
            exc,
        )

    return _serialize_user(
        user,
    )


# =============================================================================
# PATCH /users/{user_id}/lock
# =============================================================================


@router.patch(
    "/{user_id}/lock",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(users_manage_permission),
    ],
)
async def set_user_locked(
    user_id: UUID,
    payload: SetLockedRequest,
    request: Request,
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    service: UserManagementService = Depends(
        get_user_management_service,
    ),
) -> UserResponse:

    try:
        user = await service.set_locked(
            actor_user_id=principal.user_id,
            user_id=user_id,
            is_locked=payload.is_locked,
            request_id=_get_request_id(request),
            source_ip=_get_source_ip(request),
        )

    except Exception as exc:
        _raise_user_management_error(
            exc,
        )

    return _serialize_user(
        user,
    )


# =============================================================================
# POST /users/{user_id}/password/reset
# =============================================================================


@router.post(
    "/{user_id}/password/reset",
    response_model=ResetPasswordResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(users_manage_permission),
    ],
)
async def reset_user_password(
    user_id: UUID,
    payload: ResetPasswordRequest,
    request: Request,
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    service: UserManagementService = Depends(
        get_user_management_service,
    ),
) -> ResetPasswordResponse:

    try:
        revoked_sessions = await service.reset_password(
            actor_user_id=principal.user_id,
            user_id=user_id,
            new_password=payload.new_password,
            request_id=_get_request_id(request),
            source_ip=_get_source_ip(request),
        )

    except Exception as exc:
        _raise_user_management_error(
            exc,
        )

    return ResetPasswordResponse(
        success=True,
        message="User password reset successfully.",
        sessions_revoked=revoked_sessions,
    )


# =============================================================================
# POST /users/{user_id}/sessions/revoke
# =============================================================================


@router.post(
    "/{user_id}/sessions/revoke",
    response_model=RevokeSessionsResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(users_manage_permission),
    ],
)
async def revoke_user_sessions(
    user_id: UUID,
    request: Request,
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    service: UserManagementService = Depends(
        get_user_management_service,
    ),
) -> RevokeSessionsResponse:

    try:
        revoked_count = await service.revoke_sessions(
            actor_user_id=principal.user_id,
            user_id=user_id,
            request_id=_get_request_id(request),
            source_ip=_get_source_ip(request),
        )

    except Exception as exc:
        _raise_user_management_error(
            exc,
        )

    return RevokeSessionsResponse(
        success=True,
        message="User sessions revoked successfully.",
        revoked_count=revoked_count,
    )


# =============================================================================
# GET /users/{user_id}/audit
# =============================================================================


@router.get(
    "/{user_id}/audit",
    response_model=UserActivityListResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(users_read_permission),
    ],
)
async def get_user_audit(
    user_id: UUID,
    request: Request,
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    audit_service: AuditService = Depends(
        get_audit_service,
    ),
    page: int = Query(
        default=DEFAULT_AUDIT_PAGE,
        ge=1,
        description="One-based page number.",
    ),
    page_size: int = Query(
        default=DEFAULT_AUDIT_PAGE_SIZE,
        ge=1,
        le=MAX_AUDIT_PAGE_SIZE,
        description="Number of audit events per page.",
    ),
    action: str | None = Query(
        default=None,
        max_length=MAX_ACTION_LENGTH,
    ),
    outcome: str | None = Query(
        default=None,
        max_length=MAX_OUTCOME_LENGTH,
    ),
    target_user_id: UUID | None = Query(
        default=None,
    ),
    source_ip: str | None = Query(
        default=None,
        max_length=MAX_SOURCE_IP_LENGTH,
    ),
    date_from: datetime | None = Query(
        default=None,
    ),
    date_to: datetime | None = Query(
        default=None,
    ),
) -> UserActivityListResponse:
    """
    Return Individual User Audit history together with
    backend-authoritative filtered statistics.

    Permission:

        users:read

    Canonical source:

        AuditService
            |
            v
        AuditRepository
            |
            v
        siem_auth_audit

    User association:

        actor_user_id = user_id
        OR
        target_user_id = user_id

    Supported filters:

        action
        outcome
        target_user_id
        source_ip
        date_from
        date_to

    Pagination:

        page
        page_size

    Response:

        activities
        total
        limit
        offset
        statistics

    Statistics are calculated against the complete filtered
    dataset, NOT the current page.

    Therefore, for example:

        page_size = 30
        total = 143

    statistics.total remains:

        143

    regardless of whether the request is:

        page=1
        page=2
        page=3
        page=4
        page=5

    The same filters are passed to both:

        AuditService.get_user_events()
        AuditService.get_user_statistics()

    This guarantees that the event list and statistic cards
    represent the same filtered dataset.
    """

    # Keep these dependencies explicit in the authenticated route
    # contract. Permission enforcement is handled by FastAPI dependencies.
    _ = principal
    _ = request

    _validate_date_range(
        date_from,
        date_to,
    )

    try:
        # ---------------------------------------------------------------------
        # Paginated filtered events
        # ---------------------------------------------------------------------

        events_result = await audit_service.get_user_events(
            user_id=user_id,
            page=page,
            page_size=page_size,
            action=action,
            outcome=outcome,
            target_user_id=target_user_id,
            source_ip=source_ip,
            date_from=date_from,
            date_to=date_to,
        )

        # ---------------------------------------------------------------------
        # Complete filtered statistics
        # ---------------------------------------------------------------------

        statistics_result = (
            await audit_service.get_user_statistics(
                user_id=user_id,
                action=action,
                outcome=outcome,
                target_user_id=target_user_id,
                source_ip=source_ip,
                date_from=date_from,
                date_to=date_to,
            )
        )

    except Exception as exc:
        _raise_audit_error(
            exc,
        )

    # =========================================================================
    # Normalize event service result
    # =========================================================================

    if isinstance(
        events_result,
        tuple,
    ):
        events = events_result[0]
        total = events_result[1]

    else:
        events = getattr(
            events_result,
            "events",
            getattr(
                events_result,
                "activities",
                [],
            ),
        )

        total = getattr(
            events_result,
            "total",
            len(events),
        )

    # =========================================================================
    # Normalize statistics
    # =========================================================================

    statistics = _serialize_user_audit_statistics(
        statistics_result,
    )

    # =========================================================================
    # Response
    # =========================================================================

    return UserActivityListResponse(
        activities=_serialize_audit_events(
            events,
        ),
        total=int(
            total,
        ),
        limit=page_size,
        offset=(page - 1) * page_size,
        statistics=statistics,
    )


# =============================================================================
# DELETE /users/{user_id}
# =============================================================================


@router.delete(
    "/{user_id}",
    response_model=DeleteUserResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(users_manage_permission),
    ],
)
async def delete_user(
    user_id: UUID,
    request: Request,
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    service: UserManagementService = Depends(
        get_user_management_service,
    ),
) -> DeleteUserResponse:

    try:
        await service.delete_user(
            actor_user_id=principal.user_id,
            user_id=user_id,
            request_id=_get_request_id(request),
            source_ip=_get_source_ip(request),
        )

    except Exception as exc:
        _raise_user_management_error(
            exc,
        )

    return DeleteUserResponse(
        success=True,
        message="User deleted successfully.",
    )


# =============================================================================
# Public Signup
# =============================================================================

# Intentionally absent.


# =============================================================================
# Public Exports
# =============================================================================


__all__ = [
    "router",
    "users_read_permission",
    "users_manage_permission",
    "roles_manage_permission",
]