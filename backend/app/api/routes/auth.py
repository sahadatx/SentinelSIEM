from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from app.api.dependencies import (
    get_authentication_service,
    get_current_principal,
)
from app.auth.authentication import (
    AuthenticationError,
    AuthenticationService,
)
from app.auth.models import (
    SessionRecord,
    UserIdentity,
    UserPrincipal,
)

# ============================================================================
# Router
# ============================================================================

router = APIRouter(
    prefix="/auth",
    tags=["authentication"],
)


# ============================================================================
# Constants
# ============================================================================

MAX_LOGIN_LENGTH = 320
MAX_PASSWORD_LENGTH = 1024
MAX_REQUEST_ID_LENGTH = 128
MAX_USER_AGENT_LENGTH = 512
MAX_DISPLAY_NAME_LENGTH = 255


# ============================================================================
# Request Schemas
# ============================================================================


class LoginRequest(BaseModel):
    """
    Credentials submitted to the authentication endpoint.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    login: str = Field(
        ...,
        min_length=1,
        max_length=MAX_LOGIN_LENGTH,
        description="Username or email address.",
    )

    password: str = Field(
        ...,
        min_length=1,
        max_length=MAX_PASSWORD_LENGTH,
        description="Account password.",
    )


class UpdateProfileRequest(BaseModel):
    """
    Self-service profile update request.

    Only display_name can be changed through this endpoint.

    Security-sensitive account fields such as:

        - username
        - email
        - roles
        - active state
        - locked state
        - password state

    are deliberately excluded.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    display_name: str | None = Field(
        default=None,
        max_length=MAX_DISPLAY_NAME_LENGTH,
        description="User display name. Null clears the display name.",
    )


class ChangePasswordRequest(BaseModel):
    """
    Authenticated password-change request.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    current_password: str = Field(
        ...,
        min_length=1,
        max_length=MAX_PASSWORD_LENGTH,
        description="Current account password.",
    )

    new_password: str = Field(
        ...,
        min_length=1,
        max_length=MAX_PASSWORD_LENGTH,
        description="New account password.",
    )


# ============================================================================
# Response Schemas
# ============================================================================


class UserResponse(BaseModel):
    """
    Safe authenticated-user representation.

    Never exposes:

        - password hash
        - password_changed_at
        - force_password_change
        - failed_login_count
        - JWT
        - refresh token
        - token JTI
        - secrets
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    user_id: str
    username: str
    roles: list[str]
    permissions: list[str]
    session_id: str


class LoginResponse(BaseModel):
    """
    Successful authentication response.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class SessionResponse(BaseModel):
    """
    Safe server-side authentication-session representation.

    token_id/JTI is intentionally excluded.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    session_id: str
    user_id: str
    created_at: str
    expires_at: str
    revoked_at: str | None
    ip_address: str | None
    user_agent: str | None
    is_current: bool


class ActiveSessionsResponse(BaseModel):
    """
    Active sessions response.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    sessions: list[SessionResponse]
    count: int


class RevokeAllSessionsResponse(BaseModel):
    """
    Result of revoking all sessions.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    revoked_count: int


class PasswordChangeResponse(BaseModel):
    """
    Password-change result.

    The access token is deliberately NOT returned.

    Password changes revoke all sessions, including the current session,
    so the client must authenticate again using the new password.
    """

    model_config = ConfigDict(
        extra="forbid",
    )

    message: str
    revoked_sessions: int


# ============================================================================
# Internal Helpers
# ============================================================================


def _principal_to_response(
    principal: UserPrincipal,
) -> UserResponse:
    """
    Convert an authenticated domain principal into a safe API response.

    Domain objects are never returned directly through FastAPI.
    """

    return UserResponse(
        user_id=str(principal.user_id),
        username=principal.username,
        roles=sorted(str(role) for role in principal.roles),
        permissions=sorted(str(permission) for permission in principal.permissions),
        session_id=str(principal.session_id),
    )


def _session_to_response(
    session: SessionRecord,
    *,
    current_session_id: str | None = None,
) -> SessionResponse:
    """
    Convert an internal SessionRecord into a safe API representation.

    token_id/JTI is deliberately omitted.
    """

    return SessionResponse(
        session_id=str(session.session_id),
        user_id=str(session.user_id),
        created_at=session.created_at.isoformat(),
        expires_at=session.expires_at.isoformat(),
        revoked_at=(session.revoked_at.isoformat() if session.revoked_at is not None else None),
        ip_address=session.ip_address,
        user_agent=session.user_agent,
        is_current=(
            current_session_id is not None and str(session.session_id) == current_session_id
        ),
    )


def _request_ip(
    request: Request,
) -> str | None:
    """
    Return the direct client IP.

    X-Forwarded-For is intentionally not trusted here.

    Trusted proxy handling belongs to the infrastructure/middleware layer.
    """

    client = request.client

    if client is None:
        return None

    host = client.host.strip()

    return host or None


def _request_id(
    request: Request,
) -> str | None:
    """
    Return a bounded request correlation identifier.
    """

    value = request.headers.get(
        "X-Request-ID",
    )

    if value is None:
        return None

    normalized = value.strip()

    if not normalized:
        return None

    return normalized[:MAX_REQUEST_ID_LENGTH]


def _user_agent(
    request: Request,
) -> str | None:
    """
    Return a bounded User-Agent value.
    """

    value = request.headers.get(
        "User-Agent",
    )

    if value is None:
        return None

    normalized = value.strip()

    if not normalized:
        return None

    return normalized[:MAX_USER_AGENT_LENGTH]


def _authentication_failure() -> HTTPException:
    """
    Canonical public authentication failure.

    Deliberately does not disclose whether the failure was caused by:

        - unknown account
        - invalid password
        - inactive account
        - locked account
        - automatic lockout
        - invalid session
        - invalid JWT
    """

    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials.",
        headers={
            "WWW-Authenticate": "Bearer",
        },
    )


def _authentication_service_unavailable() -> HTTPException:
    """
    Generic authentication-service failure.
    """

    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Authentication service unavailable.",
    )


def _profile_update_failure() -> HTTPException:
    """
    Generic profile-update failure.
    """

    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Unable to update profile.",
    )


def _password_change_failure() -> HTTPException:
    """
    Generic password-change failure.

    Does not expose whether the current password was incorrect,
    account state was invalid, or password persistence failed.
    """

    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Unable to change password.",
    )


# ============================================================================
# Login
# ============================================================================


@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate user",
    description=(
        "Authenticate a user with username/email and password and issue a JWT access token."
    ),
)
async def login(
    payload: LoginRequest,
    request: Request,
    authentication: AuthenticationService = Depends(
        get_authentication_service,
    ),
) -> LoginResponse:
    """
    Authenticate credentials and create an authenticated session.

    Public security behavior:

        - Invalid credentials return generic 401.
        - Account existence is not disclosed.
        - Account lock state is not disclosed.
        - Account activation state is not disclosed.
        - Password verification details are not disclosed.
    """

    try:
        result = await authentication.login(
            login=payload.login,
            password=payload.password,
            ip_address=_request_ip(request),
            user_agent=_user_agent(request),
            request_id=_request_id(request),
        )

    except AuthenticationError:
        raise _authentication_failure() from None

    except Exception:
        raise _authentication_service_unavailable() from None

    return LoginResponse(
        access_token=result.access_token,
        token_type="bearer",
        user=_principal_to_response(
            result.principal,
        ),
    )


# ============================================================================
# Current Authenticated User
# ============================================================================


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current user",
    description=("Return the identity and current RBAC information of the authenticated user."),
)
async def me(
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
) -> UserResponse:
    """
    Return the current authenticated principal.

    Authentication is delegated to get_current_principal().
    """

    return _principal_to_response(
        principal,
    )


# ============================================================================
# Update Current User
# ============================================================================


@router.patch(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Update current user profile",
    description=("Update self-service profile information for the current authenticated user."),
)
async def update_me(
    payload: UpdateProfileRequest,
    request: Request,
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    authentication: AuthenticationService = Depends(
        get_authentication_service,
    ),
) -> UserResponse:
    """
    Update the authenticated user's profile.

    Only display_name can be changed.
    """

    try:
        updated_user: UserIdentity = await authentication.update_current_user(
            principal=principal,
            display_name=payload.display_name,
            request_id=_request_id(request),
            ip_address=_request_ip(request),
        )

    except AuthenticationError:
        raise _profile_update_failure() from None

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to update profile.",
        ) from None

    # ------------------------------------------------------------------------
    # Important:
    #
    # update_current_user() returns UserIdentity, but UserResponse requires
    # current RBAC state and current session ID.
    #
    # Therefore rebuild the safe response from the authenticated principal
    # and the updated identity.
    # ------------------------------------------------------------------------

    permissions = authentication._roles.permissions_for(
        updated_user.roles,
    )

    updated_principal = UserPrincipal(
        user_id=updated_user.user_id,
        username=updated_user.username,
        roles=frozenset(updated_user.roles),
        permissions=permissions,
        session_id=principal.session_id,
    )

    return _principal_to_response(
        updated_principal,
    )


# ============================================================================
# Change Current Password
# ============================================================================


@router.post(
    "/me/password",
    response_model=PasswordChangeResponse,
    status_code=status.HTTP_200_OK,
    summary="Change current password",
    description=(
        "Change the authenticated user's password. All existing "
        "authentication sessions are revoked after a successful change."
    ),
)
async def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    authentication: AuthenticationService = Depends(
        get_authentication_service,
    ),
) -> PasswordChangeResponse:
    """
    Change the current authenticated user's password.

    Security behavior:

        - Current password is verified.
        - New password is never returned.
        - Password hash is never returned.
        - All existing sessions are revoked.
        - Current session is also revoked.
        - Client must log in again using the new password.
    """

    try:
        revoked_count = await authentication.change_current_password(
            principal=principal,
            current_password=payload.current_password,
            new_password=payload.new_password,
            request_id=_request_id(request),
            ip_address=_request_ip(request),
        )

    except AuthenticationError:
        raise _password_change_failure() from None

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to change password.",
        ) from None

    return PasswordChangeResponse(
        message=("Password changed successfully. Please authenticate again."),
        revoked_sessions=revoked_count,
    )


# ============================================================================
# Active Sessions
# ============================================================================


@router.get(
    "/me/sessions",
    response_model=ActiveSessionsResponse,
    status_code=status.HTTP_200_OK,
    summary="List active sessions",
    description=(
        "Return the currently active authentication sessions belonging to the authenticated user."
    ),
)
async def active_sessions(
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    authentication: AuthenticationService = Depends(
        get_authentication_service,
    ),
) -> ActiveSessionsResponse:
    """
    List active sessions for the authenticated user.

    token_id/JTI is never exposed.
    """

    try:
        sessions = await authentication.list_active_sessions(
            principal.user_id,
        )

    except AuthenticationError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to retrieve authentication sessions.",
        ) from None

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to retrieve authentication sessions.",
        ) from None

    current_session_id = str(
        principal.session_id,
    )

    response_sessions = [
        _session_to_response(
            session,
            current_session_id=current_session_id,
        )
        for session in sessions
    ]

    return ActiveSessionsResponse(
        sessions=response_sessions,
        count=len(response_sessions),
    )


# ============================================================================
# Revoke All Sessions
# ============================================================================


@router.post(
    "/me/sessions/revoke-all",
    response_model=RevokeAllSessionsResponse,
    status_code=status.HTTP_200_OK,
    summary="Revoke all current-user sessions",
    description=("Revoke all active authentication sessions belonging to the authenticated user."),
)
async def revoke_all_sessions(
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    authentication: AuthenticationService = Depends(
        get_authentication_service,
    ),
) -> RevokeAllSessionsResponse:
    """
    Revoke every active session belonging to the current user.

    This includes the current session.
    """

    try:
        count = await authentication.revoke_all_sessions(
            principal.user_id,
        )

    except AuthenticationError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to revoke authentication sessions.",
        ) from None

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to revoke authentication sessions.",
        ) from None

    return RevokeAllSessionsResponse(
        revoked_count=count,
    )


# ============================================================================
# Logout
# ============================================================================


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Logout current session",
    description=(
        "Revoke the current authenticated session so the associated "
        "access token can no longer be used."
    ),
)
async def logout(
    request: Request,
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    authentication: AuthenticationService = Depends(
        get_authentication_service,
    ),
) -> None:
    """
    Revoke the current authenticated session.
    """

    try:
        await authentication.logout(
            principal,
            request_id=_request_id(request),
            ip_address=_request_ip(request),
        )

    except AuthenticationError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to complete logout.",
        ) from None

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to complete logout.",
        ) from None

    return None


# ============================================================================
# Public Exports
# ============================================================================


__all__ = [
    "router",
    "LoginRequest",
    "UpdateProfileRequest",
    "ChangePasswordRequest",
    "LoginResponse",
    "UserResponse",
    "SessionResponse",
    "ActiveSessionsResponse",
    "RevokeAllSessionsResponse",
    "PasswordChangeResponse",
]
