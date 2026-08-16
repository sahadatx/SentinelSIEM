from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.api.dependencies import (
    get_authentication_service,
    get_current_principal,
)
from app.auth.authentication import (
    AuthenticationError,
    AuthenticationService,
)
from app.auth.models import UserPrincipal


router = APIRouter(
    prefix="/auth",
    tags=["authentication"],
)


# ============================================================================
# Request / Response Schemas
# ============================================================================


class LoginRequest(BaseModel):
    """Credentials submitted to the authentication endpoint."""

    login: str = Field(
        ...,
        min_length=1,
        max_length=320,
        description="Username or email address.",
    )

    password: str = Field(
        ...,
        min_length=1,
        max_length=1024,
        description="Account password.",
    )


class UserResponse(BaseModel):
    """Authenticated user information returned by the API."""

    user_id: str
    username: str
    roles: list[str]
    permissions: list[str]
    session_id: str


class LoginResponse(BaseModel):
    """Successful authentication response."""

    access_token: str
    token_type: str = "bearer"
    user: UserResponse


# ============================================================================
# Internal Helpers
# ============================================================================


def _principal_to_response(
    principal: UserPrincipal,
) -> UserResponse:
    """Convert an authenticated principal into an API response."""

    return UserResponse(
        user_id=str(principal.user_id),
        username=principal.username,
        roles=sorted(principal.roles),
        permissions=sorted(principal.permissions),
        session_id=str(principal.session_id),
    )


def _request_ip(
    request: Request,
) -> str | None:
    """Return the direct client IP address when available."""

    client = request.client

    if client is None:
        return None

    return client.host


def _request_id(
    request: Request,
) -> str | None:
    """Return the request correlation ID when available."""

    return request.headers.get("X-Request-ID")


def _user_agent(
    request: Request,
) -> str | None:
    """Return the client user-agent when available."""

    return request.headers.get("user-agent")


# ============================================================================
# Login
# ============================================================================


@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate user",
    description=(
        "Authenticate a user with username/email and password and "
        "issue a JWT access token."
    ),
)
async def login(
    payload: LoginRequest,
    request: Request,
    authentication: AuthenticationService = Depends(
        get_authentication_service,
    ),
) -> LoginResponse:
    """Authenticate credentials and create an authenticated session."""

    try:
        result = await authentication.login(
            login=payload.login,
            password=payload.password,
            ip_address=_request_ip(request),
            user_agent=_user_agent(request),
            request_id=_request_id(request),
        )

    except AuthenticationError:
        # Do not reveal whether the account exists, is locked, inactive,
        # or whether the password itself was incorrect.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        ) from None

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
    description=(
        "Return the identity and RBAC information of the "
        "currently authenticated user."
    ),
)
async def me(
    principal: UserPrincipal = Depends(
        get_current_principal,
    ),
    authentication: AuthenticationService = Depends(
        get_authentication_service,
    ),
) -> UserResponse:
    """Return the current authenticated principal.

    The dependency validates the JWT and session before this endpoint
    executes. AuthenticationService is intentionally included here so
    the route remains compatible with the centralized authentication
    dependency configuration.
    """

    # `principal` has already been fully authenticated by
    # get_current_principal().
    #
    # Keep the authentication service dependency explicit so this route
    # remains coupled to the Phase 17 authentication composition root,
    # without duplicating token validation here.
    _ = authentication

    return _principal_to_response(
        principal,
    )


# ============================================================================
# Logout
# ============================================================================


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Logout current session",
    description=(
        "Revoke the current authenticated session so the "
        "associated access token can no longer be used."
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
    """Revoke the current authenticated session."""

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

    return None