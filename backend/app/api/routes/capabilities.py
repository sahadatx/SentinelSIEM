from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.dependencies import require_permission
from app.api.schemas.stubs import CapabilityResponse


router = APIRouter(
    tags=["platform"],
)


# ============================================================================
# Detection Capability
# ============================================================================


@router.get(
    "/detections",
    response_model=CapabilityResponse,
    summary="Detection capability",
)
def detections() -> CapabilityResponse:
    """Return the availability status of the detection API capability."""

    return CapabilityResponse(
        resource="detections",
        status="available",
        message=(
            "Detection API contract is reserved for the detection "
            "service integration."
        ),
    )


# ============================================================================
# Asset Capability
# ============================================================================


@router.get(
    "/assets",
    response_model=CapabilityResponse,
    summary="Asset capability",
)
def assets() -> CapabilityResponse:
    """Return the availability status of asset management."""

    return CapabilityResponse(
        resource="assets",
        status="planned",
        message=(
            "Asset management is not implemented before its dedicated "
            "platform capability is available."
        ),
    )


# ============================================================================
# User Management Capability
# ============================================================================


@router.get(
    "/users",
    response_model=CapabilityResponse,
    summary="User management capability",
    dependencies=[
        Depends(require_permission("users:read")),
    ],
)
def users() -> CapabilityResponse:
    """Return the availability status of user management."""

    return CapabilityResponse(
        resource="users",
        status="available",
        message=(
            "User identity infrastructure is available through the "
            "Phase 17 authentication and RBAC subsystem."
        ),
    )


# ============================================================================
# Role Management Capability
# ============================================================================


@router.get(
    "/roles",
    response_model=CapabilityResponse,
    summary="Role management capability",
    dependencies=[
        Depends(require_permission("roles:read")),
    ],
)
def roles() -> CapabilityResponse:
    """Return the availability status of role-based access control."""

    return CapabilityResponse(
        resource="roles",
        status="available",
        message=(
            "Role-based access control is available through the "
            "Phase 17 authorization and RBAC subsystem."
        ),
    )


# ============================================================================
# Authentication Capability
# ============================================================================


@router.get(
    "/auth",
    response_model=CapabilityResponse,
    summary="Authentication capability",
)
def auth() -> CapabilityResponse:
    """Return the availability status of authentication."""

    return CapabilityResponse(
        resource="auth",
        status="available",
        message=(
            "Authentication is available through the Phase 17 "
            "JWT-based authentication and session management subsystem."
        ),
    )


# ============================================================================
# Dashboard Capability
# ============================================================================


@router.get(
    "/dashboard",
    response_model=CapabilityResponse,
    summary="Dashboard capability",
)
def dashboard() -> CapabilityResponse:
    """Return the availability status of the dashboard API."""

    return CapabilityResponse(
        resource="dashboard",
        status="available",
        message=(
            "Dashboard aggregation API surface is available; "
            "frontend implementation is provided by the dashboard."
        ),
    )
