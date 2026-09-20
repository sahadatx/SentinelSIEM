from __future__ import annotations

from fastapi import APIRouter


# ============================================================================
# Router
# ============================================================================

router = APIRouter(
    tags=["platform"],
)


# ============================================================================
# Asset Capability
# ============================================================================


@router.get(
    "/assets",
    summary="Asset management capability",
)
def assets() -> dict[str, str]:
    """
    Return the availability status of asset management.

    Asset management backend capabilities include:

        - asset creation
        - asset listing
        - asset retrieval
        - asset updates
        - asset deletion
        - asset statistics
        - asset filtering
    """

    return {
        "resource": "assets",
        "status": "available",
        "message": (
            "Asset management is available through the SentinelSIEM "
            "asset management API."
        ),
    }


# ============================================================================
# Role Management Capability
# ============================================================================


@router.get(
    "/roles",
    summary="Role management capability",
)
def roles() -> dict[str, str]:
    """
    Return the availability status of role-based access control.
    """

    return {
        "resource": "roles",
        "status": "available",
        "message": (
            "Role-based access control is available through the "
            "Phase 17 authorization and RBAC subsystem."
        ),
    }


# ============================================================================
# Authentication Capability
# ============================================================================


@router.get(
    "/auth",
    summary="Authentication capability",
)
def auth() -> dict[str, str]:
    """
    Return the availability status of authentication.
    """

    return {
        "resource": "auth",
        "status": "available",
        "message": (
            "Authentication is available through the Phase 17 "
            "JWT-based authentication and session management subsystem."
        ),
    }


# ============================================================================
# Dashboard Capability
# ============================================================================


@router.get(
    "/dashboard",
    summary="Dashboard capability",
)
def dashboard() -> dict[str, str]:
    """
    Return the availability status of the dashboard API.
    """

    return {
        "resource": "dashboard",
        "status": "available",
        "message": (
            "Dashboard aggregation API surface is available; "
            "frontend implementation is provided by the dashboard."
        ),
    }


# ============================================================================
# Public Exports
# ============================================================================


__all__ = [
    "router",
    "assets",
    "roles",
    "auth",
    "dashboard",
]