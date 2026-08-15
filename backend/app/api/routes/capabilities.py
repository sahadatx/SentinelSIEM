from __future__ import annotations

from fastapi import APIRouter

from app.api.schemas.stubs import CapabilityResponse

router = APIRouter(tags=["platform"])


@router.get("/detections", response_model=CapabilityResponse)
def detections() -> CapabilityResponse:
    return CapabilityResponse(resource="detections", status="available", message="Detection API contract is reserved for the detection service integration.")


@router.get("/assets", response_model=CapabilityResponse)
def assets() -> CapabilityResponse:
    return CapabilityResponse(resource="assets", status="planned", message="Asset management is not implemented before its dedicated platform capability is available.")


@router.get("/users", response_model=CapabilityResponse)
def users() -> CapabilityResponse:
    return CapabilityResponse(resource="users", status="planned", message="Identity management belongs to the authentication/RBAC phase.")


@router.get("/roles", response_model=CapabilityResponse)
def roles() -> CapabilityResponse:
    return CapabilityResponse(resource="roles", status="planned", message="Role management belongs to the authentication/RBAC phase.")


@router.get("/auth", response_model=CapabilityResponse)
def auth() -> CapabilityResponse:
    return CapabilityResponse(resource="auth", status="planned", message="Authentication is intentionally deferred to the authentication/RBAC phase.")


@router.get("/dashboard", response_model=CapabilityResponse)
def dashboard() -> CapabilityResponse:
    return CapabilityResponse(resource="dashboard", status="available", message="Dashboard aggregation API surface is available; frontend implementation is a later phase.")
