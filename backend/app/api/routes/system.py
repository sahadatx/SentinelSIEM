from __future__ import annotations

from fastapi import APIRouter

from app.api.schemas.system import SystemResponse
from app.core.config import get_settings
from app.system.service import SystemService

router = APIRouter(
    prefix="/system",
    tags=["system"],
)


@router.get(
    "",
    response_model=SystemResponse,
    summary="Get system information",
    description="Return SentinelSIEM system metadata and supported capabilities.",
)
def system() -> SystemResponse:
    """Return SentinelSIEM system information."""

    service = SystemService(get_settings())
    info = service.get_system_info()

    return SystemResponse(
        service=info.service,
        version=info.version,
        environment=info.environment,
        capabilities=list(info.capabilities),
    )
