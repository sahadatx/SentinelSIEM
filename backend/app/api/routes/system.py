from __future__ import annotations

from fastapi import APIRouter

from app.api.schemas.common import SystemResponse
from app.core.config import get_settings
from app.core.version import __version__

router = APIRouter(prefix="/system", tags=["system"])


@router.get("", response_model=SystemResponse)
def system() -> SystemResponse:
    settings = get_settings()
    return SystemResponse(
        service=settings.app_name,
        version=__version__,
        environment=settings.environment,
        capabilities=["api", "websocket", "events", "alerts", "incidents", "threat-intelligence", "mitre"],
    )
