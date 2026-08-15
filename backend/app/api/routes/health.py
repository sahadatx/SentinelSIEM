from __future__ import annotations

from fastapi import APIRouter, Request

from app.api.schemas.common import HealthResponse
from app.core.config import get_settings
from app.core.health import HealthStatus
from app.core.version import __version__

router = APIRouter(prefix="/health", tags=["health"])


@router.get("", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    settings = get_settings()
    return HealthResponse(**HealthStatus(status="ok", service=settings.app_name, version=__version__).as_dict())
