from __future__ import annotations

from typing import Any

from fastapi import FastAPI

from app.core.config import get_settings
from app.core.health import HealthStatus
from app.core.version import __version__


def build_application(
    *,
    version: str = __version__,
    lifespan: Any = None,
) -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=version,
        docs_url="/docs" if settings.environment != "production" else None,
        redoc_url="/redoc" if settings.environment != "production" else None,
        lifespan=lifespan,
    )

    @app.get("/health/live", tags=["health"])
    async def live() -> dict[str, str]:
        return HealthStatus(
            status="ok",
            service=settings.app_name,
            version=version,
        ).as_dict()

    @app.get("/health/ready", tags=["health"])
    async def ready() -> dict[str, str]:
        return HealthStatus(
            status="ready",
            service=settings.app_name,
            version=version,
        ).as_dict()

    return app


app = build_application()
