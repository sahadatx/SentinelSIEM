from __future__ import annotations

from typing import Any

from fastapi import FastAPI

from app.api.dependencies import APIContainer
from app.api.middleware.request_id import RequestIDMiddleware
from app.api.router import api_router
from app.api.websocket.manager import ConnectionManager
from app.core.config import get_settings
from app.core.health import HealthStatus
from app.core.version import __version__


def build_application(
    *,
    version: str = __version__,
    lifespan: Any = None,
    api_container: APIContainer | None = None,
    websocket_manager: ConnectionManager | None = None,
) -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=version,
        docs_url="/docs" if settings.environment != "production" else None,
        redoc_url="/redoc" if settings.environment != "production" else None,
        lifespan=lifespan,
    )

    app.state.api = api_container or APIContainer()
    app.state.websocket_manager = websocket_manager or ConnectionManager()
    app.add_middleware(RequestIDMiddleware)
    app.include_router(api_router)

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
