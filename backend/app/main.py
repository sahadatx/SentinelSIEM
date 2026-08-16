from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi import FastAPI

from app.api.dependencies import APIContainer
from app.api.middleware.request_id import RequestIDMiddleware
from app.api.router import api_router
from app.api.websocket.manager import ConnectionManager
from app.core.config import get_settings
from app.core.health import HealthStatus
from app.core.version import __version__
from app.auth.tokens import TokenService
from app.storage.postgres.session import PostgresSessionManager


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

    container = api_container or APIContainer()

    # ------------------------------------------------------------------
    # PostgreSQL lifecycle
    # ------------------------------------------------------------------
    if (
        container.postgres_session_manager is None
        and settings.database_configured
    ):
        container.postgres_session_manager = PostgresSessionManager(
            settings.database_url
        )

    # ------------------------------------------------------------------
    # Authentication token service
    # ------------------------------------------------------------------
    if (
        container.token_service is None
        and settings.authentication_configured
    ):
        container.token_service = TokenService(
            secret_key=settings.auth_secret_key,
            issuer=settings.auth_issuer,
            audience=settings.auth_audience,
            algorithm=settings.auth_algorithm,
            ttl=timedelta(
                minutes=settings.auth_access_token_expire_minutes
            ),
        )

    app.state.api = container
    app.state.websocket_manager = (
        websocket_manager or ConnectionManager()
    )

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
