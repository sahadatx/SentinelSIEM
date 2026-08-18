from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Any, AsyncIterator
from urllib.parse import urlparse

from fastapi import FastAPI

from app.api.dependencies import APIContainer
from app.api.middleware.metrics import MetricsMiddleware
from app.api.middleware.request_id import RequestIDMiddleware
from app.api.router import api_router
from app.api.routes.metrics import router as metrics_router
from app.api.websocket.bridge import RedisWebSocketBridge
from app.api.websocket.manager import ConnectionManager
from app.api.websocket.publisher import WebSocketPublisher
from app.auth.tokens import TokenService
from app.core.config import get_settings
from app.core.health import HealthStatus, readiness_status
from app.core.version import __version__
from app.mitre.service import MitreService
from app.storage.opensearch.client import OpenSearchClient
from app.storage.opensearch.events import OpenSearchEventRepository
from app.storage.postgres.session import PostgresSessionManager
from app.storage.redis.client import RedisClient


def _build_opensearch_repository(
    *,
    settings: Any,
) -> OpenSearchEventRepository | None:
    """
    Build the application-scoped OpenSearch event repository.

    The repository is created only when the required OpenSearch
    configuration is available. Tests and externally supplied
    API containers may provide their own repository instance.
    """
    if not settings.opensearch_configured:
        return None

    if not settings.opensearch_url:
        return None

    if not settings.opensearch_password:
        return None

    parsed = urlparse(settings.opensearch_url)

    if parsed.hostname is None:
        raise ValueError(
            "OpenSearch URL must contain a valid hostname."
        )

    scheme = parsed.scheme.lower()

    if scheme not in {"http", "https"}:
        raise ValueError(
            "OpenSearch URL must use the http or https scheme."
        )

    use_ssl = scheme == "https"

    client = OpenSearchClient(
        hosts=[
            {
                "host": parsed.hostname,
                "port": parsed.port or (
                    443 if use_ssl else 80
                ),
            }
        ],
        username=settings.opensearch_username,
        password=settings.opensearch_password,
        use_ssl=use_ssl,
        verify_certs=settings.opensearch_verify_certs,
        ca_certs=settings.opensearch_ca_certs,
    )

    return OpenSearchEventRepository(
        client._client,
    )


def build_application(
    *,
    version: str = __version__,
    lifespan: Any = None,
    api_container: APIContainer | None = None,
    websocket_manager: ConnectionManager | None = None,
    configure_database: bool = True,
) -> FastAPI:
    """
    Build and configure the SentinelSIEM FastAPI application.

    ``configure_database`` is enabled by default so existing runtime
    behavior remains unchanged. Tests can disable automatic PostgreSQL
    initialization when they need deterministic, dependency-free
    health checks.

    Application-scoped integrations are initialized here so API routes
    and the frontend access the same shared application dependencies.
    """
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=version,
        docs_url=(
            "/docs"
            if settings.environment != "production"
            else None
        ),
        redoc_url=(
            "/redoc"
            if settings.environment != "production"
            else None
        ),
        lifespan=None,
    )

    container = api_container or APIContainer()

    # ------------------------------------------------------------------
    # MITRE ATT&CK service
    # ------------------------------------------------------------------
    if container.mitre_service is None:
        container.mitre_service = MitreService()

    # ------------------------------------------------------------------
    # PostgreSQL lifecycle
    # ------------------------------------------------------------------
    if (
        configure_database
        and container.postgres_session_manager is None
        and settings.database_configured
    ):
        container.postgres_session_manager = (
            PostgresSessionManager(
                settings.database_url,
            )
        )

    # ------------------------------------------------------------------
    # OpenSearch event repository
    # ------------------------------------------------------------------
    if container.event_repository is None:
        container.event_repository = (
            _build_opensearch_repository(
                settings=settings,
            )
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
                minutes=settings.auth_access_token_expire_minutes,
            ),
        )

    # ------------------------------------------------------------------
    # Application state
    # ------------------------------------------------------------------
    app.state.api = container

    app.state.websocket_manager = (
        websocket_manager or ConnectionManager()
    )

    app.state.websocket_redis: RedisClient | None = None
    app.state.websocket_bridge: RedisWebSocketBridge | None = None
    app.state.websocket_publisher: WebSocketPublisher | None = None

    # ------------------------------------------------------------------
    # Realtime Redis integration
    # ------------------------------------------------------------------
    #
    # One application-scoped Redis client is used for realtime
    # publication and Pub/Sub bridge setup.
    #
    if settings.redis_url:
        websocket_redis = RedisClient(
            settings.redis_url,
        )

        websocket_publisher = WebSocketPublisher(
            websocket_redis,
        )

        websocket_bridge = RedisWebSocketBridge(
            redis=websocket_redis,
            manager=app.state.websocket_manager,
        )

        app.state.websocket_redis = websocket_redis
        app.state.websocket_publisher = websocket_publisher
        app.state.websocket_bridge = websocket_bridge

        # --------------------------------------------------------------
        # Realtime publisher dependency
        # --------------------------------------------------------------
        if container.websocket_publisher is None:
            container.websocket_publisher = (
                websocket_publisher
            )

        # --------------------------------------------------------------
        # Alert realtime wiring
        # --------------------------------------------------------------
        if container.alert_manager is not None:
            container.alert_manager.set_realtime_publisher(
                websocket_publisher.publish_alert,
            )

        # --------------------------------------------------------------
        # Incident realtime wiring
        # --------------------------------------------------------------
        if container.incident_manager is not None:
            container.incident_manager.set_realtime_publisher(
                websocket_publisher.publish_incident,
            )

    # ------------------------------------------------------------------
    # Application lifespan
    # ------------------------------------------------------------------
    @asynccontextmanager
    async def application_lifespan(
        application: FastAPI,
    ) -> AsyncIterator[None]:
        """
        Start and stop application-scoped realtime integrations.

        A caller-supplied lifespan is preserved and wrapped so existing
        startup/shutdown behavior remains compatible.
        """
        if lifespan is not None:
            async with lifespan(application):
                await _start_realtime_bridge(
                    application,
                )

                try:
                    yield
                finally:
                    await _stop_realtime_bridge(
                        application,
                    )

            return

        await _start_realtime_bridge(
            application,
        )

        try:
            yield
        finally:
            await _stop_realtime_bridge(
                application,
            )

    app.router.lifespan_context = application_lifespan

    # ------------------------------------------------------------------
    # Middleware
    # ------------------------------------------------------------------
    app.add_middleware(
        RequestIDMiddleware,
    )

    app.add_middleware(
        MetricsMiddleware,
    )

    # ------------------------------------------------------------------
    # API routers
    # ------------------------------------------------------------------
    app.include_router(
        api_router,
    )

    app.include_router(
        metrics_router,
    )

    # ------------------------------------------------------------------
    # Liveness
    # ------------------------------------------------------------------
    @app.get(
        "/health/live",
        tags=["health"],
    )
    async def live() -> dict[str, str]:
        return HealthStatus(
            status="ok",
            service=settings.app_name,
            version=version,
        ).as_dict()

    # ------------------------------------------------------------------
    # Readiness
    # ------------------------------------------------------------------
    @app.get(
        "/health/ready",
        tags=["health"],
    )
    async def ready() -> dict[str, object]:
        health = await readiness_status(
            service=settings.app_name,
            version=version,
            postgres=container.postgres_session_manager,
        )

        return health.as_dict()

    return app


async def _start_realtime_bridge(
    app: FastAPI,
) -> None:
    """Start the Redis-backed WebSocket bridge."""
    redis_client = getattr(
        app.state,
        "websocket_redis",
        None,
    )

    bridge = getattr(
        app.state,
        "websocket_bridge",
        None,
    )

    if redis_client is None or bridge is None:
        return

    await redis_client.ping()
    await bridge.start()


async def _stop_realtime_bridge(
    app: FastAPI,
) -> None:
    """Stop the Redis-backed WebSocket bridge."""
    bridge = getattr(
        app.state,
        "websocket_bridge",
        None,
    )

    redis_client = getattr(
        app.state,
        "websocket_redis",
        None,
    )

    if bridge is not None:
        await bridge.stop()

    if redis_client is not None:
        await redis_client.close()


app = build_application()