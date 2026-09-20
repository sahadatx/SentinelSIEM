"""
SentinelSIEM Application Entry Point
=====================================

Application bootstrap and composition boundary for SentinelSIEM.

Responsibilities
----------------

- Create and configure the FastAPI application.
- Build application-scoped dependencies.
- Configure middleware.
- Configure application lifecycle.
- Initialize optional external integrations.
- Initialize the application-scoped detection runtime.
- Initialize the application-scoped MITRE mapping runtime.
- Register the centralized top-level API router.
- Register application-level metrics routes.
- Register application-level health endpoints.
- Serve the built SentinelSIEM frontend in production.

Architecture
------------

    Browser
        |
        v
    Application Entry Point
        |
        +-- FastAPI API
        |
        +-- React Frontend
        |
        +-- /api/v1/*
        |
        +-- /ws
        |
        +-- Health
        |
        +-- Metrics
        |
        +-- PostgreSQL
        |
        +-- OpenSearch
        |
        +-- Redis / WebSocket


Development
-----------

Development frontend serving is handled by the Vite development
server. The FastAPI application remains the backend application
boundary.

The development environment is intended to provide:

    Edit -> Save -> Browser Refresh

The browser-facing development entrypoint is:

    http://localhost:8000

Vite provides the frontend development server and proxies API and
WebSocket requests to the FastAPI backend.

The built frontend under:

    frontend/dist

is intentionally served by FastAPI only when the application runs
outside the development environment.


Production
----------

Production serves the built React frontend from:

    frontend/dist

The frontend is mounted after the API, metrics, and health routes
so application routes retain their existing precedence.


Detection Architecture
----------------------

Application startup initializes one shared detection runtime:

    rules/detection/*.yaml
            |
            v
    DetectionRuleRegistry
            |
            +-----------------------+
            |                       |
            v                       v
    DetectionService        DetectionEngine

    backend/plugins/detectors/*/plugin.py
            |
            v
    DetectorPluginRegistry
            |
            +-----------------------+
            |                       |
            v                       v
    DetectionService        DetectionEngine

The DetectionService and DetectionEngine MUST share the same
rule and plugin registries.

Event evaluation is NOT performed by this module.

Worker/event-processing integration belongs to the detection
execution phase.


MITRE ATT&CK Architecture
-------------------------

MITRE has two intentionally separate concerns.

1. MITRE ATT&CK Knowledge

    enterprise-attack.json
            |
            v
       MITRE Importer
            |
            v
       PostgreSQL
            |
            v
       MitreRepository
            |
            v
       MitreService
            |
            v
       MITRE API
            |
            v
       Read-only MITRE UI

The PostgreSQL-backed MITRE knowledge domain contains:

    Tactics
    Techniques
    Sub-Techniques
    Platforms
    References
    Relationships
    Detection guidance
    Mitigations

The dataset importer is responsible for initial population and
subsequent synchronization.

2. SentinelSIEM Detection -> MITRE Mapping

    Detection
        |
        v
    MITRE Mapping Registry
        |
        v
    MitreManager
        |
        v
    OpenSearch
        |
        v
    siem-mitre-mappings-v1

This runtime is application-scoped because detection mappings are
operational SentinelSIEM intelligence rather than authoritative
MITRE ATT&CK knowledge.

An application restart restores persisted Detection -> MITRE
mappings from OpenSearch before the API begins serving requests.

The application entry point does NOT treat the legacy in-memory
MITRE catalogs as the authoritative MITRE knowledge source.


Dependency Injection
--------------------

An explicitly supplied APIContainer is treated as an authoritative
dependency-injection boundary.

When:

    build_application(api_container=...)

is called, the application MUST NOT silently construct external
integrations such as:

    - PostgreSQL
    - OpenSearch
    - Redis
    - MITRE mapping OpenSearch runtime
    - Detection runtime

Detection runtime state is treated the same way: an explicitly
supplied detection service/engine is preserved.

Production startup may automatically construct configured
application dependencies when no explicit container is supplied.


Audit Architecture
------------------

Audit is a first-class centralized application domain.

There is exactly one canonical Global Audit router:

    app.audit.routes

Global Audit is registered through the versioned API composition layer:

    app.main
        ->
    app.api.router
        ->
    app.api.versioning.v1
        ->
    app.audit.routes

Therefore:

    /api/v1/audit
    /api/v1/audit/{audit_id}
    /api/v1/audit/{audit_id}/related
    /api/v1/audit/export

are registered only through the v1 router.

Individual User Audit remains part of User Management:

    app.api.routes.users
        ->
    /api/v1/users/{user_id}/audit


Transaction Ownership
---------------------

This module does not own individual database transactions.

Repository and service layers remain responsible for their respective
transaction boundaries.


Security
--------

This module:

- does not implement authentication
- does not implement authorization
- does not expose credentials
- does not persist audit records directly
- does not create JWT contents
- does not serialize passwords or password hashes
- does not bypass feature-level authorization

Sensitive configuration values are passed only to their respective
internal services.


Application Lifecycle
---------------------

The application lifespan manages application-scoped resources.

Startup order:

1. MITRE mapping runtime hydration
2. Redis connectivity check
3. WebSocket bridge startup

Shutdown order:

1. WebSocket bridge shutdown
2. Redis client shutdown
3. MITRE mapping runtime shutdown

A caller-supplied lifespan is preserved and wrapped.


Health
------

Liveness:

    GET /health/live

Readiness:

    GET /health/ready

Readiness reports PostgreSQL application readiness through the
existing centralized health subsystem.


Frontend
--------

Development:

    Vite development server

Production:

    frontend/dist

The production frontend is mounted after the API, metrics, and health
routes so application routes retain their existing behavior.


Public API
----------

The module exposes:

    build_application
    app
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

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
from app.detection.bootstrap import build_detection_runtime
from app.storage.opensearch.client import OpenSearchClient
from app.storage.opensearch.events import OpenSearchEventRepository
from app.storage.postgres.session import PostgresSessionManager
from app.storage.redis.client import RedisClient


# ============================================================================
# Project Paths
# ============================================================================


def _project_root() -> Path:
    """
    Return the SentinelSIEM project root.

    backend/app/main.py
        |
        +-- parents[0] -> backend/app
        +-- parents[1] -> backend
        +-- parents[2] -> project root
    """

    return Path(__file__).resolve().parents[2]


def _frontend_dist_directory() -> Path:
    """
    Return the built frontend distribution directory.
    """

    return _project_root() / "frontend" / "dist"


# ============================================================================
# OpenSearch Repository Construction
# ============================================================================


def _build_opensearch_repository(
    *,
    settings: Any,
) -> OpenSearchEventRepository | None:
    """
    Build the application-scoped OpenSearch event repository.

    OpenSearch is initialized only when the required application
    configuration is available.

    The event index is selected through centralized application
    configuration:

        settings.opensearch_event_index

    Returns
    -------
    OpenSearchEventRepository | None
        Configured repository when OpenSearch is available and configured.

    Raises
    ------
    ValueError
        If the configured OpenSearch URL is invalid.
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
            "OpenSearch URL must contain a valid hostname.",
        )

    scheme = parsed.scheme.lower()

    if scheme not in {"http", "https"}:
        raise ValueError(
            "OpenSearch URL must use the http or https scheme.",
        )

    use_ssl = scheme == "https"

    client = OpenSearchClient(
        hosts=[
            {
                "host": parsed.hostname,
                "port": parsed.port or (
                    443 if use_ssl else 80
                ),
            },
        ],
        username=settings.opensearch_username,
        password=settings.opensearch_password,
        use_ssl=use_ssl,
        verify_certs=settings.opensearch_verify_certs,
        ca_certs=settings.opensearch_ca_certs,
    )

    return OpenSearchEventRepository(
        client._client,
        index=settings.opensearch_event_index,
    )


# ============================================================================
# Detection Runtime Construction
# ============================================================================


def _build_detection_runtime(
    *,
    application: FastAPI,
    container: APIContainer,
    supplied_api_container: bool,
) -> None:
    """
    Initialize the application-scoped detection runtime.

    A caller-supplied APIContainer is authoritative and prevents
    automatic construction of the detection runtime.

    Detection assets are resolved relative to the project root.

    Runtime assets:

        rules/detection
        backend/plugins/detectors
    """

    if supplied_api_container:
        return

    if (
        container.detection_service is not None
        or container.detection_engine is not None
    ):
        return

    project_root = _project_root()

    rules_directory = (
        project_root
        / "rules"
        / "detection"
    )

    plugins_directory = (
        project_root
        / "backend"
        / "plugins"
        / "detectors"
    )

    runtime = build_detection_runtime(
        rules_directory=rules_directory,
        plugins_directory=plugins_directory,
    )

    container.detection_service = runtime.detection_service
    container.detection_engine = runtime.detection_engine

    application.state.detection_runtime = runtime


# ============================================================================
# Frontend Registration
# ============================================================================


def _register_frontend(
    *,
    application: FastAPI,
    settings: Any,
) -> None:
    """
    Register the built React frontend for non-development environments.

    Development frontend serving is intentionally delegated to Vite.
    """

    if settings.environment == "development":
        return

    frontend_dist = _frontend_dist_directory()

    if not frontend_dist.is_dir():
        return

    index_file = frontend_dist / "index.html"

    if not index_file.is_file():
        return

    application.mount(
        "/",
        StaticFiles(
            directory=str(frontend_dist),
            html=True,
        ),
        name="frontend",
    )


# ============================================================================
# Application Factory
# ============================================================================


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

    Dependency behavior
    -------------------

    When api_container is not supplied:

        Configured application dependencies may be initialized
        automatically.

    When api_container is supplied:

        The supplied dependency state is authoritative.

        Missing external integrations are NOT automatically created.

    Parameters
    ----------
    version:
        Application version exposed by FastAPI.

    lifespan:
        Optional caller-provided lifespan context.

    api_container:
        Optional application dependency container.

    websocket_manager:
        Optional externally supplied WebSocket connection manager.

    configure_database:
        Controls automatic PostgreSQL initialization for an
        application-owned dependency container.

    Returns
    -------
    FastAPI
        Fully configured SentinelSIEM application.
    """

    settings = get_settings()

    # ------------------------------------------------------------------------
    # FastAPI Application
    # ------------------------------------------------------------------------

    application = FastAPI(
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

    # ------------------------------------------------------------------------
    # Dependency Container Ownership
    # ------------------------------------------------------------------------

    supplied_api_container = api_container is not None

    container = (
        api_container
        if api_container is not None
        else APIContainer()
    )

    # ------------------------------------------------------------------------
    # Detection Runtime
    # ------------------------------------------------------------------------

    _build_detection_runtime(
        application=application,
        container=container,
        supplied_api_container=supplied_api_container,
    )

    # ------------------------------------------------------------------------
    # PostgreSQL Lifecycle
    # ------------------------------------------------------------------------

    if (
        not supplied_api_container
        and configure_database
        and container.postgres_session_manager is None
        and settings.database_configured
    ):
        container.postgres_session_manager = PostgresSessionManager(
            settings.database_url,
        )

    # ------------------------------------------------------------------------
    # OpenSearch Event Repository
    # ------------------------------------------------------------------------

    if (
        not supplied_api_container
        and container.event_repository is None
    ):
        container.event_repository = _build_opensearch_repository(
            settings=settings,
        )

    # ------------------------------------------------------------------------
    # Authentication Token Service
    # ------------------------------------------------------------------------

    if (
        not supplied_api_container
        and container.token_service is None
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

    # ------------------------------------------------------------------------
    # Application State
    # ------------------------------------------------------------------------

    application.state.api = container

    application.state.websocket_manager = (
        websocket_manager
        if websocket_manager is not None
        else ConnectionManager()
    )

    application.state.websocket_redis: RedisClient | None = None
    application.state.websocket_bridge: RedisWebSocketBridge | None = None
    application.state.websocket_publisher: WebSocketPublisher | None = None

    # ------------------------------------------------------------------------
    # Redis / WebSocket Realtime Integration
    # ------------------------------------------------------------------------

    if (
        not supplied_api_container
        and settings.redis_url
    ):
        websocket_redis = RedisClient(
            settings.redis_url,
        )

        websocket_publisher = WebSocketPublisher(
            websocket_redis,
        )

        websocket_bridge = RedisWebSocketBridge(
            redis=websocket_redis,
            manager=application.state.websocket_manager,
        )

        application.state.websocket_redis = websocket_redis
        application.state.websocket_publisher = websocket_publisher
        application.state.websocket_bridge = websocket_bridge

        # --------------------------------------------------------------------
        # Realtime Publisher Dependency
        # --------------------------------------------------------------------

        if container.websocket_publisher is None:
            container.websocket_publisher = websocket_publisher

        # --------------------------------------------------------------------
        # Alert Realtime Wiring
        # --------------------------------------------------------------------

        if container.alert_manager is not None:
            container.alert_manager.set_realtime_publisher(
                websocket_publisher.publish_alert,
            )

        # --------------------------------------------------------------------
        # Incident Realtime Wiring
        # --------------------------------------------------------------------

        if container.incident_manager is not None:
            container.incident_manager.set_realtime_publisher(
                websocket_publisher.publish_incident,
            )

    # ------------------------------------------------------------------------
    # Application Lifespan
    # ------------------------------------------------------------------------

    @asynccontextmanager
    async def application_lifespan(
        app_instance: FastAPI,
    ) -> AsyncIterator[None]:
        """
        Manage application-scoped resources.

        Startup sequence:

            MITRE mapping runtime hydration
                |
                v
            Redis / WebSocket startup
                |
                v
            Application ready

        Shutdown sequence:

            WebSocket shutdown
                |
                v
            MITRE mapping runtime shutdown

        MITRE ATT&CK knowledge itself is PostgreSQL-backed and is
        accessed through the MITRE repository/service dependency chain.
        Dataset synchronization is performed by the dedicated MITRE
        importer/CLI and is not performed on every application startup.
        """

        mitre_initialized = False

        try:
            # ----------------------------------------------------------------
            # MITRE Detection-Mapping Runtime
            # ----------------------------------------------------------------
            #
            # This initializes the SentinelSIEM Detection -> MITRE mapping
            # runtime backed by OpenSearch.
            #
            # It does NOT load the authoritative MITRE ATT&CK knowledge
            # catalog. That knowledge is maintained by:
            #
            #     enterprise-attack.json
            #             |
            #             v
            #         importer
            #             |
            #             v
            #         PostgreSQL
            #
            # Therefore startup hydration here remains limited to the
            # application-scoped operational mapping runtime.
            #

            if not supplied_api_container:
                await container.initialize_mitre_runtime()
                mitre_initialized = True

            # ----------------------------------------------------------------
            # Caller-Supplied Lifespan
            # ----------------------------------------------------------------

            if lifespan is not None:
                async with lifespan(app_instance):
                    await _start_realtime_bridge(
                        app_instance,
                    )

                    try:
                        yield
                    finally:
                        await _stop_realtime_bridge(
                            app_instance,
                        )

                return

            # ----------------------------------------------------------------
            # Default Lifespan
            # ----------------------------------------------------------------

            await _start_realtime_bridge(
                app_instance,
            )

            try:
                yield
            finally:
                await _stop_realtime_bridge(
                    app_instance,
                )

        finally:
            # ----------------------------------------------------------------
            # MITRE Mapping Runtime Shutdown
            # ----------------------------------------------------------------

            if mitre_initialized:
                await container.shutdown_mitre_runtime()

    application.router.lifespan_context = application_lifespan

    # ------------------------------------------------------------------------
    # Middleware
    # ------------------------------------------------------------------------

    application.add_middleware(
        RequestIDMiddleware,
    )

    application.add_middleware(
        MetricsMiddleware,
    )

    # ------------------------------------------------------------------------
    # Top-Level API Router
    # ------------------------------------------------------------------------

    application.include_router(
        api_router,
    )

    # ------------------------------------------------------------------------
    # Application-Level Metrics
    # ------------------------------------------------------------------------

    application.include_router(
        metrics_router,
    )

    # ------------------------------------------------------------------------
    # Liveness
    # ------------------------------------------------------------------------

    @application.get(
        "/health/live",
        tags=["health"],
    )
    async def live() -> dict[str, str]:
        """
        Return application liveness status.
        """

        return HealthStatus(
            status="ok",
            service=settings.app_name,
            version=version,
        ).as_dict()

    # ------------------------------------------------------------------------
    # Readiness
    # ------------------------------------------------------------------------

    @application.get(
        "/health/ready",
        tags=["health"],
    )
    async def ready() -> dict[str, object]:
        """
        Return application readiness status.

        PostgreSQL readiness is evaluated through the existing centralized
        health subsystem.
        """

        health = await readiness_status(
            service=settings.app_name,
            version=version,
            postgres=container.postgres_session_manager,
        )

        return health.as_dict()

    # ------------------------------------------------------------------------
    # React Frontend
    # ------------------------------------------------------------------------
    #
    # Production:
    #     FastAPI serves frontend/dist.
    #
    # Development:
    #     Vite serves the frontend source tree.
    #
    # API, metrics, and health routes are registered first.
    #

    _register_frontend(
        application=application,
        settings=settings,
    )

    return application


# ============================================================================
# Realtime Bridge Startup
# ============================================================================


async def _start_realtime_bridge(
    application: FastAPI,
) -> None:
    """
    Start the Redis-backed WebSocket bridge.

    If Redis/WebSocket integration is not configured, this function
    intentionally performs no action.
    """

    redis_client = getattr(
        application.state,
        "websocket_redis",
        None,
    )

    bridge = getattr(
        application.state,
        "websocket_bridge",
        None,
    )

    if redis_client is None or bridge is None:
        return

    await redis_client.ping()
    await bridge.start()


# ============================================================================
# Realtime Bridge Shutdown
# ============================================================================


async def _stop_realtime_bridge(
    application: FastAPI,
) -> None:
    """
    Stop the Redis-backed WebSocket bridge and close Redis resources.
    """

    bridge = getattr(
        application.state,
        "websocket_bridge",
        None,
    )

    redis_client = getattr(
        application.state,
        "websocket_redis",
        None,
    )

    if bridge is not None:
        await bridge.stop()

    if redis_client is not None:
        await redis_client.close()


# ============================================================================
# Default Application Instance
# ============================================================================


app = build_application()


# ============================================================================
# Public Exports
# ============================================================================

__all__ = [
    "app",
    "build_application",
]