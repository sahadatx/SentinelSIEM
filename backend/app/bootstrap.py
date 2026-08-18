from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI

from app.core.config import get_settings
from app.core.lifecycle import ApplicationLifecycle
from app.core.logging import configure_logging
from app.core.version import __version__


async def _close_resource(resource: Any) -> None:
    """
    Close an asynchronous resource when it exposes a close() method.

    Shutdown must remain defensive so application cleanup does not fail
    because an optional dependency was not initialized or does not expose
    an asynchronous close operation.
    """
    if resource is None:
        return

    close = getattr(resource, "close", None)

    if close is None:
        return

    result = close()

    if result is not None:
        await result


async def _close_application_resources(
    app: FastAPI,
) -> None:
    """
    Close application-scoped resources owned by the API container.

    PostgreSQL and OpenSearch are both application-scoped integrations.
    They must be closed during graceful application shutdown.
    """
    api_container = getattr(
        app.state,
        "api",
        None,
    )

    if api_container is None:
        return

    # ------------------------------------------------------------------
    # PostgreSQL connection pool
    # ------------------------------------------------------------------
    session_manager = getattr(
        api_container,
        "postgres_session_manager",
        None,
    )

    if session_manager is not None:
        await _close_resource(session_manager)

    # ------------------------------------------------------------------
    # OpenSearch client
    # ------------------------------------------------------------------
    #
    # The OpenSearchEventRepository holds the underlying OpenSearch client
    # in its ``client`` attribute.
    #
    # This is intentionally resolved defensively so externally supplied
    # repositories and test doubles remain supported.
    #
    event_repository = getattr(
        api_container,
        "event_repository",
        None,
    )

    if event_repository is not None:
        opensearch_client = getattr(
            event_repository,
            "client",
            None,
        )

        await _close_resource(opensearch_client)


def create_lifespan() -> object:
    """
    Create the FastAPI application lifespan handler.

    Startup configures logging and application lifecycle management.
    Shutdown closes application-managed infrastructure resources in a
    defensive and deterministic manner.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        settings = get_settings()
        configure_logging(settings.log_level)

        lifecycle = ApplicationLifecycle()

        try:
            yield
        finally:
            # ----------------------------------------------------------
            # Application lifecycle shutdown
            # ----------------------------------------------------------
            await lifecycle.shutdown()

            # ----------------------------------------------------------
            # Infrastructure resource shutdown
            # ----------------------------------------------------------
            await _close_application_resources(app)

    return lifespan


def create_application() -> FastAPI:
    """
    Create the production FastAPI application with its lifespan handler.
    """
    from app.main import build_application

    return build_application(
        version=__version__,
        lifespan=create_lifespan(),
    )


__all__ = [
    "create_application",
    "create_lifespan",
]