from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.config import get_settings
from app.core.lifecycle import ApplicationLifecycle
from app.core.logging import configure_logging
from app.core.version import __version__


def create_lifespan() -> object:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        settings = get_settings()
        configure_logging(settings.log_level)

        lifecycle = ApplicationLifecycle()

        try:
            yield
        finally:
            await lifecycle.shutdown()

            # Close the PostgreSQL connection pool.
            api_container = getattr(app.state, "api", None)

            if api_container is not None:
                session_manager = getattr(
                    api_container,
                    "postgres_session_manager",
                    None,
                )

                if session_manager is not None:
                    await session_manager.close()

    return lifespan


def create_application() -> FastAPI:
    from app.main import build_application

    return build_application(
        version=__version__,
        lifespan=create_lifespan(),
    )


__all__ = ["create_application"]
