from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from app.core.exceptions import LifecycleError

ShutdownHook = Callable[[], Awaitable[None]]

logger = logging.getLogger(__name__)


class ApplicationLifecycle:
    """Coordinates controlled startup and shutdown hooks."""

    def __init__(self) -> None:
        self._shutdown_hooks: list[ShutdownHook] = []

    def register_shutdown_hook(self, hook: ShutdownHook) -> None:
        self._shutdown_hooks.append(hook)

    async def shutdown(self) -> None:
        failures: list[Exception] = []
        for hook in reversed(self._shutdown_hooks):
            try:
                await hook()
            except Exception as exc:  # noqa: BLE001
                logger.exception("Lifecycle shutdown hook failed.")
                failures.append(exc)

        if failures:
            raise LifecycleError("One or more shutdown hooks failed.")
