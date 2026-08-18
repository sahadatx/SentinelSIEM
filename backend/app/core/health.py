from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Protocol

from app.core.metrics import REGISTRY


logger = logging.getLogger(__name__)


class AsyncHealthDependency(Protocol):
    """Protocol for asynchronous health-check dependencies."""

    async def ping(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class HealthStatus:
    """Application health/readiness response."""

    status: str
    service: str
    version: str
    checks: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        """Convert health status to a JSON-compatible dictionary."""
        payload: dict[str, object] = {
            "status": self.status,
            "service": self.service,
            "version": self.version,
        }

        if self.checks:
            payload["checks"] = dict(self.checks)

        return payload


async def readiness_status(
    *,
    service: str,
    version: str,
    postgres: AsyncHealthDependency | None = None,
) -> HealthStatus:
    """
    Evaluate application readiness and configured dependency health.

    A missing optional dependency is not considered a failed readiness
    check. Dependencies explicitly supplied by the caller are checked.
    """

    checks: dict[str, str] = {}
    status = "ready"

    if postgres is not None:
        try:
            ready = await postgres.ping()
        except Exception:  # noqa: BLE001
            logger.exception(
                "PostgreSQL readiness check failed."
            )
            ready = False

        checks["postgres"] = "ok" if ready else "failed"

        REGISTRY.set_gauge(
            "siem_postgres_health",
            1.0 if ready else 0.0,
            help_text=(
                "PostgreSQL dependency health "
                "(1=healthy, 0=unhealthy)."
            ),
        )

        if not ready:
            status = "not_ready"

    REGISTRY.set_gauge(
        "siem_application_ready",
        1.0 if status == "ready" else 0.0,
        help_text=(
            "Application readiness state "
            "(1=ready, 0=not ready)."
        ),
    )

    return HealthStatus(
        status=status,
        service=service,
        version=version,
        checks=checks,
    )