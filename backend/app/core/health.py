from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from app.core.metrics import REGISTRY


class AsyncHealthDependency(Protocol):
    async def ping(self) -> bool: ...


@dataclass(frozen=True, slots=True)
class HealthStatus:
    status: str
    service: str
    version: str
    checks: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
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
    checks: dict[str, str] = {}
    status = "ready"

    if postgres is not None:
        try:
            ready = await postgres.ping()
        except Exception:  # noqa: BLE001
            ready = False
        checks["postgres"] = "ok" if ready else "failed"
        if not ready:
            status = "not_ready"

        REGISTRY.set_gauge(
            "siem_postgres_health",
            1.0 if ready else 0.0,
            help_text="PostgreSQL dependency health (1=healthy, 0=unhealthy).",
        )

    REGISTRY.set_gauge(
        "siem_application_ready",
        1.0 if status == "ready" else 0.0,
        help_text="Application readiness state (1=ready, 0=not ready).",
    )

    return HealthStatus(status=status, service=service, version=version, checks=checks)
