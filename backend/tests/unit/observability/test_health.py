from __future__ import annotations

import pytest

from app.core.health import readiness_status


class HealthyDependency:
    async def ping(self) -> bool:
        return True


class UnhealthyDependency:
    async def ping(self) -> bool:
        return False


class FailingDependency:
    async def ping(self) -> bool:
        raise RuntimeError("database unavailable")


@pytest.mark.anyio
async def test_readiness_is_ready_without_dependencies() -> None:
    status = await readiness_status(
        service="siem-security-platform",
        version="0.1.0",
    )

    assert status.status == "ready"
    assert status.service == "siem-security-platform"
    assert status.version == "0.1.0"
    assert status.checks == {}


@pytest.mark.anyio
async def test_readiness_is_ready_when_postgres_is_healthy() -> None:
    status = await readiness_status(
        service="siem-security-platform",
        version="0.1.0",
        postgres=HealthyDependency(),
    )

    assert status.status == "ready"
    assert status.checks == {
        "postgres": "ok",
    }


@pytest.mark.anyio
async def test_readiness_is_not_ready_when_postgres_is_unhealthy() -> None:
    status = await readiness_status(
        service="siem-security-platform",
        version="0.1.0",
        postgres=UnhealthyDependency(),
    )

    assert status.status == "not_ready"
    assert status.checks == {
        "postgres": "failed",
    }


@pytest.mark.anyio
async def test_readiness_fails_closed_when_postgres_ping_raises() -> None:
    status = await readiness_status(
        service="siem-security-platform",
        version="0.1.0",
        postgres=FailingDependency(),
    )

    assert status.status == "not_ready"
    assert status.checks == {
        "postgres": "failed",
    }


@pytest.mark.anyio
async def test_readiness_updates_health_metrics() -> None:
    status = await readiness_status(
        service="siem-security-platform",
        version="0.1.0",
        postgres=HealthyDependency(),
    )

    assert status.status == "ready"
    assert status.checks["postgres"] == "ok"
