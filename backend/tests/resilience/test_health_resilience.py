from __future__ import annotations

import pytest

from app.core.health import readiness_status


class FailingDependency:
    async def ping(self) -> bool:
        raise RuntimeError("database unavailable")


@pytest.mark.anyio
async def test_readiness_fails_closed_on_dependency_exception() -> None:
    status = await readiness_status(
        service="sentinelsiem",
        version="0.1.0",
        postgres=FailingDependency(),
    )

    assert status.status == "not_ready"
    assert status.checks["postgres"] == "failed"
