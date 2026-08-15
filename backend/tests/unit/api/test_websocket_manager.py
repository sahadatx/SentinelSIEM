from __future__ import annotations

import pytest

from app.api.websocket.manager import ConnectionManager


@pytest.fixture
def anyio_backend() -> str:
    """Run websocket unit tests on the asyncio backend only."""
    return "asyncio"


class FakeWebSocket:
    async def accept(self) -> None: pass
    async def close(self, code: int, reason: str) -> None: pass
    async def send_json(self, payload: dict) -> None: pass


@pytest.mark.anyio
async def test_connection_manager_enforces_limit(anyio_backend: str) -> None:
    manager = ConnectionManager(max_connections=1)
    first = FakeWebSocket()
    second = FakeWebSocket()
    await manager.connect(first)  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="connection limit"):
        await manager.connect(second)  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_disconnect_removes_connection(anyio_backend: str) -> None:
    manager = ConnectionManager()
    websocket = FakeWebSocket()
    connection_id = await manager.connect(websocket)  # type: ignore[arg-type]
    assert manager.connection_count == 1
    await manager.disconnect(connection_id)
    assert manager.connection_count == 0
