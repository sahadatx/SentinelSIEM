from __future__ import annotations

from uuid import UUID

import pytest

from app.api.websocket.manager import ConnectionManager


@pytest.fixture
def anyio_backend() -> str:
    """Run websocket unit tests on the asyncio backend only."""
    return "asyncio"


class FakeWebSocket:
    def __init__(self) -> None:
        self.accepted = False
        self.closed = False
        self.messages: list[dict] = []

    async def accept(self) -> None:
        self.accepted = True

    async def close(
        self,
        code: int,
        reason: str,
    ) -> None:
        self.closed = True

    async def send_json(
        self,
        payload: dict,
    ) -> None:
        self.messages.append(payload)


async def _authenticated_connection(
    manager: ConnectionManager,
    websocket: FakeWebSocket,
    *,
    permissions: frozenset[str],
) -> str:
    connection_id = await manager.connect(
        websocket,  # type: ignore[arg-type]
    )

    await manager.authenticate(
        connection_id,
        user_id=UUID(
            "600854d0-e030-41bc-bc65-0224ff36fa4a",
        ),
        username="test-user",
        roles=frozenset({"ADMIN"}),
        permissions=permissions,
    )

    return connection_id


@pytest.mark.anyio
async def test_connection_manager_enforces_limit(
    anyio_backend: str,
) -> None:
    manager = ConnectionManager(
        max_connections=1,
    )

    first = FakeWebSocket()
    second = FakeWebSocket()

    await manager.connect(
        first,  # type: ignore[arg-type]
    )

    with pytest.raises(
        RuntimeError,
        match="connection limit",
    ):
        await manager.connect(
            second,  # type: ignore[arg-type]
        )


@pytest.mark.anyio
async def test_disconnect_removes_connection(
    anyio_backend: str,
) -> None:
    manager = ConnectionManager()
    websocket = FakeWebSocket()

    connection_id = await manager.connect(
        websocket,  # type: ignore[arg-type]
    )

    assert manager.connection_count == 1

    await manager.disconnect(
        connection_id,
    )

    assert manager.connection_count == 0


@pytest.mark.anyio
async def test_notifications_channel_requires_dashboard_permission(
    anyio_backend: str,
) -> None:
    manager = ConnectionManager()
    websocket = FakeWebSocket()

    connection_id = await _authenticated_connection(
        manager,
        websocket,
        permissions=frozenset(),
    )

    with pytest.raises(
        PermissionError,
        match="Insufficient permission",
    ):
        await manager.update_channels(
            connection_id,
            {"notifications"},
        )


@pytest.mark.anyio
async def test_notifications_channel_allows_dashboard_permission(
    anyio_backend: str,
) -> None:
    manager = ConnectionManager()
    websocket = FakeWebSocket()

    connection_id = await _authenticated_connection(
        manager,
        websocket,
        permissions=frozenset(
            {"dashboard:read"},
        ),
    )

    channels = await manager.update_channels(
        connection_id,
        {"notifications"},
    )

    assert channels == ("notifications",)


@pytest.mark.anyio
async def test_notifications_are_published_to_subscribers(
    anyio_backend: str,
) -> None:
    manager = ConnectionManager()
    websocket = FakeWebSocket()

    connection_id = await _authenticated_connection(
        manager,
        websocket,
        permissions=frozenset(
            {"dashboard:read"},
        ),
    )

    await manager.update_channels(
        connection_id,
        {"notifications"},
    )

    payload = {
        "event_type": "system",
        "title": "Phase20 notification test",
        "message": "Realtime notification delivery works.",
    }

    delivered = await manager.publish(
        "notifications",
        payload,
    )

    assert delivered == 1
    assert len(websocket.messages) == 1

    message = websocket.messages[0]

    assert message["type"] == "stream"
    assert message["channel"] == "notifications"
    assert message["data"] == payload


@pytest.mark.anyio
async def test_publish_rejects_unsupported_channel(
    anyio_backend: str,
) -> None:
    manager = ConnectionManager()

    with pytest.raises(
        ValueError,
        match="Unsupported WebSocket channel",
    ):
        await manager.publish(
            "unsupported",
            {"message": "invalid"},
        )
