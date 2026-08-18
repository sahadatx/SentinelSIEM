from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID, uuid4

from fastapi import WebSocket


@dataclass(slots=True)
class Connection:
    connection_id: str
    websocket: WebSocket
    user_id: UUID | None = None
    username: str | None = None
    roles: frozenset[str] = field(default_factory=frozenset)
    permissions: frozenset[str] = field(default_factory=frozenset)
    channels: set[str] = field(default_factory=set)


class ConnectionManager:
    """Bounded, failure-isolated WebSocket connection manager."""

    ALLOWED_CHANNELS = frozenset(
        {
            "events",
            "alerts",
            "incidents",
            "notifications",
        }
    )

    CHANNEL_PERMISSIONS = {
        "events": "events:read",
        "alerts": "alerts:read",
        "incidents": "incidents:read",
        "notifications": "dashboard:read",
    }

    def __init__(
        self,
        *,
        max_connections: int = 1000,
        max_message_bytes: int = 1_000_000,
    ) -> None:
        if max_connections < 1:
            raise ValueError("max_connections must be positive")

        if max_message_bytes < 1:
            raise ValueError(
                "max_message_bytes must be positive",
            )

        self.max_connections = max_connections
        self.max_message_bytes = max_message_bytes
        self._connections: dict[str, Connection] = {}
        self._lock = asyncio.Lock()

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    async def connect(
        self,
        websocket: WebSocket,
    ) -> str:
        async with self._lock:
            if len(self._connections) >= self.max_connections:
                await websocket.close(
                    code=1013,
                    reason="connection limit reached",
                )
                raise RuntimeError(
                    "WebSocket connection limit reached",
                )

            await websocket.accept()

            connection_id = uuid4().hex

            self._connections[connection_id] = Connection(
                connection_id=connection_id,
                websocket=websocket,
            )

            return connection_id

    async def authenticate(
        self,
        connection_id: str,
        *,
        user_id: UUID,
        username: str,
        roles: frozenset[str],
        permissions: frozenset[str],
    ) -> Connection:
        async with self._lock:
            connection = self._connections.get(connection_id)

            if connection is None:
                raise RuntimeError(
                    "WebSocket connection no longer exists",
                )

            connection.user_id = user_id
            connection.username = username
            connection.roles = roles
            connection.permissions = permissions

            connection.channels = {
                channel
                for channel, permission in self.CHANNEL_PERMISSIONS.items()
                if permission in permissions
            }

            return connection

    async def disconnect(
        self,
        connection_id: str,
    ) -> None:
        async with self._lock:
            self._connections.pop(
                connection_id,
                None,
            )

    async def update_channels(
        self,
        connection_id: str,
        requested_channels: set[str],
    ) -> tuple[str, ...]:
        async with self._lock:
            connection = self._connections.get(connection_id)

            if connection is None:
                raise RuntimeError(
                    "WebSocket connection no longer exists",
                )

            if connection.user_id is None:
                raise PermissionError(
                    "WebSocket authentication is required",
                )

            requested = requested_channels & self.ALLOWED_CHANNELS

            denied = {
                channel
                for channel in requested
                if self.CHANNEL_PERMISSIONS[channel]
                not in connection.permissions
            }

            if denied:
                raise PermissionError(
                    "Insufficient permission for requested channel(s)",
                )

            connection.channels = requested

            return tuple(sorted(connection.channels))

    async def publish(
        self,
        channel: str,
        payload: dict[str, Any],
    ) -> int:
        if channel not in self.ALLOWED_CHANNELS:
            raise ValueError(
                f"Unsupported WebSocket channel: {channel}",
            )

        message = {
            "type": "stream",
            "channel": channel,
            "data": payload,
        }

        encoded_size = len(
            str(message).encode("utf-8"),
        )

        if encoded_size > self.max_message_bytes:
            raise ValueError(
                "WebSocket message exceeds configured size limit",
            )

        async with self._lock:
            targets = [
                connection
                for connection in self._connections.values()
                if channel in connection.channels
            ]

        delivered = 0
        stale: list[str] = []

        for connection in targets:
            try:
                await connection.websocket.send_json(
                    message,
                )
                delivered += 1

            except Exception:
                stale.append(
                    connection.connection_id,
                )

        for connection_id in stale:
            await self.disconnect(connection_id)

        return delivered