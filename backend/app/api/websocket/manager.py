from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from fastapi import WebSocket


@dataclass(slots=True)
class Connection:
    connection_id: str
    websocket: WebSocket
    channels: set[str] = field(default_factory=set)


class ConnectionManager:
    """Bounded, failure-isolated WebSocket connection manager."""

    def __init__(self, *, max_connections: int = 1000, max_message_bytes: int = 1_000_000) -> None:
        if max_connections < 1:
            raise ValueError("max_connections must be positive")
        if max_message_bytes < 1:
            raise ValueError("max_message_bytes must be positive")
        self.max_connections = max_connections
        self.max_message_bytes = max_message_bytes
        self._connections: dict[str, Connection] = {}
        self._lock = asyncio.Lock()

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    async def connect(self, websocket: WebSocket, channels: set[str] | None = None) -> str:
        async with self._lock:
            if len(self._connections) >= self.max_connections:
                await websocket.close(code=1013, reason="connection limit reached")
                raise RuntimeError("WebSocket connection limit reached")
            await websocket.accept()
            connection_id = uuid4().hex
            self._connections[connection_id] = Connection(
                connection_id=connection_id,
                websocket=websocket,
                channels=channels or {"events", "alerts", "incidents", "notifications"},
            )
            return connection_id

    async def disconnect(self, connection_id: str) -> None:
        async with self._lock:
            self._connections.pop(connection_id, None)

    async def publish(self, channel: str, payload: dict[str, Any]) -> int:
        message = {"channel": channel, "data": payload}
        encoded_size = len(str(message).encode("utf-8"))
        if encoded_size > self.max_message_bytes:
            raise ValueError("WebSocket message exceeds configured size limit")

        async with self._lock:
            targets = [c for c in self._connections.values() if channel in c.channels]

        delivered = 0
        stale: list[str] = []
        for connection in targets:
            try:
                await connection.websocket.send_json(message)
                delivered += 1
            except Exception:
                stale.append(connection.connection_id)

        for connection_id in stale:
            await self.disconnect(connection_id)
        return delivered
