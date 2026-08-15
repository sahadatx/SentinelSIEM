from __future__ import annotations

from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.api.dependencies import get_api_container
from .manager import ConnectionManager

router = APIRouter(tags=["websocket"])


def get_connection_manager(websocket: WebSocket) -> ConnectionManager:
    manager = getattr(websocket.app.state, "websocket_manager", None)
    if not isinstance(manager, ConnectionManager):
        raise RuntimeError("WebSocket manager is not configured")
    return manager


@router.websocket("/ws")
async def websocket_stream(websocket: WebSocket) -> None:
    manager = get_connection_manager(websocket)
    connection_id = await manager.connect(websocket)
    try:
        await websocket.send_json({"type": "connected", "connection_id": connection_id})
        while True:
            message: dict[str, Any] = await websocket.receive_json()
            action = message.get("action")
            if action == "ping":
                await websocket.send_json({"type": "pong"})
            elif action == "subscribe":
                channels = message.get("channels", [])
                if not isinstance(channels, list) or not all(isinstance(x, str) for x in channels):
                    await websocket.send_json({"type": "error", "code": "INVALID_SUBSCRIPTION"})
                    continue
                connection = manager._connections.get(connection_id)
                if connection is not None:
                    connection.channels = set(channels) & {"events", "alerts", "incidents", "notifications"}
                    await websocket.send_json({"type": "subscribed", "channels": sorted(connection.channels)})
            else:
                await websocket.send_json({"type": "error", "code": "UNSUPPORTED_ACTION"})
    except WebSocketDisconnect:
        pass
    finally:
        await manager.disconnect(connection_id)
