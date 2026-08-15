from __future__ import annotations

from typing import Any

from .manager import ConnectionManager


async def publish_incident(manager: ConnectionManager, payload: dict[str, Any]) -> int:
    return await manager.publish("incidents", payload)
