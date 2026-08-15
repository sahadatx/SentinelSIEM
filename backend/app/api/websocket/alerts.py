from __future__ import annotations

from typing import Any

from .manager import ConnectionManager


async def publish_alert(manager: ConnectionManager, payload: dict[str, Any]) -> int:
    return await manager.publish("alerts", payload)
