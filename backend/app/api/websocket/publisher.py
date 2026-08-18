from __future__ import annotations

from typing import Any

from app.storage.redis.client import RedisClient

WEBSOCKET_EVENTS_CHANNEL = "siem:websocket:events"
WEBSOCKET_ALERTS_CHANNEL = "siem:websocket:alerts"
WEBSOCKET_INCIDENTS_CHANNEL = "siem:websocket:incidents"
WEBSOCKET_NOTIFICATIONS_CHANNEL = "siem:websocket:notifications"

WEBSOCKET_CHANNELS = frozenset(
    {
        WEBSOCKET_EVENTS_CHANNEL,
        WEBSOCKET_ALERTS_CHANNEL,
        WEBSOCKET_INCIDENTS_CHANNEL,
        WEBSOCKET_NOTIFICATIONS_CHANNEL,
    }
)


class WebSocketPublisher:
    """Publish realtime security payloads through Redis Pub/Sub."""

    def __init__(
        self,
        redis: RedisClient,
    ) -> None:
        self._redis = redis

    async def publish(
        self,
        channel: str,
        payload: dict[str, Any],
    ) -> int:
        """
        Publish a realtime payload to a supported Redis channel.

        Returns the number of Redis subscribers that received
        the message.
        """
        normalized_channel = channel.strip()

        if not normalized_channel:
            raise ValueError(
                "channel must not be empty"
            )

        if normalized_channel not in WEBSOCKET_CHANNELS:
            raise ValueError(
                f"Unsupported WebSocket Redis channel: "
                f"{normalized_channel}"
            )

        return await self._redis.publish_json(
            normalized_channel,
            payload,
        )

    async def publish_event(
        self,
        payload: dict[str, Any],
    ) -> int:
        """Publish a security event to the events channel."""
        return await self.publish(
            WEBSOCKET_EVENTS_CHANNEL,
            payload,
        )

    async def publish_alert(
        self,
        payload: dict[str, Any],
    ) -> int:
        """Publish an alert to the alerts channel."""
        return await self.publish(
            WEBSOCKET_ALERTS_CHANNEL,
            payload,
        )

    async def publish_incident(
        self,
        payload: dict[str, Any],
    ) -> int:
        """Publish an incident to the incidents channel."""
        return await self.publish(
            WEBSOCKET_INCIDENTS_CHANNEL,
            payload,
        )

    async def publish_notification(
        self,
        payload: dict[str, Any],
    ) -> int:
        """Publish a system notification to the notifications channel."""
        return await self.publish(
            WEBSOCKET_NOTIFICATIONS_CHANNEL,
            payload,
        )
