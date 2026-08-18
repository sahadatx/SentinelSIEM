from __future__ import annotations

import asyncio
import json
from typing import Any
from uuid import UUID

from app.alerts.manager import AlertManager
from app.alerts.models import (
    AlertCreate,
    AlertSeverity,
    AlertSourceType,
)
from app.api.websocket.bridge import RedisWebSocketBridge
from app.api.websocket.manager import ConnectionManager
from app.api.websocket.publisher import WebSocketPublisher


class FakePubSub:
    """Small in-memory Pub/Sub adapter for deterministic integration tests."""

    def __init__(
        self,
        owner: FakeRedisClient,
    ) -> None:
        self._owner = owner
        self._channels: tuple[str, ...] = ()
        self._queue: asyncio.Queue[
            dict[str, Any]
        ] = asyncio.Queue()

    async def subscribe(
        self,
        *channels: str,
    ) -> None:
        self._channels = tuple(channels)

        for channel in self._channels:
            self._owner.register_subscriber(
                channel,
                self,
            )

    async def unsubscribe(
        self,
        *channels: str,
    ) -> None:
        for channel in channels:
            self._owner.unregister_subscriber(
                channel,
                self,
            )

    async def get_message(
        self,
        *,
        ignore_subscribe_messages: bool = True,
        timeout: float = 1.0,
    ) -> dict[str, Any] | None:
        del ignore_subscribe_messages

        try:
            return await asyncio.wait_for(
                self._queue.get(),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            return None

    async def publish(
        self,
        channel: str,
        payload: str,
    ) -> None:
        await self._queue.put(
            {
                "type": "message",
                "channel": channel,
                "data": payload,
            }
        )

    async def aclose(self) -> None:
        for channel in self._channels:
            self._owner.unregister_subscriber(
                channel,
                self,
            )

        self._channels = ()


class FakeRedisClient:
    """
    In-memory RedisClient-compatible adapter.

    This intentionally models only the Redis methods required by
    WebSocketPublisher and RedisWebSocketBridge.
    """

    def __init__(self) -> None:
        self._subscribers: dict[
            str,
            set[FakePubSub],
        ] = {}

    async def publish_json(
        self,
        channel: str,
        payload: dict[str, Any],
    ) -> int:
        encoded = json.dumps(
            payload,
            default=str,
        )

        subscribers = tuple(
            self._subscribers.get(
                channel,
                set(),
            )
        )

        for subscriber in subscribers:
            await subscriber.publish(
                channel,
                encoded,
            )

        return len(subscribers)

    def create_pubsub(self) -> FakePubSub:
        return FakePubSub(self)

    def register_subscriber(
        self,
        channel: str,
        subscriber: FakePubSub,
    ) -> None:
        self._subscribers.setdefault(
            channel,
            set(),
        ).add(subscriber)

    def unregister_subscriber(
        self,
        channel: str,
        subscriber: FakePubSub,
    ) -> None:
        subscribers = self._subscribers.get(
            channel,
        )

        if subscribers is None:
            return

        subscribers.discard(
            subscriber,
        )

        if not subscribers:
            self._subscribers.pop(
                channel,
                None,
            )


class FakeWebSocket:
    """
    Minimal WebSocket test double compatible with ConnectionManager.
    """

    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []
        self.accepted = False
        self.closed = False
        self.close_code: int | None = None
        self.close_reason: str | None = None

    async def accept(self) -> None:
        self.accepted = True

    async def send_json(
        self,
        payload: dict[str, Any],
    ) -> None:
        self.messages.append(
            payload,
        )

    async def close(
        self,
        code: int = 1000,
        reason: str = "",
    ) -> None:
        self.closed = True
        self.close_code = code
        self.close_reason = reason


def _create_alert() -> AlertCreate:
    return AlertCreate(
        source_type=AlertSourceType.DETECTION,
        source_id="phase20-realtime-test",
        rule_id="phase20-alert-realtime",
        title="Phase20 Alert Realtime Test",
        description=(
            "Integration test alert for realtime delivery."
        ),
        severity=AlertSeverity.HIGH,
        risk_score=82.0,
        priority="high",
        evidence_ids=("phase20-event-001",),
        asset_id="phase20-host",
    )


def test_phase20_alert_realtime_end_to_end() -> None:
    """
    Validate the complete alert realtime delivery path:

        AlertManager
            -> WebSocketPublisher
            -> Redis Pub/Sub
            -> RedisWebSocketBridge
            -> ConnectionManager
            -> alerts WebSocket channel
    """

    async def scenario() -> None:
        redis = FakeRedisClient()
        manager = ConnectionManager()

        publisher = WebSocketPublisher(
            redis,
        )

        bridge = RedisWebSocketBridge(
            redis=redis,
            manager=manager,
        )

        await bridge.start()

        connection_id: str | None = None

        try:
            websocket = FakeWebSocket()

            connection_id = await manager.connect(
                websocket,
            )

            assert websocket.accepted is True

            await manager.authenticate(
                connection_id,
                user_id=UUID(
                    "600854d0-e030-41bc-bc65-0224ff36fa4a",
                ),
                username="phase20-admin",
                roles=frozenset({"ADMIN"}),
                permissions=frozenset(
                    {
                        "alerts:read",
                        "alerts:manage",
                        "dashboard:read",
                    }
                ),
            )

            subscribed_channels = await manager.update_channels(
                connection_id,
                {"alerts"},
            )

            assert subscribed_channels == ("alerts",)

            alert_manager = AlertManager(
                realtime_publisher=publisher.publish_alert,
            )

            alert = alert_manager.create(
                _create_alert(),
                actor="phase20-test",
            )

            # AlertManager schedules the async realtime publisher as a
            # background task. Give the event loop several opportunities
            # to run both the publisher and the Redis bridge.
            for _ in range(20):
                if websocket.messages:
                    break

                await asyncio.sleep(0)

            assert alert.alert_id is not None
            assert len(websocket.messages) == 1

            message = websocket.messages[0]

            assert message["type"] == "stream"
            assert message["channel"] == "alerts"

            payload = message["data"]

            assert payload["event_type"] == "created"

            alert_payload = payload["alert"]

            assert (
                alert_payload["alert_id"]
                == str(alert.alert_id)
            )

            assert (
                alert_payload["title"]
                == "Phase20 Alert Realtime Test"
            )

            assert alert_payload["status"] == "new"

            assert (
                alert_payload["severity"]
                == "high"
            )

            assert (
                alert_payload["risk_score"]
                == 82.0
            )

        finally:
            await bridge.stop()

            if connection_id is not None:
                await manager.disconnect(
                    connection_id,
                )

    asyncio.run(
        scenario(),
    )
