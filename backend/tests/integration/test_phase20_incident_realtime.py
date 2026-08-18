from __future__ import annotations

import asyncio
import json
from typing import Any
from uuid import UUID

from app.api.websocket.bridge import RedisWebSocketBridge
from app.api.websocket.manager import ConnectionManager
from app.api.websocket.publisher import WebSocketPublisher
from app.incidents.manager import IncidentManager
from app.incidents.models import (
    IncidentCreate,
    IncidentSeverity,
)


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

    Models only the Redis methods required by the WebSocket
    publisher and bridge.
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
    """Minimal WebSocket test double compatible with ConnectionManager."""

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


def _create_incident() -> IncidentCreate:
    return IncidentCreate(
        title="Phase20 Incident Realtime Test",
        description=(
            "Integration test incident for realtime delivery."
        ),
        severity=IncidentSeverity.HIGH,
        alert_ids=(
            UUID(
                "8c7d9fd4-76d8-4385-8f8c-1a8f12c6d123",
            ),
        ),
        evidence_ids=("phase20-event-001",),
        related_event_ids=(
            "phase20-event-001",
            "phase20-event-002",
        ),
        asset_ids=("phase20-host",),
        initial_assignee=None,
        ownership_group="SOC-TIER-1",
    )


def test_phase20_incident_realtime_end_to_end() -> None:
    """
    Validate the complete incident realtime delivery path:

        IncidentManager
            -> WebSocketPublisher
            -> Redis Pub/Sub
            -> RedisWebSocketBridge
            -> ConnectionManager
            -> incidents WebSocket channel
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
                        "incidents:read",
                        "dashboard:read",
                    }
                ),
            )

            subscribed_channels = await manager.update_channels(
                connection_id,
                {"incidents"},
            )

            assert subscribed_channels == ("incidents",)

            incident_manager = IncidentManager(
                realtime_publisher=(
                    publisher.publish_incident
                ),
            )

            incident = incident_manager.create(
                _create_incident(),
                actor="phase20-test",
            )

            # Allow the scheduled publisher and Redis bridge
            # to process the realtime event.
            for _ in range(20):
                if websocket.messages:
                    break

                await asyncio.sleep(0)

            assert incident.incident_id is not None
            assert len(websocket.messages) == 1

            message = websocket.messages[0]

            assert message["type"] == "stream"
            assert message["channel"] == "incidents"

            payload = message["data"]

            assert payload["event_type"] == "created"

            incident_payload = payload["incident"]

            assert (
                incident_payload["incident_id"]
                == str(incident.incident_id)
            )

            assert (
                incident_payload["title"]
                == "Phase20 Incident Realtime Test"
            )

            assert (
                incident_payload["status"]
                == "new"
            )

            assert (
                incident_payload["severity"]
                == "high"
            )

            assert (
                incident_payload["ownership_group"]
                == "SOC-TIER-1"
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
