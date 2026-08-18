from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from app.api.websocket.manager import ConnectionManager
from app.api.websocket.publisher import (
    WEBSOCKET_ALERTS_CHANNEL,
    WEBSOCKET_EVENTS_CHANNEL,
    WEBSOCKET_INCIDENTS_CHANNEL,
    WEBSOCKET_NOTIFICATIONS_CHANNEL,
)
from app.storage.redis.client import RedisClient

logger = logging.getLogger(__name__)


REDIS_TO_WEBSOCKET_CHANNELS: dict[str, str] = {
    WEBSOCKET_EVENTS_CHANNEL: "events",
    WEBSOCKET_ALERTS_CHANNEL: "alerts",
    WEBSOCKET_INCIDENTS_CHANNEL: "incidents",
    WEBSOCKET_NOTIFICATIONS_CHANNEL: "notifications",
}


class RedisWebSocketBridge:
    """
    Bridge Redis Pub/Sub messages to local authenticated
    WebSocket connections.
    """

    def __init__(
        self,
        *,
        redis: RedisClient,
        manager: ConnectionManager,
    ) -> None:
        self.redis = redis
        self.manager = manager

        self._task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()
        self._started = False

    async def start(self) -> None:
        """Start the Redis Pub/Sub bridge."""
        if self._started:
            raise RuntimeError(
                "Redis WebSocket bridge is already running."
            )

        self._started = True
        self._stop_event.clear()

        self._task = asyncio.create_task(
            self._run(),
            name="redis-websocket-bridge",
        )

        logger.info(
            "Redis WebSocket bridge started "
            "(channels=%s).",
            tuple(
                REDIS_TO_WEBSOCKET_CHANNELS.keys()
            ),
        )

    async def stop(self) -> None:
        """Stop the Redis Pub/Sub bridge gracefully."""
        if not self._started:
            return

        self._started = False
        self._stop_event.set()

        task = self._task
        self._task = None

        if task is not None:
            task.cancel()

            await asyncio.gather(
                task,
                return_exceptions=True,
            )

        logger.info(
            "Redis WebSocket bridge stopped."
        )

    async def _run(self) -> None:
        """Consume Redis messages and forward them to WebSockets."""
        pubsub = self.redis.create_pubsub()

        redis_channels = tuple(
            REDIS_TO_WEBSOCKET_CHANNELS.keys()
        )

        try:
            await pubsub.subscribe(
                *redis_channels,
            )

            logger.info(
                "Redis WebSocket bridge subscribed "
                "(channels=%s).",
                redis_channels,
            )

            while not self._stop_event.is_set():
                message = await pubsub.get_message(
                    ignore_subscribe_messages=True,
                    timeout=1.0,
                )

                if not message:
                    continue

                redis_channel = message.get(
                    "channel"
                )

                if isinstance(redis_channel, bytes):
                    redis_channel = redis_channel.decode(
                        "utf-8",
                        errors="replace",
                    )

                if not isinstance(redis_channel, str):
                    logger.warning(
                        "Ignoring Redis message with invalid channel."
                    )
                    continue

                websocket_channel = (
                    REDIS_TO_WEBSOCKET_CHANNELS.get(
                        redis_channel
                    )
                )

                if websocket_channel is None:
                    logger.warning(
                        "Ignoring unsupported Redis channel: %s",
                        redis_channel,
                    )
                    continue

                raw_data = message.get("data")

                if isinstance(raw_data, bytes):
                    raw_data = raw_data.decode(
                        "utf-8",
                        errors="replace",
                    )

                if not isinstance(raw_data, str):
                    logger.warning(
                        "Ignoring non-string Redis payload "
                        "(channel=%s).",
                        redis_channel,
                    )
                    continue

                try:
                    payload: Any = json.loads(
                        raw_data,
                    )
                except json.JSONDecodeError:
                    logger.warning(
                        "Ignoring invalid JSON Redis payload "
                        "(channel=%s).",
                        redis_channel,
                        exc_info=True,
                    )
                    continue

                if not isinstance(payload, dict):
                    logger.warning(
                        "Ignoring non-object Redis payload "
                        "(channel=%s).",
                        redis_channel,
                    )
                    continue

                try:
                    delivered = await self.manager.publish(
                        websocket_channel,
                        payload,
                    )

                    logger.debug(
                        "Redis realtime payload forwarded "
                        "(redis_channel=%s, websocket_channel=%s, "
                        "delivered=%d).",
                        redis_channel,
                        websocket_channel,
                        delivered,
                    )

                except Exception:
                    logger.exception(
                        "Failed to forward Redis realtime payload "
                        "(redis_channel=%s, websocket_channel=%s).",
                        redis_channel,
                        websocket_channel,
                    )

        except asyncio.CancelledError:
            raise

        except Exception:
            logger.exception(
                "Redis WebSocket bridge terminated unexpectedly."
            )

        finally:
            try:
                await pubsub.unsubscribe(
                    *redis_channels,
                )
            except Exception:
                logger.debug(
                    "Failed to unsubscribe Redis WebSocket bridge.",
                    exc_info=True,
                )

            try:
                await pubsub.aclose()
            except Exception:
                logger.debug(
                    "Failed to close Redis Pub/Sub.",
                    exc_info=True,
                )