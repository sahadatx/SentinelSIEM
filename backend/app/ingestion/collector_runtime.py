from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from app.core.config import Settings, get_settings
from app.ingestion.collectors.registry import CollectorRegistry
from app.ingestion.collectors.tcp import TCPCollector
from app.ingestion.manager import IngestionManager
from app.ingestion.queues.redis import RedisEventQueue
from app.storage.redis.client import RedisClient

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class CollectorSettings:
    """Validated configuration required by the collector runtime."""

    redis_url: str
    queue_name: str
    host: str
    port: int
    name: str
    source: str
    max_line_bytes: int
    queue_size: int

    @classmethod
    def from_application_settings(
        cls,
        settings: Settings,
    ) -> CollectorSettings:
        """Build collector configuration from centralized settings."""

        if not settings.redis_url:
            raise ValueError("Redis URL must be configured for collector runtime.")

        return cls(
            redis_url=settings.redis_url,
            queue_name=settings.event_queue_name,
            host=settings.collector_host,
            port=settings.collector_port,
            name=settings.collector_name,
            source=settings.collector_source,
            max_line_bytes=settings.collector_max_line_bytes,
            queue_size=settings.collector_queue_size,
        )

    @classmethod
    def from_environment(cls) -> CollectorSettings:
        """Load collector settings through the central Settings model."""
        settings = get_settings()

        try:
            return cls.from_application_settings(settings)
        except Exception as exc:
            raise RuntimeError("Collector runtime configuration is invalid.") from exc


class CollectorRuntime:
    """Run registered collectors and forward events to Redis."""

    def __init__(
        self,
        settings: CollectorSettings,
    ) -> None:
        self.settings = settings

        self.redis = RedisClient(
            settings.redis_url,
        )

        self.queue = RedisEventQueue(
            self.redis.client,
            queue_name=settings.queue_name,
        )

        self.registry = CollectorRegistry()

        self.tcp_collector = TCPCollector(
            name=settings.name,
            host=settings.host,
            port=settings.port,
            source=settings.source,
            max_line_bytes=settings.max_line_bytes,
            queue_size=settings.queue_size,
        )

        self.registry.register(
            self.tcp_collector,
        )

        self.manager = IngestionManager(
            self.registry.collectors
            if hasattr(self.registry, "collectors")
            else (self.tcp_collector,),
        )

        self._stop_event = asyncio.Event()
        self._forward_task: asyncio.Task[None] | None = None
        self._started = False

    def request_stop(self) -> None:
        """Request graceful collector shutdown."""
        if self._stop_event.is_set():
            return

        logger.info("Collector runtime shutdown requested.")
        self._stop_event.set()

    def _install_signal_handlers(self) -> None:
        """Install SIGINT and SIGTERM handlers."""
        loop = asyncio.get_running_loop()

        for sig in (asyncio.signal.SIGINT if False else None,):
            del sig

        import signal

        for sig in (
            signal.SIGINT,
            signal.SIGTERM,
        ):
            try:
                loop.add_signal_handler(
                    sig,
                    self.request_stop,
                )
            except (NotImplementedError, RuntimeError):
                logger.debug(
                    "Signal handler for %s is unavailable.",
                    sig.name,
                )

    async def _forward_events(self) -> None:
        """Forward collector events into the Redis ingestion queue."""

        try:
            async for event in self.tcp_collector.collect():
                await self.queue.put(event)

        except asyncio.CancelledError:
            raise

        except Exception:
            logger.exception("Collector event forwarding failed.")
            raise

    async def start(self) -> None:
        """Start collectors and forward acquired events to Redis."""
        if self._started:
            raise RuntimeError("Collector runtime is already running.")

        self._started = True
        self._install_signal_handlers()

        logger.info(
            "Starting collector runtime (collector=%s, source=%s, listen=%s:%d, queue=%s).",
            self.settings.name,
            self.settings.source,
            self.settings.host,
            self.settings.port,
            self.settings.queue_name,
        )

        try:
            await self.redis.ping()
            logger.info("Redis connection verified.")

            await self.manager.start()

            self._forward_task = asyncio.create_task(
                self._forward_events(),
                name="collector-event-forwarder",
            )

            logger.info("Collector runtime is ready.")

            await self._stop_event.wait()

        finally:
            await self.close()

    async def close(self) -> None:
        """Stop collectors and close Redis."""
        if not self._started:
            return

        self._started = False

        logger.info("Stopping collector runtime.")

        if self._forward_task is not None:
            self._forward_task.cancel()

            await asyncio.gather(
                self._forward_task,
                return_exceptions=True,
            )

            self._forward_task = None

        try:
            await self.manager.stop()
        except Exception:
            logger.exception("Failed to stop collectors.")

        try:
            await self.redis.close()
        except Exception:
            logger.exception("Failed to close Redis client.")

        logger.info("Collector runtime stopped.")


async def run_collector() -> None:
    """Create and run the configured collector runtime."""
    settings = CollectorSettings.from_environment()

    runtime = CollectorRuntime(
        settings,
    )

    await runtime.start()
