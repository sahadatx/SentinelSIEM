from __future__ import annotations

import asyncio
import logging
import signal
from dataclasses import dataclass
from urllib.parse import urlparse

from app.core.config import Settings, get_settings
from app.domain.events.factory import to_canonical_event
from app.domain.events.models import RawEvent
from app.ingestion.pipeline import IngestionPipeline
from app.ingestion.queues.redis import RedisEventQueue
from app.storage.opensearch.client import OpenSearchClient
from app.storage.opensearch.events import OpenSearchEventRepository
from app.storage.redis.client import (
    RedisClient,
    WEBSOCKET_EVENTS_CHANNEL,
)

logger = logging.getLogger(__name__)


def _build_opensearch_hosts(
    url: str,
) -> list[dict[str, object]]:
    """Convert an OpenSearch URL into the client host format."""
    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError(
            "OpenSearch URL must use http:// or https://."
        )

    if not parsed.hostname:
        raise ValueError(
            "OpenSearch URL must contain a hostname."
        )

    port = parsed.port

    if port is None:
        port = 443 if parsed.scheme == "https" else 80

    return [
        {
            "host": parsed.hostname,
            "port": port,
        }
    ]


@dataclass(frozen=True, slots=True)
class WorkerSettings:
    """Validated configuration required by the ingestion worker."""

    redis_url: str
    opensearch_url: str
    opensearch_username: str
    opensearch_password: str
    opensearch_verify_certs: bool
    opensearch_ca_certs: str | None
    event_queue_name: str
    retry_delay_seconds: float

    @classmethod
    def from_application_settings(
        cls,
        settings: Settings,
    ) -> WorkerSettings:
        """
        Build worker configuration from centralized application settings.
        """

        settings.validate_ingestion_configuration()

        assert settings.redis_url is not None
        assert settings.opensearch_url is not None
        assert settings.opensearch_password is not None

        return cls(
            redis_url=settings.redis_url,
            opensearch_url=settings.opensearch_url,
            opensearch_username=settings.opensearch_username,
            opensearch_password=settings.opensearch_password,
            opensearch_verify_certs=settings.opensearch_verify_certs,
            opensearch_ca_certs=settings.opensearch_ca_certs,
            event_queue_name=settings.event_queue_name,
            retry_delay_seconds=settings.worker_retry_delay_seconds,
        )

    @classmethod
    def from_environment(cls) -> WorkerSettings:
        """
        Build worker configuration from the centralized Settings object.

        This method is retained as the worker-facing entry point for
        backward compatibility, but all environment loading and validation
        is delegated to Settings.
        """

        settings = get_settings()

        try:
            return cls.from_application_settings(settings)
        except Exception as exc:
            raise RuntimeError(
                "Ingestion worker configuration is invalid."
            ) from exc


class IngestionWorker:
    """Long-running Redis-backed ingestion worker."""

    def __init__(
        self,
        settings: WorkerSettings,
    ) -> None:
        self.settings = settings

        self.redis = RedisClient(
            settings.redis_url,
        )

        self.opensearch = OpenSearchClient(
            _build_opensearch_hosts(
                settings.opensearch_url,
            ),
            username=settings.opensearch_username,
            password=settings.opensearch_password,
            use_ssl=settings.opensearch_url.startswith(
                "https://",
            ),
            verify_certs=settings.opensearch_verify_certs,
            ca_certs=settings.opensearch_ca_certs,
        )

        self.repository = OpenSearchEventRepository(
            self.opensearch.client,
        )

        self.queue = RedisEventQueue(
            self.redis.client,
            queue_name=settings.event_queue_name,
        )

        self.pipeline = IngestionPipeline(
            queue=self.queue,
            processor=self._process_event,
        )

        self._stop_event = asyncio.Event()
        self._started = False

    async def _process_event(
        self,
        event: RawEvent,
    ) -> None:
        """
        Convert a raw event to canonical form, persist it,
        and publish it for realtime WebSocket delivery.
        """
        canonical = to_canonical_event(event)

        # Persist first. Realtime delivery only happens after
        # successful OpenSearch persistence.
        await self.repository.save(
            canonical,
        )

        # Publish the persisted canonical event through Redis
        # so the backend WebSocket process can deliver it to
        # authenticated subscribers.
        await self.redis.publish_json(
            WEBSOCKET_EVENTS_CHANNEL,
            canonical.model_dump(
                mode="json",
            ),
        )

        logger.debug(
            "Canonical event persisted and published "
            "for realtime delivery (event_id=%s).",
            canonical.event_id,
        )

    def request_stop(self) -> None:
        """Request graceful worker shutdown."""
        if self._stop_event.is_set():
            return

        logger.info(
            "Ingestion worker shutdown requested.",
        )
        self._stop_event.set()

    def _install_signal_handlers(self) -> None:
        """Install SIGINT/SIGTERM handlers when supported."""
        loop = asyncio.get_running_loop()

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

    async def _wait_before_retry(self) -> None:
        """Wait for shutdown or the configured retry delay."""
        try:
            await asyncio.wait_for(
                self._stop_event.wait(),
                timeout=self.settings.retry_delay_seconds,
            )
        except TimeoutError:
            return

    async def _verify_dependencies(self) -> None:
        """Verify Redis, OpenSearch, and the target event index."""
        await self.redis.ping()
        logger.info(
            "Redis connection verified.",
        )

        await self.opensearch.ping()
        logger.info(
            "OpenSearch connection verified.",
        )

        await self.repository.ensure_index()
        logger.info(
            "OpenSearch event index verified: %s",
            self.repository.index,
        )

    async def start(self) -> None:
        """Start the worker and process queued events."""
        if self._started:
            raise RuntimeError(
                "Ingestion worker is already running."
            )

        self._started = True
        self._install_signal_handlers()

        logger.info(
            "Starting ingestion worker (queue=%s, opensearch=%s).",
            self.settings.event_queue_name,
            self.settings.opensearch_url,
        )

        try:
            await self._verify_dependencies()

            logger.info(
                "Ingestion worker is ready.",
            )

            while not self._stop_event.is_set():
                try:
                    await self.pipeline.process_one()

                except asyncio.CancelledError:
                    raise

                except Exception:
                    logger.exception(
                        "Worker queue processing failed.",
                    )
                    await self._wait_before_retry()

        finally:
            await self.close()

    async def close(self) -> None:
        """Close worker-owned external connections."""
        if not self._started:
            return

        self._started = False

        logger.info(
            "Stopping ingestion worker.",
        )

        try:
            await self.opensearch.close()
        except Exception:
            logger.exception(
                "Failed to close OpenSearch client.",
            )

        try:
            await self.redis.close()
        except Exception:
            logger.exception(
                "Failed to close Redis client.",
            )

        logger.info(
            "Ingestion worker stopped.",
        )


async def run_worker() -> None:
    """Create and run the configured ingestion worker."""
    worker_settings = WorkerSettings.from_environment()

    worker = IngestionWorker(
        worker_settings,
    )

    await worker.start()