from __future__ import annotations

import asyncio
import logging
import signal
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from app.alerts.manager import AlertManager
from app.alerts.service import AlertService
from app.correlation.bootstrap import (
    CorrelationRuntime,
    build_correlation_runtime,
)
from app.correlation.result import CorrelationResult
from app.core.config import Settings, get_settings
from app.detection.bootstrap import (
    DetectionRuntime,
    build_detection_runtime,
)
from app.detection.result import DetectionResult
from app.domain.events.models import (
    CanonicalSecurityEvent,
    RawEvent,
)
from app.ingestion.pipeline import IngestionPipeline
from app.ingestion.queues.redis import RedisEventQueue
from app.parsing.bootstrap import create_parsing_router
from app.parsing.router import ParsingRouter
from app.parsing.source_routes import SourceRouteResolver
from app.storage.opensearch.alerts import OpenSearchAlertRepository
from app.storage.opensearch.client import OpenSearchClient
from app.storage.opensearch.detections import (
    OpenSearchDetectionRepository,
)
from app.storage.opensearch.events import OpenSearchEventRepository
from app.storage.redis.client import (
    WEBSOCKET_EVENTS_CHANNEL,
    RedisClient,
)

logger = logging.getLogger(__name__)


# =========================================================
# Redis WebSocket Alert Channel
# =========================================================

WEBSOCKET_ALERTS_CHANNEL = "siem:websocket:alerts"


# =========================================================
# OpenSearch Configuration
# =========================================================


def _build_opensearch_hosts(
    url: str,
) -> list[dict[str, object]]:
    """
    Convert an OpenSearch URL into the client host format.

    Supported schemes:
        - http
        - https
    """

    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError(
            "OpenSearch URL must use http:// or https://.",
        )

    if not parsed.hostname:
        raise ValueError(
            "OpenSearch URL must contain a hostname.",
        )

    port = parsed.port

    if port is None:
        port = (
            443
            if parsed.scheme == "https"
            else 80
        )

    return [
        {
            "host": parsed.hostname,
            "port": port,
        },
    ]


# =========================================================
# Worker Settings
# =========================================================


@dataclass(frozen=True, slots=True)
class WorkerSettings:
    """
    Validated configuration required by the ingestion worker.
    """

    redis_url: str

    opensearch_url: str
    opensearch_username: str
    opensearch_password: str
    opensearch_verify_certs: bool
    opensearch_ca_certs: str | None
    opensearch_event_index: str

    event_queue_name: str

    retry_delay_seconds: float

    @classmethod
    def from_application_settings(
        cls,
        settings: Settings,
    ) -> WorkerSettings:
        """
        Build worker configuration from centralized
        application settings.
        """

        settings.validate_ingestion_configuration()

        assert settings.redis_url is not None
        assert settings.opensearch_url is not None
        assert settings.opensearch_password is not None

        return cls(
            redis_url=settings.redis_url,
            opensearch_url=settings.opensearch_url,
            opensearch_username=(
                settings.opensearch_username
            ),
            opensearch_password=(
                settings.opensearch_password
            ),
            opensearch_verify_certs=(
                settings.opensearch_verify_certs
            ),
            opensearch_ca_certs=(
                settings.opensearch_ca_certs
            ),
            opensearch_event_index=(
                settings.opensearch_event_index
            ),
            event_queue_name=settings.event_queue_name,
            retry_delay_seconds=(
                settings.worker_retry_delay_seconds
            ),
        )

    @classmethod
    def from_environment(
        cls,
    ) -> WorkerSettings:
        """
        Build worker configuration from the centralized
        Settings object.
        """

        settings = get_settings()

        try:
            return cls.from_application_settings(
                settings,
            )

        except Exception as exc:
            raise RuntimeError(
                "Ingestion worker configuration is invalid.",
            ) from exc


# =========================================================
# Ingestion Worker
# =========================================================


class IngestionWorker:
    """
    Long-running Redis-backed ingestion worker.

    Production flow:

        Redis Event Queue
                ↓
        IngestionPipeline
                ↓
        ParsingRouter
                ↓
        ParsingPipeline
                ↓
        Parser
                ↓
        Normalizer
                ↓
        Canonicalization
                ↓
        CanonicalSecurityEvent
                ↓
        EventRepository
                │
                ├───────────────────────────────┐
                ↓                               ↓
        DetectionEngine                 CorrelationEngine
                ↓                               ↓
        DetectionResult[]               CorrelationResult[]
                ↓                               ↓
        DetectionRepository              Correlation state
                ↓                               ↓
        DetectionAlertAdapter            CorrelationAlertAdapter
                ↓                               ↓
                └───────────────┬───────────────┘
                                ↓
                           AlertService
                                ↓
                           AlertManager
                                ↓
                          AlertRepository
                                ↓
                       Alert Redis Channel
                                ↓
                         Alert WebSocket

    Responsibilities:
        - Own Redis/OpenSearch infrastructure lifecycle.
        - Consume RawEvent instances.
        - Route events through the production parsing subsystem.
        - Persist canonical events.
        - Publish persisted canonical events.
        - Execute the detection runtime.
        - Persist every DetectionResult.
        - Execute the correlation runtime.
        - Convert detection results into alerts.
        - Convert correlation results into alerts.
        - Persist alerts through AlertManager.
        - Publish final alert states for realtime delivery.

    The worker does not:
        - Implement parsers.
        - Implement normalizers.
        - Implement canonical mapping.
        - Register parsing components.
        - Implement detection rules.
        - Implement correlation rules.
        - Implement alert-domain rules.
        - Implement lifecycle rules.
    """

    def __init__(
        self,
        settings: WorkerSettings,
        *,
        parsing_router: ParsingRouter | None = None,
        source_route_resolver: (
            SourceRouteResolver | None
        ) = None,
        detection_runtime: DetectionRuntime | None = None,
        correlation_runtime: (
            CorrelationRuntime | None
        ) = None,
        alert_manager: AlertManager | None = None,
        alert_repository: (
            OpenSearchAlertRepository | None
        ) = None,
        detection_repository: (
            OpenSearchDetectionRepository | None
        ) = None,
    ) -> None:
        """
        Initialize the ingestion worker.

        Runtime dependencies are injectable for tests and
        specialized deployments.

        When omitted, production runtimes/repositories are
        constructed automatically.
        """

        self.settings = settings

        # -------------------------------------------------
        # Redis
        # -------------------------------------------------

        self.redis = RedisClient(
            settings.redis_url,
        )

        # -------------------------------------------------
        # OpenSearch
        # -------------------------------------------------

        self.opensearch = OpenSearchClient(
            _build_opensearch_hosts(
                settings.opensearch_url,
            ),
            username=settings.opensearch_username,
            password=settings.opensearch_password,
            use_ssl=settings.opensearch_url.startswith(
                "https://",
            ),
            verify_certs=(
                settings.opensearch_verify_certs
            ),
            ca_certs=settings.opensearch_ca_certs,
        )

        # -------------------------------------------------
        # Event Repository
        # -------------------------------------------------

        self.repository = OpenSearchEventRepository(
            self.opensearch.client,
            index=settings.opensearch_event_index,
        )

        # -------------------------------------------------
        # Detection Result Repository
        # -------------------------------------------------
        #
        # Detection results are persisted independently
        # from alerts.
        #
        # IMPORTANT:
        #
        # Both normal and suppressed DetectionResults are
        # persisted.
        #
        # Alert creation happens only after persistence and
        # only for non-suppressed results.
        #

        self.detection_repository = (
            detection_repository
            if detection_repository is not None
            else OpenSearchDetectionRepository(
                self.opensearch.client,
            )
        )

        # -------------------------------------------------
        # Alert Repository
        # -------------------------------------------------

        self.alert_repository = (
            alert_repository
            if alert_repository is not None
            else OpenSearchAlertRepository(
                self.opensearch.client,
            )
        )

        # -------------------------------------------------
        # Event Queue
        # -------------------------------------------------

        self.queue = RedisEventQueue(
            self.redis.client,
            queue_name=settings.event_queue_name,
        )

        # -------------------------------------------------
        # Production Parsing Router
        # -------------------------------------------------

        self.parsing_router = (
            parsing_router
            if parsing_router is not None
            else create_parsing_router()
        )

        self.source_route_resolver = (
            source_route_resolver
            if source_route_resolver is not None
            else SourceRouteResolver()
        )

        # -------------------------------------------------
        # Detection Runtime
        # -------------------------------------------------
        #
        # The worker owns its own detection runtime because
        # the worker is a separate process from FastAPI.
        #

        self.detection_runtime = (
            detection_runtime
            if detection_runtime is not None
            else self._build_detection_runtime()
        )

        self.detection_engine = (
            self.detection_runtime.detection_engine
        )

        self.detection_service = (
            self.detection_runtime.detection_service
        )

        # -------------------------------------------------
        # Correlation Runtime
        # -------------------------------------------------

        self.correlation_runtime = (
            correlation_runtime
            if correlation_runtime is not None
            else self._build_correlation_runtime()
        )

        self.correlation_engine = (
            self.correlation_runtime.correlation_engine
        )

        # -------------------------------------------------
        # Alert Manager
        # -------------------------------------------------
        #
        # Detection and Correlation alerts both use the
        # same AlertManager.
        #

        self.alert_manager = (
            alert_manager
            if alert_manager is not None
            else AlertManager(
                repository=self.alert_repository,
                realtime_publisher=(
                    self._publish_alert_realtime
                ),
            )
        )

        # -------------------------------------------------
        # Alert Service
        # -------------------------------------------------
        #
        # AlertService owns:
        #   DetectionAlertAdapter
        #   CorrelationAlertAdapter
        #

        self.alert_service = AlertService(
            manager=self.alert_manager,
        )

        # -------------------------------------------------
        # Ingestion Pipeline
        # -------------------------------------------------

        self.pipeline = IngestionPipeline(
            queue=self.queue,
            processor=self._process_event,
        )

        # -------------------------------------------------
        # Lifecycle
        # -------------------------------------------------

        self._stop_event = asyncio.Event()
        self._started = False

    # =====================================================
    # Detection Runtime
    # =====================================================

    def _build_detection_runtime(
        self,
    ) -> DetectionRuntime:
        """
        Build the production detection runtime.

        Detection rule/plugin discovery remains centralized
        in app.detection.bootstrap.
        """

        project_root = Path(__file__).resolve().parents[3]

        rules_directory = (
            project_root
            / "rules"
            / "detection"
        )

        plugins_directory = (
            project_root
            / "plugins"
            / "detectors"
        )

        logger.info(
            "Building detection runtime "
            "(rules=%s, plugins=%s).",
            rules_directory,
            plugins_directory,
        )

        runtime = build_detection_runtime(
            rules_directory=rules_directory,
            plugins_directory=plugins_directory,
        )

        statistics = (
            runtime.detection_service.statistics()
        )

        logger.info(
            "Detection runtime ready "
            "(rules=%d, plugins=%d).",
            statistics.total_rules,
            statistics.total_plugins,
        )

        return runtime

    # =====================================================
    # Correlation Runtime
    # =====================================================

    def _build_correlation_runtime(
        self,
    ) -> CorrelationRuntime:
        """
        Build the production correlation runtime.

        Correlation rule discovery remains centralized in
        app.correlation.bootstrap.
        """

        project_root = Path(__file__).resolve().parents[3]

        rules_directory = (
            project_root
            / "rules"
            / "correlation"
        )

        logger.info(
            "Building correlation runtime "
            "(rules=%s).",
            rules_directory,
        )

        runtime = build_correlation_runtime(
            rules_directory=rules_directory,
        )

        logger.info(
            "Correlation runtime ready "
            "(rules=%d, enabled=%d).",
            len(runtime.rule_registry),
            len(
                runtime.rule_registry.enabled(),
            ),
        )

        return runtime

    # =====================================================
    # Event Processing
    # =====================================================

    async def _process_event(
        self,
        event: RawEvent,
    ) -> None:
        """
        Process one RawEvent through the complete
        production flow.

        Detection and Correlation remain independent.

        An event does not need to produce a DetectionResult
        in order to participate in correlation.
        """

        # -------------------------------------------------
        # Resolve parsing route
        # -------------------------------------------------

        route_name = (
            self.source_route_resolver.resolve(
                event,
            )
        )

        # -------------------------------------------------
        # Parse + Normalize + Canonicalize
        # -------------------------------------------------

        canonical = self.parsing_router.process(
            event,
            route_name=route_name,
        )

        if not isinstance(
            canonical,
            CanonicalSecurityEvent,
        ):
            raise TypeError(
                "ingestion parsing route must return "
                "CanonicalSecurityEvent",
            )

        # -------------------------------------------------
        # Persist canonical event FIRST
        # -------------------------------------------------

        await self.repository.save(
            canonical,
        )

        # -------------------------------------------------
        # Publish persisted event
        # -------------------------------------------------

        await self.redis.publish_json(
            WEBSOCKET_EVENTS_CHANNEL,
            canonical.model_dump(
                mode="json",
            ),
        )

        logger.debug(
            (
                "Canonical event persisted and published "
                "(event_id=%s)."
            ),
            canonical.event_id,
        )

        # =================================================
        # Detection
        # =================================================
        #
        # DetectionEngine only evaluates and returns
        # DetectionResult objects.
        #
        # DetectionResult persistence belongs here in the
        # worker orchestration layer.
        #

        detection_results = (
            self.detection_engine.evaluate(
                canonical,
            )
        )

        # -------------------------------------------------
        # Persist ALL DetectionResults
        # -------------------------------------------------
        #
        # This MUST happen before filtering suppressed
        # results for alert generation.
        #
        # Therefore:
        #
        #   suppressed=True  -> persisted
        #   suppressed=False -> persisted
        #
        # Only the latter can become an Alert.
        #

        valid_detection_results = tuple(
            result
            for result in detection_results
            if isinstance(
                result,
                DetectionResult,
            )
        )

        if valid_detection_results:
            logger.info(
                (
                    "Detection results generated "
                    "(event_id=%s, results=%d)."
                ),
                canonical.event_id,
                len(valid_detection_results),
            )

            for result in valid_detection_results:
                await self.detection_repository.save(
                    result,
                )

                logger.debug(
                    (
                        "Detection result persisted "
                        "(detection_id=%s, rule_id=%s, "
                        "event_id=%s, suppressed=%s)."
                    ),
                    result.detection_id,
                    result.rule_id,
                    result.event_id,
                    result.suppressed,
                )

            # ---------------------------------------------
            # Separate persisted results into:
            #
            #   - alert eligible
            #   - suppressed
            # ---------------------------------------------

            alert_results = tuple(
                result
                for result in valid_detection_results
                if not result.suppressed
            )

            suppressed_count = (
                len(valid_detection_results)
                - len(alert_results)
            )

            if suppressed_count:
                logger.debug(
                    (
                        "Detection results suppressed "
                        "after persistence "
                        "(event_id=%s, suppressed=%d)."
                    ),
                    canonical.event_id,
                    suppressed_count,
                )

            # ---------------------------------------------
            # DetectionResult → AlertService
            # ---------------------------------------------

            if alert_results:
                detection_alerts = (
                    self.alert_service
                    .create_from_detections(
                        alert_results,
                        actor="detection-engine",
                    )
                )

                # -----------------------------------------
                # Automatic escalation
                # -----------------------------------------

                for alert in detection_alerts:
                    final_alert = (
                        self.alert_manager
                        .evaluate_escalation(
                            alert.alert_id,
                            actor="detection-engine",
                        )
                    )

                    logger.info(
                        (
                            "Detection alert generated "
                            "(alert_id=%s, rule_id=%s, "
                            "event_id=%s, status=%s, "
                            "severity=%s, "
                            "risk_score=%.1f)."
                        ),
                        final_alert.alert_id,
                        final_alert.rule_id,
                        canonical.event_id,
                        final_alert.status.value,
                        final_alert.severity.value,
                        final_alert.risk_score,
                    )

        else:
            logger.debug(
                "No detection results for event_id=%s.",
                canonical.event_id,
            )

        # =================================================
        # Correlation
        # =================================================
        #
        # Correlation always runs independently from
        # Detection.
        #

        correlation_results = (
            self.correlation_engine.evaluate(
                canonical,
            )
        )

        if not correlation_results:
            logger.debug(
                (
                    "No correlation matches for "
                    "event_id=%s."
                ),
                canonical.event_id,
            )

            return

        logger.info(
            (
                "Correlation matches generated "
                "(event_id=%s, matches=%d)."
            ),
            canonical.event_id,
            len(correlation_results),
        )

        # -------------------------------------------------
        # CorrelationResult validation
        # -------------------------------------------------

        valid_correlation_results = tuple(
            result
            for result in correlation_results
            if isinstance(
                result,
                CorrelationResult,
            )
        )

        if not valid_correlation_results:
            logger.warning(
                (
                    "Correlation engine returned no "
                    "valid CorrelationResult objects "
                    "(event_id=%s)."
                ),
                canonical.event_id,
            )

            return

        # -------------------------------------------------
        # CorrelationResult → AlertService
        # -------------------------------------------------

        correlation_alerts = (
            self.alert_service
            .create_from_correlations(
                valid_correlation_results,
                actor="correlation-engine",
            )
        )

        # -------------------------------------------------
        # Automatic escalation
        # -------------------------------------------------

        for alert in correlation_alerts:
            final_alert = (
                self.alert_manager
                .evaluate_escalation(
                    alert.alert_id,
                    actor="correlation-engine",
                )
            )

            logger.info(
                (
                    "Correlation alert generated "
                    "(alert_id=%s, rule_id=%s, "
                    "correlation_id=%s, status=%s, "
                    "severity=%s, "
                    "risk_score=%.1f)."
                ),
                final_alert.alert_id,
                final_alert.rule_id,
                final_alert.source_id,
                final_alert.status.value,
                final_alert.severity.value,
                final_alert.risk_score,
            )

    # =====================================================
    # Alert Realtime Publisher
    # =====================================================

    async def _publish_alert_realtime(
        self,
        payload: dict[str, object],
    ) -> int:
        """
        Publish an alert payload to the dedicated Redis
        WebSocket channel.
        """

        return await self.redis.publish_json(
            WEBSOCKET_ALERTS_CHANNEL,
            payload,
        )

    # =====================================================
    # Shutdown Request
    # =====================================================

    def request_stop(self) -> None:
        """
        Request graceful worker shutdown.
        """

        if self._stop_event.is_set():
            return

        logger.info(
            "Ingestion worker shutdown requested.",
        )

        self._stop_event.set()

    # =====================================================
    # Signal Handling
    # =====================================================

    def _install_signal_handlers(self) -> None:
        """
        Install SIGINT/SIGTERM handlers when supported.
        """

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

            except (
                NotImplementedError,
                RuntimeError,
            ):
                logger.debug(
                    "Signal handler for %s is unavailable.",
                    sig.name,
                )

    # =====================================================
    # Retry / Shutdown Wait
    # =====================================================

    async def _wait_before_retry(self) -> None:
        """
        Wait for shutdown or the configured retry delay.
        """

        try:
            await asyncio.wait_for(
                self._stop_event.wait(),
                timeout=self.settings.retry_delay_seconds,
            )

        except TimeoutError:
            return

    # =====================================================
    # Dependency Verification
    # =====================================================

    async def _verify_dependencies(self) -> None:
        """
        Verify Redis, OpenSearch and all required indexes.
        """

        # -------------------------------------------------
        # Redis
        # -------------------------------------------------

        await self.redis.ping()

        logger.info(
            "Redis connection verified.",
        )

        # -------------------------------------------------
        # OpenSearch
        # -------------------------------------------------

        await self.opensearch.ping()

        logger.info(
            "OpenSearch connection verified.",
        )

        # -------------------------------------------------
        # Event index
        # -------------------------------------------------

        await self.repository.ensure_index()

        logger.info(
            "OpenSearch event index verified: %s",
            self.repository.index,
        )

        # -------------------------------------------------
        # Detection result index
        # -------------------------------------------------

        await self.detection_repository.ensure_index()

        logger.info(
            "OpenSearch detection result index verified: %s",
            self.detection_repository.index,
        )

        # -------------------------------------------------
        # Alert indexes
        # -------------------------------------------------

        await self.alert_repository.ensure_index()

        logger.info(
            "OpenSearch alert indexes verified.",
        )

    # =====================================================
    # Worker Start
    # =====================================================

    async def start(self) -> None:
        """
        Start the worker and process queued events.
        """

        if self._started:
            raise RuntimeError(
                "Ingestion worker is already running.",
            )

        self._started = True

        self._install_signal_handlers()

        logger.info(
            (
                "Starting ingestion worker "
                "(queue=%s, opensearch=%s, "
                "event_index=%s, "
                "detection_index=%s, "
                "alert_index=%s)."
            ),
            self.settings.event_queue_name,
            self.settings.opensearch_url,
            self.settings.opensearch_event_index,
            getattr(
                self.detection_repository,
                "index",
                "unknown",
            ),
            getattr(
                self.alert_repository,
                "index",
                "unknown",
            ),
        )

        try:
            # ---------------------------------------------
            # Verify infrastructure
            # ---------------------------------------------

            await self._verify_dependencies()

            detection_statistics = (
                self.detection_service.statistics()
            )

            logger.info(
                (
                    "Ingestion worker is ready "
                    "(detection_rules=%d, "
                    "detection_plugins=%d, "
                    "correlation_rules=%d, "
                    "enabled_correlation_rules=%d)."
                ),
                detection_statistics.total_rules,
                detection_statistics.total_plugins,
                len(
                    self.correlation_runtime
                    .rule_registry
                ),
                len(
                    self.correlation_runtime
                    .rule_registry
                    .enabled()
                ),
            )

            # ---------------------------------------------
            # Processing loop
            # ---------------------------------------------

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

    # =====================================================
    # Worker Shutdown
    # =====================================================

    async def close(self) -> None:
        """
        Close worker-owned external connections.

        Shutdown is defensive so failure of one external
        dependency does not prevent the other from closing.
        """

        if not self._started:
            return

        self._started = False

        logger.info(
            "Stopping ingestion worker.",
        )

        # -------------------------------------------------
        # OpenSearch
        # -------------------------------------------------

        try:
            await self.opensearch.close()

        except Exception:
            logger.exception(
                "Failed to close OpenSearch client.",
            )

        # -------------------------------------------------
        # Redis
        # -------------------------------------------------

        try:
            await self.redis.close()

        except Exception:
            logger.exception(
                "Failed to close Redis client.",
            )

        logger.info(
            "Ingestion worker stopped.",
        )


# =========================================================
# Worker Entrypoint
# =========================================================


async def run_worker() -> None:
    """
    Create and run the configured ingestion worker.
    """

    worker_settings = (
        WorkerSettings.from_environment()
    )

    worker = IngestionWorker(
        worker_settings,
    )

    await worker.start()


# =========================================================
# Public API
# =========================================================

__all__ = [
    "IngestionWorker",
    "WorkerSettings",
    "run_worker",
]