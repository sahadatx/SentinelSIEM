from __future__ import annotations

from collections.abc import Iterable

from app.core.metrics import REGISTRY, Timer
from app.detection.context import DetectionContext
from app.detection.evaluator import DetectionEvaluator
from app.detection.plugin_registry import DetectorPluginRegistry
from app.detection.registry import DetectionRuleRegistry
from app.detection.result import DetectionResult
from app.detection.suppression import DetectionSuppression
from app.domain.events.models import CanonicalSecurityEvent, EnrichedEvent


_DETECTION_EVALUATIONS_HELP = (
    "Total detection engine evaluations."
)

_DETECTION_MATCHES_HELP = (
    "Total detection results produced."
)

_DETECTION_SUPPRESSED_HELP = (
    "Total detection matches suppressed by duplicate suppression."
)

_DETECTION_FAILURES_HELP = (
    "Total detection engine failures."
)

_DETECTION_LATENCY_HELP = (
    "Detection engine evaluation latency in seconds."
)

_PLUGIN_EVALUATIONS_HELP = (
    "Total detector plugin evaluations."
)

_PLUGIN_FAILURES_HELP = (
    "Total detector plugin evaluation failures."
)


DetectionEvent = CanonicalSecurityEvent | EnrichedEvent


class DetectionEngine:
    """
    Rule-driven detection engine with optional detector plugins.

    The engine evaluates enabled detection rules against canonical security
    events and returns validated DetectionResult objects.

    Responsibilities
    ----------------
    - Evaluate enabled detection rules.
    - Build DetectionContext instances.
    - Apply duplicate rule/event suppression.
    - Execute enabled detector plugins.
    - Return detection results.
    - Record detection and plugin metrics.

    Non-responsibilities
    --------------------
    - Does not persist detection results.
    - Does not create alerts.
    - Does not manage incidents.
    - Does not calculate risk scores.
    - Does not perform RBAC.
    - Does not manage detection rule CRUD.
    - Does not provide distributed suppression.

    RBAC is enforced at the API/service boundary.
    Persistence belongs to the repository/storage layer.
    Alert creation belongs to the Alert subsystem.
    """

    def __init__(
        self,
        registry: DetectionRuleRegistry,
        *,
        evaluator: DetectionEvaluator | None = None,
        suppression: DetectionSuppression | None = None,
        plugin_registry: DetectorPluginRegistry | None = None,
    ) -> None:
        self.registry = registry
        self.evaluator = evaluator or DetectionEvaluator()
        self.suppression = suppression or DetectionSuppression()
        self.plugins = plugin_registry or DetectorPluginRegistry()

    def evaluate(
        self,
        event: DetectionEvent,
    ) -> tuple[DetectionResult, ...]:
        """
        Evaluate one event against all enabled rules and detector plugins.

        Rule evaluation and plugin evaluation are both performed within the
        same engine invocation.

        A plugin failure is isolated from the remaining plugins and rule
        evaluation. The failure is recorded in metrics and evaluation
        continues with the next plugin.

        Unexpected engine-level failures are counted and re-raised.
        """
        REGISTRY.inc_counter(
            "siem_detection_evaluations_total",
            help_text=_DETECTION_EVALUATIONS_HELP,
        )

        with Timer(
            REGISTRY,
            "siem_detection_latency_seconds",
            help_text=_DETECTION_LATENCY_HELP,
        ):
            try:
                context = DetectionContext(event)
                results: list[DetectionResult] = []

                results.extend(
                    self._evaluate_rules(
                        event=event,
                        context=context,
                    )
                )

                results.extend(
                    self._evaluate_plugins(event)
                )

                return tuple(results)

            except Exception:
                REGISTRY.inc_counter(
                    "siem_detection_failures_total",
                    help_text=_DETECTION_FAILURES_HELP,
                )
                raise

    def evaluate_many(
        self,
        events: Iterable[DetectionEvent],
    ) -> tuple[DetectionResult, ...]:
        """
        Evaluate multiple events sequentially.

        Each event is evaluated independently through ``evaluate()``.

        If an engine-level exception escapes from an individual event,
        evaluation stops and that exception is propagated to the caller.
        """
        results: list[DetectionResult] = []

        for event in events:
            results.extend(self.evaluate(event))

        return tuple(results)

    def _evaluate_rules(
        self,
        *,
        event: DetectionEvent,
        context: DetectionContext,
    ) -> list[DetectionResult]:
        """
        Evaluate all currently enabled detection rules.
        """
        results: list[DetectionResult] = []

        event_id = str(event.event_id)

        for rule in self.registry.enabled():
            matched = self.evaluator.evaluate(
                rule,
                context,
            )

            if not matched:
                continue

            suppressed = self.suppression.is_suppressed(
                rule.id,
                event_id,
            )

            result = DetectionResult(
                rule_id=rule.id,
                rule_name=rule.name,
                event_id=event.event_id,
                severity=rule.severity,
                category=rule.category,
                description=rule.description,
                tags=tuple(rule.tags),
                suppressed=suppressed,
            )

            results.append(result)

            if suppressed:
                REGISTRY.inc_counter(
                    "siem_detection_suppressed_total",
                    help_text=_DETECTION_SUPPRESSED_HELP,
                )
                continue

            REGISTRY.inc_counter(
                "siem_detection_matches_total",
                help_text=_DETECTION_MATCHES_HELP,
            )

            self.suppression.suppress(
                rule.id,
                event_id,
            )

        return results

    def _evaluate_plugins(
        self,
        event: DetectionEvent,
    ) -> list[DetectionResult]:
        """
        Evaluate all enabled detector plugins.

        Plugin failures are isolated so that one broken plugin does not
        prevent the rule engine or other detector plugins from processing
        the same event.
        """
        results: list[DetectionResult] = []

        for plugin in self.plugins.enabled():
            plugin_id = plugin.metadata.id

            REGISTRY.inc_counter(
                "siem_detector_plugin_evaluations_total",
                help_text=_PLUGIN_EVALUATIONS_HELP,
                labels={"plugin": plugin_id},
            )

            try:
                plugin_results = plugin.detect(event)
            except Exception:
                REGISTRY.inc_counter(
                    "siem_detector_plugin_failures_total",
                    help_text=_PLUGIN_FAILURES_HELP,
                    labels={"plugin": plugin_id},
                )

                # Plugin failure is isolated from the main detection
                # pipeline. Continue evaluating the remaining plugins.
                continue

            validated_results = self._validate_plugin_results(
                plugin_results
            )

            if not validated_results:
                continue

            results.extend(validated_results)

            REGISTRY.inc_counter(
                "siem_detection_matches_total",
                value=float(len(validated_results)),
                help_text=_DETECTION_MATCHES_HELP,
            )

        return results

    @staticmethod
    def _validate_plugin_results(
        plugin_results: Iterable[DetectionResult],
    ) -> tuple[DetectionResult, ...]:
        """
        Validate and normalize results returned by detector plugins.

        Plugins are expected to return DetectionResult instances. The
        explicit validation boundary prevents invalid plugin output from
        silently entering the detection pipeline.
        """
        validated: list[DetectionResult] = []

        for result in plugin_results:
            if isinstance(result, DetectionResult):
                validated.append(result)
                continue

            validated.append(
                DetectionResult.model_validate(result)
            )

        return tuple(validated)