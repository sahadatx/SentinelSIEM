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

_DETECTION_EVALUATIONS_HELP = "Total detection engine evaluations."
_DETECTION_MATCHES_HELP = "Total detection results produced."
_DETECTION_SUPPRESSED_HELP = (
    "Total detection matches suppressed by duplicate suppression."
)
_DETECTION_FAILURES_HELP = "Total detection engine failures."
_DETECTION_LATENCY_HELP = (
    "Detection engine evaluation latency in seconds."
)
_PLUGIN_EVALUATIONS_HELP = "Total detector plugin evaluations."
_PLUGIN_FAILURES_HELP = "Total detector plugin evaluation failures."


class DetectionEngine:
    """Rule-driven engine with optional Phase 08 detector plugins."""

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
        event: CanonicalSecurityEvent | EnrichedEvent,
    ) -> tuple[DetectionResult, ...]:
        results: list[DetectionResult] = []

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

                for rule in self.registry.enabled():
                    matched = self.evaluator.evaluate(rule, context)

                    if not matched:
                        continue

                    event_key = str(event.event_id)
                    suppressed = self.suppression.is_suppressed(
                        rule.id,
                        event_key,
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
                    else:
                        REGISTRY.inc_counter(
                            "siem_detection_matches_total",
                            help_text=_DETECTION_MATCHES_HELP,
                        )

                    self.suppression.suppress(
                        rule.id,
                        event_key,
                    )

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
                        raise

                    results.extend(plugin_results)

                    if plugin_results:
                        REGISTRY.inc_counter(
                            "siem_detection_matches_total",
                            value=float(len(plugin_results)),
                            help_text=_DETECTION_MATCHES_HELP,
                        )

            except Exception:
                REGISTRY.inc_counter(
                    "siem_detection_failures_total",
                    help_text=_DETECTION_FAILURES_HELP,
                )
                raise

        return tuple(results)

    def evaluate_many(
        self,
        events: Iterable[
            CanonicalSecurityEvent | EnrichedEvent
        ],
    ) -> tuple[DetectionResult, ...]:
        results: list[DetectionResult] = []

        for event in events:
            results.extend(self.evaluate(event))

        return tuple(results)