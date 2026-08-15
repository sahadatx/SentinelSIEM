from __future__ import annotations

from collections.abc import Iterable

from app.detection.context import DetectionContext
from app.detection.evaluator import DetectionEvaluator
from app.detection.plugin_registry import DetectorPluginRegistry
from app.detection.registry import DetectionRuleRegistry
from app.detection.result import DetectionResult
from app.detection.suppression import DetectionSuppression
from app.domain.events.models import CanonicalSecurityEvent, EnrichedEvent


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
        context = DetectionContext(event)
        results: list[DetectionResult] = []

        for rule in self.registry.enabled():
            if not self.evaluator.evaluate(rule, context):
                continue

            event_key = str(event.event_id)
            suppressed = self.suppression.is_suppressed(rule.id, event_key)

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
            self.suppression.suppress(rule.id, event_key)

        for plugin in self.plugins.enabled():
            results.extend(plugin.detect(event))

        return tuple(results)

    def evaluate_many(
        self,
        events: Iterable[CanonicalSecurityEvent | EnrichedEvent],
    ) -> tuple[DetectionResult, ...]:
        results: list[DetectionResult] = []

        for event in events:
            results.extend(self.evaluate(event))

        return tuple(results)
