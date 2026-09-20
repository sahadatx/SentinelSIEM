from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from app.core.metrics import REGISTRY, Timer
from app.correlation.context import (
    CorrelationEvent,
    get_field,
    group_key,
    matches,
)
from app.correlation.evaluator import (
    evaluate_sequence,
    evaluate_threshold,
)
from app.correlation.registry import CorrelationRuleRegistry
from app.correlation.result import CorrelationResult
from app.correlation.schema import CorrelationMode, CorrelationRule
from app.correlation.state import CorrelationState
from app.correlation.window import within_window


class CorrelationEngine:
    """Stateful, bounded-window multi-event correlation engine."""

    def __init__(self, registry: CorrelationRuleRegistry) -> None:
        self._registry = registry
        self._state: dict[
            tuple[str, tuple[object, ...]],
            CorrelationState,
        ] = {}

    @staticmethod
    def _event_matches_rule(
        event: CorrelationEvent,
        rule: CorrelationRule,
    ) -> bool:
        """Return True when an event satisfies all rule conditions."""

        if not rule.conditions:
            return True

        for condition in rule.conditions:
            if condition.equals is not None:
                if not matches(
                    event,
                    condition.field,
                    condition.equals,
                ):
                    return False

            if condition.exists is not None:
                exists = get_field(event, condition.field) is not None
                if exists != condition.exists:
                    return False

        return True

    def evaluate(
        self,
        event: CorrelationEvent,
    ) -> tuple[CorrelationResult, ...]:
        results: list[CorrelationResult] = []

        REGISTRY.inc_counter(
            "siem_correlation_evaluations_total",
            help_text="Total correlation engine evaluations.",
        )

        with Timer(
            REGISTRY,
            "siem_correlation_latency_seconds",
            help_text="Correlation engine evaluation latency in seconds.",
        ):
            try:
                event_time = event.timestamp

                for rule in self._registry.enabled():
                    key = (
                        rule.id,
                        group_key(event, rule.group_by),
                    )

                    state = self._state.get(key)

                    if state is None or not within_window(
                        state.started_at,
                        event_time,
                        rule.window_seconds,
                    ):
                        state = CorrelationState(
                            started_at=event_time,
                        )
                        self._state[key] = state

                    if rule.mode is CorrelationMode.THRESHOLD:
                        if not self._event_matches_rule(event, rule):
                            continue

                        state.add(event)

                        matched = evaluate_threshold(
                            state.events,
                            rule,
                        )

                    else:
                        state.add(event)

                        matched = evaluate_sequence(
                            state.events,
                            rule,
                        )

                    if not matched:
                        continue

                    event_ids = tuple(
                        str(item.event_id)
                        for item in state.events
                    )

                    results.append(
                        CorrelationResult(
                            correlation_id=str(uuid4()),
                            rule_id=rule.id,
                            event_ids=event_ids,
                            severity=rule.severity,
                            description=rule.description,
                            detected_at=datetime.now(UTC),
                            group_key=key[1],
                            evidence_count=len(event_ids),
                        )
                    )

                    REGISTRY.inc_counter(
                        "siem_correlation_matches_total",
                        help_text="Total correlation rule matches.",
                    )

                    # Consume the matched window to prevent repeated
                    # alerts from the same evidence. Future events
                    # begin a fresh correlation.
                    self._state.pop(key, None)

            except Exception:
                REGISTRY.inc_counter(
                    "siem_correlation_failures_total",
                    help_text="Total correlation engine failures.",
                )
                raise

        return tuple(results)

    def evaluate_many(
        self,
        events: list[CorrelationEvent],
    ) -> tuple[CorrelationResult, ...]:
        results: list[CorrelationResult] = []

        for event in events:
            results.extend(self.evaluate(event))

        return tuple(results)

    def clear(self) -> None:
        self._state.clear()
