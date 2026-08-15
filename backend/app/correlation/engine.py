from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from app.correlation.context import CorrelationEvent, group_key
from app.correlation.evaluator import evaluate_sequence, evaluate_threshold
from app.correlation.registry import CorrelationRuleRegistry
from app.correlation.result import CorrelationResult
from app.correlation.schema import CorrelationMode
from app.correlation.state import CorrelationState
from app.correlation.window import within_window


class CorrelationEngine:
    """Stateful, bounded-window multi-event correlation engine."""

    def __init__(self, registry: CorrelationRuleRegistry) -> None:
        self._registry = registry
        self._state: dict[tuple[str, tuple[object, ...]], CorrelationState] = {}

    def evaluate(self, event: CorrelationEvent) -> tuple[CorrelationResult, ...]:
        results: list[CorrelationResult] = []
        event_time = event.timestamp

        for rule in self._registry.enabled():
            key = (rule.id, group_key(event, rule.group_by))
            state = self._state.get(key)

            if state is None or not within_window(
                state.started_at,
                event_time,
                rule.window_seconds,
            ):
                state = CorrelationState(started_at=event_time)
                self._state[key] = state

            state.add(event)

            matched = (
                evaluate_threshold(state.events, rule)
                if rule.mode is CorrelationMode.THRESHOLD
                else evaluate_sequence(state.events, rule)
            )

            if matched:
                event_ids = tuple(str(item.event_id) for item in state.events)
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
                # Consume the matched window to prevent repeated alerts from
                # the same evidence. Future events begin a fresh correlation.
                self._state.pop(key, None)

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
