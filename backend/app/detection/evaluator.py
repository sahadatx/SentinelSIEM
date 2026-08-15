from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from app.detection.context import DetectionContext
from app.detection.schema import DetectionRule, RuleCondition


class DetectionEvaluator:
    """Deterministic evaluator for declarative event rules."""

    def evaluate(
        self,
        rule: DetectionRule,
        context: DetectionContext,
    ) -> bool:
        if not rule.enabled:
            return False

        results = [
            self._evaluate_condition(condition, context)
            for condition in rule.conditions
        ]

        if rule.match == "all":
            return all(results)

        return any(results)

    def _evaluate_condition(
        self,
        condition: RuleCondition,
        context: DetectionContext,
    ) -> bool:
        actual = context.get(condition.field)
        expected = condition.value

        if condition.operator == "exists":
            return actual is not None

        if condition.operator == "equals":
            return bool(actual == expected)

        if condition.operator == "not_equals":
            return bool(actual != expected)

        if condition.operator == "in":
            return bool(actual in self._as_iterable(expected))

        if condition.operator == "not_in":
            return bool(actual not in self._as_iterable(expected))

        if condition.operator == "contains":
            return self._evaluate_contains(actual, expected)

        raise ValueError(
            f"unsupported detection operator: {condition.operator}"
        )

    @staticmethod
    def _evaluate_contains(
        actual: Any,
        expected: Any,
    ) -> bool:
        if isinstance(actual, str) and isinstance(expected, str):
            return expected in actual

        if isinstance(actual, Iterable) and not isinstance(
            actual,
            (str, bytes, dict),
        ):
            return bool(expected in actual)

        return False

    @staticmethod
    def _as_iterable(value: Any) -> tuple[Any, ...]:
        if isinstance(value, (list, tuple, set, frozenset)):
            return tuple(value)

        return (value,)
