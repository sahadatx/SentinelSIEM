from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from app.detection.context import DetectionContext
from app.detection.schema import DetectionRule, RuleCondition


class DetectionEvaluator:
    """
    Deterministic evaluator for declarative detection rules.

    Responsibilities
    ----------------
    - Evaluate enabled detection rules against a DetectionContext.
    - Support all operators declared by RuleCondition.
    - Respect the rule's `all` / `any` match strategy.
    - Remain side-effect free and deterministic.

    Non-responsibilities
    --------------------
    - Does not load or persist detection rules.
    - Does not create alerts.
    - Does not calculate risk scores.
    - Does not perform suppression.
    - Does not mutate DetectionRule or DetectionContext.
    - Does not perform RBAC/permission checks.

    RBAC is enforced at the API/service boundary.
    """

    def evaluate(
        self,
        rule: DetectionRule,
        context: DetectionContext,
    ) -> bool:
        """
        Evaluate a single detection rule against an event context.

        Disabled rules never match.

        For `match="all"` every condition must match.

        For `match="any"` at least one condition must match.

        DetectionRule already validates that at least one condition exists,
        so both `all()` and `any()` operate on a non-empty condition set.
        """
        if not rule.enabled:
            return False

        condition_results = tuple(
            self._evaluate_condition(condition, context)
            for condition in rule.conditions
        )

        if rule.match == "all":
            return all(condition_results)

        if rule.match == "any":
            return any(condition_results)

        # DetectionRule uses a Literal for `match`, so this should normally
        # be unreachable. Keeping the explicit failure makes the evaluator
        # defensive if the model/schema changes in the future.
        raise ValueError(
            f"unsupported detection match strategy: {rule.match}"
        )

    def _evaluate_condition(
        self,
        condition: RuleCondition,
        context: DetectionContext,
    ) -> bool:
        """
        Evaluate one rule condition against the supplied context.
        """
        actual = context.get(condition.field)
        expected = condition.value
        operator = condition.operator

        if operator == "exists":
            return actual is not None

        if operator == "equals":
            return actual == expected

        if operator == "not_equals":
            return actual != expected

        if operator == "in":
            return self._evaluate_in(actual, expected)

        if operator == "not_in":
            return self._evaluate_not_in(actual, expected)

        if operator == "contains":
            return self._evaluate_contains(actual, expected)

        # `ConditionOperator` is a Literal, therefore normal validated
        # requests cannot reach this branch. It protects the evaluator
        # against invalid runtime values.
        raise ValueError(
            f"unsupported detection operator: {operator}"
        )

    @classmethod
    def _evaluate_in(
        cls,
        actual: Any,
        expected: Any,
    ) -> bool:
        """
        Return True when the actual value exists in the expected collection.

        A scalar expected value is treated as a single-item collection.
        """
        candidates = cls._as_iterable(expected)

        try:
            return actual in candidates
        except TypeError:
            return False

    @classmethod
    def _evaluate_not_in(
        cls,
        actual: Any,
        expected: Any,
    ) -> bool:
        """
        Return True when the actual value does not exist in the expected
        collection.
        """
        candidates = cls._as_iterable(expected)

        try:
            return actual not in candidates
        except TypeError:
            return False

    @staticmethod
    def _evaluate_contains(
        actual: Any,
        expected: Any,
    ) -> bool:
        """
        Evaluate the `contains` operator.

        Supported forms
        ---------------
        String:
            actual="authentication failure"
            expected="failure"

        Sequence/set:
            actual=["login", "authentication"]
            expected="login"

        Mapping:
            intentionally unsupported.

        Bytes:
            intentionally unsupported.

        This avoids treating dictionary keys or arbitrary objects as
        supported detection values unless explicitly defined by the
        evaluator contract.
        """
        if isinstance(actual, str) and isinstance(expected, str):
            return expected in actual

        if isinstance(actual, Iterable) and not isinstance(
            actual,
            (str, bytes, dict),
        ):
            try:
                return expected in actual
            except TypeError:
                return False

        return False

    @staticmethod
    def _as_iterable(
        value: Any,
    ) -> tuple[Any, ...]:
        """
        Normalize a condition value into a tuple.

        Collections supported as multi-value inputs:
        - list
        - tuple
        - set
        - frozenset

        All other values are treated as one scalar value.

        `None` therefore becomes `(None,)`, which keeps the operation
        deterministic and avoids silently interpreting None as an empty
        collection.
        """
        if isinstance(value, (list, tuple, set, frozenset)):
            return tuple(value)

        return (value,)