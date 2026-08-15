from __future__ import annotations

from collections.abc import Iterable

from app.correlation.schema import CorrelationRule


class CorrelationRuleRegistry:
    """In-memory registry for validated correlation rules."""

    def __init__(self, rules: Iterable[CorrelationRule] = ()) -> None:
        self._rules: dict[str, CorrelationRule] = {}
        for rule in rules:
            self.register(rule)

    def register(self, rule: CorrelationRule) -> None:
        if rule.id in self._rules:
            raise ValueError(f"duplicate correlation rule: {rule.id}")
        self._rules[rule.id] = rule

    def get(self, rule_id: str) -> CorrelationRule | None:
        return self._rules.get(rule_id)

    def enabled(self) -> tuple[CorrelationRule, ...]:
        return tuple(rule for rule in self._rules.values() if rule.enabled)

    def all(self) -> tuple[CorrelationRule, ...]:
        return tuple(self._rules.values())

    def __len__(self) -> int:
        return len(self._rules)
