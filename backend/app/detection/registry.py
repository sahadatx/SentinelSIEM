from __future__ import annotations

from app.detection.schema import DetectionRule


class DetectionRuleRegistry:
    """In-memory registry of validated Phase 07 detection rules."""

    def __init__(self) -> None:
        self._rules: dict[str, DetectionRule] = {}

    def register(self, rule: DetectionRule) -> None:
        if rule.id in self._rules:
            raise ValueError(f"duplicate detection rule: {rule.id}")
        self._rules[rule.id] = rule

    def replace(self, rule: DetectionRule) -> None:
        self._rules[rule.id] = rule

    def get(self, rule_id: str) -> DetectionRule | None:
        return self._rules.get(rule_id)

    def all(self) -> tuple[DetectionRule, ...]:
        return tuple(self._rules.values())

    def enabled(self) -> tuple[DetectionRule, ...]:
        return tuple(rule for rule in self._rules.values() if rule.enabled)

    def clear(self) -> None:
        self._rules.clear()
