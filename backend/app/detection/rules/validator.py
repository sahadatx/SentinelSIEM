from __future__ import annotations

from app.detection.schema import DetectionRule


class DetectionRuleValidator:
    """Semantic validation beyond Pydantic schema validation."""

    def validate(self, rule: DetectionRule) -> None:
        if rule.match == "any" and len(rule.conditions) < 1:
            raise ValueError(f"rule {rule.id} requires at least one condition")

        for condition in rule.conditions:
            if condition.operator in {"in", "not_in"}:
                if not isinstance(condition.value, list):
                    raise ValueError(
                        f"rule {rule.id}: {condition.operator} requires a list value"
                    )
            elif condition.operator == "exists" and condition.value is not None:
                raise ValueError(
                    f"rule {rule.id}: exists must not define value"
                )
