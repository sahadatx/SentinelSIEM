from __future__ import annotations

from collections.abc import Sequence

from app.correlation.context import CorrelationEvent, get_field, matches
from app.correlation.schema import CorrelationRule


def evaluate_threshold(events: Sequence[CorrelationEvent], rule: CorrelationRule) -> bool:
    if rule.threshold is None:
        return False
    return len(events) >= rule.threshold


def evaluate_sequence(
    events: Sequence[CorrelationEvent],
    rule: CorrelationRule,
) -> bool:
    if not rule.conditions:
        return False

    step = 0
    for event in events:
        condition = rule.conditions[step]
        if condition.equals is not None and not matches(
            event, condition.field, condition.equals
        ):
            continue
        if condition.exists is not None:
            exists = get_field(event, condition.field) is not None
            if exists != condition.exists:
                continue
        step += 1
        if step == len(rule.conditions):
            return True
    return False
