from __future__ import annotations

from collections.abc import Sequence

from app.correlation.context import CorrelationEvent, get_field, matches
from app.correlation.schema import CorrelationRule


def _matches_conditions(
    event: CorrelationEvent,
    rule: CorrelationRule,
) -> bool:
    """Return True when an event satisfies every rule condition."""

    if not rule.conditions:
        return True

    for condition in rule.conditions:
        if condition.equals is not None:
            if not matches(event, condition.field, condition.equals):
                return False

        if condition.exists is not None:
            exists = get_field(event, condition.field) is not None
            if exists != condition.exists:
                return False

    return True


def evaluate_threshold(
    events: Sequence[CorrelationEvent],
    rule: CorrelationRule,
) -> bool:
    """Evaluate a threshold using only events matching rule conditions."""

    if rule.threshold is None:
        return False

    matching_events = [
        event
        for event in events
        if _matches_conditions(event, rule)
    ]

    return len(matching_events) >= rule.threshold


def evaluate_sequence(
    events: Sequence[CorrelationEvent],
    rule: CorrelationRule,
) -> bool:
    """Evaluate an ordered sequence of correlation conditions."""

    if not rule.conditions:
        return False

    step = 0

    for event in events:
        condition = rule.conditions[step]

        if condition.equals is not None and not matches(
            event,
            condition.field,
            condition.equals,
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
