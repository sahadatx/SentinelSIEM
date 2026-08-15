from __future__ import annotations

from dataclasses import dataclass

from app.alerts.models import Alert


@dataclass(frozen=True, slots=True)
class SuppressionPolicy:
    """Deterministic suppression policy for duplicate/noisy alerts."""

    enabled: bool = True
    minimum_occurrences: int = 10
    priority_floor: frozenset[str] = frozenset({"critical"})


class AlertSuppression:
    """Decide whether an alert should be suppressed."""

    def __init__(self, policy: SuppressionPolicy | None = None) -> None:
        self._policy = policy or SuppressionPolicy()

    def should_suppress(self, alert: Alert) -> bool:
        if not self._policy.enabled:
            return False
        if alert.priority in self._policy.priority_floor:
            return False
        return alert.occurrence_count >= self._policy.minimum_occurrences
