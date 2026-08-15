from __future__ import annotations

from dataclasses import dataclass

from app.alerts.models import Alert, AlertSeverity, AlertStatus


@dataclass(frozen=True, slots=True)
class EscalationPolicy:
    """Configurable policy for high-impact alert escalation."""

    enabled: bool = True
    severities: frozenset[AlertSeverity] = frozenset(
        {AlertSeverity.HIGH, AlertSeverity.CRITICAL}
    )
    minimum_risk_score: float = 80.0


class AlertEscalator:
    """Determine whether an alert should enter ESCALATED state."""

    def __init__(self, policy: EscalationPolicy | None = None) -> None:
        self._policy = policy or EscalationPolicy()

    def should_escalate(self, alert: Alert) -> bool:
        if not self._policy.enabled:
            return False
        if alert.status in {AlertStatus.RESOLVED, AlertStatus.CLOSED, AlertStatus.SUPPRESSED}:
            return False
        return (
            alert.severity in self._policy.severities
            or alert.risk_score >= self._policy.minimum_risk_score
        )
