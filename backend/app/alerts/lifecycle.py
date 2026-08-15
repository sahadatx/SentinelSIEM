from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from app.alerts.models import Alert, AlertAuditEntry, AlertStatus


class AlertLifecycleError(ValueError):
    """Raised when an invalid alert state transition is requested."""


_ALLOWED_TRANSITIONS: dict[
    AlertStatus,
    frozenset[AlertStatus],
] = {
    AlertStatus.NEW: frozenset(
        {
            AlertStatus.ACKNOWLEDGED,
            AlertStatus.SUPPRESSED,
        }
    ),
    AlertStatus.ACKNOWLEDGED: frozenset(
        {
            AlertStatus.INVESTIGATING,
            AlertStatus.ESCALATED,
            AlertStatus.RESOLVED,
        }
    ),
    AlertStatus.INVESTIGATING: frozenset(
        {
            AlertStatus.ESCALATED,
            AlertStatus.RESOLVED,
        }
    ),
    AlertStatus.ESCALATED: frozenset(
        {
            AlertStatus.INVESTIGATING,
            AlertStatus.RESOLVED,
        }
    ),
    AlertStatus.RESOLVED: frozenset(
        {
            AlertStatus.CLOSED,
            AlertStatus.INVESTIGATING,
        }
    ),
    AlertStatus.CLOSED: frozenset(),
    AlertStatus.SUPPRESSED: frozenset(),
}


class AlertLifecycle:
    """Validate and apply alert lifecycle transitions."""

    def can_transition(
        self,
        current: AlertStatus,
        target: AlertStatus,
    ) -> bool:
        """Return whether the requested status transition is allowed."""
        return target in _ALLOWED_TRANSITIONS[current]

    def transition(
        self,
        alert: Alert,
        target: AlertStatus,
        *,
        actor: str,
        reason: str = "",
        now: datetime | None = None,
    ) -> tuple[Alert, AlertAuditEntry]:
        """Apply a validated lifecycle transition and create its audit entry."""
        if not actor.strip():
            raise AlertLifecycleError("actor is required")

        if not self.can_transition(
            alert.status,
            target,
        ):
            raise AlertLifecycleError(
                "invalid alert transition: "
                f"{alert.status.value} -> {target.value}"
            )

        timestamp = now or datetime.now(UTC)

        updates: dict[str, object] = {
            "status": target,
            "updated_at": timestamp,
        }

        timestamp_fields: dict[AlertStatus, str] = {
            AlertStatus.ACKNOWLEDGED: "acknowledged_at",
            AlertStatus.INVESTIGATING: "investigating_at",
            AlertStatus.ESCALATED: "escalated_at",
            AlertStatus.RESOLVED: "resolved_at",
            AlertStatus.CLOSED: "closed_at",
            AlertStatus.SUPPRESSED: "suppressed_at",
        }

        timestamp_field = timestamp_fields.get(target)

        if timestamp_field is not None:
            updates[timestamp_field] = timestamp

        updated = alert.model_copy(
            update=updates,
        )

        audit = AlertAuditEntry(
            alert_id=UUID(str(alert.alert_id)),
            action="status_transition",
            actor=actor,
            from_status=alert.status,
            to_status=target,
            reason=reason,
            created_at=timestamp,
        )

        return updated, audit
