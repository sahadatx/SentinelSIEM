from __future__ import annotations

from uuid import UUID

from app.alerts.manager import AlertManager
from app.alerts.models import Alert, AlertAuditEntry, AlertCreate, AlertStatus


class AlertService:
    """Application-facing alert service; orchestration stays outside domain models."""

    def __init__(self, manager: AlertManager | None = None) -> None:
        self._manager = manager or AlertManager()

    def create_from_result(self, data: AlertCreate, *, actor: str = "system") -> Alert:
        return self._manager.create(data, actor=actor)

    def transition(
        self,
        alert_id: UUID,
        status: AlertStatus,
        *,
        actor: str,
        reason: str = "",
    ) -> Alert:
        return self._manager.transition(
            alert_id,
            status,
            actor=actor,
            reason=reason,
        )

    def assign(
        self,
        alert_id: UUID,
        *,
        assignee: str | None,
        ownership_group: str | None = None,
        actor: str,
    ) -> Alert:
        return self._manager.assign(
            alert_id,
            assignee=assignee,
            ownership_group=ownership_group,
            actor=actor,
        )

    def get(self, alert_id: UUID) -> Alert:
        return self._manager.get(alert_id)

    def list(self) -> list[Alert]:
        return self._manager.list_alerts()

    def audit_history(self, alert_id: UUID) -> tuple[AlertAuditEntry, ...]:
        return self._manager.audit_history(alert_id)
