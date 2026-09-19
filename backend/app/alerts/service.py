from __future__ import annotations

from uuid import UUID

from app.alerts.correlation_adapter import CorrelationAlertAdapter
from app.alerts.detection_adapter import DetectionAlertAdapter
from app.alerts.manager import AlertManager
from app.alerts.models import (
    Alert,
    AlertAuditEntry,
    AlertCreate,
    AlertStatus,
)
from app.correlation.result import CorrelationResult
from app.detection.result import DetectionResult


class AlertService:
    """
    Application-facing alert orchestration service.

    Responsibilities:

        DetectionResult
              ↓
        DetectionAlertAdapter
              ↓
        AlertCreate
              ↓
        AlertManager
              ↓
        AlertRepository


        CorrelationResult
              ↓
        CorrelationAlertAdapter
              ↓
        AlertCreate
              ↓
        AlertManager
              ↓
        AlertRepository

    The service coordinates application workflows but does not contain
    alert-domain rules itself.
    """

    def __init__(
        self,
        manager: AlertManager | None = None,
        adapter: DetectionAlertAdapter | None = None,
        correlation_adapter: CorrelationAlertAdapter | None = None,
    ) -> None:
        self._manager = manager or AlertManager()

        self._adapter = (
            adapter
            or DetectionAlertAdapter()
        )

        self._correlation_adapter = (
            correlation_adapter
            or CorrelationAlertAdapter()
        )

    # ------------------------------------------------------------------
    # Detection → Alert
    # ------------------------------------------------------------------

    def create_from_result(
        self,
        data: AlertCreate,
        *,
        actor: str = "system",
    ) -> Alert:
        """
        Create an alert from an already-adapted AlertCreate.

        This is the common application entry point for any alert source
        that has already been converted into AlertCreate.
        """

        if not isinstance(data, AlertCreate):
            raise TypeError(
                "AlertService.create_from_result expects AlertCreate"
            )

        return self._manager.create(
            data,
            actor=actor,
        )

    def create_from_detection(
        self,
        result: DetectionResult,
        *,
        actor: str = "system",
    ) -> Alert:
        """
        Convert a DetectionResult into AlertCreate and create the alert.

        DetectionResult → DetectionAlertAdapter → AlertCreate
        → AlertManager.
        """

        if not isinstance(result, DetectionResult):
            raise TypeError(
                "AlertService.create_from_detection expects "
                "DetectionResult"
            )

        alert_data = self._adapter.to_alert(result)

        return self.create_from_result(
            alert_data,
            actor=actor,
        )

    def create_from_detections(
        self,
        results: tuple[DetectionResult, ...]
        | list[DetectionResult],
        *,
        actor: str = "system",
    ) -> tuple[Alert, ...]:
        """
        Convert and create alerts for multiple detection results.
        """

        alerts: list[Alert] = []

        for result in results:
            alerts.append(
                self.create_from_detection(
                    result,
                    actor=actor,
                )
            )

        return tuple(alerts)

    # ------------------------------------------------------------------
    # Correlation → Alert
    # ------------------------------------------------------------------

    def create_from_correlation(
        self,
        result: CorrelationResult,
        *,
        actor: str = "system",
    ) -> Alert:
        """
        Convert a CorrelationResult into AlertCreate and create the alert.

        CorrelationResult → CorrelationAlertAdapter → AlertCreate
        → AlertManager.
        """

        if not isinstance(result, CorrelationResult):
            raise TypeError(
                "AlertService.create_from_correlation expects "
                "CorrelationResult"
            )

        alert_data = self._correlation_adapter.to_alert(
            result
        )

        return self.create_from_result(
            alert_data,
            actor=actor,
        )

    def create_from_correlations(
        self,
        results: tuple[CorrelationResult, ...]
        | list[CorrelationResult],
        *,
        actor: str = "system",
    ) -> tuple[Alert, ...]:
        """
        Convert and create alerts for multiple correlation results.

        Every CorrelationResult is independently adapted and submitted
        to AlertManager so normal deduplication, lifecycle auditing,
        persistence, suppression, realtime publication, and escalation
        behavior remain centralized in the alert domain.
        """

        alerts: list[Alert] = []

        for result in results:
            alerts.append(
                self.create_from_correlation(
                    result,
                    actor=actor,
                )
            )

        return tuple(alerts)

    # ------------------------------------------------------------------
    # Alert lifecycle
    # ------------------------------------------------------------------

    def transition(
        self,
        alert_id: UUID,
        status: AlertStatus,
        *,
        actor: str,
        reason: str = "",
    ) -> Alert:
        """
        Transition an alert through the domain lifecycle.

        AlertManager remains responsible for validating the transition.
        """

        return self._manager.transition(
            alert_id,
            status,
            actor=actor,
            reason=reason,
        )

    def acknowledge(
        self,
        alert_id: UUID,
        *,
        actor: str,
        reason: str = "",
    ) -> Alert:
        """
        Acknowledge a NEW alert.
        """

        return self.transition(
            alert_id,
            AlertStatus.ACKNOWLEDGED,
            actor=actor,
            reason=reason,
        )

    def investigate(
        self,
        alert_id: UUID,
        *,
        actor: str,
        reason: str = "",
    ) -> Alert:
        """
        Move an acknowledged/escalated alert into investigation.
        """

        return self.transition(
            alert_id,
            AlertStatus.INVESTIGATING,
            actor=actor,
            reason=reason,
        )

    def escalate(
        self,
        alert_id: UUID,
        *,
        actor: str,
        reason: str = "",
    ) -> Alert:
        """
        Escalate an alert.
        """

        return self.transition(
            alert_id,
            AlertStatus.ESCALATED,
            actor=actor,
            reason=reason,
        )

    def resolve(
        self,
        alert_id: UUID,
        *,
        actor: str,
        reason: str = "",
    ) -> Alert:
        """
        Resolve an alert.
        """

        return self.transition(
            alert_id,
            AlertStatus.RESOLVED,
            actor=actor,
            reason=reason,
        )

    def close(
        self,
        alert_id: UUID,
        *,
        actor: str,
        reason: str = "",
    ) -> Alert:
        """
        Close a resolved alert.
        """

        return self.transition(
            alert_id,
            AlertStatus.CLOSED,
            actor=actor,
            reason=reason,
        )

    def suppress(
        self,
        alert_id: UUID,
        *,
        actor: str,
        reason: str = "",
    ) -> Alert:
        """
        Suppress a NEW alert.
        """

        return self.transition(
            alert_id,
            AlertStatus.SUPPRESSED,
            actor=actor,
            reason=reason,
        )

    # ------------------------------------------------------------------
    # Assignment
    # ------------------------------------------------------------------

    def assign(
        self,
        alert_id: UUID,
        *,
        assignee: str | None,
        ownership_group: str | None = None,
        actor: str,
    ) -> Alert:
        """
        Assign or reassign an alert.
        """

        return self._manager.assign(
            alert_id,
            assignee=assignee,
            ownership_group=ownership_group,
            actor=actor,
        )

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get(
        self,
        alert_id: UUID,
    ) -> Alert:
        """
        Retrieve a single alert.
        """

        return self._manager.get(alert_id)

    def list(self) -> list[Alert]:
        """
        Return alerts through the manager.

        Repository-backed pagination/filtering remains handled by the
        API/application persistence flow.
        """

        return self._manager.list_alerts()

    def audit_history(
        self,
        alert_id: UUID,
    ) -> tuple[AlertAuditEntry, ...]:
        """
        Return lifecycle/audit history for an alert.
        """

        return self._manager.audit_history(
            alert_id
        )


__all__ = [
    "AlertService",
]