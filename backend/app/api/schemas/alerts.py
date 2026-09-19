from __future__ import annotations

from datetime import datetime
from uuid import UUID

from app.alerts.models import Alert, AlertAuditEntry, AlertStatus

from .common import APIModel


class AlertResponse(APIModel):
    """
    Public API representation of an alert.

    Important:
        Domain model uses `assigned_to`.
        API contract uses `assignee`.

    The mapping is intentionally explicit in `from_model()`.
    """

    alert_id: UUID

    source_type: str
    source_id: str

    rule_id: str

    title: str
    description: str

    severity: str
    risk_score: float
    priority: str

    status: str

    evidence_ids: tuple[str, ...]

    asset_id: str | None = None
    user_id: str | None = None

    occurrence_count: int

    first_seen_at: datetime
    last_seen_at: datetime

    acknowledged_at: datetime | None = None
    investigating_at: datetime | None = None
    escalated_at: datetime | None = None
    resolved_at: datetime | None = None
    closed_at: datetime | None = None
    suppressed_at: datetime | None = None

    sla_due_at: datetime | None = None
    updated_at: datetime

    assignee: str | None = None
    ownership_group: str | None = None

    @classmethod
    def from_model(cls, alert: Alert) -> AlertResponse:
        if not isinstance(alert, Alert):
            raise TypeError("AlertResponse.from_model expects Alert")

        return cls(
            alert_id=alert.alert_id,
            source_type=alert.source_type.value,
            source_id=alert.source_id,
            rule_id=alert.rule_id,
            title=alert.title,
            description=alert.description,
            severity=alert.severity.value,
            risk_score=alert.risk_score,
            priority=alert.priority,
            status=alert.status.value,
            evidence_ids=alert.evidence_ids,
            asset_id=alert.asset_id,
            user_id=alert.user_id,
            occurrence_count=alert.occurrence_count,
            first_seen_at=alert.first_seen_at,
            last_seen_at=alert.last_seen_at,
            acknowledged_at=alert.acknowledged_at,
            investigating_at=alert.investigating_at,
            escalated_at=alert.escalated_at,
            resolved_at=alert.resolved_at,
            closed_at=alert.closed_at,
            suppressed_at=alert.suppressed_at,
            sla_due_at=alert.sla_due_at,
            updated_at=alert.updated_at,

            # Explicit domain -> API mapping.
            assignee=alert.assigned_to,

            ownership_group=alert.ownership_group,
        )


class AlertListResponse(APIModel):
    """
    Paginated alert list response.
    """

    items: tuple[AlertResponse, ...]
    total: int
    page: int
    page_size: int


class AlertAuditResponse(APIModel):
    """
    Public API representation of an alert audit entry.
    """

    audit_id: UUID
    alert_id: UUID

    action: str
    actor: str

    from_status: str | None = None
    to_status: str | None = None

    reason: str

    created_at: datetime

    @classmethod
    def from_model(cls, entry: AlertAuditEntry) -> AlertAuditResponse:
        if not isinstance(entry, AlertAuditEntry):
            raise TypeError(
                "AlertAuditResponse.from_model expects AlertAuditEntry",
            )

        return cls(
            audit_id=entry.audit_id,
            alert_id=entry.alert_id,
            action=entry.action,
            actor=entry.actor,
            from_status=(
                entry.from_status.value
                if entry.from_status is not None
                else None
            ),
            to_status=(
                entry.to_status.value
                if entry.to_status is not None
                else None
            ),
            reason=entry.reason,
            created_at=entry.created_at,
        )


class AlertTransitionRequest(APIModel):
    """
    Request body for alert lifecycle transitions.

    Examples:
        acknowledged
        investigating
        escalated
        resolved
        closed
        suppressed
    """

    status: AlertStatus
    reason: str = ""


class AlertAssignmentRequest(APIModel):
    """
    Request body for assigning/reassigning an alert.

    `assignee` is the API field name.
    The domain model internally stores the value as `assigned_to`.
    """

    assignee: str | None = None
    ownership_group: str | None = None