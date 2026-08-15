from __future__ import annotations

from app.alerts.manager import AlertManager
from app.alerts.models import AlertCreate, AlertSeverity, AlertSourceType, AlertStatus


def test_real_phase11_alert_lifecycle() -> None:
    manager = AlertManager()
    alert = manager.create(
        AlertCreate(
            source_type=AlertSourceType.CORRELATION,
            source_id="account-compromise",
            rule_id="account-compromise",
            title="Possible account compromise",
            description="Correlation engine detected failed authentication followed by success.",
            severity=AlertSeverity.HIGH,
            risk_score=79.7,
            priority="high",
            evidence_ids=("event-failed", "event-success"),
            asset_id="server-01",
        )
    )

    assert alert.status == AlertStatus.NEW
    assert alert.risk_score == 79.7
    assert len(alert.evidence_ids) == 2

    alert = manager.transition(
        alert.alert_id,
        AlertStatus.ACKNOWLEDGED,
        actor="soc-analyst",
    )
    alert = manager.transition(
        alert.alert_id,
        AlertStatus.INVESTIGATING,
        actor="soc-analyst",
    )
    alert = manager.transition(
        alert.alert_id,
        AlertStatus.RESOLVED,
        actor="soc-analyst",
        reason="Activity validated and contained.",
    )
    alert = manager.transition(
        alert.alert_id,
        AlertStatus.CLOSED,
        actor="soc-lead",
    )

    assert alert.status == AlertStatus.CLOSED
    assert len(manager.audit_history(alert.alert_id)) == 5
