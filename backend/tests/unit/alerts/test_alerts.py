from __future__ import annotations

from app.alerts.manager import AlertManager
from app.alerts.models import AlertCreate, AlertSeverity, AlertSourceType, AlertStatus
from app.alerts.notification import InMemoryNotificationSink
from app.alerts.suppression import AlertSuppression, SuppressionPolicy


def _create(**overrides: object) -> AlertCreate:
    values: dict[str, object] = {
        "source_type": AlertSourceType.DETECTION,
        "source_id": "detection-001",
        "rule_id": "brute-force",
        "title": "Repeated failed authentication",
        "description": "Multiple failed authentication attempts",
        "severity": AlertSeverity.MEDIUM,
        "risk_score": 55.0,
        "priority": "medium",
        "evidence_ids": ("event-001",),
        "asset_id": "host-01",
    }
    values.update(overrides)
    return AlertCreate(**values)


def test_alert_starts_new_and_records_creation() -> None:
    manager = AlertManager()
    alert = manager.create(_create())

    assert alert.status == AlertStatus.NEW
    assert alert.occurrence_count == 1
    assert len(manager.audit_history(alert.alert_id)) == 1


def test_lifecycle_follows_expected_state_machine() -> None:
    manager = AlertManager()
    alert = manager.create(_create())

    alert = manager.transition(alert.alert_id, AlertStatus.ACKNOWLEDGED, actor="analyst")
    alert = manager.transition(alert.alert_id, AlertStatus.INVESTIGATING, actor="analyst")
    alert = manager.transition(alert.alert_id, AlertStatus.ESCALATED, actor="lead")
    alert = manager.transition(alert.alert_id, AlertStatus.RESOLVED, actor="analyst")
    alert = manager.transition(alert.alert_id, AlertStatus.CLOSED, actor="analyst")

    assert alert.status == AlertStatus.CLOSED
    assert len(manager.audit_history(alert.alert_id)) == 6


def test_invalid_lifecycle_transition_is_rejected() -> None:
    manager = AlertManager()
    alert = manager.create(_create())

    try:
        manager.transition(alert.alert_id, AlertStatus.CLOSED, actor="analyst")
    except ValueError as exc:
        assert "invalid alert transition" in str(exc)
    else:
        raise AssertionError("invalid transition was accepted")


def test_duplicate_alerts_are_deduplicated() -> None:
    manager = AlertManager()
    first = manager.create(_create())
    second = manager.create(_create())

    assert first.alert_id == second.alert_id
    assert second.occurrence_count == 2
    assert len(manager.list_alerts()) == 1


def test_suppression_policy_suppresses_noisy_noncritical_alert() -> None:
    manager = AlertManager(
        suppression=AlertSuppression(
            SuppressionPolicy(minimum_occurrences=1)
        )
    )
    alert = manager.create(_create())

    assert alert.status == AlertStatus.SUPPRESSED


def test_critical_alert_is_escalated() -> None:
    sink = InMemoryNotificationSink()
    manager = AlertManager(notification_sink=sink)
    alert = manager.create(
        _create(
            severity=AlertSeverity.CRITICAL,
            risk_score=92.0,
            priority="critical",
        )
    )
    alert = manager.evaluate_escalation(alert.alert_id, actor="system")

    assert alert.status == AlertStatus.ESCALATED
    assert sink.notifications[-1][1] == "status:escalated"


def test_assignment_is_audited() -> None:
    manager = AlertManager()
    alert = manager.create(_create())
    updated = manager.assign(
        alert.alert_id,
        assignee="analyst-01",
        ownership_group="soc-l2",
        actor="manager-01",
    )

    assert updated.assigned_to == "analyst-01"
    assert updated.ownership_group == "soc-l2"
    assert manager.audit_history(alert.alert_id)[-1].action == "assignment_changed"
