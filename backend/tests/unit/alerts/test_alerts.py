from __future__ import annotations

import asyncio
from typing import Any

from app.alerts.manager import AlertManager
from app.alerts.models import (
    AlertCreate,
    AlertSeverity,
    AlertSourceType,
    AlertStatus,
)
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

    alert = manager.transition(
        alert.alert_id,
        AlertStatus.ACKNOWLEDGED,
        actor="analyst",
    )
    alert = manager.transition(
        alert.alert_id,
        AlertStatus.INVESTIGATING,
        actor="analyst",
    )
    alert = manager.transition(
        alert.alert_id,
        AlertStatus.ESCALATED,
        actor="lead",
    )
    alert = manager.transition(
        alert.alert_id,
        AlertStatus.RESOLVED,
        actor="analyst",
    )
    alert = manager.transition(
        alert.alert_id,
        AlertStatus.CLOSED,
        actor="analyst",
    )

    assert alert.status == AlertStatus.CLOSED
    assert len(manager.audit_history(alert.alert_id)) == 6


def test_invalid_lifecycle_transition_is_rejected() -> None:
    manager = AlertManager()
    alert = manager.create(_create())

    try:
        manager.transition(
            alert.alert_id,
            AlertStatus.CLOSED,
            actor="analyst",
        )
    except ValueError as exc:
        assert "invalid alert transition" in str(exc)
    else:
        raise AssertionError(
            "invalid transition was accepted"
        )


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
            SuppressionPolicy(
                minimum_occurrences=1
            )
        )
    )
    alert = manager.create(_create())

    assert alert.status == AlertStatus.SUPPRESSED


def test_critical_alert_is_escalated() -> None:
    sink = InMemoryNotificationSink()

    manager = AlertManager(
        notification_sink=sink
    )

    alert = manager.create(
        _create(
            severity=AlertSeverity.CRITICAL,
            risk_score=92.0,
            priority="critical",
        )
    )

    alert = manager.evaluate_escalation(
        alert.alert_id,
        actor="system",
    )

    assert alert.status == AlertStatus.ESCALATED
    assert sink.notifications[-1][1] == "status:escalated"


def test_assignment_is_audited() -> None:
    manager = AlertManager()

    alert = manager.create(
        _create()
    )

    updated = manager.assign(
        alert.alert_id,
        assignee="analyst-01",
        ownership_group="soc-l2",
        actor="manager-01",
    )

    assert updated.assigned_to == "analyst-01"
    assert updated.ownership_group == "soc-l2"
    assert (
        manager.audit_history(
            alert.alert_id
        )[-1].action
        == "assignment_changed"
    )


# ============================================================================
# Realtime publisher tests
# ============================================================================


async def _wait_for_realtime_tasks() -> None:
    """
    Allow scheduled AlertManager realtime tasks to execute.

    AlertManager remains synchronous by design, while the injected
    realtime publisher is asynchronous.
    """
    await asyncio.sleep(0)


def _run(coro: Any) -> Any:
    """Run one async test helper from a synchronous pytest test."""
    return asyncio.run(coro)


def test_alert_creation_publishes_realtime_payload() -> None:
    published: list[dict[str, Any]] = []

    async def publisher(
        payload: dict[str, Any],
    ) -> int:
        published.append(payload)
        return 1

    async def scenario() -> None:
        manager = AlertManager(
            realtime_publisher=publisher,
        )

        alert = manager.create(
            _create()
        )

        await _wait_for_realtime_tasks()

        assert len(published) == 1
        assert published[0]["event_type"] == "created"
        assert published[0]["alert"]["alert_id"] == str(
            alert.alert_id
        )
        assert published[0]["alert"]["status"] == "new"

    _run(scenario())


def test_duplicate_alert_publishes_deduplicated_realtime_payload() -> None:
    published: list[dict[str, Any]] = []

    async def publisher(
        payload: dict[str, Any],
    ) -> int:
        published.append(payload)
        return 1

    async def scenario() -> None:
        manager = AlertManager(
            realtime_publisher=publisher,
        )

        first = manager.create(
            _create()
        )

        await _wait_for_realtime_tasks()

        second = manager.create(
            _create()
        )

        await _wait_for_realtime_tasks()

        assert first.alert_id == second.alert_id
        assert len(published) == 2

        assert published[0]["event_type"] == "created"
        assert published[1]["event_type"] == "deduplicated"

        assert (
            published[1]["alert"]["alert_id"]
            == str(first.alert_id)
        )
        assert (
            published[1]["alert"]["occurrence_count"]
            == 2
        )

    _run(scenario())


def test_alert_transition_publishes_realtime_status_update() -> None:
    published: list[dict[str, Any]] = []

    async def publisher(
        payload: dict[str, Any],
    ) -> int:
        published.append(payload)
        return 1

    async def scenario() -> None:
        manager = AlertManager(
            realtime_publisher=publisher,
        )

        alert = manager.create(
            _create()
        )

        await _wait_for_realtime_tasks()

        manager.transition(
            alert.alert_id,
            AlertStatus.ACKNOWLEDGED,
            actor="analyst",
            reason="Analyst reviewed the alert.",
        )

        await _wait_for_realtime_tasks()

        assert len(published) == 2

        assert published[0]["event_type"] == "created"
        assert (
            published[1]["event_type"]
            == "status:acknowledged"
        )

        assert (
            published[1]["alert"]["status"]
            == "acknowledged"
        )

    _run(scenario())


def test_alert_assignment_publishes_realtime_update() -> None:
    published: list[dict[str, Any]] = []

    async def publisher(
        payload: dict[str, Any],
    ) -> int:
        published.append(payload)
        return 1

    async def scenario() -> None:
        manager = AlertManager(
            realtime_publisher=publisher,
        )

        alert = manager.create(
            _create()
        )

        await _wait_for_realtime_tasks()

        updated = manager.assign(
            alert.alert_id,
            assignee="analyst-02",
            ownership_group="soc-l2",
            actor="manager-01",
        )

        await _wait_for_realtime_tasks()

        assert len(published) == 2

        assert (
            published[1]["event_type"]
            == "assignment_changed"
        )
        assert (
            published[1]["alert"]["alert_id"]
            == str(updated.alert_id)
        )
        assert (
            published[1]["alert"]["assigned_to"]
            == "analyst-02"
        )
        assert (
            published[1]["alert"]["ownership_group"]
            == "soc-l2"
        )

    _run(scenario())


def test_realtime_publish_failure_does_not_break_alert_creation() -> None:
    async def failing_publisher(
        payload: dict[str, Any],
    ) -> int:
        del payload
        raise RuntimeError(
            "simulated realtime publisher failure"
        )

    async def scenario() -> None:
        manager = AlertManager(
            realtime_publisher=failing_publisher,
        )

        alert = manager.create(
            _create()
        )

        await _wait_for_realtime_tasks()

        stored = manager.get(
            alert.alert_id
        )

        assert stored.alert_id == alert.alert_id
        assert stored.status == AlertStatus.NEW
        assert stored.occurrence_count == 1

    _run(scenario())
