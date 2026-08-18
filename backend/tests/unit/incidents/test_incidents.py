from __future__ import annotations

import asyncio
from typing import Any
from uuid import uuid4

import pytest

from app.incidents.manager import IncidentManager
from app.incidents.models import (
    IncidentCreate,
    IncidentSeverity,
    IncidentStatus,
)


def create_manager() -> IncidentManager:
    return IncidentManager()


def create_incident(manager: IncidentManager):
    return manager.create(
        IncidentCreate(
            title="Possible account compromise",
            description=(
                "Correlated authentication activity "
                "requires investigation."
            ),
            severity=IncidentSeverity.CRITICAL,
            alert_ids=(uuid4(),),
            related_event_ids=(
                "event-001",
                "event-002",
            ),
            asset_ids=("web-prod-01",),
        ),
        actor="detection-engine",
    )


def test_incident_starts_new() -> None:
    manager = create_manager()
    incident = create_incident(manager)

    assert incident.status == IncidentStatus.NEW
    assert len(
        manager.audit_history(
            incident.incident_id,
        )
    ) == 1


def test_full_incident_lifecycle() -> None:
    manager = create_manager()
    incident = create_incident(manager)

    for target in (
        IncidentStatus.INVESTIGATING,
        IncidentStatus.CONTAINED,
        IncidentStatus.RESOLVED,
        IncidentStatus.CLOSED,
    ):
        incident = manager.transition(
            incident.incident_id,
            target,
            actor="soc-analyst",
            reason="workflow step",
        )

    assert incident.status == IncidentStatus.CLOSED
    assert incident.resolved_at is not None
    assert incident.closed_at is not None
    assert len(
        manager.audit_history(
            incident.incident_id,
        )
    ) == 5


def test_invalid_transition_rejected() -> None:
    manager = create_manager()
    incident = create_incident(manager)

    with pytest.raises(
        ValueError,
        match="invalid incident transition",
    ):
        manager.transition(
            incident.incident_id,
            IncidentStatus.CLOSED,
            actor="soc-analyst",
        )


def test_assignment_and_investigation_are_recorded() -> None:
    manager = create_manager()
    incident = create_incident(manager)

    incident = manager.assign(
        incident.incident_id,
        assignee="investigator-01",
        ownership_group="SOC-TIER-2",
        actor="soc-manager",
    )

    note = manager.add_note(
        incident.incident_id,
        author="investigator-01",
        content=(
            "Confirmed suspicious authentication sequence."
        ),
    )

    assert incident.assigned_to == "investigator-01"
    assert incident.ownership_group == "SOC-TIER-2"
    assert note.author == "investigator-01"
    assert len(
        manager.notes(
            incident.incident_id,
        )
    ) == 1


def test_evidence_and_timeline() -> None:
    manager = create_manager()
    incident = create_incident(manager)

    evidence = manager.add_evidence(
        incident.incident_id,
        evidence_id="event-003",
        evidence_type="security_event",
        reference="opensearch:event-003",
        collected_by="investigator-01",
    )

    assert evidence.evidence_id == "event-003"
    assert len(
        manager.evidence(
            incident.incident_id,
        )
    ) == 1

    assert (
        "event-003"
        in manager.get(
            incident.incident_id,
        ).evidence_ids
    )

    assert len(
        manager.timeline(
            incident.incident_id,
        )
    ) >= 2


# ============================================================================
# Realtime publisher tests
# ============================================================================


async def _flush_realtime_tasks() -> None:
    """Allow scheduled realtime tasks to execute."""
    await asyncio.sleep(0)


def test_incident_creation_publishes_realtime_event() -> None:
    published: list[dict[str, Any]] = []

    async def publisher(
        payload: dict[str, Any],
    ) -> int:
        published.append(payload)
        return 1

    async def scenario() -> None:
        manager = IncidentManager(
            realtime_publisher=publisher,
        )

        incident = create_incident(manager)

        await _flush_realtime_tasks()

        assert len(published) == 1

        payload = published[0]

        assert payload["event_type"] == "created"
        assert (
            payload["incident"]["incident_id"]
            == str(incident.incident_id)
        )
        assert (
            payload["incident"]["status"]
            == "new"
        )
        assert (
            payload["incident"]["title"]
            == "Possible account compromise"
        )

    asyncio.run(scenario())


def test_incident_status_transition_publishes_realtime_event() -> None:
    published: list[dict[str, Any]] = []

    async def publisher(
        payload: dict[str, Any],
    ) -> int:
        published.append(payload)
        return 1

    async def scenario() -> None:
        manager = IncidentManager(
            realtime_publisher=publisher,
        )

        incident = create_incident(manager)

        await _flush_realtime_tasks()

        manager.transition(
            incident.incident_id,
            IncidentStatus.INVESTIGATING,
            actor="soc-analyst",
            reason="Investigation started.",
        )

        await _flush_realtime_tasks()

        assert len(published) == 2

        assert (
            published[0]["event_type"]
            == "created"
        )

        assert (
            published[1]["event_type"]
            == "status:investigating"
        )

        assert (
            published[1]["incident"]["status"]
            == "investigating"
        )

    asyncio.run(scenario())


def test_incident_assignment_publishes_realtime_event() -> None:
    published: list[dict[str, Any]] = []

    async def publisher(
        payload: dict[str, Any],
    ) -> int:
        published.append(payload)
        return 1

    async def scenario() -> None:
        manager = IncidentManager(
            realtime_publisher=publisher,
        )

        incident = create_incident(manager)

        await _flush_realtime_tasks()

        updated = manager.assign(
            incident.incident_id,
            assignee="investigator-02",
            ownership_group="SOC-TIER-2",
            actor="soc-manager",
        )

        await _flush_realtime_tasks()

        assert len(published) == 2

        payload = published[1]

        assert (
            payload["event_type"]
            == "assignment_changed"
        )

        assert (
            payload["incident"]["incident_id"]
            == str(updated.incident_id)
        )

        assert (
            payload["incident"]["assigned_to"]
            == "investigator-02"
        )

        assert (
            payload["incident"]["ownership_group"]
            == "SOC-TIER-2"
        )

    asyncio.run(scenario())


def test_investigation_note_publishes_realtime_event() -> None:
    published: list[dict[str, Any]] = []

    async def publisher(
        payload: dict[str, Any],
    ) -> int:
        published.append(payload)
        return 1

    async def scenario() -> None:
        manager = IncidentManager(
            realtime_publisher=publisher,
        )

        incident = create_incident(manager)

        await _flush_realtime_tasks()

        note = manager.add_note(
            incident.incident_id,
            author="investigator-01",
            content="Suspicious authentication confirmed.",
        )

        await _flush_realtime_tasks()

        assert len(published) == 2

        payload = published[1]

        assert (
            payload["event_type"]
            == "investigation_note"
        )

        assert (
            payload["incident"]["incident_id"]
            == str(incident.incident_id)
        )

        assert payload["note"]["author"] == note.author
        assert (
            payload["note"]["content"]
            == note.content
        )

    asyncio.run(scenario())


def test_evidence_addition_publishes_realtime_event() -> None:
    published: list[dict[str, Any]] = []

    async def publisher(
        payload: dict[str, Any],
    ) -> int:
        published.append(payload)
        return 1

    async def scenario() -> None:
        manager = IncidentManager(
            realtime_publisher=publisher,
        )

        incident = create_incident(manager)

        await _flush_realtime_tasks()

        evidence = manager.add_evidence(
            incident.incident_id,
            evidence_id="event-004",
            evidence_type="security_event",
            reference="opensearch:event-004",
            collected_by="investigator-01",
        )

        await _flush_realtime_tasks()

        assert len(published) == 2

        payload = published[1]

        assert (
            payload["event_type"]
            == "evidence_added"
        )

        assert (
            payload["incident"]["incident_id"]
            == str(incident.incident_id)
        )

        assert (
            "event-004"
            in payload["incident"]["evidence_ids"]
        )

        assert (
            payload["evidence"]["evidence_id"]
            == evidence.evidence_id
        )

    asyncio.run(scenario())


def test_realtime_publish_failure_does_not_break_incident_creation() -> None:
    async def failing_publisher(
        payload: dict[str, Any],
    ) -> int:
        del payload
        raise RuntimeError(
            "simulated incident realtime publisher failure"
        )

    async def scenario() -> None:
        manager = IncidentManager(
            realtime_publisher=failing_publisher,
        )

        incident = create_incident(manager)

        await _flush_realtime_tasks()

        stored = manager.get(
            incident.incident_id,
        )

        assert (
            stored.incident_id
            == incident.incident_id
        )

        assert stored.status == IncidentStatus.NEW

        assert len(
            manager.audit_history(
                incident.incident_id,
            )
        ) == 1

    asyncio.run(scenario())
