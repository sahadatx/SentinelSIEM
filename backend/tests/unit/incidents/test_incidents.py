from __future__ import annotations

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
            description="Correlated authentication activity requires investigation.",
            severity=IncidentSeverity.CRITICAL,
            alert_ids=(uuid4(),),
            related_event_ids=("event-001", "event-002"),
            asset_ids=("web-prod-01",),
        ),
        actor="detection-engine",
    )


def test_incident_starts_new() -> None:
    manager = create_manager()
    incident = create_incident(manager)

    assert incident.status == IncidentStatus.NEW
    assert len(manager.audit_history(incident.incident_id)) == 1


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
    assert len(manager.audit_history(incident.incident_id)) == 5


def test_invalid_transition_rejected() -> None:
    manager = create_manager()
    incident = create_incident(manager)

    with pytest.raises(ValueError, match="invalid incident transition"):
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
        content="Confirmed suspicious authentication sequence.",
    )

    assert incident.assigned_to == "investigator-01"
    assert incident.ownership_group == "SOC-TIER-2"
    assert note.author == "investigator-01"
    assert len(manager.notes(incident.incident_id)) == 1


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
    assert len(manager.evidence(incident.incident_id)) == 1
    assert "event-003" in manager.get(incident.incident_id).evidence_ids
    assert len(manager.timeline(incident.incident_id)) >= 2
