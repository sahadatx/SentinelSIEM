from __future__ import annotations

from uuid import uuid4

from app.incidents.manager import IncidentManager
from app.incidents.models import IncidentCreate, IncidentSeverity, IncidentStatus


def test_phase12_real_incident_workflow() -> None:
    manager = IncidentManager()

    alert_id = uuid4()
    incident = manager.create(
        IncidentCreate(
            title="SSH account compromise investigation",
            description=(
                "Five failed SSH logins followed by a successful login "
                "on a production asset."
            ),
            severity=IncidentSeverity.CRITICAL,
            alert_ids=(alert_id,),
            evidence_ids=("event-001", "event-002"),
            related_event_ids=(
                "event-001",
                "event-002",
                "event-003",
                "event-004",
                "event-005",
                "event-006",
            ),
            related_ioc_ids=("ioc-ip-203.0.113.50",),
            asset_ids=("web-prod-01",),
            initial_assignee="soc-analyst-01",
            ownership_group="SOC",
        ),
        actor="alert-manager",
    )

    incident = manager.transition(
        incident.incident_id,
        IncidentStatus.INVESTIGATING,
        actor="soc-analyst-01",
        reason="Critical alert converted into investigation",
    )
    incident = manager.add_note(
        incident.incident_id,
        author="soc-analyst-01",
        content="Authentication sequence confirms likely account compromise.",
    )
    assert incident.incident_id is not None

    manager.add_evidence(
        incident.incident_id,
        evidence_id="packet-capture-001",
        evidence_type="packet_capture",
        reference="capture://incident/packet-capture-001",
        collected_by="soc-analyst-01",
    )

    incident = manager.transition(
        incident.incident_id,
        IncidentStatus.CONTAINED,
        actor="soc-analyst-01",
        reason="Threat contained",
    )
    incident = manager.transition(
        incident.incident_id,
        IncidentStatus.RESOLVED,
        actor="soc-analyst-01",
        reason="Investigation complete",
    )
    incident = manager.transition(
        incident.incident_id,
        IncidentStatus.CLOSED,
        actor="soc-manager",
        reason="Closure approved",
    )

    assert incident.status == IncidentStatus.CLOSED
    assert len(manager.audit_history(incident.incident_id)) == 5
    assert len(manager.notes(incident.incident_id)) == 1
    assert len(manager.evidence(incident.incident_id)) == 1
    assert len(manager.timeline(incident.incident_id)) >= 6

    print("REAL PHASE 12 INCIDENT TEST PASSED")
    print(f"Incident ID       : {incident.incident_id}")
    print(f"Status            : {incident.status.value}")
    print(f"Severity          : {incident.severity.value}")
    print(f"Alerts linked     : {len(incident.alert_ids)}")
    print(f"Events linked     : {len(incident.related_event_ids)}")
    print(f"IOCs linked       : {len(incident.related_ioc_ids)}")
    print(f"Evidence records  : {len(manager.evidence(incident.incident_id))}")
    print(f"Timeline entries  : {len(manager.timeline(incident.incident_id))}")
