from __future__ import annotations

from datetime import UTC, datetime

from app.incidents.models import Incident, IncidentAuditEntry, IncidentStatus

_ALLOWED_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.NEW: frozenset({IncidentStatus.INVESTIGATING}),
    IncidentStatus.INVESTIGATING: frozenset(
        {IncidentStatus.CONTAINED, IncidentStatus.RESOLVED}
    ),
    IncidentStatus.CONTAINED: frozenset(
        {IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED}
    ),
    IncidentStatus.RESOLVED: frozenset({IncidentStatus.CLOSED, IncidentStatus.INVESTIGATING}),
    IncidentStatus.CLOSED: frozenset(),
}


class IncidentLifecycle:
    """Validate and apply incident state transitions."""

    def transition(
        self,
        incident: Incident,
        target: IncidentStatus,
        *,
        actor: str,
        reason: str = "",
    ) -> tuple[Incident, IncidentAuditEntry]:
        if not actor.strip():
            raise ValueError("actor is required")

        allowed = _ALLOWED_TRANSITIONS[incident.status]
        if target not in allowed:
            raise ValueError(
                f"invalid incident transition: "
                f"{incident.status.value} -> {target.value}"
            )

        now = datetime.now(UTC)
        update: dict[str, object] = {
            "status": target,
            "last_updated_at": now,
        }

        if target == IncidentStatus.RESOLVED:
            update["resolved_at"] = now
        elif target == IncidentStatus.CLOSED:
            update["closed_at"] = now

        updated = incident.model_copy(update=update)
        audit = IncidentAuditEntry(
            incident_id=incident.incident_id,
            action="status_transition",
            actor=actor,
            from_status=incident.status,
            to_status=target,
            reason=reason,
            created_at=now,
        )
        return updated, audit
