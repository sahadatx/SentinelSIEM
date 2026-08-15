from __future__ import annotations

from datetime import UTC, datetime

from app.incidents.models import Incident


class IncidentAssignment:
    """Apply incident ownership changes."""

    def assign(
        self,
        incident: Incident,
        *,
        assignee: str | None,
        ownership_group: str | None,
    ) -> Incident:
        return incident.model_copy(
            update={
                "assigned_to": assignee,
                "ownership_group": ownership_group,
                "last_updated_at": datetime.now(UTC),
            }
        )
