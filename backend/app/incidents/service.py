from __future__ import annotations

from uuid import UUID

from app.incidents.manager import IncidentManager
from app.incidents.models import Incident, IncidentCreate, IncidentStatus


class IncidentService:
    """Application-facing facade for incident workflows."""

    def __init__(self, manager: IncidentManager | None = None) -> None:
        self._manager = manager or IncidentManager()

    def create_incident(
        self,
        data: IncidentCreate,
        *,
        actor: str = "system",
    ) -> Incident:
        return self._manager.create(data, actor=actor)

    def transition(
        self,
        incident_id: UUID,
        target: IncidentStatus,
        *,
        actor: str,
        reason: str = "",
    ) -> Incident:
        return self._manager.transition(
            incident_id,
            target,
            actor=actor,
            reason=reason,
        )

    def get(self, incident_id: UUID) -> Incident:
        return self._manager.get(incident_id)

    def manager(self) -> IncidentManager:
        return self._manager
