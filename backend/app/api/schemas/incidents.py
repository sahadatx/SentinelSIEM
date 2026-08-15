from __future__ import annotations

from uuid import UUID

from app.incidents.models import Incident
from .common import APIModel


class IncidentResponse(APIModel):
    incident_id: UUID
    title: str
    description: str
    severity: str
    status: str
    alert_ids: tuple[UUID, ...]
    evidence_ids: tuple[str, ...]
    related_event_ids: tuple[UUID, ...]
    related_ioc_ids: tuple[str, ...]
    asset_ids: tuple[str, ...]
    assigned_to: str | None = None
    ownership_group: str | None = None
    first_seen_at: object
    last_updated_at: object

    @classmethod
    def from_model(cls, incident: Incident) -> "IncidentResponse":
        return cls.model_validate(incident.model_dump(mode="json"))
