from __future__ import annotations

from uuid import UUID

from app.alerts.models import Alert
from .common import APIModel


class AlertResponse(APIModel):
    alert_id: UUID
    source_type: str
    source_id: str
    rule_id: str
    title: str
    description: str
    severity: str
    risk_score: float
    priority: str
    evidence_ids: tuple[str, ...]
    asset_id: str | None = None
    user_id: str | None = None
    occurrence_count: int
    first_seen_at: object
    last_seen_at: object
    updated_at: object
    status: str
    assignee: str | None = None
    ownership_group: str | None = None

    @classmethod
    def from_model(cls, alert: Alert) -> "AlertResponse":
        return cls.model_validate(alert.model_dump(mode="json"))
