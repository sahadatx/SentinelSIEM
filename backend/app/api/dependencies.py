from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import Request

from app.alerts.manager import AlertManager
from app.incidents.manager import IncidentManager
from app.threat_intelligence.service import ThreatIntelligenceService


@dataclass(slots=True)
class APIContainer:
    """Application dependencies exposed to API routes.

    Storage-backed components are injected by the composition root. In-memory
    managers are safe defaults for the currently implemented domain services.
    """

    event_repository: Any | None = None
    alert_manager: AlertManager | None = None
    incident_manager: IncidentManager | None = None
    threat_intelligence: ThreatIntelligenceService | None = None
    mitre_service: Any | None = None

    def __post_init__(self) -> None:
        if self.alert_manager is None:
            self.alert_manager = AlertManager()
        if self.incident_manager is None:
            self.incident_manager = IncidentManager()
        if self.threat_intelligence is None:
            self.threat_intelligence = ThreatIntelligenceService()


def get_api_container(request: Request) -> APIContainer:
    container = getattr(request.app.state, "api", None)
    if not isinstance(container, APIContainer):
        raise RuntimeError("API dependency container is not configured")
    return container
