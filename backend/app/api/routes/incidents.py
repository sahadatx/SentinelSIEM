from __future__ import annotations

from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException

from app.api.dependencies import APIContainer, get_api_container
from app.api.schemas.common import PageResponse, Pagination
from app.api.schemas.incidents import IncidentResponse

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=PageResponse[IncidentResponse])
def list_incidents(container: APIContainer = Depends(get_api_container)) -> PageResponse[IncidentResponse]:
    incidents = container.incident_manager.list_incidents() if container.incident_manager else []
    return PageResponse(
        items=[IncidentResponse.from_model(item) for item in incidents],
        pagination=Pagination(page=1, page_size=max(len(incidents), 1), total=len(incidents)),
    )


@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: UUID, container: APIContainer = Depends(get_api_container)) -> IncidentResponse:
    if container.incident_manager is None:
        raise HTTPException(status_code=503, detail="incident manager is not configured")
    try:
        return IncidentResponse.from_model(container.incident_manager.get(incident_id))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="incident not found") from exc
