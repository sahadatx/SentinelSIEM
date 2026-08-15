from __future__ import annotations

from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.dependencies import APIContainer, get_api_container
from app.api.schemas.common import PageResponse, Pagination
from app.api.schemas.iocs import IOCMatchResponse, IOCResponse

router = APIRouter(prefix="/iocs", tags=["threat-intelligence"])


@router.get("/{ioc_id}", response_model=IOCResponse)
def get_ioc(ioc_id: UUID, container: APIContainer = Depends(get_api_container)) -> IOCResponse:
    if container.threat_intelligence is None:
        raise HTTPException(status_code=503, detail="threat intelligence service is not configured")
    try:
        return IOCResponse.from_model(container.threat_intelligence.get_ioc(ioc_id))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="IOC not found") from exc


@router.get("", response_model=PageResponse[IOCResponse])
def list_iocs(container: APIContainer = Depends(get_api_container)) -> PageResponse[IOCResponse]:
    service = container.threat_intelligence
    if service is None:
        raise HTTPException(status_code=503, detail="threat intelligence service is not configured")
    manager = service._manager
    items = manager.list_active()
    return PageResponse(
        items=[IOCResponse.from_model(item) for item in items],
        pagination=Pagination(page=1, page_size=max(len(items), 1), total=len(items)),
    )


@router.get("/match", response_model=list[IOCMatchResponse])
def match_ioc(
    observable: str = Query(min_length=1, max_length=2048),
    container: APIContainer = Depends(get_api_container),
) -> list[IOCMatchResponse]:
    if container.threat_intelligence is None:
        raise HTTPException(status_code=503, detail="threat intelligence service is not configured")
    return [IOCMatchResponse.from_model(match) for match in container.threat_intelligence.enrich(observable)]
