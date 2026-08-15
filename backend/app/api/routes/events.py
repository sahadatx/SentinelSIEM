from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Query

from app.api.dependencies import APIContainer
from app.api.schemas.common import PageResponse, Pagination
from app.api.schemas.events import EventResponse
from app.api.dependencies import get_api_container
from fastapi import Depends

router = APIRouter(prefix="/events", tags=["events"])


@router.get("", response_model=PageResponse[EventResponse])
async def list_events(
    container: APIContainer = Depends(get_api_container),
    query: str | None = Query(default=None, max_length=500),
    source: str | None = Query(default=None, max_length=200),
    source_ip: str | None = Query(default=None, max_length=64),
    severity: str | None = Query(default=None, max_length=32),
    category: str | None = Query(default=None, max_length=64),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=1000),
) -> PageResponse[EventResponse]:
    if container.event_repository is None:
        raise HTTPException(status_code=503, detail="event repository is not configured")
    result = await container.event_repository.search(
        query=query,
        source=source,
        source_ip=source_ip,
        severity=severity,
        category=category,
        limit=page_size,
    )
    return PageResponse(
        items=[EventResponse.from_event(event) for event in result.events],
        pagination=Pagination(page=page, page_size=page_size, total=result.total),
    )


@router.get("/{event_id}", response_model=EventResponse)
async def get_event(event_id: UUID, container: APIContainer = Depends(get_api_container)) -> EventResponse:
    if container.event_repository is None:
        raise HTTPException(status_code=503, detail="event repository is not configured")
    event = await container.event_repository.get(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="event not found")
    return EventResponse.from_event(event)
