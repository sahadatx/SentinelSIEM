from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from app.api.dependencies import APIContainer, get_api_container
from app.api.schemas.common import PageResponse, Pagination
from app.api.schemas.events import (
    EventFilterOptions,
    EventResponse,
    EventStatisticsResponse,
)


router = APIRouter(
    prefix="/events",
    tags=["events"],
)


@router.get(
    "",
    response_model=PageResponse[EventResponse],
)
async def list_events(
    container: APIContainer = Depends(get_api_container),
    query: str | None = Query(
        default=None,
        max_length=500,
    ),
    source: str | None = Query(
        default=None,
        max_length=200,
    ),
    source_ip: str | None = Query(
        default=None,
        max_length=64,
    ),
    destination_ip: str | None = Query(
        default=None,
        max_length=64,
    ),
    username: str | None = Query(
        default=None,
        max_length=255,
    ),
    action: str | None = Query(
        default=None,
        max_length=128,
    ),
    outcome: str | None = Query(
        default=None,
        max_length=64,
    ),
    severity: str | None = Query(
        default=None,
        max_length=32,
    ),
    category: str | None = Query(
        default=None,
        max_length=64,
    ),
    start_time: datetime | None = Query(
        default=None,
    ),
    end_time: datetime | None = Query(
        default=None,
    ),
    page: int = Query(
        default=1,
        ge=1,
    ),
    page_size: int = Query(
        default=50,
        ge=1,
        le=1000,
    ),
) -> PageResponse[EventResponse]:
    """
    Return persisted security events with filtering and pagination.

    Supported filters:

    - free-text search
    - source
    - source IP
    - destination IP
    - username
    - action
    - outcome
    - severity
    - category
    - start timestamp
    - end timestamp
    """

    if container.event_repository is None:
        raise HTTPException(
            status_code=503,
            detail="event repository is not configured",
        )

    if (
        start_time is not None
        and end_time is not None
        and start_time > end_time
    ):
        raise HTTPException(
            status_code=400,
            detail="start_time must not be later than end_time",
        )

    offset = (page - 1) * page_size

    result = await container.event_repository.search(
        query=query,
        source=source,
        source_ip=source_ip,
        destination_ip=destination_ip,
        username=username,
        action=action,
        outcome=outcome,
        severity=severity,
        category=category,
        start_time=start_time,
        end_time=end_time,
        offset=offset,
        limit=page_size,
    )

    return PageResponse(
        items=[
            EventResponse.from_event(event)
            for event in result.events
        ],
        pagination=Pagination(
            page=page,
            page_size=page_size,
            total=result.total,
            total_pages=(
                (result.total + page_size - 1) // page_size
                if result.total > 0
                else 0
            ),
        ),
    )


@router.get(
    "/statistics",
    response_model=EventStatisticsResponse,
)
async def get_event_statistics(
    container: APIContainer = Depends(get_api_container),
    query: str | None = Query(
        default=None,
        max_length=500,
    ),
    source: str | None = Query(
        default=None,
        max_length=200,
    ),
    source_ip: str | None = Query(
        default=None,
        max_length=64,
    ),
    destination_ip: str | None = Query(
        default=None,
        max_length=64,
    ),
    username: str | None = Query(
        default=None,
        max_length=255,
    ),
    action: str | None = Query(
        default=None,
        max_length=128,
    ),
    outcome: str | None = Query(
        default=None,
        max_length=64,
    ),
    severity: str | None = Query(
        default=None,
        max_length=32,
    ),
    category: str | None = Query(
        default=None,
        max_length=64,
    ),
    start_time: datetime | None = Query(
        default=None,
    ),
    end_time: datetime | None = Query(
        default=None,
    ),
) -> EventStatisticsResponse:
    """
    Return aggregate Event KPI statistics for the complete
    filtered dataset.

    Statistics are independent of pagination and include:

    - total events
    - critical events
    - high-severity events
    - medium-severity events
    - low-severity events
    - informational events

    The same filters used by the Events table are applied here so
    the KPI cards always represent the currently filtered dataset.
    """

    if container.event_repository is None:
        raise HTTPException(
            status_code=503,
            detail="event repository is not configured",
        )

    if (
        start_time is not None
        and end_time is not None
        and start_time > end_time
    ):
        raise HTTPException(
            status_code=400,
            detail="start_time must not be later than end_time",
        )

    get_statistics = getattr(
        container.event_repository,
        "get_statistics",
        None,
    )

    if get_statistics is None:
        raise HTTPException(
            status_code=501,
            detail="event statistics are not supported",
        )

    statistics = await get_statistics(
        query=query,
        source=source,
        source_ip=source_ip,
        destination_ip=destination_ip,
        username=username,
        action=action,
        outcome=outcome,
        severity=severity,
        category=category,
        start_time=start_time,
        end_time=end_time,
    )

    return EventStatisticsResponse(
        total=statistics.total,
        critical=statistics.critical,
        high=statistics.high,
        medium=statistics.medium,
        low=statistics.low,
        info=statistics.info,
    )


@router.get(
    "/filter-options",
    response_model=EventFilterOptions,
)
async def get_event_filter_options(
    container: APIContainer = Depends(get_api_container),
) -> EventFilterOptions:
    """
    Return dynamic values used by Events filter dropdowns.

    Values are obtained from persisted event data through the
    event repository. No event values are hardcoded here or
    in the frontend.
    """

    if container.event_repository is None:
        raise HTTPException(
            status_code=503,
            detail="event repository is not configured",
        )

    get_filter_options = getattr(
        container.event_repository,
        "get_filter_options",
        None,
    )

    if get_filter_options is None:
        raise HTTPException(
            status_code=501,
            detail="event filter options are not supported",
        )

    options = await get_filter_options()

    # The repository deliberately returns a storage-layer
    # EventFilterOptionsResult rather than an API/Pydantic model.
    #
    # Convert it explicitly at the API boundary instead of
    # passing the custom object to Pydantic model_validate().

    return EventFilterOptions(
        sources=list(options.sources),
        users=list(options.users),
        actions=list(options.actions),
        outcomes=list(options.outcomes),
        severities=list(options.severities),
        categories=list(options.categories),
    )


@router.get(
    "/{event_id}",
    response_model=EventResponse,
)
async def get_event(
    event_id: UUID,
    container: APIContainer = Depends(get_api_container),
) -> EventResponse:
    """
    Return a single persisted security event.
    """

    if container.event_repository is None:
        raise HTTPException(
            status_code=503,
            detail="event repository is not configured",
        )

    event = await container.event_repository.get(event_id)

    if event is None:
        raise HTTPException(
            status_code=404,
            detail="event not found",
        )

    return EventResponse.from_event(event)