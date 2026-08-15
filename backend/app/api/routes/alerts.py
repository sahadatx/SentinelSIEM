from __future__ import annotations

from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException

from app.api.dependencies import APIContainer, get_api_container
from app.api.schemas.alerts import AlertResponse
from app.api.schemas.common import PageResponse, Pagination

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=PageResponse[AlertResponse])
def list_alerts(container: APIContainer = Depends(get_api_container)) -> PageResponse[AlertResponse]:
    alerts = container.alert_manager.list_alerts() if container.alert_manager else []
    return PageResponse(
        items=[AlertResponse.from_model(alert) for alert in alerts],
        pagination=Pagination(page=1, page_size=max(len(alerts), 1), total=len(alerts)),
    )


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(alert_id: UUID, container: APIContainer = Depends(get_api_container)) -> AlertResponse:
    if container.alert_manager is None:
        raise HTTPException(status_code=503, detail="alert manager is not configured")
    try:
        return AlertResponse.from_model(container.alert_manager.get(alert_id))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="alert not found") from exc
