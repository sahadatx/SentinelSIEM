from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

from app.core.metrics import REGISTRY

router = APIRouter(prefix="/metrics", tags=["observability"])


@router.get("", response_class=PlainTextResponse, include_in_schema=False)
async def metrics() -> PlainTextResponse:
    return PlainTextResponse(
        REGISTRY.render(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
