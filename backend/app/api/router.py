from __future__ import annotations

from fastapi import APIRouter

from app.api.versioning.v1 import router as v1_router
from app.api.websocket.events import router as websocket_router

api_router = APIRouter()
api_router.include_router(v1_router)
api_router.include_router(websocket_router)
