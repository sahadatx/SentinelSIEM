from __future__ import annotations

from fastapi import APIRouter

from app.api.routes.alerts import router as alerts_router
from app.api.routes.auth import router as auth_router
from app.api.routes.capabilities import router as capabilities_router
from app.api.routes.events import router as events_router
from app.api.routes.health import router as health_router
from app.api.routes.incidents import router as incidents_router
from app.api.routes.iocs import router as iocs_router
from app.api.routes.mitre import router as mitre_router
from app.api.routes.system import router as system_router


router = APIRouter(prefix="/api/v1")


# ---------------------------------------------------------------------------
# Platform / health
# ---------------------------------------------------------------------------

router.include_router(health_router)
router.include_router(system_router)


# ---------------------------------------------------------------------------
# Phase 17 — Authentication / Authorization
# ---------------------------------------------------------------------------

router.include_router(auth_router)


# ---------------------------------------------------------------------------
# Security data APIs
# ---------------------------------------------------------------------------

router.include_router(events_router)
router.include_router(alerts_router)
router.include_router(incidents_router)
router.include_router(iocs_router)
router.include_router(mitre_router)


# ---------------------------------------------------------------------------
# Capability / reserved platform APIs
# ---------------------------------------------------------------------------

router.include_router(capabilities_router)