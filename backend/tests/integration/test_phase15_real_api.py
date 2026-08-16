from __future__ import annotations

from fastapi.testclient import TestClient

from app.api.dependencies import APIContainer
from app.main import build_application


def test_real_phase15_api_surface() -> None:
    """Validate the Phase 15 API surface after Phase 17 auth integration."""

    app = build_application(api_container=APIContainer())
    client = TestClient(app)

    # ------------------------------------------------------------------
    # Public / capability-independent endpoints
    # ------------------------------------------------------------------

    assert client.get("/api/v1/health").status_code == 200
    assert client.get("/api/v1/system").status_code == 200
    assert client.get("/api/v1/alerts").status_code == 200
    assert client.get("/api/v1/incidents").status_code == 200
    assert client.get("/api/v1/iocs").status_code == 200

    # ------------------------------------------------------------------
    # Existing Phase 15 repository dependency
    # ------------------------------------------------------------------

    # The event repository is intentionally not configured in this
    # integration test container.
    assert client.get("/api/v1/events").status_code == 503

    # ------------------------------------------------------------------
    # Phase 17 authentication boundary
    # ------------------------------------------------------------------

    # User-management capability is now protected by the Phase 17
    # authentication and authorization subsystem.
    #
    # No Bearer token is supplied here, therefore authentication must
    # fail before permission evaluation.
    assert client.get("/api/v1/users").status_code == 401

    print("REAL PHASE 15 API VALIDATION PASSED")
