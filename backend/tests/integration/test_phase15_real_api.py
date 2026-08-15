from __future__ import annotations

from fastapi.testclient import TestClient

from app.api.dependencies import APIContainer
from app.main import build_application


def test_real_phase15_api_surface() -> None:
    app = build_application(api_container=APIContainer())
    client = TestClient(app)

    assert client.get("/api/v1/health").status_code == 200
    assert client.get("/api/v1/system").status_code == 200
    assert client.get("/api/v1/alerts").status_code == 200
    assert client.get("/api/v1/incidents").status_code == 200
    assert client.get("/api/v1/iocs").status_code == 200
    assert client.get("/api/v1/events").status_code == 503
    assert client.get("/api/v1/users").status_code == 200

    print("REAL PHASE 15 API VALIDATION PASSED")
