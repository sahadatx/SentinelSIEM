from __future__ import annotations

from fastapi.testclient import TestClient

from app.api.dependencies import APIContainer
from app.main import build_application


def test_v1_health_and_system() -> None:
    app = build_application(api_container=APIContainer())
    client = TestClient(app)
    health = client.get("/api/v1/health")
    system = client.get("/api/v1/system")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert system.status_code == 200
    assert "api" in system.json()["capabilities"]


def test_events_without_repository_returns_service_unavailable() -> None:
    app = build_application(api_container=APIContainer())
    client = TestClient(app)
    response = client.get("/api/v1/events")
    assert response.status_code == 503


def test_request_id_is_returned() -> None:
    app = build_application(api_container=APIContainer())
    client = TestClient(app)
    response = client.get("/api/v1/system", headers={"X-Request-ID": "test-request-123"})
    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "test-request-123"
