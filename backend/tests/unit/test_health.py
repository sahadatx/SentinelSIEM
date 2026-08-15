from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import build_application


def test_liveness_endpoint() -> None:
    app = build_application()
    client = TestClient(app)

    response = client.get("/health/live")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["service"] == "siem-security-platform"


def test_readiness_endpoint() -> None:
    app = build_application()
    client = TestClient(app)

    response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json()["status"] == "ready"
