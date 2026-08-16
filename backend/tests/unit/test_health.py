from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import build_application


def test_liveness_endpoint() -> None:
    app = build_application(
        configure_database=False,
    )
    client = TestClient(app)

    response = client.get("/health/live")

    assert response.status_code == 200

    payload = response.json()

    assert payload["status"] == "ok"
    assert payload["service"] == "siem-security-platform"
    assert payload["version"] == "0.1.0"


def test_readiness_endpoint() -> None:
    app = build_application(
        configure_database=False,
    )
    client = TestClient(app)

    response = client.get("/health/ready")

    assert response.status_code == 200

    payload = response.json()

    assert payload["status"] == "ready"
    assert payload["service"] == "siem-security-platform"
    assert payload["version"] == "0.1.0"
    assert "checks" not in payload
