from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import build_application


def test_metrics_endpoint_uses_prometheus_content_type() -> None:
    client = TestClient(build_application())

    response = client.get("/metrics")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(
        "text/plain; version=0.0.4"
    )
