from __future__ import annotations

from collections.abc import Awaitable, Callable
from time import monotonic

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.metrics import REGISTRY


class MetricsMiddleware(BaseHTTPMiddleware):
    """Record bounded, low-cardinality HTTP metrics."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        started = monotonic()
        method = request.method

        try:
            response = await call_next(request)
        except Exception:
            REGISTRY.inc_counter(
                "siem_http_requests_total",
                help_text="Total HTTP requests processed by the API.",
                labels={"method": method, "status": "500"},
            )
            REGISTRY.inc_counter(
                "siem_http_errors_total",
                help_text=(
                    "Total HTTP requests that terminated with an exception."
                ),
                labels={"method": method},
            )
            REGISTRY.observe(
                "siem_http_request_duration_seconds",
                monotonic() - started,
                help_text="HTTP request duration in seconds.",
                labels={"method": method},
            )
            raise

        status = str(response.status_code)

        REGISTRY.inc_counter(
            "siem_http_requests_total",
            help_text="Total HTTP requests processed by the API.",
            labels={"method": method, "status": status},
        )

        if response.status_code >= 500:
            REGISTRY.inc_counter(
                "siem_http_errors_total",
                help_text="Total HTTP requests that returned a server error.",
                labels={"method": method},
            )

        REGISTRY.observe(
            "siem_http_request_duration_seconds",
            monotonic() - started,
            help_text="HTTP request duration in seconds.",
            labels={"method": method},
        )

        return response
