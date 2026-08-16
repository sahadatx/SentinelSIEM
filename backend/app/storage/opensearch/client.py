from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from opensearchpy import AsyncOpenSearch

from app.core.metrics import REGISTRY, Timer

_OPENSEARCH_LATENCY_HELP = (
    "OpenSearch operation latency in seconds."
)
_OPENSEARCH_FAILURES_HELP = (
    "Total OpenSearch operation failures."
)
_OPENSEARCH_HEALTH_HELP = (
    "OpenSearch health status (1=healthy, 0=unhealthy)."
)


class OpenSearchClient:
    """Small lifecycle wrapper around the async OpenSearch client."""

    def __init__(
        self,
        hosts: list[Mapping[str, Any]],
        *,
        username: str | None = None,
        password: str | None = None,
        use_ssl: bool = True,
        verify_certs: bool = True,
    ) -> None:
        kwargs: dict[str, Any] = {
            "hosts": hosts,
            "use_ssl": use_ssl,
            "verify_certs": verify_certs,
        }

        if username is not None:
            kwargs["http_auth"] = (
                username,
                password or "",
            )

        self._client = AsyncOpenSearch(**kwargs)

    @property
    def client(self) -> AsyncOpenSearch:
        return self._client

    async def ping(self) -> bool:
        try:
            with Timer(
                REGISTRY,
                "siem_opensearch_operation_latency_seconds",
                help_text=_OPENSEARCH_LATENCY_HELP,
                labels={"operation": "ping"},
            ):
                result = bool(await self._client.ping())

        except Exception:
            REGISTRY.inc_counter(
                "siem_opensearch_operation_failures_total",
                help_text=_OPENSEARCH_FAILURES_HELP,
                labels={"operation": "ping"},
            )
            REGISTRY.set_gauge(
                "siem_opensearch_health",
                0.0,
                help_text=_OPENSEARCH_HEALTH_HELP,
            )
            raise

        REGISTRY.set_gauge(
            "siem_opensearch_health",
            1.0 if result else 0.0,
            help_text=_OPENSEARCH_HEALTH_HELP,
        )

        return result

    async def close(self) -> None:
        await self._client.close()