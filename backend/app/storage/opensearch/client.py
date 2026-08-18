from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from opensearchpy import AsyncOpenSearch

from app.core.metrics import REGISTRY, Timer

_OPENSEARCH_CLIENT_LATENCY_HELP = (
    "OpenSearch client operation latency in seconds."
)
_OPENSEARCH_FAILURES_HELP = (
    "Total OpenSearch operation failures."
)
_OPENSEARCH_HEALTH_HELP = (
    "OpenSearch health status (1=healthy, 0=unhealthy)."
)


class OpenSearchClient:
    """Small lifecycle wrapper around the asynchronous OpenSearch client."""

    def __init__(
        self,
        hosts: list[Mapping[str, Any]],
        *,
        username: str | None = None,
        password: str | None = None,
        use_ssl: bool = True,
        verify_certs: bool = True,
        ca_certs: str | None = None,
    ) -> None:
        """Initialize the OpenSearch client.

        Args:
            hosts: OpenSearch host definitions accepted by opensearch-py.
            username: Optional HTTP basic authentication username.
            password: Optional HTTP basic authentication password.
            use_ssl: Enable HTTPS/TLS transport.
            verify_certs: Verify the server certificate when TLS is enabled.
            ca_certs: Optional path to a trusted CA bundle used for
                server-certificate verification.
        """
        if verify_certs and use_ssl and not ca_certs:
            raise ValueError(
                "ca_certs must be provided when TLS certificate "
                "verification is enabled."
            )

        if ca_certs and not use_ssl:
            raise ValueError(
                "ca_certs cannot be configured when SSL is disabled."
            )

        kwargs: dict[str, Any] = {
            "hosts": hosts,
            "use_ssl": use_ssl,
            "verify_certs": verify_certs,
        }

        if ca_certs is not None:
            kwargs["ca_certs"] = ca_certs

        if username is not None:
            kwargs["http_auth"] = (
                username,
                password or "",
            )

        self._client = AsyncOpenSearch(**kwargs)

    @property
    def client(self) -> AsyncOpenSearch:
        """Return the underlying asynchronous OpenSearch client."""
        return self._client

    async def ping(self) -> bool:
        """Check OpenSearch availability and update health metrics."""
        try:
            with Timer(
                REGISTRY,
                "siem_opensearch_client_operation_latency_seconds",
                help_text=_OPENSEARCH_CLIENT_LATENCY_HELP,
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
        """Close the underlying OpenSearch connection."""
        await self._client.close()
