from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from opensearchpy import AsyncOpenSearch


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
            kwargs["http_auth"] = (username, password or "")
        self._client = AsyncOpenSearch(**kwargs)

    @property
    def client(self) -> AsyncOpenSearch:
        return self._client

    async def ping(self) -> bool:
        return bool(await self._client.ping())

    async def close(self) -> None:
        await self._client.close()
