from __future__ import annotations

from app.api.schemas.common import APIModel


class SystemResponse(APIModel):
    """Public system metadata returned by the System API."""

    service: str
    version: str
    environment: str
    capabilities: list[str]
