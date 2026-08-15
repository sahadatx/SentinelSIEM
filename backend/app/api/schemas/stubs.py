from __future__ import annotations

from .common import APIModel


class CapabilityResponse(APIModel):
    resource: str
    status: str
    message: str
