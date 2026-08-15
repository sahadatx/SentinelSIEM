from __future__ import annotations

from uuid import UUID

from app.threat_intelligence.models import IOC, IOCMatch
from .common import APIModel


class IOCResponse(APIModel):
    ioc_id: UUID
    ioc_type: str
    value: str
    confidence: float
    source: str
    first_seen: object
    last_seen: object
    expiration: object | None = None
    feed: str | None = None
    reputation: str
    status: str
    metadata: dict[str, object]

    @classmethod
    def from_model(cls, ioc: IOC) -> "IOCResponse":
        return cls.model_validate(ioc.model_dump(mode="json"))


class IOCMatchResponse(APIModel):
    ioc_id: UUID
    ioc_type: str
    value: str
    confidence: float
    reputation: str

    @classmethod
    def from_model(cls, match: IOCMatch) -> "IOCMatchResponse":
        return cls.model_validate(match.model_dump(mode="json"))
