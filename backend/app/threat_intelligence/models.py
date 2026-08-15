from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class IOCType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    HOSTNAME = "hostname"


class IOCStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class Reputation(StrEnum):
    UNKNOWN = "unknown"
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class IOC(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    ioc_id: UUID = Field(default_factory=uuid4)
    ioc_type: IOCType
    value: str = Field(min_length=1)
    normalized_value: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    source: str = Field(min_length=1)
    first_seen: datetime
    last_seen: datetime
    expiration: datetime | None = None
    reputation: Reputation = Reputation.UNKNOWN
    status: IOCStatus = IOCStatus.ACTIVE
    feed: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)


class IOCCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ioc_type: IOCType
    value: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    source: str = Field(min_length=1)
    expiration: datetime | None = None
    reputation: Reputation = Reputation.UNKNOWN
    feed: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)


class IOCMatch(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    ioc_id: UUID
    ioc_type: IOCType
    value: str
    confidence: float
    reputation: Reputation
    source: str


def utcnow() -> datetime:
    return datetime.now(UTC)
