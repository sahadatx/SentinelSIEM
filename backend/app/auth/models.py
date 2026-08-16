from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class UserIdentity:
    user_id: UUID
    username: str
    email: str
    password_hash: str
    roles: frozenset[str] = field(default_factory=frozenset)
    is_active: bool = True
    is_locked: bool = False
    failed_login_count: int = 0
    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)


@dataclass(frozen=True, slots=True)
class UserPrincipal:
    user_id: UUID
    username: str
    roles: frozenset[str]
    permissions: frozenset[str]
    session_id: UUID


@dataclass(frozen=True, slots=True)
class SessionRecord:
    session_id: UUID = field(default_factory=uuid4)
    user_id: UUID = field(default_factory=uuid4)
    token_id: str = ""
    created_at: datetime = field(default_factory=utcnow)
    expires_at: datetime = field(default_factory=utcnow)
    revoked_at: datetime | None = None
    ip_address: str | None = None
    user_agent: str | None = None

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None and utcnow() < self.expires_at


@dataclass(frozen=True, slots=True)
class AuditRecord:
    action: str
    outcome: str
    actor_user_id: UUID | None = None
    target_user_id: UUID | None = None
    request_id: str | None = None
    session_id: UUID | None = None
    source_ip: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=utcnow)
