from __future__ import annotations

from datetime import datetime, timedelta, timezone
from threading import RLock
from uuid import UUID, uuid4

from .models import SessionRecord


class SessionError(ValueError):
    """Raised when a session is missing, expired, or revoked."""


class SessionStore:
    """Thread-safe reference implementation of the session-store contract.

    The application depends on this interface rather than the in-memory
    implementation. Production wiring should use a durable DB/Redis adapter.
    """

    def __init__(self) -> None:
        self._sessions: dict[UUID, SessionRecord] = {}
        self._lock = RLock()

    def create(self, *, user_id: UUID, token_id: str, ttl: timedelta,
               ip_address: str | None = None, user_agent: str | None = None,
               now: datetime | None = None) -> SessionRecord:
        if not token_id or len(token_id) > 128:
            raise ValueError("Invalid token identifier.")
        if ttl <= timedelta(0):
            raise ValueError("Session TTL must be positive.")
        created_at = now or datetime.now(timezone.utc)
        record = SessionRecord(
            session_id=uuid4(), user_id=user_id, token_id=token_id,
            created_at=created_at, expires_at=created_at + ttl,
            ip_address=ip_address, user_agent=user_agent[:512] if user_agent else None,
        )
        with self._lock:
            self._sessions[record.session_id] = record
        return record

    def get_active(self, session_id: UUID, *, now: datetime | None = None) -> SessionRecord:
        with self._lock:
            record = self._sessions.get(session_id)
        if record is None:
            raise SessionError("Session not found.")
        current = now or datetime.now(timezone.utc)
        if record.revoked_at is not None:
            raise SessionError("Session has been revoked.")
        if current >= record.expires_at:
            raise SessionError("Session has expired.")
        return record

    def bind_token(self, session_id: UUID, token_id: str) -> SessionRecord:
        if not token_id or len(token_id) > 128:
            raise ValueError("Invalid token identifier.")
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                raise SessionError("Session not found.")
            updated = SessionRecord(
                session_id=record.session_id, user_id=record.user_id, token_id=token_id,
                created_at=record.created_at, expires_at=record.expires_at,
                revoked_at=record.revoked_at, ip_address=record.ip_address,
                user_agent=record.user_agent,
            )
            self._sessions[session_id] = updated
            return updated

    def revoke(self, session_id: UUID, *, now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None or record.revoked_at is not None:
                return False
            self._sessions[session_id] = SessionRecord(
                session_id=record.session_id, user_id=record.user_id, token_id=record.token_id,
                created_at=record.created_at, expires_at=record.expires_at, revoked_at=current,
                ip_address=record.ip_address, user_agent=record.user_agent,
            )
            return True

    def revoke_user_sessions(self, user_id: UUID, *, now: datetime | None = None) -> int:
        current = now or datetime.now(timezone.utc)
        count = 0
        with self._lock:
            for sid, record in tuple(self._sessions.items()):
                if record.user_id == user_id and record.revoked_at is None:
                    self._sessions[sid] = SessionRecord(
                        session_id=record.session_id, user_id=record.user_id, token_id=record.token_id,
                        created_at=record.created_at, expires_at=record.expires_at, revoked_at=current,
                        ip_address=record.ip_address, user_agent=record.user_agent,
                    )
                    count += 1
        return count

    def purge_expired(self, *, now: datetime | None = None) -> int:
        current = now or datetime.now(timezone.utc)
        with self._lock:
            expired = [sid for sid, record in self._sessions.items() if record.expires_at <= current]
            for sid in expired:
                self._sessions.pop(sid, None)
            return len(expired)
