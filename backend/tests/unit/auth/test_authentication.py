from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

from app.auth.authentication import (
    AuthenticationError,
    AuthenticationService,
)
from app.auth.audit import AuditSink
from app.auth.models import AuditRecord, SessionRecord, UserIdentity
from app.auth.password import PasswordHasher
from app.auth.roles import RoleRegistry
from app.auth.sessions import SessionError
from app.auth.tokens import TokenService


# ============================================================================
# Fake User Repository
# ============================================================================


class FakeUserRepository:
    """Async in-memory user repository."""

    def __init__(
        self,
        users: list[UserIdentity],
    ) -> None:
        self.users = users

    async def get_by_login(
        self,
        login: str,
    ) -> UserIdentity | None:
        normalized = login.strip().lower()

        for user in self.users:
            if (
                user.username.lower() == normalized
                or user.email.lower() == normalized
            ):
                return user

        return None

    async def get_by_id(
        self,
        user_id: UUID,
    ) -> UserIdentity | None:
        for user in self.users:
            if user.user_id == user_id:
                return user

        return None


# ============================================================================
# Fake Session Repository
# ============================================================================


class FakeSessionRepository:
    """Async in-memory session repository."""

    def __init__(self) -> None:
        self.sessions: dict[UUID, SessionRecord] = {}

    async def create(
        self,
        session: SessionRecord,
    ) -> SessionRecord:
        self.sessions[session.session_id] = session
        return session

    async def get_active(
        self,
        session_id: UUID,
    ) -> SessionRecord | None:
        session = self.sessions.get(session_id)

        if session is None:
            return None

        now = datetime.now(timezone.utc)

        if session.revoked_at is not None:
            return None

        if session.expires_at <= now:
            return None

        return session

    async def bind_token(
        self,
        session_id: UUID,
        token_id: str,
    ) -> SessionRecord:
        session = self.sessions.get(session_id)

        if session is None:
            raise SessionError("Session does not exist.")

        updated = replace(
            session,
            token_id=token_id,
        )

        self.sessions[session_id] = updated

        return updated

    async def revoke(
        self,
        session_id: UUID,
    ) -> bool:
        session = self.sessions.get(session_id)

        if session is None:
            return False

        if session.revoked_at is not None:
            return False

        updated = replace(
            session,
            revoked_at=datetime.now(timezone.utc),
        )

        self.sessions[session_id] = updated

        return True

    async def revoke_user_sessions(
        self,
        user_id: UUID,
    ) -> int:
        now = datetime.now(timezone.utc)
        count = 0

        for session_id, session in list(
            self.sessions.items(),
        ):
            if (
                session.user_id == user_id
                and session.revoked_at is None
                and session.expires_at > now
            ):
                self.sessions[session_id] = replace(
                    session,
                    revoked_at=now,
                )
                count += 1

        return count

    async def purge_expired(self) -> int:
        now = datetime.now(timezone.utc)

        expired_ids = [
            session_id
            for session_id, session in self.sessions.items()
            if session.expires_at <= now
        ]

        for session_id in expired_ids:
            del self.sessions[session_id]

        return len(expired_ids)


# ============================================================================
# Test Audit Sink
# ============================================================================


class RecordingAuditSink:
    """Async audit sink that records events for assertions."""

    def __init__(self) -> None:
        self.events: list[AuditRecord] = []

    async def record(
        self,
        record: AuditRecord,
    ) -> None:
        self.events.append(record)


# ============================================================================
# Test Service Factory
# ============================================================================


def build_service() -> tuple[
    AuthenticationService,
    RecordingAuditSink,
]:
    """Build an isolated authentication service."""

    password_hasher = PasswordHasher()

    user = UserIdentity(
        user_id=uuid4(),
        username="analyst",
        email="analyst@example.test",
        password_hash=password_hasher.hash(
            "Correct-Horse-Battery-7!",
        ),
        roles=frozenset(
            {
                "SOC_ANALYST",
            },
        ),
        is_active=True,
        is_locked=False,
    )

    users = FakeUserRepository(
        [user],
    )

    sessions = FakeSessionRepository()

    audit = RecordingAuditSink()

    tokens = TokenService(
        secret_key=(
            "test-secret-key-with-at-least-32-characters"
        ),
        issuer="sentinelsiem",
        audience="sentinelsiem-api",
        ttl=timedelta(minutes=30),
        algorithm="HS256",
    )

    service = AuthenticationService(
        users=users,
        tokens=tokens,
        sessions=sessions,
        password_hasher=password_hasher,
        audit=audit,
        roles=RoleRegistry(),
        session_ttl=timedelta(minutes=30),
    )

    return service, audit


# ============================================================================
# Login
# ============================================================================


@pytest.mark.asyncio
async def test_login_by_username_and_email_and_logout() -> None:
    """Authenticate by email, validate token, then logout."""

    service, audit = build_service()

    result = await service.login(
        login="analyst@example.test",
        password="Correct-Horse-Battery-7!",
    )

    assert result.access_token
    assert result.principal.username == "analyst"
    assert result.principal.user_id

    principal = await service.authenticate_token(
        result.access_token,
    )

    assert principal.username == "analyst"
    assert principal.user_id == result.principal.user_id
    assert principal.session_id == result.principal.session_id

    revoked = await service.logout(
        principal,
    )

    assert revoked is True

    with pytest.raises(AuthenticationError):
        await service.authenticate_token(
            result.access_token,
        )

    assert audit.events


@pytest.mark.asyncio
async def test_login_by_username() -> None:
    """Authenticate using username."""

    service, _ = build_service()

    result = await service.login(
        login="analyst",
        password="Correct-Horse-Battery-7!",
    )

    assert result.access_token
    assert result.principal.username == "analyst"


@pytest.mark.asyncio
async def test_login_normalizes_username_and_email() -> None:
    """Login should normalize case and surrounding whitespace."""

    service, _ = build_service()

    result = await service.login(
        login="  ANALYST@EXAMPLE.TEST  ",
        password="Correct-Horse-Battery-7!",
    )

    assert result.access_token
    assert result.principal.username == "analyst"


# ============================================================================
# Invalid Credentials
# ============================================================================


@pytest.mark.asyncio
async def test_invalid_password_is_generic_failure() -> None:
    """Wrong passwords must produce generic authentication failure."""

    service, audit = build_service()

    with pytest.raises(AuthenticationError) as exc_info:
        await service.login(
            login="analyst",
            password="Wrong-Password-123!",
        )

    assert str(exc_info.value) == "Invalid credentials."

    assert audit.events

    record = audit.events[-1]

    assert record.action == "authentication.login"
    assert record.outcome == "failure"


@pytest.mark.asyncio
async def test_unknown_user_is_generic_failure() -> None:
    """Unknown users must not reveal account existence."""

    service, audit = build_service()

    with pytest.raises(AuthenticationError) as exc_info:
        await service.login(
            login="unknown@example.test",
            password="Correct-Horse-Battery-7!",
        )

    assert str(exc_info.value) == "Invalid credentials."

    assert audit.events

    record = audit.events[-1]

    assert record.action == "authentication.login"
    assert record.outcome == "failure"


@pytest.mark.asyncio
async def test_empty_login_is_rejected() -> None:
    """Whitespace-only login must fail."""

    service, audit = build_service()

    with pytest.raises(AuthenticationError) as exc_info:
        await service.login(
            login="   ",
            password="Correct-Horse-Battery-7!",
        )

    assert str(exc_info.value) == "Invalid credentials."

    assert audit.events

    record = audit.events[-1]

    assert record.action == "authentication.login"
    assert record.outcome == "failure"


# ============================================================================
# User State
# ============================================================================


@pytest.mark.asyncio
async def test_inactive_user_is_rejected() -> None:
    """Inactive accounts must not authenticate."""

    password_hasher = PasswordHasher()

    user = UserIdentity(
        user_id=uuid4(),
        username="inactive",
        email="inactive@example.test",
        password_hash=password_hasher.hash(
            "Correct-Horse-Battery-7!",
        ),
        roles=frozenset({"SOC_ANALYST"}),
        is_active=False,
        is_locked=False,
    )

    users = FakeUserRepository([user])
    sessions = FakeSessionRepository()
    audit = RecordingAuditSink()

    tokens = TokenService(
        secret_key=(
            "test-secret-key-with-at-least-32-characters"
        ),
        issuer="sentinelsiem",
        audience="sentinelsiem-api",
        ttl=timedelta(minutes=30),
        algorithm="HS256",
    )

    service = AuthenticationService(
        users=users,
        tokens=tokens,
        sessions=sessions,
        password_hasher=password_hasher,
        audit=audit,
        roles=RoleRegistry(),
    )

    with pytest.raises(AuthenticationError) as exc_info:
        await service.login(
            login="inactive",
            password="Correct-Horse-Battery-7!",
        )

    assert str(exc_info.value) == "Invalid credentials."


@pytest.mark.asyncio
async def test_locked_user_is_rejected() -> None:
    """Locked accounts must not authenticate."""

    password_hasher = PasswordHasher()

    user = UserIdentity(
        user_id=uuid4(),
        username="locked",
        email="locked@example.test",
        password_hash=password_hasher.hash(
            "Correct-Horse-Battery-7!",
        ),
        roles=frozenset({"SOC_ANALYST"}),
        is_active=True,
        is_locked=True,
    )

    users = FakeUserRepository([user])
    sessions = FakeSessionRepository()
    audit = RecordingAuditSink()

    tokens = TokenService(
        secret_key=(
            "test-secret-key-with-at-least-32-characters"
        ),
        issuer="sentinelsiem",
        audience="sentinelsiem-api",
        ttl=timedelta(minutes=30),
        algorithm="HS256",
    )

    service = AuthenticationService(
        users=users,
        tokens=tokens,
        sessions=sessions,
        password_hasher=password_hasher,
        audit=audit,
        roles=RoleRegistry(),
    )

    with pytest.raises(AuthenticationError) as exc_info:
        await service.login(
            login="locked",
            password="Correct-Horse-Battery-7!",
        )

    assert str(exc_info.value) == "Invalid credentials."


# ============================================================================
# Token Validation
# ============================================================================


@pytest.mark.asyncio
async def test_invalid_token_is_rejected() -> None:
    """Malformed access tokens must be rejected."""

    service, audit = build_service()

    with pytest.raises(AuthenticationError):
        await service.authenticate_token(
            "not-a-valid-jwt",
        )

    assert audit.events

    record = audit.events[-1]

    assert record.action == "authentication.token_validation"
    assert record.outcome == "failure"


@pytest.mark.asyncio
async def test_logout_revokes_session() -> None:
    """Logout must invalidate the associated session."""

    service, _ = build_service()

    result = await service.login(
        login="analyst",
        password="Correct-Horse-Battery-7!",
    )

    principal = await service.authenticate_token(
        result.access_token,
    )

    assert await service.logout(principal) is True

    with pytest.raises(AuthenticationError):
        await service.authenticate_token(
            result.access_token,
        )


# ============================================================================
# Session Revocation
# ============================================================================


@pytest.mark.asyncio
async def test_revoke_all_sessions() -> None:
    """All active sessions for a user must be revoked."""

    service, _ = build_service()

    first = await service.login(
        login="analyst",
        password="Correct-Horse-Battery-7!",
    )

    second = await service.login(
        login="analyst",
        password="Correct-Horse-Battery-7!",
    )

    assert first.principal.user_id == second.principal.user_id
    assert first.principal.session_id != second.principal.session_id

    count = await service.revoke_all_sessions(
        first.principal.user_id,
    )

    assert count == 2

    with pytest.raises(AuthenticationError):
        await service.authenticate_token(
            first.access_token,
        )

    with pytest.raises(AuthenticationError):
        await service.authenticate_token(
            second.access_token,
        )
