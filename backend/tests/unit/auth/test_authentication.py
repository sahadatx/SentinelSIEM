from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from app.auth.audit import AuditRecord
from app.auth.authentication import (
    AuthenticationError,
    AuthenticationService,
)
from app.auth.models import (
    AuditAction,
    AuditOutcome,
    SessionRecord,
    UserIdentity,
)
from app.auth.password import PasswordHasher
from app.auth.roles import RoleRegistry
from app.auth.sessions import SessionError
from app.auth.tokens import TokenService

# ============================================================================
# Test Constants
# ============================================================================

TEST_PASSWORD = "Correct-Horse-Battery-7!"
WRONG_PASSWORD = "Wrong-Password-123!"

TEST_SECRET = "test-secret-key-with-at-least-32-characters"
TEST_ISSUER = "sentinelsiem"
TEST_AUDIENCE = "sentinelsiem-api"

SESSION_TTL = timedelta(minutes=30)
TOKEN_TTL = timedelta(minutes=30)

DEFAULT_USERNAME = "analyst"
DEFAULT_EMAIL = "analyst@example.test"
DEFAULT_ROLE = "SOC_ANALYST"


# ============================================================================
# Fake User Repository
# ============================================================================


class FakeUserRepository:
    """
    Minimal in-memory user repository used by AuthenticationService tests.

    This fake intentionally implements only the repository behavior required
    by AuthenticationService. Detailed repository behavior belongs in the
    repository/user-management test suites.
    """

    def __init__(self, users: list[UserIdentity]) -> None:
        self.users = list(users)

    async def get_by_login(
        self,
        login: str,
    ) -> UserIdentity | None:
        normalized = login.strip().lower()

        for user in self.users:
            if user.username.lower() == normalized or user.email.lower() == normalized:
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

    async def record_failed_login(
        self,
        user_id: UUID,
        *,
        max_attempts: int = 5,
    ) -> UserIdentity | None:
        user = await self.get_by_id(user_id)

        if user is None:
            return None

        failed_count = user.failed_login_count + 1

        updated = replace(
            user,
            failed_login_count=failed_count,
            is_locked=(user.is_locked or failed_count >= max_attempts),
            updated_at=datetime.now(UTC),
        )

        self._replace(updated)

        return updated

    async def reset_failed_login_count(
        self,
        user_id: UUID,
    ) -> UserIdentity | None:
        user = await self.get_by_id(user_id)

        if user is None:
            return None

        updated = replace(
            user,
            failed_login_count=0,
            updated_at=datetime.now(UTC),
        )

        self._replace(updated)

        return updated

    async def record_successful_login(
        self,
        user_id: UUID,
    ) -> UserIdentity | None:
        user = await self.get_by_id(user_id)

        if user is None:
            return None

        if not user.is_active or user.is_locked:
            return user

        now = datetime.now(UTC)

        updated = replace(
            user,
            failed_login_count=0,
            last_login_at=now,
            updated_at=now,
        )

        self._replace(updated)

        return updated

    async def set_last_login_at(
        self,
        user_id: UUID,
        last_login_at: datetime,
    ) -> UserIdentity | None:
        user = await self.get_by_id(user_id)

        if user is None:
            return None

        if last_login_at.tzinfo is None:
            raise ValueError(
                "Timestamp must be timezone-aware.",
            )

        updated = replace(
            user,
            last_login_at=last_login_at.astimezone(UTC),
            updated_at=datetime.now(UTC),
        )

        self._replace(updated)

        return updated

    def _replace(self, updated: UserIdentity) -> None:
        for index, current in enumerate(self.users):
            if current.user_id == updated.user_id:
                self.users[index] = updated
                return


# ============================================================================
# Fake Session Repository
# ============================================================================


class FakeSessionRepository:
    """
    Minimal session repository required by AuthenticationService.

    Repository-specific lifecycle tests are intentionally not kept here.
    """

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

        now = datetime.now(UTC)

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
            raise SessionError(
                "Session does not exist.",
            )

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

        self.sessions[session_id] = replace(
            session,
            revoked_at=datetime.now(UTC),
        )

        return True

    async def revoke_user_sessions(
        self,
        user_id: UUID,
    ) -> int:
        now = datetime.now(UTC)
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


# ============================================================================
# Recording Audit Sink
# ============================================================================


class RecordingAuditSink:
    """In-memory audit sink for authentication tests."""

    def __init__(self) -> None:
        self.events: list[AuditRecord] = []

    async def record(
        self,
        record: AuditRecord,
    ) -> None:
        self.events.append(record)


# ============================================================================
# Test Factory
# ============================================================================


def make_user(
    *,
    username: str = DEFAULT_USERNAME,
    email: str = DEFAULT_EMAIL,
    password: str = TEST_PASSWORD,
    roles: frozenset[str] = frozenset({DEFAULT_ROLE}),
    is_active: bool = True,
    is_locked: bool = False,
    failed_login_count: int = 0,
) -> UserIdentity:
    """Create an isolated test identity."""

    hasher = PasswordHasher()

    return UserIdentity(
        user_id=uuid4(),
        username=username,
        email=email,
        password_hash=hasher.hash(password),
        roles=roles,
        is_active=is_active,
        is_locked=is_locked,
        failed_login_count=failed_login_count,
    )


def build_service(
    *,
    user: UserIdentity | None = None,
) -> tuple[
    AuthenticationService,
    RecordingAuditSink,
    FakeUserRepository,
    FakeSessionRepository,
]:
    """
    Build a completely isolated AuthenticationService.

    No database, Redis, Docker, network, or application lifespan is used.
    """

    password_hasher = PasswordHasher()

    if user is None:
        user = make_user()

    users = FakeUserRepository([user])
    sessions = FakeSessionRepository()
    audit = RecordingAuditSink()

    tokens = TokenService(
        secret_key=TEST_SECRET,
        issuer=TEST_ISSUER,
        audience=TEST_AUDIENCE,
        ttl=TOKEN_TTL,
        algorithm="HS256",
    )

    service = AuthenticationService(
        users=users,
        tokens=tokens,
        sessions=sessions,
        password_hasher=password_hasher,
        audit=audit,
        roles=RoleRegistry(),
        session_ttl=SESSION_TTL,
    )

    return (
        service,
        audit,
        users,
        sessions,
    )


# ============================================================================
# Authentication — Successful Login
# ============================================================================


@pytest.mark.asyncio
async def test_login_by_username() -> None:
    service, audit, _, _ = build_service()

    result = await service.login(
        login=DEFAULT_USERNAME,
        password=TEST_PASSWORD,
    )

    assert result.access_token
    assert result.principal.user_id
    assert result.principal.session_id
    assert result.principal.username == DEFAULT_USERNAME

    assert audit.events

    record = audit.events[-1]

    assert record.action == AuditAction.LOGIN_SUCCESS
    assert record.outcome == AuditOutcome.SUCCESS


@pytest.mark.asyncio
async def test_login_by_email() -> None:
    service, audit, _, _ = build_service()

    result = await service.login(
        login=DEFAULT_EMAIL,
        password=TEST_PASSWORD,
    )

    assert result.access_token
    assert result.principal.username == DEFAULT_USERNAME
    assert audit.events[-1].action == AuditAction.LOGIN_SUCCESS


@pytest.mark.asyncio
async def test_login_normalizes_login_input() -> None:
    service, _, _, _ = build_service()

    result = await service.login(
        login=f"  {DEFAULT_EMAIL.upper()}  ",
        password=TEST_PASSWORD,
    )

    assert result.access_token
    assert result.principal.username == DEFAULT_USERNAME


@pytest.mark.asyncio
async def test_successful_login_returns_expected_principal() -> None:
    service, _, _, _ = build_service()

    result = await service.login(
        login=DEFAULT_USERNAME,
        password=TEST_PASSWORD,
    )

    principal = result.principal

    assert principal.user_id
    assert principal.username == DEFAULT_USERNAME
    assert principal.roles == frozenset({DEFAULT_ROLE})
    assert principal.session_id

    assert not hasattr(principal, "password")
    assert not hasattr(principal, "password_hash")


# ============================================================================
# Authentication — Invalid Credentials
# ============================================================================


@pytest.mark.asyncio
async def test_invalid_password_returns_generic_error() -> None:
    service, audit, users, _ = build_service()

    with pytest.raises(AuthenticationError) as exc_info:
        await service.login(
            login=DEFAULT_USERNAME,
            password=WRONG_PASSWORD,
        )

    assert str(exc_info.value) == "Invalid credentials."

    user = await users.get_by_login(DEFAULT_USERNAME)

    assert user is not None
    assert user.failed_login_count == 1

    record = audit.events[-1]

    assert record.action == AuditAction.LOGIN_FAILURE
    assert record.outcome == AuditOutcome.FAILURE


@pytest.mark.asyncio
async def test_unknown_user_returns_generic_error() -> None:
    service, audit, _, _ = build_service()

    with pytest.raises(AuthenticationError) as exc_info:
        await service.login(
            login="unknown@example.test",
            password=TEST_PASSWORD,
        )

    assert str(exc_info.value) == "Invalid credentials."

    record = audit.events[-1]

    assert record.action == AuditAction.LOGIN_FAILURE
    assert record.outcome == AuditOutcome.FAILURE
    assert record.target_user_id is None


@pytest.mark.asyncio
async def test_empty_login_is_rejected() -> None:
    service, audit, _, _ = build_service()

    with pytest.raises(AuthenticationError) as exc_info:
        await service.login(
            login="   ",
            password=TEST_PASSWORD,
        )

    assert str(exc_info.value) == "Invalid credentials."
    assert audit.events[-1].action == AuditAction.LOGIN_FAILURE


@pytest.mark.asyncio
async def test_empty_password_is_rejected() -> None:
    service, audit, _, _ = build_service()

    with pytest.raises(AuthenticationError) as exc_info:
        await service.login(
            login=DEFAULT_USERNAME,
            password="",
        )

    assert str(exc_info.value) == "Invalid credentials."
    assert audit.events[-1].action == AuditAction.LOGIN_FAILURE


@pytest.mark.asyncio
async def test_authentication_does_not_reveal_account_existence() -> None:
    service, _, _, _ = build_service()

    with pytest.raises(AuthenticationError) as known_error:
        await service.login(
            login=DEFAULT_USERNAME,
            password=WRONG_PASSWORD,
        )

    with pytest.raises(AuthenticationError) as unknown_error:
        await service.login(
            login="does-not-exist@example.test",
            password=WRONG_PASSWORD,
        )

    assert str(known_error.value) == str(unknown_error.value)
    assert str(known_error.value) == "Invalid credentials."


# ============================================================================
# Authentication — Account State
# ============================================================================


@pytest.mark.asyncio
async def test_inactive_account_is_rejected() -> None:
    user = make_user(
        username="inactive",
        email="inactive@example.test",
        is_active=False,
    )

    service, audit, _, _ = build_service(user=user)

    with pytest.raises(AuthenticationError) as exc_info:
        await service.login(
            login="inactive",
            password=TEST_PASSWORD,
        )

    assert str(exc_info.value) == "Invalid credentials."
    assert audit.events[-1].action == AuditAction.LOGIN_FAILURE


@pytest.mark.asyncio
async def test_locked_account_is_rejected() -> None:
    user = make_user(
        username="locked",
        email="locked@example.test",
        is_locked=True,
    )

    service, audit, _, _ = build_service(user=user)

    with pytest.raises(AuthenticationError) as exc_info:
        await service.login(
            login="locked",
            password=TEST_PASSWORD,
        )

    assert str(exc_info.value) == "Invalid credentials."
    assert audit.events[-1].action == AuditAction.LOGIN_FAILURE


# ============================================================================
# Authentication — Failed Login Protection
# ============================================================================


@pytest.mark.asyncio
async def test_failed_login_increments_counter() -> None:
    service, _, users, _ = build_service()

    with pytest.raises(AuthenticationError):
        await service.login(
            login=DEFAULT_USERNAME,
            password=WRONG_PASSWORD,
        )

    user = await users.get_by_login(DEFAULT_USERNAME)

    assert user is not None
    assert user.failed_login_count == 1


@pytest.mark.asyncio
async def test_repeated_failed_logins_lock_account() -> None:
    service, _, users, _ = build_service()

    for _ in range(5):
        with pytest.raises(AuthenticationError):
            await service.login(
                login=DEFAULT_USERNAME,
                password=WRONG_PASSWORD,
            )

    user = await users.get_by_login(DEFAULT_USERNAME)

    assert user is not None
    assert user.failed_login_count >= 5
    assert user.is_locked is True


@pytest.mark.asyncio
async def test_locked_account_cannot_login_with_correct_password() -> None:
    service, _, users, _ = build_service()

    for _ in range(5):
        with pytest.raises(AuthenticationError):
            await service.login(
                login=DEFAULT_USERNAME,
                password=WRONG_PASSWORD,
            )

    user = await users.get_by_login(DEFAULT_USERNAME)

    assert user is not None
    assert user.is_locked is True

    with pytest.raises(AuthenticationError) as exc_info:
        await service.login(
            login=DEFAULT_USERNAME,
            password=TEST_PASSWORD,
        )

    assert str(exc_info.value) == "Invalid credentials."


@pytest.mark.asyncio
async def test_successful_login_resets_failed_login_counter() -> None:
    service, _, users, _ = build_service()

    for _ in range(2):
        with pytest.raises(AuthenticationError):
            await service.login(
                login=DEFAULT_USERNAME,
                password=WRONG_PASSWORD,
            )

    before = await users.get_by_login(DEFAULT_USERNAME)

    assert before is not None
    assert before.failed_login_count == 2

    await service.login(
        login=DEFAULT_USERNAME,
        password=TEST_PASSWORD,
    )

    after = await users.get_by_login(DEFAULT_USERNAME)

    assert after is not None
    assert after.failed_login_count == 0
    assert after.last_login_at is not None


# ============================================================================
# Authentication — Token Validation
# ============================================================================


@pytest.mark.asyncio
async def test_valid_access_token_authenticates_user() -> None:
    service, _, _, _ = build_service()

    result = await service.login(
        login=DEFAULT_USERNAME,
        password=TEST_PASSWORD,
    )

    principal = await service.authenticate_token(
        result.access_token,
    )

    assert principal.user_id == result.principal.user_id
    assert principal.username == DEFAULT_USERNAME
    assert principal.session_id == result.principal.session_id


@pytest.mark.asyncio
async def test_invalid_access_token_is_rejected() -> None:
    service, audit, _, _ = build_service()

    with pytest.raises(AuthenticationError):
        await service.authenticate_token(
            "not-a-valid-jwt",
        )

    assert audit.events

    record = audit.events[-1]

    assert record.action == AuditAction.LOGIN_FAILURE
    assert record.outcome == AuditOutcome.FAILURE


@pytest.mark.asyncio
async def test_empty_access_token_is_rejected() -> None:
    service, _, _, _ = build_service()

    with pytest.raises(AuthenticationError):
        await service.authenticate_token("")


# ============================================================================
# Authentication — Session Binding
# ============================================================================


@pytest.mark.asyncio
async def test_successful_login_creates_authenticated_session() -> None:
    service, _, _, sessions = build_service()

    result = await service.login(
        login=DEFAULT_USERNAME,
        password=TEST_PASSWORD,
    )

    session = sessions.sessions.get(
        result.principal.session_id,
    )

    assert session is not None
    assert session.user_id == result.principal.user_id
    assert session.session_id == result.principal.session_id
    assert session.revoked_at is None
    assert session.expires_at > datetime.now(UTC)
    assert session.token_id


@pytest.mark.asyncio
async def test_authenticated_session_belongs_to_user() -> None:
    service, _, _, sessions = build_service()

    result = await service.login(
        login=DEFAULT_USERNAME,
        password=TEST_PASSWORD,
    )

    session = sessions.sessions[result.principal.session_id]

    assert session.user_id == result.principal.user_id


# ============================================================================
# Authentication — Logout
# ============================================================================


@pytest.mark.asyncio
async def test_logout_revokes_authenticated_session() -> None:
    service, _, _, sessions = build_service()

    result = await service.login(
        login=DEFAULT_USERNAME,
        password=TEST_PASSWORD,
    )

    principal = await service.authenticate_token(
        result.access_token,
    )

    assert await service.logout(principal) is True

    session = sessions.sessions.get(
        principal.session_id,
    )

    assert session is not None
    assert session.revoked_at is not None


@pytest.mark.asyncio
async def test_logout_invalidates_access_token() -> None:
    service, _, _, _ = build_service()

    result = await service.login(
        login=DEFAULT_USERNAME,
        password=TEST_PASSWORD,
    )

    principal = await service.authenticate_token(
        result.access_token,
    )

    assert await service.logout(principal) is True

    with pytest.raises(AuthenticationError):
        await service.authenticate_token(
            result.access_token,
        )


@pytest.mark.asyncio
async def test_logout_emits_success_audit_event() -> None:
    service, audit, _, _ = build_service()

    result = await service.login(
        login=DEFAULT_USERNAME,
        password=TEST_PASSWORD,
    )

    principal = await service.authenticate_token(
        result.access_token,
    )

    await service.logout(principal)

    logout_events = [event for event in audit.events if event.action == AuditAction.LOGOUT]

    assert logout_events

    record = logout_events[-1]

    assert record.outcome == AuditOutcome.SUCCESS
    assert record.actor_user_id == principal.user_id
    assert record.session_id == principal.session_id


# ============================================================================
# Authentication — Multiple Sessions
# ============================================================================


@pytest.mark.asyncio
async def test_multiple_successful_logins_create_distinct_sessions() -> None:
    service, _, _, sessions = build_service()

    first = await service.login(
        login=DEFAULT_USERNAME,
        password=TEST_PASSWORD,
    )

    second = await service.login(
        login=DEFAULT_USERNAME,
        password=TEST_PASSWORD,
    )

    assert first.principal.session_id != second.principal.session_id
    assert len(sessions.sessions) == 2


@pytest.mark.asyncio
async def test_revoke_all_sessions_invalidates_user_sessions() -> None:
    service, _, _, sessions = build_service()

    first = await service.login(
        login=DEFAULT_USERNAME,
        password=TEST_PASSWORD,
    )

    await service.login(
        login=DEFAULT_USERNAME,
        password=TEST_PASSWORD,
    )

    count = await service.revoke_all_sessions(
        first.principal.user_id,
    )

    assert count == 2

    for session in sessions.sessions.values():
        assert session.revoked_at is not None


@pytest.mark.asyncio
async def test_revoke_all_sessions_invalidates_all_access_tokens() -> None:
    service, _, _, _ = build_service()

    first = await service.login(
        login=DEFAULT_USERNAME,
        password=TEST_PASSWORD,
    )

    second = await service.login(
        login=DEFAULT_USERNAME,
        password=TEST_PASSWORD,
    )

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


# ============================================================================
# Authentication — Audit Security
# ============================================================================


def serialize_audit(record: AuditRecord) -> str:
    """Serialize an audit record for secret-leak assertions."""
    return repr(record)


@pytest.mark.asyncio
async def test_successful_login_audit_does_not_contain_password() -> None:
    service, audit, _, _ = build_service()

    await service.login(
        login=DEFAULT_USERNAME,
        password=TEST_PASSWORD,
    )

    serialized = serialize_audit(audit.events[-1])

    assert TEST_PASSWORD not in serialized
    assert "password_hash" not in serialized.lower()


@pytest.mark.asyncio
async def test_failed_login_audit_does_not_contain_password() -> None:
    service, audit, _, _ = build_service()

    with pytest.raises(AuthenticationError):
        await service.login(
            login=DEFAULT_USERNAME,
            password=WRONG_PASSWORD,
        )

    serialized = serialize_audit(audit.events[-1])

    assert TEST_PASSWORD not in serialized
    assert WRONG_PASSWORD not in serialized
    assert "password_hash" not in serialized.lower()


@pytest.mark.asyncio
async def test_successful_login_audit_contains_identity() -> None:
    service, audit, _, _ = build_service()

    result = await service.login(
        login=DEFAULT_USERNAME,
        password=TEST_PASSWORD,
    )

    record = audit.events[-1]

    assert record.action == AuditAction.LOGIN_SUCCESS
    assert record.outcome == AuditOutcome.SUCCESS
    assert record.actor_user_id == result.principal.user_id


@pytest.mark.asyncio
async def test_failed_login_audit_contains_failure_outcome() -> None:
    service, audit, _, _ = build_service()

    with pytest.raises(AuthenticationError):
        await service.login(
            login=DEFAULT_USERNAME,
            password=WRONG_PASSWORD,
        )

    record = audit.events[-1]

    assert record.action == AuditAction.LOGIN_FAILURE
    assert record.outcome == AuditOutcome.FAILURE
