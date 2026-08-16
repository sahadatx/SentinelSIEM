from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    delete,
    select,
    update,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID as PGUUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from app.auth.models import AuditRecord, SessionRecord, UserIdentity
from app.auth.repositories import (
    AuthAuditRepository,
    AuthAuditRepositoryError,
    SessionRepository,
    SessionRepositoryError,
    UserRepository,
    UserRepositoryError,
)
from app.storage.postgres.models import Base

if TYPE_CHECKING:
    from app.storage.postgres.session import PostgresSessionManager


# ============================================================================
# Helpers
# ============================================================================


def _utcnow() -> datetime:
    """Return the current timezone-aware UTC datetime."""

    return datetime.now(timezone.utc)


def _ensure_utc(value: datetime) -> datetime:
    """
    Normalize a datetime to timezone-aware UTC.

    PostgreSQL TIMESTAMPTZ values should normally already be timezone-aware,
    but this keeps the repository boundary defensive.
    """

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


# ============================================================================
# SQLAlchemy mappings
# ============================================================================
#
# These classes map the existing Phase 17 database schema.
#
# They are NOT migrations.
# They do NOT create or modify tables at runtime.
#
# Authoritative schema:
#
#     backend/app/storage/migrations/002_authentication.sql
#
# ============================================================================


class AuthUser(Base):
    """SQLAlchemy mapping for siem_users."""

    __tablename__ = "siem_users"

    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
    )

    username: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        unique=True,
    )

    email: Mapped[str] = mapped_column(
        String(320),
        nullable=False,
        unique=True,
    )

    password_hash: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    is_locked: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    failed_login_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )


class AuthRole(Base):
    """SQLAlchemy mapping for siem_roles."""

    __tablename__ = "siem_roles"

    role_name: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )

    description: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        default="",
    )


class AuthPermission(Base):
    """SQLAlchemy mapping for siem_permissions."""

    __tablename__ = "siem_permissions"

    permission_name: Mapped[str] = mapped_column(
        String(128),
        primary_key=True,
    )

    description: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        default="",
    )


class AuthUserRole(Base):
    """SQLAlchemy mapping for siem_user_roles."""

    __tablename__ = "siem_user_roles"

    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "siem_users.user_id",
            ondelete="CASCADE",
        ),
        primary_key=True,
    )

    role_name: Mapped[str] = mapped_column(
        String(64),
        ForeignKey(
            "siem_roles.role_name",
            ondelete="RESTRICT",
        ),
        primary_key=True,
    )


class AuthRolePermission(Base):
    """SQLAlchemy mapping for siem_role_permissions."""

    __tablename__ = "siem_role_permissions"

    role_name: Mapped[str] = mapped_column(
        String(64),
        ForeignKey(
            "siem_roles.role_name",
            ondelete="CASCADE",
        ),
        primary_key=True,
    )

    permission_name: Mapped[str] = mapped_column(
        String(128),
        ForeignKey(
            "siem_permissions.permission_name",
            ondelete="CASCADE",
        ),
        primary_key=True,
    )


class AuthSession(Base):
    """SQLAlchemy mapping for siem_sessions."""

    __tablename__ = "siem_sessions"

    session_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
    )

    user_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "siem_users.user_id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    token_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        unique=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    ip_address: Mapped[str | None] = mapped_column(
        INET,
        nullable=True,
    )

    user_agent: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
    )


class AuthAudit(Base):
    """SQLAlchemy mapping for siem_auth_audit."""

    __tablename__ = "siem_auth_audit"

    audit_id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
    )

    action: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    outcome: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    actor_user_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "siem_users.user_id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    target_user_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey(
            "siem_users.user_id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    session_id: Mapped[UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=True,
    )

    request_id: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )

    source_ip: Mapped[str | None] = mapped_column(
        INET,
        nullable=True,
    )

    # PostgreSQL column is named "metadata".
    #
    # "metadata" is reserved by SQLAlchemy's Declarative API,
    # therefore the Python-side attribute is named "audit_metadata".
    audit_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )


# ============================================================================
# PostgreSQL User Repository
# ============================================================================


class PostgresUserRepository(UserRepository):
    """
    PostgreSQL-backed authentication user repository.

    Reads users and their assigned roles from the dedicated Phase 17
    authentication tables.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_by_login(
        self,
        login: str,
    ) -> UserIdentity | None:
        """Find an authentication identity by username or email."""

        normalized = login.strip().lower()

        if not normalized:
            return None

        try:
            result = await self.session.execute(
                select(AuthUser).where(
                    (AuthUser.username == normalized)
                    | (AuthUser.email == normalized)
                )
            )

            user = result.scalar_one_or_none()

            if user is None:
                return None

            return await self._to_identity(user)

        except UserRepositoryError:
            raise

        except Exception as exc:
            raise UserRepositoryError(
                "Unable to retrieve authentication identity."
            ) from exc

    async def get_by_id(
        self,
        user_id: UUID,
    ) -> UserIdentity | None:
        """Find an authentication identity by UUID."""

        try:
            result = await self.session.execute(
                select(AuthUser).where(
                    AuthUser.user_id == user_id
                )
            )

            user = result.scalar_one_or_none()

            if user is None:
                return None

            return await self._to_identity(user)

        except UserRepositoryError:
            raise

        except Exception as exc:
            raise UserRepositoryError(
                "Unable to retrieve authentication identity."
            ) from exc

    async def _to_identity(
        self,
        user: AuthUser,
    ) -> UserIdentity:
        """Convert the SQLAlchemy user entity into the domain identity model."""

        try:
            result = await self.session.execute(
                select(AuthUserRole.role_name).where(
                    AuthUserRole.user_id == user.user_id
                )
            )

            roles = frozenset(
                str(role)
                for role in result.scalars().all()
            )

            return UserIdentity(
                user_id=user.user_id,
                username=user.username,
                email=user.email,
                password_hash=user.password_hash,
                roles=roles,
                is_active=user.is_active,
                is_locked=user.is_locked,
                failed_login_count=user.failed_login_count,
                created_at=_ensure_utc(user.created_at),
                updated_at=_ensure_utc(user.updated_at),
            )

        except UserRepositoryError:
            raise

        except Exception as exc:
            raise UserRepositoryError(
                "Authentication identity data is invalid."
            ) from exc


# ============================================================================
# PostgreSQL Session Repository
# ============================================================================


class PostgresSessionRepository(SessionRepository):
    """
    PostgreSQL-backed authentication session repository.

    Sessions are persisted in siem_sessions.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self,
        session: SessionRecord,
    ) -> SessionRecord:
        """
        Persist a new authentication session.

        The Phase 17 migration requires token_id to be non-null and unique.

        AuthenticationService creates the session before the JWT is issued,
        so an empty token_id cannot be persisted safely.

        A session-specific temporary identifier is therefore persisted.
        bind_token() replaces it with the real JWT JTI immediately afterward.
        """

        if session.expires_at <= session.created_at:
            raise SessionRepositoryError(
                "Authentication session expiration must be "
                "after session creation."
            )

        pending_token_id = (
            session.token_id
            if session.token_id
            else f"pending:{session.session_id}"
        )

        if len(pending_token_id) > 128:
            raise SessionRepositoryError(
                "Authentication token identifier is invalid."
            )

        try:
            record = AuthSession(
                session_id=session.session_id,
                user_id=session.user_id,
                token_id=pending_token_id,
                created_at=_ensure_utc(session.created_at),
                expires_at=_ensure_utc(session.expires_at),
                revoked_at=(
                    _ensure_utc(session.revoked_at)
                    if session.revoked_at is not None
                    else None
                ),
                ip_address=session.ip_address,
                user_agent=session.user_agent,
            )

            self.session.add(record)

            await self.session.flush()

            return session

        except SessionRepositoryError:
            raise

        except Exception as exc:
            raise SessionRepositoryError(
                "Unable to persist authentication session."
            ) from exc

    async def get_active(
        self,
        session_id: UUID,
    ) -> SessionRecord | None:
        """Return an active, non-expired session."""

        try:
            now = _utcnow()

            result = await self.session.execute(
                select(AuthSession).where(
                    AuthSession.session_id == session_id,
                    AuthSession.revoked_at.is_(None),
                    AuthSession.expires_at > now,
                )
            )

            record = result.scalar_one_or_none()

            if record is None:
                return None

            return self._to_session(record)

        except SessionRepositoryError:
            raise

        except Exception as exc:
            raise SessionRepositoryError(
                "Unable to retrieve authentication session."
            ) from exc

    async def bind_token(
        self,
        session_id: UUID,
        token_id: str,
    ) -> SessionRecord:
        """Replace the temporary session token identifier with the JWT JTI."""

        if not token_id:
            raise ValueError(
                "Token identifier cannot be empty."
            )

        if len(token_id) > 128:
            raise ValueError(
                "Token identifier is too long."
            )

        try:
            now = _utcnow()

            result = await self.session.execute(
                select(AuthSession).where(
                    AuthSession.session_id == session_id,
                    AuthSession.revoked_at.is_(None),
                    AuthSession.expires_at > now,
                )
            )

            record = result.scalar_one_or_none()

            if record is None:
                raise SessionRepositoryError(
                    "Authentication session is not active."
                )

            record.token_id = token_id

            await self.session.flush()

            return self._to_session(record)

        except SessionRepositoryError:
            raise

        except ValueError:
            raise

        except Exception as exc:
            raise SessionRepositoryError(
                "Unable to bind token to authentication session."
            ) from exc

    async def revoke(
        self,
        session_id: UUID,
    ) -> bool:
        """Revoke a single authentication session."""

        try:
            result = await self.session.execute(
                select(AuthSession).where(
                    AuthSession.session_id == session_id
                )
            )

            record = result.scalar_one_or_none()

            if record is None:
                return False

            if record.revoked_at is not None:
                return False

            record.revoked_at = _utcnow()

            await self.session.flush()

            return True

        except Exception as exc:
            raise SessionRepositoryError(
                "Unable to revoke authentication session."
            ) from exc

    async def revoke_user_sessions(
        self,
        user_id: UUID,
    ) -> int:
        """Revoke all currently active sessions for a user."""

        try:
            now = _utcnow()

            result = await self.session.execute(
                update(AuthSession)
                .where(
                    AuthSession.user_id == user_id,
                    AuthSession.revoked_at.is_(None),
                    AuthSession.expires_at > now,
                )
                .values(
                    revoked_at=now
                )
            )

            await self.session.flush()

            return int(result.rowcount or 0)

        except Exception as exc:
            raise SessionRepositoryError(
                "Unable to revoke user authentication sessions."
            ) from exc

    async def purge_expired(self) -> int:
        """Delete expired authentication sessions."""

        try:
            now = _utcnow()

            result = await self.session.execute(
                delete(AuthSession).where(
                    AuthSession.expires_at <= now
                )
            )

            await self.session.flush()

            return int(result.rowcount or 0)

        except Exception as exc:
            raise SessionRepositoryError(
                "Unable to purge expired authentication sessions."
            ) from exc

    @staticmethod
    def _to_session(
        record: AuthSession,
    ) -> SessionRecord:
        """Convert an ORM session entity into the domain model."""

        try:
            token_id = record.token_id

            # Temporary placeholders must never be treated as JWT JTIs.
            if token_id.startswith("pending:"):
                token_id = ""

            return SessionRecord(
                session_id=record.session_id,
                user_id=record.user_id,
                token_id=token_id,
                created_at=_ensure_utc(record.created_at),
                expires_at=_ensure_utc(record.expires_at),
                revoked_at=(
                    _ensure_utc(record.revoked_at)
                    if record.revoked_at is not None
                    else None
                ),
                ip_address=record.ip_address,
                user_agent=record.user_agent,
            )

        except (TypeError, ValueError) as exc:
            raise SessionRepositoryError(
                "Authentication session data is invalid."
            ) from exc


# ============================================================================
# PostgreSQL Authentication Audit Repository
# ============================================================================


class PostgresAuthAuditRepository(AuthAuditRepository):
    """
    PostgreSQL-backed authentication audit repository.

    This repository uses the AsyncSession supplied by the caller.

    It performs:
        add()
        flush()

    It does NOT commit.

    This is intentional because normal authentication operations participate
    in the request transaction managed by get_db_session().
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def record(
        self,
        record: AuditRecord,
    ) -> None:
        """Persist an authentication audit event in the current transaction."""

        try:
            audit = AuthAudit(
                action=record.action,
                outcome=record.outcome,
                actor_user_id=record.actor_user_id,
                target_user_id=record.target_user_id,
                session_id=record.session_id,
                request_id=record.request_id,
                source_ip=record.source_ip,
                audit_metadata=dict(record.metadata),
                created_at=_ensure_utc(record.timestamp),
            )

            self.session.add(audit)

            await self.session.flush()

        except AuthAuditRepositoryError:
            raise

        except Exception as exc:
            raise AuthAuditRepositoryError(
                "Unable to persist authentication audit event."
            ) from exc


# ============================================================================
# Durable Authentication Audit Repository
# ============================================================================


class PostgresDurableAuthAuditRepository(AuthAuditRepository):
    """
    PostgreSQL authentication audit repository using an independent
    transaction.

    This repository is specifically intended for security-critical events
    that must survive rollback of the main HTTP request transaction.

    Primary use case:

        Failed authentication / invalid login

    Example flow:

        HTTP request
            |
            +---- main request transaction
            |          |
            |          +---- authentication fails
            |          |
            |          +---- rollback
            |
            +---- independent audit transaction
                       |
                       +---- INSERT audit
                       |
                       +---- COMMIT

    Therefore a 401 response or outer transaction rollback cannot remove
    the security audit event.
    """

    def __init__(
        self,
        session_manager: PostgresSessionManager,
    ) -> None:
        self._session_manager = session_manager

    async def record(
        self,
        record: AuditRecord,
    ) -> None:
        """
        Persist and commit an audit event using a separate DB transaction.

        The caller's transaction is never committed or rolled back here.
        """

        try:
            async with self._session_manager.session() as audit_session:
                repository = PostgresAuthAuditRepository(
                    audit_session
                )

                await repository.record(record)

                # Explicitly commit the independent audit transaction.
                await audit_session.commit()

        except AuthAuditRepositoryError:
            raise

        except Exception as exc:
            raise AuthAuditRepositoryError(
                "Unable to durably persist authentication audit event."
            ) from exc


# ============================================================================
# Public exports
# ============================================================================


__all__ = [
    "AuthAudit",
    "AuthPermission",
    "AuthRole",
    "AuthRolePermission",
    "AuthSession",
    "AuthUser",
    "AuthUserRole",
    "PostgresAuthAuditRepository",
    "PostgresDurableAuthAuditRepository",
    "PostgresSessionRepository",
    "PostgresUserRepository",
]
