from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import (
    AuditRecord,
    SessionRecord,
    UserIdentity,
)
from app.auth.repositories import (
    AuthAuditRepository,
    AuthAuditRepositoryError,
    SessionRepository,
    SessionRepositoryError,
    UserRepository,
    UserRepositoryError,
)
from app.storage.postgres.models import (
    AuthAudit,
    AuthRole,
    AuthSession,
    AuthUser,
    AuthUserRole,
    StorageRecord,
)


"""
SentinelSIEM PostgreSQL Repository Layer
========================================

Concrete PostgreSQL persistence implementations for:

    - Generic structured storage
    - Authentication users
    - Authentication sessions
    - Authentication / identity audit

Architecture
------------

    API
      |
      v
    Service
      |
      v
    Repository Contract
      |
      v
    PostgreSQL Repository
      |
      v
    PostgreSQL

Repository responsibilities
----------------------------

Repositories are persistence boundaries.

Repositories MAY:

    - SELECT
    - INSERT
    - UPDATE
    - DELETE
    - flush ORM state
    - acquire row locks where atomic persistence requires it

Repositories MUST NOT:

    - commit
    - rollback
    - perform authorization
    - make RBAC decisions
    - enforce service workflow policy
    - decide whether an administrator may modify another administrator
    - decide whether a user may delete themselves
    - decide whether the last active ADMIN may be removed
    - revoke sessions as a side effect of unrelated persistence operations

Transaction ownership
---------------------

The service/application layer owns the transaction:

    BEGIN
        repository operations
    COMMIT / ROLLBACK

Security
--------

Plaintext passwords MUST never reach this layer.

Only already-generated password hashes may be persisted.

Access tokens and refresh tokens are never persisted.

JWT JTI/token_id is internal security-sensitive state.

Pending token identifiers are never exposed as real JTIs.

Audit metadata is copied before persistence.

Audit records are immutable.

Timestamp policy
----------------

Authentication and audit timestamps MUST be timezone-aware.

All accepted timestamps are normalized to UTC.

Pagination
----------

User listing and audit listing use deterministic ordering.

Users:

    created_at DESC
    user_id DESC

Audit:

    created_at DESC
    audit_id DESC

Canonical audit storage
-----------------------

Authentication and identity audit events are stored only in:

    siem_auth_audit

User Audit is a filtered view of the same canonical audit stream.

There is intentionally no duplicate User Audit table.
"""


# ============================================================================
# Constants
# ============================================================================

DEFAULT_MAX_FAILED_LOGIN_ATTEMPTS = 5

PENDING_TOKEN_PREFIX = "pending:"
MAX_TOKEN_ID_LENGTH = 128

DEFAULT_USER_PAGE_SIZE = 50
MAX_USER_PAGE_SIZE = 200

DEFAULT_AUDIT_PAGE_SIZE = 50
MAX_AUDIT_PAGE_SIZE = 200


# ============================================================================
# Time Helpers
# ============================================================================


def _utc_now() -> datetime:
    """
    Return the current timezone-aware UTC timestamp.
    """
    return datetime.now(UTC)


def _validate_utc(value: datetime) -> datetime:
    """
    Validate and normalize a datetime to UTC.

    Raises:
        ValueError:
            If value is not a datetime or is timezone-naive.
    """
    if not isinstance(value, datetime):
        raise ValueError("Timestamp must be a datetime.")

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Timestamp must be timezone-aware.")

    return value.astimezone(UTC)


# ============================================================================
# Generic Validation Helpers
# ============================================================================


def _validate_user_id(user_id: UUID) -> UUID:
    """
    Validate a user UUID.
    """
    if not isinstance(user_id, UUID):
        raise ValueError("user_id must be a valid UUID.")

    return user_id


def _validate_session_id(session_id: UUID) -> UUID:
    """
    Validate a session UUID.
    """
    if not isinstance(session_id, UUID):
        raise ValueError("session_id must be a valid UUID.")

    return session_id


def _validate_limit_offset(
    limit: int,
    offset: int,
    *,
    max_limit: int,
) -> None:
    """
    Validate pagination arguments.
    """
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("limit must be an integer.")

    if isinstance(offset, bool) or not isinstance(offset, int):
        raise ValueError("offset must be an integer.")

    if limit < 1:
        raise ValueError("limit must be greater than zero.")

    if limit > max_limit:
        raise ValueError(
            f"limit must not exceed {max_limit}."
        )

    if offset < 0:
        raise ValueError(
            "offset must not be negative."
        )


def _validate_optional_bool(
    value: bool | None,
    *,
    field_name: str,
) -> bool | None:
    """
    Validate an optional boolean.
    """
    if value is None:
        return None

    if not isinstance(value, bool):
        raise ValueError(
            f"{field_name} must be a boolean."
        )

    return value


def _validate_optional_timestamp(
    value: datetime | None,
    *,
    field_name: str,
) -> datetime | None:
    """
    Validate and normalize an optional timestamp.
    """
    if value is None:
        return None

    try:
        return _validate_utc(value)
    except ValueError as exc:
        raise ValueError(
            f"{field_name} must be timezone-aware."
        ) from exc


def _validate_string_field(
    value: str,
    *,
    field_name: str,
    max_length: int | None = None,
) -> str:
    """
    Validate a required string.
    """
    if not isinstance(value, str):
        raise ValueError(
            f"{field_name} must be a string."
        )

    normalized = value.strip()

    if not normalized:
        raise ValueError(
            f"{field_name} must not be empty."
        )

    if (
        max_length is not None
        and len(normalized) > max_length
    ):
        raise ValueError(
            f"{field_name} is too long."
        )

    return normalized


def _validate_optional_string(
    value: str | None,
    *,
    field_name: str,
    max_length: int | None = None,
) -> str | None:
    """
    Validate an optional string.

    Empty strings are normalized to None.
    """
    if value is None:
        return None

    if not isinstance(value, str):
        raise ValueError(
            f"{field_name} must be a string."
        )

    normalized = value.strip()

    if not normalized:
        return None

    if (
        max_length is not None
        and len(normalized) > max_length
    ):
        raise ValueError(
            f"{field_name} is too long."
        )

    return normalized


def _normalize_login(value: str) -> str:
    """
    Normalize username/email login input.
    """
    if not isinstance(value, str):
        raise ValueError(
            "login must be a string."
        )

    normalized = value.strip().lower()

    if not normalized:
        raise ValueError(
            "login must not be empty."
        )

    return normalized


def _normalize_role(value: str) -> str:
    """
    Normalize role names to canonical uppercase.
    """
    if not isinstance(value, str):
        raise ValueError(
            "role must be a string."
        )

    normalized = value.strip().upper()

    if not normalized:
        raise ValueError(
            "role must not be empty."
        )

    return normalized


def _validate_token_id(token_id: str) -> str:
    """
    Validate an internal JWT JTI/token identifier.
    """
    if not isinstance(token_id, str):
        raise ValueError(
            "token_id must be a string."
        )

    normalized = token_id.strip()

    if not normalized:
        raise ValueError(
            "token_id must not be empty."
        )

    if len(normalized) > MAX_TOKEN_ID_LENGTH:
        raise ValueError(
            "token_id is too long."
        )

    return normalized


def _validate_password_hash(
    password_hash: str,
) -> str:
    """
    Validate an already-generated password hash.

    Plaintext passwords must never reach this method.
    """
    if not isinstance(password_hash, str):
        raise ValueError(
            "password_hash must be a string."
        )

    normalized = password_hash.strip()

    if not normalized:
        raise ValueError(
            "password_hash must not be empty."
        )

    return normalized


# ============================================================================
# Domain Conversion
# ============================================================================


def _user_to_domain(
    user: AuthUser,
    roles: frozenset[str],
) -> UserIdentity:
    """
    Convert AuthUser ORM model to UserIdentity.
    """
    return UserIdentity(
        user_id=user.user_id,
        username=user.username,
        email=user.email,
        password_hash=user.password_hash,
        roles=roles,
        is_active=user.is_active,
        is_locked=user.is_locked,
        failed_login_count=user.failed_login_count,
        display_name=user.display_name,
        force_password_change=user.force_password_change,
        password_changed_at=(
            _validate_utc(
                user.password_changed_at
            )
            if user.password_changed_at is not None
            else None
        ),
        last_login_at=(
            _validate_utc(
                user.last_login_at
            )
            if user.last_login_at is not None
            else None
        ),
        created_at=_validate_utc(
            user.created_at
        ),
        updated_at=_validate_utc(
            user.updated_at
        ),
    )


def _session_to_domain(
    session: AuthSession,
) -> SessionRecord:
    """
    Convert AuthSession ORM model to SessionRecord.

    Pending token IDs are intentionally hidden.
    """
    token_id = session.token_id

    if token_id.startswith(
        PENDING_TOKEN_PREFIX
    ):
        token_id = ""

    return SessionRecord(
        session_id=session.session_id,
        user_id=session.user_id,
        token_id=token_id,
        created_at=_validate_utc(
            session.created_at
        ),
        expires_at=_validate_utc(
            session.expires_at
        ),
        revoked_at=(
            _validate_utc(
                session.revoked_at
            )
            if session.revoked_at is not None
            else None
        ),
        ip_address=(
            str(session.ip_address)
            if session.ip_address is not None
            else None
        ),
        user_agent=session.user_agent,
    )


def _audit_to_model(
    record: AuditRecord,
) -> AuthAudit:
    """
    Convert AuditRecord to AuthAudit ORM model.
    """
    if not isinstance(
        record,
        AuditRecord,
    ):
        raise ValueError(
            "record must be an AuditRecord."
        )

    timestamp = _validate_utc(
        record.timestamp
    )

    metadata = dict(
        record.metadata or {}
    )

    return AuthAudit(
        action=record.action,
        outcome=record.outcome,
        actor_user_id=record.actor_user_id,
        target_user_id=record.target_user_id,
        session_id=record.session_id,
        request_id=record.request_id,
        source_ip=record.source_ip,
        audit_metadata=metadata,
        created_at=timestamp,
    )


def _audit_to_domain(
    audit: AuthAudit,
) -> AuditRecord:
    """
    Convert AuthAudit ORM model to AuditRecord.
    """
    return AuditRecord(
        action=audit.action,
        outcome=audit.outcome,
        actor_user_id=audit.actor_user_id,
        target_user_id=audit.target_user_id,
        session_id=audit.session_id,
        request_id=audit.request_id,
        source_ip=(
            str(audit.source_ip)
            if audit.source_ip is not None
            else None
        ),
        metadata=dict(
            audit.audit_metadata or {}
        ),
        timestamp=_validate_utc(
            audit.created_at
        ),
    )


# ============================================================================
# PostgreSQL Generic Storage Repository
# ============================================================================


class PostgresStorageRepository:
    """
    Generic structured storage repository.
    """

    def __init__(
        self,
        session: AsyncSession,
    ) -> None:
        self.session = session

    async def upsert(
        self,
        *,
        entity_type: str,
        entity_id: str,
        payload: dict[str, Any],
    ) -> StorageRecord:
        """
        Create or replace a structured storage record.
        """
        normalized_entity_type = _validate_string_field(
            entity_type,
            field_name="entity_type",
        )

        normalized_entity_id = _validate_string_field(
            entity_id,
            field_name="entity_id",
        )

        if not isinstance(payload, dict):
            raise ValueError(
                "payload must be a dictionary."
            )

        try:
            result = await self.session.execute(
                select(StorageRecord).where(
                    StorageRecord.entity_type
                    == normalized_entity_type,
                    StorageRecord.entity_id
                    == normalized_entity_id,
                )
            )

            record = result.scalar_one_or_none()

            if record is None:
                record = StorageRecord(
                    entity_type=normalized_entity_type,
                    entity_id=normalized_entity_id,
                    payload=dict(payload),
                )

                self.session.add(record)

            else:
                record.payload = dict(payload)

            await self.session.flush()

            return record

        except IntegrityError as exc:
            raise RuntimeError(
                "Unable to persist generic storage record."
            ) from exc

        except SQLAlchemyError as exc:
            raise RuntimeError(
                "Unable to persist generic storage record."
            ) from exc

    async def get(
        self,
        *,
        entity_type: str,
        entity_id: str,
    ) -> StorageRecord | None:
        """
        Retrieve one structured storage record.
        """
        normalized_entity_type = _validate_string_field(
            entity_type,
            field_name="entity_type",
        )

        normalized_entity_id = _validate_string_field(
            entity_id,
            field_name="entity_id",
        )

        try:
            result = await self.session.execute(
                select(StorageRecord).where(
                    StorageRecord.entity_type
                    == normalized_entity_type,
                    StorageRecord.entity_id
                    == normalized_entity_id,
                )
            )

            return result.scalar_one_or_none()

        except SQLAlchemyError as exc:
            raise RuntimeError(
                "Unable to retrieve generic storage record."
            ) from exc


# ============================================================================
# PostgreSQL User Repository
# ============================================================================


class PostgresUserRepository(UserRepository):
    """
    Concrete PostgreSQL implementation of UserRepository.

    Supports:

        - identity lookup
        - user listing
        - user counting
        - role management
        - active/disabled state
        - lock state
        - failed-login tracking
        - password state
        - user deletion
    """

    def __init__(
        self,
        session: AsyncSession,
    ) -> None:
        self.session = session

    # ========================================================================
    # Internal Helpers
    # ========================================================================

    async def _get_user(
        self,
        user_id: UUID,
        *,
        for_update: bool = False,
    ) -> AuthUser | None:
        """
        Retrieve one AuthUser.

        for_update=True acquires a row-level lock.
        """
        _validate_user_id(user_id)

        statement = select(AuthUser).where(
            AuthUser.user_id == user_id
        )

        if for_update:
            statement = statement.with_for_update()

        try:
            result = await self.session.execute(
                statement
            )

            return result.scalar_one_or_none()

        except SQLAlchemyError as exc:
            raise UserRepositoryError(
                "Unable to retrieve authentication user."
            ) from exc

    async def _get_roles(
        self,
        user_id: UUID,
    ) -> frozenset[str]:
        """
        Retrieve all roles assigned to one user.
        """
        _validate_user_id(user_id)

        try:
            result = await self.session.execute(
                select(
                    AuthUserRole.role_name
                ).where(
                    AuthUserRole.user_id
                    == user_id
                )
            )

            return frozenset(
                str(role)
                for role in result.scalars().all()
            )

        except SQLAlchemyError as exc:
            raise UserRepositoryError(
                "Unable to retrieve user roles."
            ) from exc

    async def _to_domain(
        self,
        user: AuthUser,
    ) -> UserIdentity:
        """
        Convert ORM user to domain object.
        """
        roles = await self._get_roles(
            user.user_id
        )

        return _user_to_domain(
            user,
            roles,
        )

    async def _role_exists(
        self,
        role: str,
    ) -> bool:
        """
        Check whether a role exists.
        """
        normalized_role = _normalize_role(
            role
        )

        try:
            result = await self.session.execute(
                select(
                    AuthRole.role_name
                ).where(
                    AuthRole.role_name
                    == normalized_role
                )
            )

            return (
                result.scalar_one_or_none()
                is not None
            )

        except SQLAlchemyError as exc:
            raise UserRepositoryError(
                "Unable to verify user role."
            ) from exc

    # ========================================================================
    # Identity Lookup
    # ========================================================================

    async def get_by_login(
        self,
        login: str,
    ) -> UserIdentity | None:
        """
        Find a user by username or email.
        """
        normalized_login = _normalize_login(
            login
        )

        try:
            result = await self.session.execute(
                select(AuthUser).where(
                    or_(
                        func.lower(
                            AuthUser.username
                        )
                        == normalized_login,
                        func.lower(
                            AuthUser.email
                        )
                        == normalized_login,
                    )
                )
            )

            user = result.scalar_one_or_none()

            if user is None:
                return None

            return await self._to_domain(
                user
            )

        except UserRepositoryError:
            raise

        except SQLAlchemyError as exc:
            raise UserRepositoryError(
                "Unable to retrieve authentication identity."
            ) from exc

    async def get_by_id(
        self,
        user_id: UUID,
    ) -> UserIdentity | None:
        """
        Find a user by UUID.
        """
        try:
            user = await self._get_user(
                user_id
            )

            if user is None:
                return None

            return await self._to_domain(
                user
            )

        except UserRepositoryError:
            raise

        except SQLAlchemyError as exc:
            raise UserRepositoryError(
                "Unable to retrieve authentication identity."
            ) from exc

    # ========================================================================
    # Canonical User Filter Builder
    # ========================================================================

    def _build_user_filters(
        self,
        *,
        search: str | None = None,
        role: str | None = None,
        is_active: bool | None = None,
        is_locked: bool | None = None,
        force_password_change: bool | None = None,
        created_from: datetime | None = None,
        created_to: datetime | None = None,
        last_login_from: datetime | None = None,
        last_login_to: datetime | None = None,
    ) -> list[Any]:
        """
        Build the canonical WHERE conditions for user listing.

        IMPORTANT:

        This method is shared by list_users() and count_users().

        Therefore both methods ALWAYS use identical filtering semantics.
        """

        conditions: list[Any] = []

        # --------------------------------------------------------------------
        # Search
        # --------------------------------------------------------------------

        normalized_search = _validate_optional_string(
            search,
            field_name="search",
            max_length=200,
        )

        if normalized_search is not None:
            pattern = (
                f"%{normalized_search}%"
            )

            conditions.append(
                or_(
                    AuthUser.username.ilike(
                        pattern
                    ),
                    AuthUser.email.ilike(
                        pattern
                    ),
                    AuthUser.display_name.ilike(
                        pattern
                    ),
                )
            )

        # --------------------------------------------------------------------
        # Role
        # --------------------------------------------------------------------

        normalized_role = None

        if role is not None:
            normalized_role = _normalize_role(
                role
            )

            role_exists = (
                select(1)
                .select_from(AuthUserRole)
                .where(
                    AuthUserRole.user_id
                    == AuthUser.user_id,
                    AuthUserRole.role_name
                    == normalized_role,
                )
                .exists()
            )

            conditions.append(
                role_exists
            )

        # --------------------------------------------------------------------
        # Active state
        # --------------------------------------------------------------------

        normalized_is_active = (
            _validate_optional_bool(
                is_active,
                field_name="is_active",
            )
        )

        if normalized_is_active is not None:
            conditions.append(
                AuthUser.is_active
                == normalized_is_active
            )

        # --------------------------------------------------------------------
        # Lock state
        # --------------------------------------------------------------------

        normalized_is_locked = (
            _validate_optional_bool(
                is_locked,
                field_name="is_locked",
            )
        )

        if normalized_is_locked is not None:
            conditions.append(
                AuthUser.is_locked
                == normalized_is_locked
            )

        # --------------------------------------------------------------------
        # Force password change
        # --------------------------------------------------------------------

        normalized_force_password_change = (
            _validate_optional_bool(
                force_password_change,
                field_name="force_password_change",
            )
        )

        if (
            normalized_force_password_change
            is not None
        ):
            conditions.append(
                AuthUser.force_password_change
                == normalized_force_password_change
            )

        # --------------------------------------------------------------------
        # Created date range
        # --------------------------------------------------------------------

        normalized_created_from = (
            _validate_optional_timestamp(
                created_from,
                field_name="created_from",
            )
        )

        normalized_created_to = (
            _validate_optional_timestamp(
                created_to,
                field_name="created_to",
            )
        )

        if (
            normalized_created_from is not None
            and normalized_created_to is not None
            and normalized_created_from
            > normalized_created_to
        ):
            raise ValueError(
                "created_from must not be later than created_to."
            )

        if normalized_created_from is not None:
            conditions.append(
                AuthUser.created_at
                >= normalized_created_from
            )

        if normalized_created_to is not None:
            conditions.append(
                AuthUser.created_at
                <= normalized_created_to
            )

        # --------------------------------------------------------------------
        # Last login range
        # --------------------------------------------------------------------

        normalized_last_login_from = (
            _validate_optional_timestamp(
                last_login_from,
                field_name="last_login_from",
            )
        )

        normalized_last_login_to = (
            _validate_optional_timestamp(
                last_login_to,
                field_name="last_login_to",
            )
        )

        if (
            normalized_last_login_from is not None
            and normalized_last_login_to is not None
            and normalized_last_login_from
            > normalized_last_login_to
        ):
            raise ValueError(
                "last_login_from must not be later than last_login_to."
            )

        if normalized_last_login_from is not None:
            conditions.append(
                AuthUser.last_login_at
                >= normalized_last_login_from
            )

        if normalized_last_login_to is not None:
            conditions.append(
                AuthUser.last_login_at
                <= normalized_last_login_to
            )

        return conditions

    def _build_user_select(
        self,
        *,
        search: str | None = None,
        role: str | None = None,
        is_active: bool | None = None,
        is_locked: bool | None = None,
        force_password_change: bool | None = None,
        created_from: datetime | None = None,
        created_to: datetime | None = None,
        last_login_from: datetime | None = None,
        last_login_to: datetime | None = None,
    ):
        """
        Build canonical user SELECT statement.
        """
        conditions = self._build_user_filters(
            search=search,
            role=role,
            is_active=is_active,
            is_locked=is_locked,
            force_password_change=force_password_change,
            created_from=created_from,
            created_to=created_to,
            last_login_from=last_login_from,
            last_login_to=last_login_to,
        )

        statement = select(
            AuthUser
        )

        if conditions:
            statement = statement.where(
                *conditions
            )

        return statement

    # ========================================================================
    # User Listing
    # ========================================================================

    async def list_users(
        self,
        *,
        search: str | None = None,
        role: str | None = None,
        is_active: bool | None = None,
        is_locked: bool | None = None,
        force_password_change: bool | None = None,
        created_from: datetime | None = None,
        created_to: datetime | None = None,
        last_login_from: datetime | None = None,
        last_login_to: datetime | None = None,
        limit: int = DEFAULT_USER_PAGE_SIZE,
        offset: int = 0,
    ) -> list[UserIdentity]:
        """
        Return one deterministic page of users.
        """
        try:
            _validate_limit_offset(
                limit,
                offset,
                max_limit=MAX_USER_PAGE_SIZE,
            )

            statement = self._build_user_select(
                search=search,
                role=role,
                is_active=is_active,
                is_locked=is_locked,
                force_password_change=force_password_change,
                created_from=created_from,
                created_to=created_to,
                last_login_from=last_login_from,
                last_login_to=last_login_to,
            )

        except ValueError as exc:
            raise UserRepositoryError(
                str(exc)
            ) from exc

        statement = (
            statement
            .order_by(
                AuthUser.created_at.desc(),
                AuthUser.user_id.desc(),
            )
            .limit(limit)
            .offset(offset)
        )

        try:
            result = await self.session.execute(
                statement
            )

            users = result.scalars().all()

            return [
                await self._to_domain(user)
                for user in users
            ]

        except UserRepositoryError:
            raise

        except SQLAlchemyError as exc:
            raise UserRepositoryError(
                "Unable to list users."
            ) from exc

    # ========================================================================
    # User Count
    # ========================================================================

    async def count_users(
        self,
        *,
        search: str | None = None,
        role: str | None = None,
        is_active: bool | None = None,
        is_locked: bool | None = None,
        force_password_change: bool | None = None,
        created_from: datetime | None = None,
        created_to: datetime | None = None,
        last_login_from: datetime | None = None,
        last_login_to: datetime | None = None,
    ) -> int:
        """
        Count users using EXACTLY the same filter semantics as list_users().
        """
        try:
            conditions = self._build_user_filters(
                search=search,
                role=role,
                is_active=is_active,
                is_locked=is_locked,
                force_password_change=force_password_change,
                created_from=created_from,
                created_to=created_to,
                last_login_from=last_login_from,
                last_login_to=last_login_to,
            )

        except ValueError as exc:
            raise UserRepositoryError(
                str(exc)
            ) from exc

        statement = select(
            func.count(AuthUser.user_id)
        )

        if conditions:
            statement = statement.where(
                *conditions
            )

        try:
            result = await self.session.execute(
                statement
            )

            return int(
                result.scalar_one()
            )

        except SQLAlchemyError as exc:
            raise UserRepositoryError(
                "Unable to count users."
            ) from exc

    # ========================================================================
    # User Creation
    # ========================================================================

    async def create_user(
        self,
        user: UserIdentity,
        *,
        role: str,
    ) -> UserIdentity:
        """
        Persist a new user and initial role.
        """
        if not isinstance(
            user,
            UserIdentity,
        ):
            raise ValueError(
                "user must be a UserIdentity."
            )

        user_id = _validate_user_id(
            user.user_id
        )

        username = _validate_string_field(
            user.username,
            field_name="username",
            max_length=100,
        )

        email = _validate_string_field(
            user.email,
            field_name="email",
            max_length=320,
        ).lower()

        password_hash = _validate_password_hash(
            user.password_hash
        )

        role_name = _normalize_role(
            role
        )

        if not isinstance(
            user.is_active,
            bool,
        ):
            raise ValueError(
                "is_active must be a boolean."
            )

        if not isinstance(
            user.is_locked,
            bool,
        ):
            raise ValueError(
                "is_locked must be a boolean."
            )

        if not isinstance(
            user.force_password_change,
            bool,
        ):
            raise ValueError(
                "force_password_change must be a boolean."
            )

        if (
            isinstance(
                user.failed_login_count,
                bool,
            )
            or not isinstance(
                user.failed_login_count,
                int,
            )
            or user.failed_login_count < 0
        ):
            raise ValueError(
                "failed_login_count must be a non-negative integer."
            )

        if not await self._role_exists(
            role_name
        ):
            raise ValueError(
                f"Unknown role: {role_name}"
            )

        created_at = _validate_utc(
            user.created_at
        )

        password_changed_at = (
            _validate_utc(
                user.password_changed_at
            )
            if user.password_changed_at is not None
            else None
        )

        last_login_at = (
            _validate_utc(
                user.last_login_at
            )
            if user.last_login_at is not None
            else None
        )

        try:
            record = AuthUser(
                user_id=user_id,
                username=username,
                email=email,
                password_hash=password_hash,
                is_active=user.is_active,
                is_locked=user.is_locked,
                failed_login_count=(
                    user.failed_login_count
                ),
                display_name=user.display_name,
                force_password_change=(
                    user.force_password_change
                ),
                password_changed_at=(
                    password_changed_at
                ),
                last_login_at=last_login_at,
                created_at=created_at,
                updated_at=_utc_now(),
            )

            self.session.add(record)

            self.session.add(
                AuthUserRole(
                    user_id=user_id,
                    role_name=role_name,
                )
            )

            await self.session.flush()

            return await self._to_domain(
                record
            )

        except IntegrityError as exc:
            raise UserRepositoryError(
                "Unable to create user because "
                "a database constraint was violated."
            ) from exc

        except SQLAlchemyError as exc:
            raise UserRepositoryError(
                "Unable to create user."
            ) from exc

    # ========================================================================
    # Profile Update
    # ========================================================================

    async def update_user(
        self,
        user: UserIdentity,
    ) -> UserIdentity | None:
        """
        Update editable profile fields only.

        Security state is intentionally not modified here.
        """
        if not isinstance(
            user,
            UserIdentity,
        ):
            raise ValueError(
                "user must be a UserIdentity."
            )

        _validate_user_id(
            user.user_id
        )

        username = _validate_string_field(
            user.username,
            field_name="username",
            max_length=100,
        )

        email = _validate_string_field(
            user.email,
            field_name="email",
            max_length=320,
        ).lower()

        record = await self._get_user(
            user.user_id
        )

        if record is None:
            return None

        try:
            record.username = username
            record.email = email
            record.display_name = user.display_name
            record.updated_at = _utc_now()

            await self.session.flush()

            return await self._to_domain(
                record
            )

        except IntegrityError as exc:
            raise UserRepositoryError(
                "Unable to update user because "
                "a database constraint was violated."
            ) from exc

        except SQLAlchemyError as exc:
            raise UserRepositoryError(
                "Unable to update user."
            ) from exc

    # ========================================================================
    # Role Management
    # ========================================================================

    async def set_role(
        self,
        user_id: UUID,
        role: str,
    ) -> UserIdentity | None:
        """
        Replace all current user roles with one role.

        Authorization belongs to the service layer.
        """
        _validate_user_id(
            user_id
        )

        role_name = _normalize_role(
            role
        )

        user = await self._get_user(
            user_id
        )

        if user is None:
            return None

        if not await self._role_exists(
            role_name
        ):
            raise ValueError(
                f"Unknown role: {role_name}"
            )

        try:
            await self.session.execute(
                delete(AuthUserRole).where(
                    AuthUserRole.user_id
                    == user_id
                )
            )

            self.session.add(
                AuthUserRole(
                    user_id=user_id,
                    role_name=role_name,
                )
            )

            user.updated_at = _utc_now()

            await self.session.flush()

            return await self._to_domain(
                user
            )

        except IntegrityError as exc:
            raise UserRepositoryError(
                "Unable to assign user role."
            ) from exc

        except SQLAlchemyError as exc:
            raise UserRepositoryError(
                "Unable to assign user role."
            ) from exc

    # ========================================================================
    # Active / Disabled State
    # ========================================================================

    async def set_active(
        self,
        user_id: UUID,
        is_active: bool,
    ) -> UserIdentity | None:
        """
        Set account active/disabled state.

        Session revocation belongs to the service layer.
        """
        _validate_user_id(
            user_id
        )

        if not isinstance(
            is_active,
            bool,
        ):
            raise ValueError(
                "is_active must be a boolean."
            )

        user = await self._get_user(
            user_id
        )

        if user is None:
            return None

        try:
            user.is_active = is_active
            user.updated_at = _utc_now()

            await self.session.flush()

            return await self._to_domain(
                user
            )

        except SQLAlchemyError as exc:
            raise UserRepositoryError(
                "Unable to update user active state."
            ) from exc

    # ========================================================================
    # Lock State
    # ========================================================================

    async def set_locked(
        self,
        user_id: UUID,
        is_locked: bool,
    ) -> UserIdentity | None:
        """
        Set account lock state.

        Unlocking resets failed_login_count.

        Administrative authorization belongs to the service layer.
        """
        _validate_user_id(
            user_id
        )

        if not isinstance(
            is_locked,
            bool,
        ):
            raise ValueError(
                "is_locked must be a boolean."
            )

        user = await self._get_user(
            user_id,
            for_update=True,
        )

        if user is None:
            return None

        try:
            user.is_locked = is_locked

            if not is_locked:
                user.failed_login_count = 0

            user.updated_at = _utc_now()

            await self.session.flush()

            return await self._to_domain(
                user
            )

        except SQLAlchemyError as exc:
            raise UserRepositoryError(
                "Unable to update user lock state."
            ) from exc

    # ========================================================================
    # Failed Login
    # ========================================================================

    async def record_failed_login(
        self,
        user_id: UUID,
        *,
        max_attempts: int = DEFAULT_MAX_FAILED_LOGIN_ATTEMPTS,
    ) -> UserIdentity | None:
        """
        Atomically record one failed login attempt.

        Row-level locking prevents lost increments under concurrent
        authentication attempts.
        """
        _validate_user_id(
            user_id
        )

        if (
            isinstance(max_attempts, bool)
            or not isinstance(
                max_attempts,
                int,
            )
        ):
            raise ValueError(
                "max_attempts must be an integer."
            )

        if max_attempts < 1:
            raise ValueError(
                "max_attempts must be greater than zero."
            )

        try:
            user = await self._get_user(
                user_id,
                for_update=True,
            )

            if user is None:
                return None

            user.failed_login_count += 1

            if (
                user.failed_login_count
                >= max_attempts
            ):
                user.is_locked = True

            user.updated_at = _utc_now()

            await self.session.flush()

            return await self._to_domain(
                user
            )

        except UserRepositoryError:
            raise

        except SQLAlchemyError as exc:
            raise UserRepositoryError(
                "Unable to register failed login attempt."
            ) from exc

    async def reset_failed_login_count(
        self,
        user_id: UUID,
    ) -> UserIdentity | None:
        """
        Reset failed login count.

        IMPORTANT:

        This does NOT unlock the account.
        """
        _validate_user_id(
            user_id
        )

        try:
            user = await self._get_user(
                user_id,
                for_update=True,
            )

            if user is None:
                return None

            user.failed_login_count = 0
            user.updated_at = _utc_now()

            await self.session.flush()

            return await self._to_domain(
                user
            )

        except UserRepositoryError:
            raise

        except SQLAlchemyError as exc:
            raise UserRepositoryError(
                "Unable to reset failed login count."
            ) from exc

    # ========================================================================
    # Successful Login
    # ========================================================================

    async def record_successful_login(
        self,
        user_id: UUID,
    ) -> UserIdentity | None:
        """
        Record successful authentication.

        Returns None if the account is disabled or locked.
        """
        _validate_user_id(
            user_id
        )

        try:
            user = await self._get_user(
                user_id,
                for_update=True,
            )

            if user is None:
                return None

            if (
                not user.is_active
                or user.is_locked
            ):
                return None

            now = _utc_now()

            user.failed_login_count = 0
            user.last_login_at = now
            user.updated_at = now

            await self.session.flush()

            return await self._to_domain(
                user
            )

        except UserRepositoryError:
            raise

        except SQLAlchemyError as exc:
            raise UserRepositoryError(
                "Unable to record successful login."
            ) from exc

    async def set_last_login_at(
        self,
        user_id: UUID,
        last_login_at: datetime,
    ) -> UserIdentity | None:
        """
        Update successful login timestamp.
        """
        _validate_user_id(
            user_id
        )

        timestamp = _validate_utc(
            last_login_at
        )

        try:
            user = await self._get_user(
                user_id
            )

            if user is None:
                return None

            user.last_login_at = timestamp
            user.updated_at = _utc_now()

            await self.session.flush()

            return await self._to_domain(
                user
            )

        except UserRepositoryError:
            raise

        except SQLAlchemyError as exc:
            raise UserRepositoryError(
                "Unable to update last login timestamp."
            ) from exc

    # ========================================================================
    # Force Password Change
    # ========================================================================

    async def set_force_password_change(
        self,
        user_id: UUID,
        force_password_change: bool,
    ) -> UserIdentity | None:
        """
        Set force-password-change state.
        """
        _validate_user_id(
            user_id
        )

        if not isinstance(
            force_password_change,
            bool,
        ):
            raise ValueError(
                "force_password_change must be a boolean."
            )

        try:
            user = await self._get_user(
                user_id
            )

            if user is None:
                return None

            user.force_password_change = (
                force_password_change
            )

            user.updated_at = _utc_now()

            await self.session.flush()

            return await self._to_domain(
                user
            )

        except UserRepositoryError:
            raise

        except SQLAlchemyError as exc:
            raise UserRepositoryError(
                "Unable to update password-change state."
            ) from exc

    # ========================================================================
    # Password Reset
    # ========================================================================

    async def reset_password(
        self,
        user_id: UUID,
        password_hash: str,
    ) -> bool:
        """
        Replace password hash and reset authentication failure state.

        Session revocation is intentionally NOT performed here.
        """
        _validate_user_id(
            user_id
        )

        normalized_hash = (
            _validate_password_hash(
                password_hash
            )
        )

        try:
            user = await self._get_user(
                user_id,
                for_update=True,
            )

            if user is None:
                return False

            now = _utc_now()

            user.password_hash = (
                normalized_hash
            )

            user.password_changed_at = now
            user.failed_login_count = 0
            user.updated_at = now

            await self.session.flush()

            return True

        except UserRepositoryError:
            raise

        except SQLAlchemyError as exc:
            raise UserRepositoryError(
                "Unable to reset user password."
            ) from exc

    async def set_password_state(
        self,
        user_id: UUID,
        password_hash: str,
        *,
        password_changed_at: datetime,
        force_password_change: bool = False,
    ) -> UserIdentity | None:
        """
        Atomically update password-related security state.
        """
        _validate_user_id(
            user_id
        )

        normalized_hash = (
            _validate_password_hash(
                password_hash
            )
        )

        timestamp = _validate_utc(
            password_changed_at
        )

        if not isinstance(
            force_password_change,
            bool,
        ):
            raise ValueError(
                "force_password_change must be a boolean."
            )

        try:
            user = await self._get_user(
                user_id,
                for_update=True,
            )

            if user is None:
                return None

            now = _utc_now()

            user.password_hash = (
                normalized_hash
            )

            user.password_changed_at = (
                timestamp
            )

            user.force_password_change = (
                force_password_change
            )

            user.failed_login_count = 0
            user.updated_at = now

            await self.session.flush()

            return await self._to_domain(
                user
            )

        except UserRepositoryError:
            raise

        except SQLAlchemyError as exc:
            raise UserRepositoryError(
                "Unable to update password security state."
            ) from exc

    # ========================================================================
    # Delete User
    # ========================================================================

    async def delete_user(
        self,
        user_id: UUID,
    ) -> bool:
        """
        Permanently delete a user.

        Business/security authorization is handled by the service layer.
        """
        _validate_user_id(
            user_id
        )

        try:
            user = await self._get_user(
                user_id
            )

            if user is None:
                return False

            await self.session.delete(
                user
            )

            await self.session.flush()

            return True

        except IntegrityError as exc:
            raise UserRepositoryError(
                "Unable to delete user because "
                "dependent database records prevented deletion."
            ) from exc

        except SQLAlchemyError as exc:
            raise UserRepositoryError(
                "Unable to delete user."
            ) from exc


# ============================================================================
# PostgreSQL Session Repository
# ============================================================================


class PostgresSessionRepository(SessionRepository):
    """
    Concrete PostgreSQL session repository.
    """

    def __init__(
        self,
        session: AsyncSession,
    ) -> None:
        self.session = session

    # ========================================================================
    # Create
    # ========================================================================

    async def create(
        self,
        session: SessionRecord,
    ) -> SessionRecord:
        """
        Persist a new authentication session.
        """
        if not isinstance(
            session,
            SessionRecord,
        ):
            raise ValueError(
                "session must be a SessionRecord."
            )

        _validate_session_id(
            session.session_id
        )

        _validate_user_id(
            session.user_id
        )

        created_at = _validate_utc(
            session.created_at
        )

        expires_at = _validate_utc(
            session.expires_at
        )

        if expires_at <= created_at:
            raise ValueError(
                "expires_at must be later than created_at."
            )

        token_id = session.token_id

        if not isinstance(
            token_id,
            str,
        ):
            raise ValueError(
                "token_id must be a string."
            )

        token_id = token_id.strip()

        if not token_id:
            token_id = (
                f"{PENDING_TOKEN_PREFIX}"
                f"{session.session_id}"
            )

        token_id = _validate_token_id(
            token_id
        )

        revoked_at = (
            _validate_utc(
                session.revoked_at
            )
            if session.revoked_at is not None
            else None
        )

        try:
            record = AuthSession(
                session_id=session.session_id,
                user_id=session.user_id,
                token_id=token_id,
                created_at=created_at,
                expires_at=expires_at,
                revoked_at=revoked_at,
                ip_address=session.ip_address,
                user_agent=session.user_agent,
            )

            self.session.add(record)

            await self.session.flush()

            return _session_to_domain(
                record
            )

        except IntegrityError as exc:
            raise SessionRepositoryError(
                "Unable to create authentication session "
                "because a database constraint was violated."
            ) from exc

        except SQLAlchemyError as exc:
            raise SessionRepositoryError(
                "Unable to persist authentication session."
            ) from exc

    # ========================================================================
    # Active Session Lookup
    # ========================================================================

    async def get_active(
        self,
        session_id: UUID,
    ) -> SessionRecord | None:
        """
        Retrieve one active non-expired session.
        """
        _validate_session_id(
            session_id
        )

        now = _utc_now()

        try:
            result = await self.session.execute(
                select(AuthSession).where(
                    AuthSession.session_id
                    == session_id,
                    AuthSession.revoked_at.is_(None),
                    AuthSession.expires_at > now,
                )
            )

            record = (
                result.scalar_one_or_none()
            )

            if record is None:
                return None

            return _session_to_domain(
                record
            )

        except SQLAlchemyError as exc:
            raise SessionRepositoryError(
                "Unable to retrieve authentication session."
            ) from exc

    async def list_active_user_sessions(
        self,
        user_id: UUID,
    ) -> list[SessionRecord]:
        """
        Retrieve all active sessions belonging to one user.
        """
        _validate_user_id(
            user_id
        )

        now = _utc_now()

        try:
            result = await self.session.execute(
                select(AuthSession)
                .where(
                    AuthSession.user_id
                    == user_id,
                    AuthSession.revoked_at.is_(None),
                    AuthSession.expires_at > now,
                )
                .order_by(
                    AuthSession.created_at.desc(),
                    AuthSession.session_id.desc(),
                )
            )

            records = result.scalars().all()

            return [
                _session_to_domain(record)
                for record in records
            ]

        except SQLAlchemyError as exc:
            raise SessionRepositoryError(
                "Unable to list active user sessions."
            ) from exc

    # ========================================================================
    # Bind Token
    # ========================================================================

    async def bind_token(
        self,
        session_id: UUID,
        token_id: str,
    ) -> SessionRecord:
        """
        Bind a real JWT JTI to an active session.
        """
        _validate_session_id(
            session_id
        )

        normalized_token_id = (
            _validate_token_id(
                token_id
            )
        )

        if normalized_token_id.startswith(
            PENDING_TOKEN_PREFIX
        ):
            raise ValueError(
                "token_id cannot use the reserved pending prefix."
            )

        now = _utc_now()

        try:
            result = await self.session.execute(
                select(AuthSession)
                .where(
                    AuthSession.session_id
                    == session_id,
                    AuthSession.revoked_at.is_(None),
                    AuthSession.expires_at > now,
                )
                .with_for_update()
            )

            record = (
                result.scalar_one_or_none()
            )

            if record is None:
                raise SessionRepositoryError(
                    "Authentication session is not active."
                )

            record.token_id = (
                normalized_token_id
            )

            await self.session.flush()

            return _session_to_domain(
                record
            )

        except SessionRepositoryError:
            raise

        except IntegrityError as exc:
            raise SessionRepositoryError(
                "Unable to bind token to authentication "
                "session because the token identifier "
                "already exists."
            ) from exc

        except SQLAlchemyError as exc:
            raise SessionRepositoryError(
                "Unable to bind token to authentication session."
            ) from exc

    # ========================================================================
    # Revoke One Session
    # ========================================================================

    async def revoke(
        self,
        session_id: UUID,
    ) -> bool:
        """
        Revoke one session.

        Idempotent:
            already revoked -> False
            active -> True
        """
        _validate_session_id(
            session_id
        )

        now = _utc_now()

        try:
            result = await self.session.execute(
                update(AuthSession)
                .where(
                    AuthSession.session_id
                    == session_id,
                    AuthSession.revoked_at.is_(None),
                )
                .values(
                    revoked_at=now
                )
            )

            await self.session.flush()

            return bool(
                result.rowcount == 1
            )

        except SQLAlchemyError as exc:
            raise SessionRepositoryError(
                "Unable to revoke authentication session."
            ) from exc

    # ========================================================================
    # Revoke User Sessions
    # ========================================================================

    async def revoke_user_sessions(
        self,
        user_id: UUID,
    ) -> int:
        """
        Revoke all currently active sessions for one user.
        """
        _validate_user_id(
            user_id
        )

        now = _utc_now()

        try:
            result = await self.session.execute(
                update(AuthSession)
                .where(
                    AuthSession.user_id
                    == user_id,
                    AuthSession.revoked_at.is_(None),
                    AuthSession.expires_at > now,
                )
                .values(
                    revoked_at=now
                )
            )

            await self.session.flush()

            return int(
                result.rowcount or 0
            )

        except SQLAlchemyError as exc:
            raise SessionRepositoryError(
                "Unable to revoke user authentication sessions."
            ) from exc

    # ========================================================================
    # Purge Expired
    # ========================================================================

    async def purge_expired(
        self,
    ) -> int:
        """
        Permanently delete expired sessions.
        """
        now = _utc_now()

        try:
            result = await self.session.execute(
                delete(AuthSession).where(
                    AuthSession.expires_at <= now
                )
            )

            await self.session.flush()

            return int(
                result.rowcount or 0
            )

        except SQLAlchemyError as exc:
            raise SessionRepositoryError(
                "Unable to purge expired authentication sessions."
            ) from exc


# ============================================================================
# PostgreSQL Authentication Audit Repository
# ============================================================================


class PostgresAuthAuditRepository(
    AuthAuditRepository
):
    """
    Concrete PostgreSQL authentication audit repository.

    Canonical source:

        siem_auth_audit

    User Audit is a filtered view of the canonical stream.
    """

    def __init__(
        self,
        session: AsyncSession,
    ) -> None:
        self.session = session

    # ========================================================================
    # Record
    # ========================================================================

    async def record(
        self,
        record: AuditRecord,
    ) -> None:
        """
        Persist one immutable authentication audit event.
        """
        if not isinstance(
            record,
            AuditRecord,
        ):
            raise ValueError(
                "record must be an AuditRecord."
            )

        try:
            model = _audit_to_model(
                record
            )

            self.session.add(model)

            await self.session.flush()

        except ValueError as exc:
            raise AuthAuditRepositoryError(
                "Invalid authentication audit record."
            ) from exc

        except IntegrityError as exc:
            raise AuthAuditRepositoryError(
                "Unable to persist authentication audit record."
            ) from exc

        except SQLAlchemyError as exc:
            raise AuthAuditRepositoryError(
                "Unable to persist authentication audit record."
            ) from exc

    # ========================================================================
    # User Audit Filter Builder
    # ========================================================================

    def _build_user_audit_filters(
        self,
        user_id: UUID,
        *,
        actor_user_id: UUID | None = None,
        action: str | None = None,
        outcome: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        search: str | None = None,
    ) -> list[Any]:
        """
        Build canonical User Audit filters.

        User association is:

            target_user_id = requested user
            OR
            actor_user_id = requested user
        """
        _validate_user_id(
            user_id
        )

        conditions: list[Any] = [
            or_(
                AuthAudit.target_user_id
                == user_id,
                AuthAudit.actor_user_id
                == user_id,
            )
        ]

        # --------------------------------------------------------------------
        # Actor filter
        # --------------------------------------------------------------------

        if actor_user_id is not None:
            _validate_user_id(
                actor_user_id
            )

            conditions.append(
                AuthAudit.actor_user_id
                == actor_user_id
            )

        # --------------------------------------------------------------------
        # Action
        # --------------------------------------------------------------------

        normalized_action = (
            _validate_optional_string(
                action,
                field_name="action",
            )
        )

        if normalized_action is not None:
            conditions.append(
                AuthAudit.action
                == normalized_action
            )

        # --------------------------------------------------------------------
        # Outcome
        # --------------------------------------------------------------------

        normalized_outcome = (
            _validate_optional_string(
                outcome,
                field_name="outcome",
            )
        )

        if normalized_outcome is not None:
            conditions.append(
                AuthAudit.outcome
                == normalized_outcome
            )

        # --------------------------------------------------------------------
        # Date range
        # --------------------------------------------------------------------

        normalized_date_from = (
            _validate_optional_timestamp(
                date_from,
                field_name="date_from",
            )
        )

        normalized_date_to = (
            _validate_optional_timestamp(
                date_to,
                field_name="date_to",
            )
        )

        if (
            normalized_date_from is not None
            and normalized_date_to is not None
            and normalized_date_from
            > normalized_date_to
        ):
            raise ValueError(
                "date_from must not be later than date_to."
            )

        if normalized_date_from is not None:
            conditions.append(
                AuthAudit.created_at
                >= normalized_date_from
            )

        if normalized_date_to is not None:
            conditions.append(
                AuthAudit.created_at
                <= normalized_date_to
            )

        # --------------------------------------------------------------------
        # Search
        #
        # Only approved non-secret fields participate.
        # --------------------------------------------------------------------

        normalized_search = (
            _validate_optional_string(
                search,
                field_name="search",
                max_length=200,
            )
        )

        if normalized_search is not None:
            pattern = (
                f"%{normalized_search}%"
            )

            conditions.append(
                or_(
                    AuthAudit.action.ilike(
                        pattern
                    ),
                    AuthAudit.outcome.ilike(
                        pattern
                    ),
                    AuthAudit.request_id.ilike(
                        pattern
                    ),
                )
            )

        return conditions

    def _build_user_audit_select(
        self,
        user_id: UUID,
        *,
        actor_user_id: UUID | None = None,
        action: str | None = None,
        outcome: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        search: str | None = None,
    ):
        """
        Build canonical User Audit SELECT.
        """
        conditions = self._build_user_audit_filters(
            user_id,
            actor_user_id=actor_user_id,
            action=action,
            outcome=outcome,
            date_from=date_from,
            date_to=date_to,
            search=search,
        )

        statement = select(
            AuthAudit
        )

        if conditions:
            statement = statement.where(
                *conditions
            )

        return statement

    # ========================================================================
    # User Audit Listing
    # ========================================================================

    async def list_user_audit(
        self,
        user_id: UUID,
        *,
        actor_user_id: UUID | None = None,
        action: str | None = None,
        outcome: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        search: str | None = None,
        limit: int = DEFAULT_AUDIT_PAGE_SIZE,
        offset: int = 0,
    ) -> list[AuditRecord]:
        """
        Return paginated user-related audit events.
        """
        try:
            _validate_limit_offset(
                limit,
                offset,
                max_limit=MAX_AUDIT_PAGE_SIZE,
            )

            statement = (
                self._build_user_audit_select(
                    user_id,
                    actor_user_id=actor_user_id,
                    action=action,
                    outcome=outcome,
                    date_from=date_from,
                    date_to=date_to,
                    search=search,
                )
            )

        except ValueError as exc:
            raise AuthAuditRepositoryError(
                str(exc)
            ) from exc

        statement = (
            statement
            .order_by(
                AuthAudit.created_at.desc(),
                AuthAudit.audit_id.desc(),
            )
            .limit(limit)
            .offset(offset)
        )

        try:
            result = await self.session.execute(
                statement
            )

            records = result.scalars().all()

            return [
                _audit_to_domain(record)
                for record in records
            ]

        except SQLAlchemyError as exc:
            raise AuthAuditRepositoryError(
                "Unable to retrieve user audit events."
            ) from exc

    # ========================================================================
    # User Audit Count
    # ========================================================================

    async def count_user_audit(
        self,
        user_id: UUID,
        *,
        actor_user_id: UUID | None = None,
        action: str | None = None,
        outcome: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        search: str | None = None,
    ) -> int:
        """
        Count user-related audit events.

        Filter semantics are exactly the same as list_user_audit().
        """
        try:
            conditions = self._build_user_audit_filters(
                user_id,
                actor_user_id=actor_user_id,
                action=action,
                outcome=outcome,
                date_from=date_from,
                date_to=date_to,
                search=search,
            )

        except ValueError as exc:
            raise AuthAuditRepositoryError(
                str(exc)
            ) from exc

        statement = select(
            func.count(AuthAudit.audit_id)
        )

        if conditions:
            statement = statement.where(
                *conditions
            )

        try:
            result = await self.session.execute(
                statement
            )

            return int(
                result.scalar_one()
            )

        except SQLAlchemyError as exc:
            raise AuthAuditRepositoryError(
                "Unable to count user audit events."
            ) from exc


# ============================================================================
# Public Exports
# ============================================================================

__all__ = [
    "DEFAULT_AUDIT_PAGE_SIZE",
    "DEFAULT_MAX_FAILED_LOGIN_ATTEMPTS",
    "DEFAULT_USER_PAGE_SIZE",
    "MAX_AUDIT_PAGE_SIZE",
    "MAX_TOKEN_ID_LENGTH",
    "MAX_USER_PAGE_SIZE",
    "PENDING_TOKEN_PREFIX",
    "PostgresAuthAuditRepository",
    "PostgresSessionRepository",
    "PostgresStorageRepository",
    "PostgresUserRepository",
]