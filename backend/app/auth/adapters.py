from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from sqlalchemy import case, delete, func, select, update
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
)

if TYPE_CHECKING:
    from app.storage.postgres.session import PostgresSessionManager


# ============================================================================
# Constants
# ============================================================================

DEFAULT_MAX_FAILED_LOGIN_ATTEMPTS = 5

PENDING_TOKEN_PREFIX = "pending:"

MAX_USERNAME_LENGTH = 100
MAX_EMAIL_LENGTH = 320
MAX_ROLE_LENGTH = 64
MAX_PERMISSION_LENGTH = 128
MAX_DISPLAY_NAME_LENGTH = 150
MAX_USER_AGENT_LENGTH = 512
MAX_REQUEST_ID_LENGTH = 128
MAX_TOKEN_ID_LENGTH = 128
MAX_AUDIT_ACTION_LENGTH = 128
MAX_AUDIT_OUTCOME_LENGTH = 32


SENSITIVE_AUDIT_KEYS = frozenset(
    {
        "password",
        "password_hash",
        "passwd",
        "pass",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "jwt",
        "jti",
        "authorization",
        "cookie",
        "set_cookie",
        "api_key",
        "apikey",
        "private_key",
        "client_secret",
        "credential",
        "credentials",
        "hash",
    }
)

REDACTED_VALUE = "[REDACTED]"


# ============================================================================
# Time Helpers
# ============================================================================


def _utcnow() -> datetime:
    """
    Return the current timezone-aware UTC timestamp.
    """
    return datetime.now(UTC)


def _ensure_utc(
    value: datetime | None,
) -> datetime | None:
    """
    Normalize a datetime to timezone-aware UTC.

    Naive timestamps are interpreted as UTC.
    """
    if value is None:
        return None

    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)

    return value.astimezone(UTC)


def _validate_timestamp(
    value: datetime | None,
    *,
    field_name: str,
) -> datetime | None:
    """
    Validate and normalize an optional timestamp.

    Naive timestamps are rejected because API/service contracts require
    timezone-aware timestamps.
    """
    if value is None:
        return None

    if not isinstance(value, datetime):
        raise UserRepositoryError(
            f"{field_name} must be a datetime."
        )

    if value.tzinfo is None:
        raise UserRepositoryError(
            f"{field_name} must be timezone-aware."
        )

    return value.astimezone(UTC)


# ============================================================================
# Normalization / Validation Helpers
# ============================================================================


def _normalize_username(
    value: str,
) -> str:
    """
    Normalize username input.
    """
    if not isinstance(value, str):
        raise ValueError("Username must be a string.")

    normalized = value.strip().lower()

    if not normalized:
        raise ValueError("Username cannot be empty.")

    return normalized


def _normalize_email(
    value: str,
) -> str:
    """
    Normalize email input.
    """
    if not isinstance(value, str):
        raise ValueError("Email must be a string.")

    normalized = value.strip().lower()

    if not normalized:
        raise ValueError("Email cannot be empty.")

    return normalized


def _normalize_role(
    value: str,
) -> str:
    """
    Normalize SentinelSIEM role names.
    """
    if not isinstance(value, str):
        raise ValueError("Role must be a string.")

    normalized = value.strip().upper()

    if not normalized:
        raise ValueError("Role cannot be empty.")

    return normalized


def _normalize_search(
    value: str | None,
) -> str | None:
    """
    Normalize optional user search input.
    """
    if value is None:
        return None

    if not isinstance(value, str):
        raise ValueError("Search value must be a string.")

    normalized = value.strip().lower()

    return normalized or None


def _validate_failed_login_threshold(
    value: int,
) -> int:
    """
    Validate automatic account-lock threshold.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            "Maximum failed login attempts must be an integer."
        )

    if value < 1:
        raise ValueError(
            "Maximum failed login attempts must be greater than zero."
        )

    return value


def _require_non_empty(
    value: str,
    *,
    field_name: str,
) -> str:
    """
    Require a non-empty string.
    """
    if not isinstance(value, str):
        raise ValueError(
            f"{field_name} must be a string."
        )

    normalized = value.strip()

    if not normalized:
        raise ValueError(
            f"{field_name} cannot be empty."
        )

    return normalized


def _validate_length(
    value: str,
    *,
    field_name: str,
    maximum: int,
) -> str:
    """
    Validate maximum string length.
    """
    if len(value) > maximum:
        raise ValueError(
            f"{field_name} cannot exceed {maximum} characters."
        )

    return value


def _validate_user_id(
    user_id: UUID,
) -> UUID:
    """
    Validate a user UUID.
    """
    if not isinstance(user_id, UUID):
        raise ValueError(
            "User identifier must be a valid UUID."
        )

    return user_id


def _validate_session_id(
    session_id: UUID,
) -> UUID:
    """
    Validate a session UUID.
    """
    if not isinstance(session_id, UUID):
        raise ValueError(
            "Session identifier must be a valid UUID."
        )

    return session_id


def _validate_user_agent(
    user_agent: str | None,
) -> str | None:
    """
    Validate optional user-agent value.
    """
    if user_agent is None:
        return None

    if not isinstance(user_agent, str):
        raise ValueError(
            "User agent must be a string."
        )

    if len(user_agent) > MAX_USER_AGENT_LENGTH:
        raise ValueError(
            "User agent is too long."
        )

    return user_agent


def _validate_token_id(
    token_id: str,
) -> str:
    """
    Validate a real JWT JTI.
    """
    if not isinstance(token_id, str):
        raise ValueError(
            "Token identifier must be a string."
        )

    token_id = token_id.strip()

    if not token_id:
        raise ValueError(
            "Token identifier cannot be empty."
        )

    if len(token_id) > MAX_TOKEN_ID_LENGTH:
        raise ValueError(
            "Token identifier is too long."
        )

    if token_id.startswith(PENDING_TOKEN_PREFIX):
        raise ValueError(
            "Token identifier cannot use the reserved pending prefix."
        )

    return token_id


# ============================================================================
# Audit Metadata Sanitization
# ============================================================================


def _is_sensitive_key(
    key: str,
) -> bool:
    """
    Determine whether an audit metadata key may contain sensitive material.
    """
    normalized = (
        key.strip()
        .lower()
        .replace("-", "_")
    )

    if normalized in SENSITIVE_AUDIT_KEYS:
        return True

    sensitive_fragments = (
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "private_key",
        "credential",
        "authorization",
        "cookie",
    )

    return any(
        fragment in normalized
        for fragment in sensitive_fragments
    )


def _sanitize_audit_value(
    value: Any,
    *,
    key: str | None = None,
) -> Any:
    """
    Recursively convert audit metadata into safe JSON-compatible values.

    Sensitive keys are redacted before JSONB persistence.
    """
    if key is not None and _is_sensitive_key(key):
        return REDACTED_VALUE

    if isinstance(value, Mapping):
        return {
            str(item_key): _sanitize_audit_value(
                item_value,
                key=str(item_key),
            )
            for item_key, item_value in value.items()
        }

    if isinstance(
        value,
        (list, tuple, set, frozenset),
    ):
        return [
            _sanitize_audit_value(item)
            for item in value
        ]

    if isinstance(value, UUID):
        return str(value)

    if isinstance(value, datetime):
        normalized = _ensure_utc(value)

        return (
            normalized.isoformat()
            if normalized is not None
            else None
        )

    if isinstance(
        value,
        (str, int, float, bool),
    ):
        return value

    if value is None:
        return None

    return str(value)


def _sanitize_audit_metadata(
    metadata: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """
    Return safe JSON-compatible audit metadata.
    """
    if not metadata:
        return {}

    sanitized = _sanitize_audit_value(
        dict(metadata)
    )

    if not isinstance(sanitized, dict):
        return {}

    return sanitized


# ============================================================================
# User Filtering
# ============================================================================


def _build_user_filter_conditions(
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
    Build the canonical user-list filtering conditions.

    IMPORTANT:

        list_users() and count_users() MUST use this exact helper.

    This guarantees identical filtering semantics between:

        list_users()
        count_users()
    """

    try:
        normalized_search = _normalize_search(search)

        normalized_role = (
            _normalize_role(role)
            if role is not None
            else None
        )

        normalized_created_from = _validate_timestamp(
            created_from,
            field_name="created_from",
        )

        normalized_created_to = _validate_timestamp(
            created_to,
            field_name="created_to",
        )

        normalized_last_login_from = _validate_timestamp(
            last_login_from,
            field_name="last_login_from",
        )

        normalized_last_login_to = _validate_timestamp(
            last_login_to,
            field_name="last_login_to",
        )

    except ValueError as exc:
        raise UserRepositoryError(str(exc)) from exc

    if (
        is_active is not None
        and (
            isinstance(is_active, bool) is False
        )
    ):
        raise UserRepositoryError(
            "is_active must be a boolean."
        )

    if (
        is_locked is not None
        and (
            isinstance(is_locked, bool) is False
        )
    ):
        raise UserRepositoryError(
            "is_locked must be a boolean."
        )

    if (
        force_password_change is not None
        and (
            isinstance(force_password_change, bool) is False
        )
    ):
        raise UserRepositoryError(
            "force_password_change must be a boolean."
        )

    if (
        normalized_created_from is not None
        and normalized_created_to is not None
        and normalized_created_from > normalized_created_to
    ):
        raise UserRepositoryError(
            "created_from cannot be later than created_to."
        )

    if (
        normalized_last_login_from is not None
        and normalized_last_login_to is not None
        and normalized_last_login_from > normalized_last_login_to
    ):
        raise UserRepositoryError(
            "last_login_from cannot be later than last_login_to."
        )

    conditions: list[Any] = []

    # ------------------------------------------------------------------------
    # Free-text search
    #
    # Approved searchable fields:
    #   - username
    #   - email
    #   - display_name
    # ------------------------------------------------------------------------

    if normalized_search:
        pattern = f"%{normalized_search}%"

        conditions.append(
            (AuthUser.username.ilike(pattern))
            | (AuthUser.email.ilike(pattern))
            | (AuthUser.display_name.ilike(pattern))
        )

    # ------------------------------------------------------------------------
    # Role
    # ------------------------------------------------------------------------

    if normalized_role is not None:
        conditions.append(
            AuthUser.user_id.in_(
                select(
                    AuthUserRole.user_id
                ).where(
                    AuthUserRole.role_name
                    == normalized_role,
                )
            )
        )

    # ------------------------------------------------------------------------
    # Active state
    # ------------------------------------------------------------------------

    if is_active is not None:
        conditions.append(
            AuthUser.is_active == is_active
        )

    # ------------------------------------------------------------------------
    # Lock state
    # ------------------------------------------------------------------------

    if is_locked is not None:
        conditions.append(
            AuthUser.is_locked == is_locked
        )

    # ------------------------------------------------------------------------
    # Force password change
    # ------------------------------------------------------------------------

    if force_password_change is not None:
        conditions.append(
            AuthUser.force_password_change
            == force_password_change
        )

    # ------------------------------------------------------------------------
    # Created date range
    # ------------------------------------------------------------------------

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

    # ------------------------------------------------------------------------
    # Last login date range
    # ------------------------------------------------------------------------

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


# ============================================================================
# PostgreSQL User Repository
# ============================================================================


class PostgresUserRepository(UserRepository):
    """
    PostgreSQL-backed authentication user repository.

    Responsibilities:

        - authentication identity lookup
        - administrative user listing
        - user statistics
        - user creation
        - profile updates
        - role assignment
        - account activation/deactivation
        - account locking/unlocking
        - failed-login lifecycle
        - successful-login lifecycle
        - password lifecycle
        - user deletion

    Transaction policy:

        This repository NEVER commits.

        The caller owns the transaction boundary.
    """

    MAX_LIST_LIMIT = 200

    def __init__(
        self,
        session: AsyncSession,
    ) -> None:
        self.session = session

    # =========================================================================
    # Authentication Lookup
    # =========================================================================

    async def get_by_login(
        self,
        login: str,
    ) -> UserIdentity | None:
        """
        Find a user by normalized username or email.
        """
        try:
            if not isinstance(login, str):
                raise ValueError(
                    "Authentication login is invalid."
                )

            normalized = login.strip().lower()

            if not normalized:
                return None

        except ValueError as exc:
            raise UserRepositoryError(str(exc)) from exc

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

        except SQLAlchemyError as exc:
            raise UserRepositoryError(
                "Unable to retrieve authentication identity."
            ) from exc

        except Exception as exc:
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
            _validate_user_id(user_id)

        except ValueError as exc:
            raise UserRepositoryError(
                "User identifier is invalid."
            ) from exc

        try:
            result = await self.session.execute(
                select(AuthUser).where(
                    AuthUser.user_id == user_id,
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

    # =========================================================================
    # Administrative User Listing
    # =========================================================================

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
        limit: int = 50,
        offset: int = 0,
    ) -> list[UserIdentity]:
        """
        List users with complete administrative filtering.

        Supported filters:

            - search
            - role
            - is_active
            - is_locked
            - force_password_change
            - created_from
            - created_to
            - last_login_from
            - last_login_to

        Search covers:

            - username
            - email
            - display_name

        Ordering:

            created_at DESC
            user_id DESC

        Transaction policy:

            This method never commits.
        """

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or limit < 1
            or limit > self.MAX_LIST_LIMIT
        ):
            raise UserRepositoryError(
                f"User list limit must be between "
                f"1 and {self.MAX_LIST_LIMIT}."
            )

        if (
            isinstance(offset, bool)
            or not isinstance(offset, int)
            or offset < 0
        ):
            raise UserRepositoryError(
                "User list offset cannot be negative."
            )

        try:
            conditions = _build_user_filter_conditions(
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

            query = select(AuthUser)

            if conditions:
                query = query.where(*conditions)

            query = (
                query
                .order_by(
                    AuthUser.created_at.desc(),
                    AuthUser.user_id.desc(),
                )
                .offset(offset)
                .limit(limit)
            )

            result = await self.session.execute(query)

            users = result.scalars().all()

            return [
                await self._to_identity(user)
                for user in users
            ]

        except UserRepositoryError:
            raise

        except SQLAlchemyError as exc:
            raise UserRepositoryError(
                "Unable to list users."
            ) from exc

        except Exception as exc:
            raise UserRepositoryError(
                "Unable to list users."
            ) from exc

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
        Count users using EXACTLY the same filtering semantics
        as list_users().

        Pagination is intentionally excluded.
        """

        try:
            conditions = _build_user_filter_conditions(
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

            query = (
                select(
                    func.count(
                        AuthUser.user_id
                    )
                )
                .select_from(AuthUser)
            )

            if conditions:
                query = query.where(*conditions)

            result = await self.session.execute(query)

            return int(result.scalar_one())

        except UserRepositoryError:
            raise

        except SQLAlchemyError as exc:
            raise UserRepositoryError(
                "Unable to count users."
            ) from exc

        except Exception as exc:
            raise UserRepositoryError(
                "Unable to count users."
            ) from exc

    # =========================================================================
    # User Creation
    # =========================================================================

    async def create_user(
        self,
        user: UserIdentity,
        *,
        role: str,
    ) -> UserIdentity:
        """
        Create a user and assign its initial role.

        Password hashing must happen outside this repository.
        """
        try:
            username = _normalize_username(
                user.username
            )

            email = _normalize_email(
                user.email
            )

            normalized_role = _normalize_role(
                role
            )

            if len(username) > MAX_USERNAME_LENGTH:
                raise ValueError(
                    "Username is too long."
                )

            if len(email) > MAX_EMAIL_LENGTH:
                raise ValueError(
                    "Email is too long."
                )

            if len(normalized_role) > MAX_ROLE_LENGTH:
                raise ValueError(
                    "Role name is too long."
                )

            if (
                not isinstance(
                    user.password_hash,
                    str,
                )
                or not user.password_hash
            ):
                raise ValueError(
                    "Password hash cannot be empty."
                )

            _validate_user_id(
                user.user_id
            )

            display_name = user.display_name

            if display_name is not None:
                if not isinstance(
                    display_name,
                    str,
                ):
                    raise ValueError(
                        "Display name must be a string."
                    )

                if len(display_name) > MAX_DISPLAY_NAME_LENGTH:
                    raise ValueError(
                        "Display name is too long."
                    )

        except ValueError as exc:
            raise UserRepositoryError(
                str(exc)
            ) from exc

        try:
            role_result = await self.session.execute(
                select(
                    AuthRole.role_name
                ).where(
                    AuthRole.role_name
                    == normalized_role,
                )
            )

            if role_result.scalar_one_or_none() is None:
                raise UserRepositoryError(
                    "Requested role does not exist."
                )

            now = _utcnow()

            record = AuthUser(
                user_id=user.user_id,
                username=username,
                email=email,
                password_hash=user.password_hash,
                is_active=bool(
                    user.is_active
                ),
                is_locked=bool(
                    user.is_locked
                ),
                failed_login_count=max(
                    0,
                    int(
                        user.failed_login_count
                    ),
                ),
                display_name=display_name,
                force_password_change=bool(
                    user.force_password_change
                ),
                password_changed_at=_ensure_utc(
                    user.password_changed_at
                ),
                last_login_at=_ensure_utc(
                    user.last_login_at
                ),
                created_at=now,
                updated_at=now,
            )

            self.session.add(record)

            await self.session.flush()

            self.session.add(
                AuthUserRole(
                    user_id=record.user_id,
                    role_name=normalized_role,
                )
            )

            await self.session.flush()

            return await self._to_identity(
                record
            )

        except UserRepositoryError:
            raise

        except IntegrityError as exc:
            raise UserRepositoryError(
                "Unable to create user because the username, "
                "email, user identifier, or role assignment "
                "conflicts with existing data."
            ) from exc

        except SQLAlchemyError as exc:
            raise UserRepositoryError(
                "Unable to create user."
            ) from exc

        except Exception as exc:
            raise UserRepositoryError(
                "Unable to create user."
            ) from exc

    # =========================================================================
    # Profile Update
    # =========================================================================

    async def update_user(
        self,
        user: UserIdentity,
    ) -> UserIdentity | None:
        """
        Update editable profile fields.

        Security lifecycle fields are intentionally excluded.
        """
        try:
            username = _normalize_username(
                user.username
            )

            email = _normalize_email(
                user.email
            )

            if len(username) > MAX_USERNAME_LENGTH:
                raise ValueError(
                    "Username is too long."
                )

            if len(email) > MAX_EMAIL_LENGTH:
                raise ValueError(
                    "Email is too long."
                )

            display_name = user.display_name

            if display_name is not None:
                if not isinstance(
                    display_name,
                    str,
                ):
                    raise ValueError(
                        "Display name must be a string."
                    )

                if len(display_name) > MAX_DISPLAY_NAME_LENGTH:
                    raise ValueError(
                        "Display name is too long."
                    )

            _validate_user_id(
                user.user_id
            )

        except ValueError as exc:
            raise UserRepositoryError(
                str(exc)
            ) from exc

        try:
            result = await self.session.execute(
                select(AuthUser).where(
                    AuthUser.user_id
                    == user.user_id,
                )
            )

            record = result.scalar_one_or_none()

            if record is None:
                return None

            record.username = username
            record.email = email
            record.display_name = display_name
            record.updated_at = _utcnow()

            await self.session.flush()

            return await self._to_identity(
                record
            )

        except UserRepositoryError:
            raise

        except IntegrityError as exc:
            raise UserRepositoryError(
                "Unable to update user because the username "
                "or email already exists."
            ) from exc

        except Exception as exc:
            raise UserRepositoryError(
                "Unable to update user."
            ) from exc

    # =========================================================================
    # Role Management
    # =========================================================================

    async def set_role(
        self,
        user_id: UUID,
        role: str,
    ) -> UserIdentity | None:
        """
        Replace the user's assigned role.
        """
        try:
            _validate_user_id(
                user_id
            )

            normalized_role = _normalize_role(
                role
            )

            if len(normalized_role) > MAX_ROLE_LENGTH:
                raise ValueError(
                    "Role name is too long."
                )

        except ValueError as exc:
            raise UserRepositoryError(
                str(exc)
            ) from exc

        try:
            user_result = await self.session.execute(
                select(AuthUser).where(
                    AuthUser.user_id
                    == user_id,
                )
            )

            user = user_result.scalar_one_or_none()

            if user is None:
                return None

            role_result = await self.session.execute(
                select(
                    AuthRole.role_name
                ).where(
                    AuthRole.role_name
                    == normalized_role,
                )
            )

            if role_result.scalar_one_or_none() is None:
                raise UserRepositoryError(
                    "Requested role does not exist."
                )

            await self.session.execute(
                delete(AuthUserRole).where(
                    AuthUserRole.user_id
                    == user_id,
                )
            )

            self.session.add(
                AuthUserRole(
                    user_id=user_id,
                    role_name=normalized_role,
                )
            )

            user.updated_at = _utcnow()

            await self.session.flush()

            return await self._to_identity(
                user
            )

        except UserRepositoryError:
            raise

        except IntegrityError as exc:
            raise UserRepositoryError(
                "Unable to assign the requested role."
            ) from exc

        except Exception as exc:
            raise UserRepositoryError(
                "Unable to update user role."
            ) from exc

    # =========================================================================
    # Active State
    # =========================================================================

    async def set_active(
        self,
        user_id: UUID,
        is_active: bool,
    ) -> UserIdentity | None:
        """
        Enable or disable a user account.
        """
        try:
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

        except ValueError as exc:
            raise UserRepositoryError(
                str(exc)
            ) from exc

        try:
            result = await self.session.execute(
                update(AuthUser)
                .where(
                    AuthUser.user_id
                    == user_id,
                )
                .values(
                    is_active=is_active,
                    updated_at=_utcnow(),
                )
                .returning(AuthUser)
            )

            record = result.scalar_one_or_none()

            if record is None:
                return None

            await self.session.flush()

            return await self._to_identity(
                record
            )

        except Exception as exc:
            raise UserRepositoryError(
                "Unable to update user active state."
            ) from exc

    # =========================================================================
    # Lock State
    # =========================================================================

    async def set_locked(
        self,
        user_id: UUID,
        is_locked: bool,
    ) -> UserIdentity | None:
        """
        Lock or unlock a user account.

        Unlocking explicitly resets failed_login_count.

        Locking does not modify the failed-login counter.
        """
        try:
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

        except ValueError as exc:
            raise UserRepositoryError(
                str(exc)
            ) from exc

        try:
            values: dict[str, Any] = {
                "is_locked": is_locked,
                "updated_at": _utcnow(),
            }

            if not is_locked:
                values[
                    "failed_login_count"
                ] = 0

            result = await self.session.execute(
                update(AuthUser)
                .where(
                    AuthUser.user_id
                    == user_id,
                )
                .values(**values)
                .returning(AuthUser)
            )

            record = result.scalar_one_or_none()

            if record is None:
                return None

            await self.session.flush()

            return await self._to_identity(
                record
            )

        except Exception as exc:
            raise UserRepositoryError(
                "Unable to update user lock state."
            ) from exc

    # =========================================================================
    # Failed Login Lifecycle
    # =========================================================================

    async def record_failed_login(
        self,
        user_id: UUID,
        *,
        max_attempts: int = DEFAULT_MAX_FAILED_LOGIN_ATTEMPTS,
    ) -> UserIdentity | None:
        """
        Atomically record one failed authentication attempt.

        The counter is incremented and automatic locking happens
        in the same SQL UPDATE statement.
        """
        try:
            _validate_user_id(
                user_id
            )

            threshold = _validate_failed_login_threshold(
                max_attempts
            )

        except ValueError as exc:
            raise UserRepositoryError(
                str(exc)
            ) from exc

        try:
            new_failed_count = (
                AuthUser.failed_login_count + 1
            )

            lock_expression = case(
                (
                    new_failed_count
                    >= threshold,
                    True,
                ),
                else_=AuthUser.is_locked,
            )

            result = await self.session.execute(
                update(AuthUser)
                .where(
                    AuthUser.user_id
                    == user_id,
                    AuthUser.is_active.is_(True),
                    AuthUser.is_locked.is_(False),
                )
                .values(
                    failed_login_count=new_failed_count,
                    is_locked=lock_expression,
                    updated_at=_utcnow(),
                )
                .returning(AuthUser)
            )

            record = result.scalar_one_or_none()

            if record is None:
                return None

            await self.session.flush()

            return await self._to_identity(
                record
            )

        except UserRepositoryError:
            raise

        except Exception as exc:
            raise UserRepositoryError(
                "Unable to register failed login attempt."
            ) from exc

    # =========================================================================
    # Successful Login Lifecycle
    # =========================================================================

    async def record_successful_login(
        self,
        user_id: UUID,
    ) -> UserIdentity | None:
        """
        Atomically record a successful login.

        Resets failed-login count and updates last_login_at.

        The account must still be active and unlocked.
        """
        try:
            _validate_user_id(
                user_id
            )

        except ValueError as exc:
            raise UserRepositoryError(
                str(exc)
            ) from exc

        try:
            now = _utcnow()

            result = await self.session.execute(
                update(AuthUser)
                .where(
                    AuthUser.user_id
                    == user_id,
                    AuthUser.is_active.is_(True),
                    AuthUser.is_locked.is_(False),
                )
                .values(
                    failed_login_count=0,
                    last_login_at=now,
                    updated_at=now,
                )
                .returning(AuthUser)
            )

            record = result.scalar_one_or_none()

            if record is None:
                return None

            await self.session.flush()

            return await self._to_identity(
                record
            )

        except Exception as exc:
            raise UserRepositoryError(
                "Unable to update successful login state."
            ) from exc

    async def reset_failed_login_count(
        self,
        user_id: UUID,
    ) -> UserIdentity | None:
        """
        Reset failed-login count without unlocking the account.
        """
        try:
            _validate_user_id(
                user_id
            )

        except ValueError as exc:
            raise UserRepositoryError(
                str(exc)
            ) from exc

        try:
            result = await self.session.execute(
                update(AuthUser)
                .where(
                    AuthUser.user_id
                    == user_id,
                )
                .values(
                    failed_login_count=0,
                    updated_at=_utcnow(),
                )
                .returning(AuthUser)
            )

            record = result.scalar_one_or_none()

            if record is None:
                return None

            await self.session.flush()

            return await self._to_identity(
                record
            )

        except Exception as exc:
            raise UserRepositoryError(
                "Unable to reset failed login count."
            ) from exc

    async def set_last_login_at(
        self,
        user_id: UUID,
        last_login_at: datetime,
    ) -> UserIdentity | None:
        """
        Update the last successful-login timestamp.
        """
        try:
            _validate_user_id(
                user_id
            )

            normalized_timestamp = _validate_timestamp(
                last_login_at,
                field_name="last_login_at",
            )

            if normalized_timestamp is None:
                raise ValueError(
                    "Last login timestamp cannot be null."
                )

        except (
            ValueError,
            UserRepositoryError,
        ) as exc:
            raise UserRepositoryError(
                str(exc)
            ) from exc

        try:
            result = await self.session.execute(
                update(AuthUser)
                .where(
                    AuthUser.user_id
                    == user_id,
                )
                .values(
                    last_login_at=normalized_timestamp,
                    updated_at=_utcnow(),
                )
                .returning(AuthUser)
            )

            record = result.scalar_one_or_none()

            if record is None:
                return None

            await self.session.flush()

            return await self._to_identity(
                record
            )

        except Exception as exc:
            raise UserRepositoryError(
                "Unable to update last login timestamp."
            ) from exc

    # =========================================================================
    # Force Password Change
    # =========================================================================

    async def set_force_password_change(
        self,
        user_id: UUID,
        force_password_change: bool,
    ) -> UserIdentity | None:
        """
        Enable or disable force-password-change state.
        """
        try:
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

        except ValueError as exc:
            raise UserRepositoryError(
                str(exc)
            ) from exc

        try:
            result = await self.session.execute(
                update(AuthUser)
                .where(
                    AuthUser.user_id
                    == user_id,
                )
                .values(
                    force_password_change=force_password_change,
                    updated_at=_utcnow(),
                )
                .returning(AuthUser)
            )

            record = result.scalar_one_or_none()

            if record is None:
                return None

            await self.session.flush()

            return await self._to_identity(
                record
            )

        except Exception as exc:
            raise UserRepositoryError(
                "Unable to update force-password-change state."
            ) from exc

    # =========================================================================
    # Password Lifecycle
    # =========================================================================

    async def reset_password(
        self,
        user_id: UUID,
        password_hash: str,
    ) -> bool:
        """
        Replace the user's password hash.

        This operation:

            - resets failed-login counter
            - updates password_changed_at

        It intentionally does NOT unlock the account.
        """
        try:
            _validate_user_id(
                user_id
            )

            if not isinstance(
                password_hash,
                str,
            ):
                raise ValueError(
                    "Password hash must be a string."
                )

            if not password_hash:
                raise ValueError(
                    "Password hash cannot be empty."
                )

        except ValueError as exc:
            raise UserRepositoryError(
                str(exc)
            ) from exc

        try:
            now = _utcnow()

            result = await self.session.execute(
                update(AuthUser)
                .where(
                    AuthUser.user_id
                    == user_id,
                )
                .values(
                    password_hash=password_hash,
                    failed_login_count=0,
                    password_changed_at=now,
                    updated_at=now,
                )
            )

            await self.session.flush()

            return bool(
                result.rowcount == 1
            )

        except Exception as exc:
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
        Atomically replace password security state.

        Plaintext passwords are never accepted.
        """
        try:
            _validate_user_id(
                user_id
            )

            if not isinstance(
                password_hash,
                str,
            ):
                raise ValueError(
                    "Password hash must be a string."
                )

            if not password_hash:
                raise ValueError(
                    "Password hash cannot be empty."
                )

            normalized_timestamp = _validate_timestamp(
                password_changed_at,
                field_name="password_changed_at",
            )

            if normalized_timestamp is None:
                raise ValueError(
                    "Password changed timestamp cannot be null."
                )

            if not isinstance(
                force_password_change,
                bool,
            ):
                raise ValueError(
                    "force_password_change must be a boolean."
                )

        except (
            ValueError,
            UserRepositoryError,
        ) as exc:
            raise UserRepositoryError(
                str(exc)
            ) from exc

        try:
            result = await self.session.execute(
                update(AuthUser)
                .where(
                    AuthUser.user_id
                    == user_id,
                )
                .values(
                    password_hash=password_hash,
                    password_changed_at=normalized_timestamp,
                    force_password_change=force_password_change,
                    failed_login_count=0,
                    updated_at=_utcnow(),
                )
                .returning(AuthUser)
            )

            record = result.scalar_one_or_none()

            if record is None:
                return None

            await self.session.flush()

            return await self._to_identity(
                record
            )

        except Exception as exc:
            raise UserRepositoryError(
                "Unable to update password security state."
            ) from exc

    # =========================================================================
    # User Deletion
    # =========================================================================

    async def delete_user(
        self,
        user_id: UUID,
    ) -> bool:
        """
        Permanently delete a user.

        Authorization and last-admin protection belong to the service layer.
        """
        try:
            _validate_user_id(
                user_id
            )

        except ValueError as exc:
            raise UserRepositoryError(
                str(exc)
            ) from exc

        try:
            result = await self.session.execute(
                delete(AuthUser).where(
                    AuthUser.user_id
                    == user_id,
                )
            )

            await self.session.flush()

            return bool(
                result.rowcount == 1
            )

        except Exception as exc:
            raise UserRepositoryError(
                "Unable to delete user."
            ) from exc

    # =========================================================================
    # Identity Conversion
    # =========================================================================

    async def _to_identity(
        self,
        user: AuthUser,
    ) -> UserIdentity:
        """
        Convert ORM user state into the authentication domain model.
        """
        try:
            result = await self.session.execute(
                select(
                    AuthUserRole.role_name
                ).where(
                    AuthUserRole.user_id
                    == user.user_id,
                )
            )

            roles = frozenset(
                str(role)
                for role in result.scalars().all()
            )

            created_at = _ensure_utc(
                user.created_at
            )

            updated_at = _ensure_utc(
                user.updated_at
            )

            if (
                created_at is None
                or updated_at is None
            ):
                raise UserRepositoryError(
                    "Authentication identity timestamps are invalid."
                )

            return UserIdentity(
                user_id=user.user_id,
                username=user.username,
                email=user.email,
                password_hash=user.password_hash,
                roles=roles,
                is_active=bool(
                    user.is_active
                ),
                is_locked=bool(
                    user.is_locked
                ),
                failed_login_count=int(
                    user.failed_login_count
                ),
                display_name=user.display_name,
                force_password_change=bool(
                    user.force_password_change
                ),
                password_changed_at=_ensure_utc(
                    user.password_changed_at
                ),
                last_login_at=_ensure_utc(
                    user.last_login_at
                ),
                created_at=created_at,
                updated_at=updated_at,
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

    Server-side session state is authoritative during JWT validation.

    This repository NEVER commits or rolls back.
    """

    def __init__(
        self,
        session: AsyncSession,
    ) -> None:
        self.session = session

    # =========================================================================
    # Create
    # =========================================================================

    async def create(
        self,
        session: SessionRecord,
    ) -> SessionRecord:
        """
        Persist a new authentication session.
        """
        try:
            _validate_session_id(
                session.session_id
            )

            _validate_user_id(
                session.user_id
            )

            created_at = _ensure_utc(
                session.created_at
            )

            expires_at = _ensure_utc(
                session.expires_at
            )

            if (
                created_at is None
                or expires_at is None
            ):
                raise ValueError(
                    "Authentication session timestamps are invalid."
                )

            if expires_at <= created_at:
                raise ValueError(
                    "Authentication session expiration "
                    "must be after session creation."
                )

            user_agent = _validate_user_agent(
                session.user_agent
            )

            pending_token_id = (
                session.token_id
                if session.token_id
                else (
                    f"{PENDING_TOKEN_PREFIX}"
                    f"{session.session_id}"
                )
            )

            if len(pending_token_id) > MAX_TOKEN_ID_LENGTH:
                raise ValueError(
                    "Authentication token identifier is invalid."
                )

            if not pending_token_id.startswith(
                PENDING_TOKEN_PREFIX
            ):
                raise ValueError(
                    "New authentication sessions must use "
                    "a pending token identifier."
                )

        except ValueError as exc:
            raise SessionRepositoryError(
                str(exc)
            ) from exc

        try:
            record = AuthSession(
                session_id=session.session_id,
                user_id=session.user_id,
                token_id=pending_token_id,
                created_at=created_at,
                expires_at=expires_at,
                revoked_at=_ensure_utc(
                    session.revoked_at
                ),
                ip_address=session.ip_address,
                user_agent=user_agent,
            )

            self.session.add(record)

            await self.session.flush()

            return self._to_session(
                record
            )

        except SessionRepositoryError:
            raise

        except IntegrityError as exc:
            raise SessionRepositoryError(
                "Unable to persist authentication session."
            ) from exc

        except Exception as exc:
            raise SessionRepositoryError(
                "Unable to persist authentication session."
            ) from exc

    # =========================================================================
    # Active Session
    # =========================================================================

    async def get_active(
        self,
        session_id: UUID,
    ) -> SessionRecord | None:
        """
        Return an active and non-expired authentication session.
        """
        try:
            _validate_session_id(
                session_id
            )

        except ValueError as exc:
            raise SessionRepositoryError(
                str(exc)
            ) from exc

        try:
            now = _utcnow()

            result = await self.session.execute(
                select(AuthSession).where(
                    AuthSession.session_id
                    == session_id,
                    AuthSession.revoked_at.is_(None),
                    AuthSession.expires_at > now,
                )
            )

            record = result.scalar_one_or_none()

            if record is None:
                return None

            return self._to_session(
                record
            )

        except SessionRepositoryError:
            raise

        except Exception as exc:
            raise SessionRepositoryError(
                "Unable to retrieve authentication session."
            ) from exc

    # =========================================================================
    # Bind Token
    # =========================================================================

    async def bind_token(
        self,
        session_id: UUID,
        token_id: str,
    ) -> SessionRecord:
        """
        Bind a real JWT JTI to an active authentication session.
        """
        try:
            _validate_session_id(
                session_id
            )

            validated_token_id = _validate_token_id(
                token_id
            )

        except ValueError as exc:
            raise SessionRepositoryError(
                str(exc)
            ) from exc

        try:
            now = _utcnow()

            result = await self.session.execute(
                select(AuthSession).where(
                    AuthSession.session_id
                    == session_id,
                    AuthSession.revoked_at.is_(None),
                    AuthSession.expires_at > now,
                )
            )

            record = result.scalar_one_or_none()

            if record is None:
                raise SessionRepositoryError(
                    "Authentication session is not active."
                )

            if (
                record.token_id
                and not record.token_id.startswith(
                    PENDING_TOKEN_PREFIX
                )
            ):
                raise SessionRepositoryError(
                    "Authentication session already has a bound token."
                )

            record.token_id = validated_token_id

            await self.session.flush()

            return self._to_session(
                record
            )

        except SessionRepositoryError:
            raise

        except IntegrityError as exc:
            raise SessionRepositoryError(
                "Unable to bind token to authentication session."
            ) from exc

        except Exception as exc:
            raise SessionRepositoryError(
                "Unable to bind token to authentication session."
            ) from exc

    # =========================================================================
    # Revoke One Session
    # =========================================================================

    async def revoke(
        self,
        session_id: UUID,
    ) -> bool:
        """
        Revoke one authentication session.

        Returns False when missing or already revoked.
        """
        try:
            _validate_session_id(
                session_id
            )

        except ValueError as exc:
            raise SessionRepositoryError(
                str(exc)
            ) from exc

        try:
            result = await self.session.execute(
                update(AuthSession)
                .where(
                    AuthSession.session_id
                    == session_id,
                    AuthSession.revoked_at.is_(None),
                )
                .values(
                    revoked_at=_utcnow(),
                )
            )

            await self.session.flush()

            return bool(
                result.rowcount == 1
            )

        except Exception as exc:
            raise SessionRepositoryError(
                "Unable to revoke authentication session."
            ) from exc

    # =========================================================================
    # Revoke User Sessions
    # =========================================================================

    async def revoke_user_sessions(
        self,
        user_id: UUID,
    ) -> int:
        """
        Revoke all currently active sessions belonging to a user.
        """
        try:
            _validate_user_id(
                user_id
            )

        except ValueError as exc:
            raise SessionRepositoryError(
                str(exc)
            ) from exc

        try:
            now = _utcnow()

            result = await self.session.execute(
                update(AuthSession)
                .where(
                    AuthSession.user_id
                    == user_id,
                    AuthSession.revoked_at.is_(None),
                    AuthSession.expires_at > now,
                )
                .values(
                    revoked_at=now,
                )
            )

            await self.session.flush()

            return int(
                result.rowcount or 0
            )

        except Exception as exc:
            raise SessionRepositoryError(
                "Unable to revoke user authentication sessions."
            ) from exc

    # =========================================================================
    # List Active Sessions
    # =========================================================================

    async def list_active_user_sessions(
        self,
        user_id: UUID,
    ) -> list[SessionRecord]:
        """
        Return active, non-expired sessions belonging to one user.
        """
        try:
            _validate_user_id(
                user_id
            )

        except ValueError as exc:
            raise SessionRepositoryError(
                str(exc)
            ) from exc

        try:
            now = _utcnow()

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
                self._to_session(record)
                for record in records
            ]

        except SessionRepositoryError:
            raise

        except Exception as exc:
            raise SessionRepositoryError(
                "Unable to retrieve active user sessions."
            ) from exc

    # =========================================================================
    # Purge Expired
    # =========================================================================

    async def purge_expired(
        self,
    ) -> int:
        """
        Permanently remove expired authentication sessions.
        """
        try:
            now = _utcnow()

            result = await self.session.execute(
                delete(AuthSession).where(
                    AuthSession.expires_at <= now,
                )
            )

            await self.session.flush()

            return int(
                result.rowcount or 0
            )

        except Exception as exc:
            raise SessionRepositoryError(
                "Unable to purge expired authentication sessions."
            ) from exc

    # =========================================================================
    # Session Conversion
    # =========================================================================

    @staticmethod
    def _to_session(
        record: AuthSession,
    ) -> SessionRecord:
        """
        Convert ORM session data into the domain model.

        Pending token placeholders are never exposed as real JTIs.
        """
        try:
            token_id = record.token_id or ""

            if token_id.startswith(
                PENDING_TOKEN_PREFIX
            ):
                token_id = ""

            created_at = _ensure_utc(
                record.created_at
            )

            expires_at = _ensure_utc(
                record.expires_at
            )

            if (
                created_at is None
                or expires_at is None
            ):
                raise SessionRepositoryError(
                    "Authentication session timestamps are invalid."
                )

            if expires_at <= created_at:
                raise SessionRepositoryError(
                    "Authentication session expiration is invalid."
                )

            user_agent = _validate_user_agent(
                record.user_agent
            )

            return SessionRecord(
                session_id=record.session_id,
                user_id=record.user_id,
                token_id=token_id,
                created_at=created_at,
                expires_at=expires_at,
                revoked_at=_ensure_utc(
                    record.revoked_at
                ),
                ip_address=record.ip_address,
                user_agent=user_agent,
            )

        except SessionRepositoryError:
            raise

        except (
            TypeError,
            ValueError,
            AttributeError,
        ) as exc:
            raise SessionRepositoryError(
                "Authentication session data is invalid."
            ) from exc


# ============================================================================
# PostgreSQL Authentication Audit Repository
# ============================================================================


class PostgresAuthAuditRepository(AuthAuditRepository):
    """
    PostgreSQL-backed authentication audit repository.

    Records are flushed into the caller's current transaction.

    This repository NEVER commits independently.
    """

    def __init__(
        self,
        session: AsyncSession,
    ) -> None:
        self.session = session

    # =========================================================================
    # Record
    # =========================================================================

    async def record(
        self,
        record: AuditRecord,
    ) -> None:
        """
        Persist one authentication audit event.

        Metadata is recursively sanitized before JSONB persistence.
        """
        try:
            action = _require_non_empty(
                record.action,
                field_name="Audit action",
            )

            action = _validate_length(
                action,
                field_name="Audit action",
                maximum=MAX_AUDIT_ACTION_LENGTH,
            )

            outcome = _require_non_empty(
                record.outcome,
                field_name="Audit outcome",
            )

            outcome = _validate_length(
                outcome,
                field_name="Audit outcome",
                maximum=MAX_AUDIT_OUTCOME_LENGTH,
            )

            request_id = record.request_id

            if request_id is not None:
                if not isinstance(
                    request_id,
                    str,
                ):
                    raise ValueError(
                        "Audit request identifier must be a string."
                    )

                request_id = request_id.strip()

                if not request_id:
                    request_id = None

                elif len(request_id) > MAX_REQUEST_ID_LENGTH:
                    raise ValueError(
                        "Audit request identifier is too long."
                    )

            if (
                record.source_ip is not None
                and not isinstance(
                    record.source_ip,
                    str,
                )
            ):
                raise ValueError(
                    "Audit source IP must be a string."
                )

            if record.session_id is not None:
                _validate_session_id(
                    record.session_id
                )

            if record.actor_user_id is not None:
                _validate_user_id(
                    record.actor_user_id
                )

            if record.target_user_id is not None:
                _validate_user_id(
                    record.target_user_id
                )

            created_at = (
                _ensure_utc(
                    record.timestamp
                )
                or _utcnow()
            )

            metadata = _sanitize_audit_metadata(
                record.metadata
            )

            audit = AuthAudit(
                action=action,
                outcome=outcome,
                actor_user_id=record.actor_user_id,
                target_user_id=record.target_user_id,
                session_id=record.session_id,
                request_id=request_id,
                source_ip=record.source_ip,
                audit_metadata=metadata,
                created_at=created_at,
            )

            self.session.add(audit)

            await self.session.flush()

        except AuthAuditRepositoryError:
            raise

        except ValueError as exc:
            raise AuthAuditRepositoryError(
                "Invalid authentication audit event."
            ) from exc

        except IntegrityError as exc:
            raise AuthAuditRepositoryError(
                "Unable to persist authentication audit event."
            ) from exc

        except SQLAlchemyError as exc:
            raise AuthAuditRepositoryError(
                "Unable to persist authentication audit event."
            ) from exc

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

    Intended for security-critical events that must survive rollback of
    the primary request transaction.
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
        Persist and commit an authentication audit event independently.
        """
        try:
            async with self._session_manager.session() as audit_session:
                repository = PostgresAuthAuditRepository(
                    audit_session
                )

                await repository.record(
                    record
                )

                await audit_session.commit()

        except AuthAuditRepositoryError:
            raise

        except Exception as exc:
            raise AuthAuditRepositoryError(
                "Unable to durably persist authentication audit event."
            ) from exc


# ============================================================================
# Public Exports
# ============================================================================

__all__ = [
    "DEFAULT_MAX_FAILED_LOGIN_ATTEMPTS",
    "PostgresAuthAuditRepository",
    "PostgresDurableAuthAuditRepository",
    "PostgresSessionRepository",
    "PostgresUserRepository",
]