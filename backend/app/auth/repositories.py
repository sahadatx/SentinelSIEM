"""
SentinelSIEM Authentication Repository Contracts.

===============================================================================
RESPONSIBILITY
===============================================================================

This module defines persistence contracts for:

    - User identities
    - Authentication sessions
    - Authentication / identity audit events

Repository responsibilities are intentionally limited to persistence.

Architecture
------------

    API / Service
          |
          v
    Repository Contract
          |
          v
    PostgreSQL Implementation


Repositories MUST NOT implement business policy.

Business/security policy belongs to:

    - Service layer
    - Authorization layer
    - Domain/security services

Repositories MUST NOT decide:

    - RBAC authorization
    - permissions
    - self-service authorization
    - role policy
    - self-delete prevention
    - self-disable prevention
    - self-lock prevention
    - last-active-ADMIN protection
    - password policy
    - workflow authorization
    - session-revocation orchestration
    - audit authorization

===============================================================================
AUDIT ARCHITECTURE
===============================================================================

SentinelSIEM has one canonical audit stream.

Canonical authentication / identity audit source:

    siem_auth_audit

Global Audit
------------

    All supported audit events.

User Audit
----------

    A filtered actor/target view of the same canonical audit stream.

There is intentionally NO separate User Audit table.

Repository support for User Audit therefore consists of:

    list_user_audit()
    count_user_audit()

Both operate against the canonical audit source.

===============================================================================
TRANSACTION OWNERSHIP
===============================================================================

Repository implementations MUST NOT commit or rollback transactions.

The application/request/service layer owns the transaction boundary:

    BEGIN
        repository operations
    COMMIT / ROLLBACK

Repositories may flush database state where required.

Repositories MUST NOT call:

    session.commit()
    session.rollback()

===============================================================================
SECURITY
===============================================================================

Repositories MUST NEVER receive plaintext passwords.

Repositories MUST NOT persist:

    - plaintext passwords
    - access tokens
    - refresh tokens
    - API keys
    - client secrets
    - private keys
    - JWT contents
    - session secrets

Password hashes are accepted only after hashing has already occurred.

JWT JTIs / internal token identifiers are security-sensitive internal state.

They MUST NOT be exposed through:

    - API serializers
    - frontend payloads
    - audit metadata
    - application logs

Audit metadata must contain sanitized investigation context only.

===============================================================================
TIMESTAMP POLICY
===============================================================================

Authentication and audit timestamps MUST be timezone-aware.

Repository implementations MUST normalize accepted timestamps to UTC before
persistence.

===============================================================================
USER LISTING / PAGINATION
===============================================================================

Administrative user listing supports:

    - free-text search
    - role
    - active / disabled state
    - locked / unlocked state
    - force-password-change state
    - creation date range
    - last-login date range
    - limit
    - offset

The repository exposes both:

    list_users()
    count_users()

The filter semantics of these methods MUST remain identical.

Recommended deterministic ordering:

    created_at DESC
    user_id DESC

===============================================================================
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

from app.auth.models import (
    AuditRecord,
    SessionRecord,
    UserIdentity,
)


# =============================================================================
# Constants
# =============================================================================

DEFAULT_USER_LIST_LIMIT = 50
DEFAULT_USER_LIST_OFFSET = 0

DEFAULT_AUDIT_LIST_LIMIT = 50
DEFAULT_AUDIT_LIST_OFFSET = 0

DEFAULT_MAX_LOGIN_ATTEMPTS = 5


# =============================================================================
# Repository Contract Helpers
# =============================================================================


def _validate_utc_timestamp(
    value: datetime,
) -> datetime:
    """
    Validate and normalize a datetime to UTC.

    Requirements:

        - value must be a datetime
        - value must be timezone-aware

    Returns:
        UTC-normalized datetime.

    Raises:
        ValueError:
            If the value is invalid or timezone-naive.
    """
    if not isinstance(value, datetime):
        raise ValueError(
            "Timestamp must be a datetime."
        )

    if (
        value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError(
            "Timestamp must be timezone-aware."
        )

    return value.astimezone(UTC)


def _validate_positive_limit(
    value: int,
    *,
    field_name: str = "limit",
) -> int:
    """
    Validate a positive pagination limit.

    Concrete repositories may enforce a stricter maximum.
    """
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
    ):
        raise ValueError(
            f"{field_name} must be an integer."
        )

    if value < 1:
        raise ValueError(
            f"{field_name} must be greater than zero."
        )

    return value


def _validate_non_negative_offset(
    value: int,
) -> int:
    """
    Validate a non-negative pagination offset.
    """
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
    ):
        raise ValueError(
            "offset must be an integer."
        )

    if value < 0:
        raise ValueError(
            "offset cannot be negative."
        )

    return value


def _validate_login_attempt_limit(
    value: int,
) -> int:
    """
    Validate failed-login threshold.
    """
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
    ):
        raise ValueError(
            "max_attempts must be an integer."
        )

    if value < 1:
        raise ValueError(
            "max_attempts must be greater than zero."
        )

    return value


# =============================================================================
# User Repository Contract
# =============================================================================


class UserRepository(Protocol):
    """
    Async persistence contract for SentinelSIEM user identities.

    This contract contains persistence operations only.

    Authorization, RBAC, password policy, session orchestration,
    and security workflow decisions belong outside this repository.
    """

    # =========================================================================
    # Identity Lookup
    # =========================================================================

    async def get_by_login(
        self,
        login: str,
    ) -> UserIdentity | None:
        """
        Find a user by username or email.

        Args:
            login:
                Username or email lookup value.

        Returns:
            Matching user identity or None.
        """
        ...

    async def get_by_id(
        self,
        user_id: UUID,
    ) -> UserIdentity | None:
        """
        Find a user by UUID.

        Returns:
            Matching user identity or None.
        """
        ...

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
        limit: int = DEFAULT_USER_LIST_LIMIT,
        offset: int = DEFAULT_USER_LIST_OFFSET,
    ) -> list[UserIdentity]:
        """
        Return one paginated page of users.

        Search fields:

            - username
            - email
            - display_name

        Supported filters:

            - role
            - is_active
            - is_locked
            - force_password_change
            - created_from
            - created_to
            - last_login_from
            - last_login_to

        Timestamp filters MUST be timezone-aware.

        Recommended deterministic ordering:

            created_at DESC
            user_id DESC

        Security:

            Implementations MUST NOT expose credentials,
            session secrets, JWT contents, or password material
            through API-facing repository results.
        """
        ...

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
        Count users using exactly the same filter semantics as list_users().

        Pagination parameters are intentionally excluded.

        The service/API layer may combine:

            users = list_users(...)
            total = count_users(...)

        Returns:
            Total number of matching users.
        """
        ...

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
        Persist a new user.

        Preconditions supplied by the service layer:

            - username normalized
            - email normalized
            - role selected
            - password already hashed
            - security state validated

        Requirements:

            - database uniqueness constraints remain authoritative
            - plaintext password must never reach this method
            - role creation is outside repository responsibility
            - implementation MUST NOT commit
        """
        ...

    # =========================================================================
    # Editable User Profile
    # =========================================================================

    async def update_user(
        self,
        user: UserIdentity,
    ) -> UserIdentity | None:
        """
        Update editable user profile state.

        Normally editable:

            - username
            - email
            - display_name

        This method MUST NOT implicitly change:

            - password_hash
            - roles
            - is_active
            - is_locked
            - failed_login_count
            - force_password_change
            - password_changed_at
            - last_login_at

        Dedicated methods must be used for security-state transitions.

        Returns:
            Updated user or None when the user does not exist.
        """
        ...

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

        This is a persistence operation.

        Authorization and RBAC policy belong to the service/authorization
        layer.
        """
        ...

    # =========================================================================
    # Account Active State
    # =========================================================================

    async def set_active(
        self,
        user_id: UUID,
        is_active: bool,
    ) -> UserIdentity | None:
        """
        Enable or disable an account.

        This method MUST NOT:

            - authorize the operation
            - revoke sessions
            - change roles
            - change password state
            - make workflow decisions
        """
        ...

    # =========================================================================
    # Account Lock State
    # =========================================================================

    async def set_locked(
        self,
        user_id: UUID,
        is_locked: bool,
    ) -> UserIdentity | None:
        """
        Lock or unlock an account.

        This method performs persistence only.

        Explicit service-level policy determines whether the operation
        is allowed.

        Implementations MUST NOT perform RBAC or self-service checks.
        """
        ...

    # =========================================================================
    # Failed Login State
    # =========================================================================

    async def record_failed_login(
        self,
        user_id: UUID,
        *,
        max_attempts: int = DEFAULT_MAX_LOGIN_ATTEMPTS,
    ) -> UserIdentity | None:
        """
        Atomically record one failed login attempt.

        Required persistence transition:

            failed_login_count += 1

        If the resulting count reaches max_attempts:

            is_locked = True

        Requirements:

            - increment MUST be atomic
            - automatic lock MUST be atomic with the increment
            - existing administrative lock MUST NOT be removed
            - plaintext credentials MUST NOT be accepted

        Returns:
            Updated user or None if the user does not exist.
        """
        ...

    async def reset_failed_login_count(
        self,
        user_id: UUID,
    ) -> UserIdentity | None:
        """
        Reset failed-login count to zero.

        This method MUST NOT unlock the account.

        Explicit unlocking is performed separately with:

            set_locked(user_id, False)
        """
        ...

    async def record_successful_login(
        self,
        user_id: UUID,
    ) -> UserIdentity | None:
        """
        Record successful authentication state.

        Expected persistence transition:

            failed_login_count = 0
            last_login_at = current UTC timestamp
            updated_at = current UTC timestamp

        This method MUST NOT:

            - change roles
            - change active state
            - change administrative lock state
            - revoke sessions
        """
        ...

    async def set_last_login_at(
        self,
        user_id: UUID,
        last_login_at: datetime,
    ) -> UserIdentity | None:
        """
        Update the last successful login timestamp.

        Timestamp MUST be timezone-aware.

        Implementations MUST normalize the timestamp to UTC.
        """
        ...

    # =========================================================================
    # Force Password Change
    # =========================================================================

    async def set_force_password_change(
        self,
        user_id: UUID,
        force_password_change: bool,
    ) -> UserIdentity | None:
        """
        Set or clear force-password-change state.

        This method MUST NOT modify:

            - password_hash
            - password_changed_at
            - roles
            - active state
            - lock state
            - failed-login count
        """
        ...

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

        password_hash MUST already be generated by the password-hashing
        service.

        Expected persistence changes:

            - password_hash
            - password_changed_at
            - failed_login_count = 0
            - updated_at

        MUST preserve:

            - administrative lock state
            - active/disabled state
            - role state

        MUST NOT:

            - receive plaintext passwords
            - receive complete JWTs
            - revoke sessions directly
            - silently unlock the account

        Session revocation belongs to the service layer.

        Returns:
            True if the user was updated.
            False if the user does not exist.
        """
        ...

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

        Changes:

            - password_hash
            - password_changed_at
            - force_password_change
            - failed_login_count = 0
            - updated_at

        MUST preserve:

            - administrative lock state
            - active/disabled state
            - role state

        password_changed_at MUST be timezone-aware.

        Plaintext passwords MUST never reach the repository.

        Session revocation belongs to the service layer.
        """
        ...

    # =========================================================================
    # User Deletion
    # =========================================================================

    async def delete_user(
        self,
        user_id: UUID,
    ) -> bool:
        """
        Permanently delete a user.

        Authorization and safety policy belong to the service layer.

        The service layer is responsible for enforcing rules such as:

            - delete authorization
            - self-delete prevention
            - last-active-ADMIN protection
            - session-revocation orchestration

        Database foreign-key constraints remain authoritative for persistence
        dependencies.

        Returns:
            True when deleted.
            False when the user does not exist.
        """
        ...


# =============================================================================
# Session Repository Contract
# =============================================================================


class SessionRepository(Protocol):
    """
    Async persistence contract for server-side authentication sessions.

    Server-side sessions remain authoritative during authentication.
    """

    # =========================================================================
    # Session Creation
    # =========================================================================

    async def create(
        self,
        session: SessionRecord,
    ) -> SessionRecord:
        """
        Persist a new authentication session.

        Requirements:

            - session_id must be valid
            - user_id must be valid
            - created_at must be timezone-aware
            - expires_at must be timezone-aware
            - expires_at must be later than created_at

        Token/JTI state remains security-sensitive internal state.
        """
        ...

    # =========================================================================
    # Active Session Lookup
    # =========================================================================

    async def get_active(
        self,
        session_id: UUID,
    ) -> SessionRecord | None:
        """
        Return an active authentication session.

        Active means:

            revoked_at IS NULL
            AND expires_at > current UTC timestamp

        Revoked and expired sessions MUST NOT be returned.
        """
        ...

    # =========================================================================
    # Active User Sessions
    # =========================================================================

    async def list_active_user_sessions(
        self,
        user_id: UUID,
    ) -> list[SessionRecord]:
        """
        Return active sessions belonging strictly to one user.

        Requirements:

            - exact user scope
            - revoked sessions excluded
            - expired sessions excluded
            - security-sensitive token identifiers remain internal

        Recommended deterministic ordering:

            created_at DESC
            session_id DESC
        """
        ...

    # =========================================================================
    # Internal JWT JTI Binding
    # =========================================================================

    async def bind_token(
        self,
        session_id: UUID,
        token_id: str,
    ) -> SessionRecord:
        """
        Bind an internal JWT JTI to an existing active session.

        Accepts ONLY the internal token/JTI identifier.

        MUST NOT receive:

            - access tokens
            - refresh tokens
            - complete JWT strings
        """
        ...

    # =========================================================================
    # Single Session Revocation
    # =========================================================================

    async def revoke(
        self,
        session_id: UUID,
    ) -> bool:
        """
        Revoke one authentication session.

        Revocation should be idempotent.

        Returns:
            True if an active session was transitioned to revoked.
            False otherwise.
        """
        ...

    # =========================================================================
    # User Session Revocation
    # =========================================================================

    async def revoke_user_sessions(
        self,
        user_id: UUID,
    ) -> int:
        """
        Revoke all currently active sessions for one user.

        Typical service-layer callers include:

            - password reset
            - account disable
            - account lock
            - administrative session revocation
            - security response

        Returns:
            Number of sessions revoked.
        """
        ...

    # =========================================================================
    # Expired Session Cleanup
    # =========================================================================

    async def purge_expired(
        self,
    ) -> int:
        """
        Permanently remove expired authentication sessions.

        Expired means:

            expires_at <= current UTC timestamp

        Returns:
            Number of sessions removed.
        """
        ...


# =============================================================================
# Authentication Audit Repository Contract
# =============================================================================


class AuthAuditRepository(Protocol):
    """
    Async persistence contract for authentication / identity audit events.

    Canonical source:

        siem_auth_audit

    User Audit is a filtered view of the canonical authentication audit
    stream. No duplicate User Audit table is permitted.
    """

    # =========================================================================
    # Audit Persistence
    # =========================================================================

    async def record(
        self,
        record: AuditRecord,
    ) -> None:
        """
        Persist one immutable authentication/identity audit event.

        Requirements:

            - timestamp must be timezone-aware
            - timestamp normalized to UTC
            - credential material MUST NOT be persisted
            - JWT contents MUST NOT be persisted
            - session secrets MUST NOT be persisted
            - audit metadata must contain sanitized context
            - implementation MUST NOT commit independently
        """
        ...

    # =========================================================================
    # User Audit Listing
    # =========================================================================

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
        limit: int = DEFAULT_AUDIT_LIST_LIMIT,
        offset: int = DEFAULT_AUDIT_LIST_OFFSET,
    ) -> list[AuditRecord]:
        """
        Return audit events associated with one user.

        User association:

            target_user_id == user_id
            OR
            actor_user_id == user_id

        Optional filters:

            actor_user_id
            action
            outcome
            date_from
            date_to
            search

        Search MUST be restricted to explicitly approved non-secret
        audit fields.

        Timestamp filters MUST be timezone-aware.

        Pagination:

            limit
            offset

        Recommended deterministic ordering:

            timestamp DESC
            audit_id DESC

        Security:

            - user scope MUST NOT be broadened
            - credentials MUST NOT be returned
            - JWT contents MUST NOT be returned
            - session secrets MUST NOT be returned
            - secret-bearing metadata MUST NOT be searched
        """
        ...

    # =========================================================================
    # User Audit Count
    # =========================================================================

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

        Filter semantics MUST exactly match list_user_audit().

        Pagination arguments are intentionally excluded.

        Returns:
            Total number of matching audit events.
        """
        ...


# =============================================================================
# Repository Errors
# =============================================================================


class AuthenticationRepositoryError(
    RuntimeError
):
    """
    Base error for authentication repository failures.
    """


class UserRepositoryError(
    AuthenticationRepositoryError
):
    """
    User persistence or retrieval failure.
    """


class SessionRepositoryError(
    AuthenticationRepositoryError
):
    """
    Session persistence, lookup, binding, revocation,
    or cleanup failure.
    """


class AuthAuditRepositoryError(
    AuthenticationRepositoryError
):
    """
    Authentication/identity audit persistence or retrieval failure.
    """


# =============================================================================
# Abstract User Repository
# =============================================================================


class AbstractUserRepository(ABC):
    """
    Optional explicit ABC contract for user repositories.

    Concrete implementations may use either:

        - structural Protocol typing
        - explicit ABC inheritance

    The method contract remains identical.
    """

    # =========================================================================
    # Identity Lookup
    # =========================================================================

    @abstractmethod
    async def get_by_login(
        self,
        login: str,
    ) -> UserIdentity | None:
        """Find a user by username or email."""
        ...

    @abstractmethod
    async def get_by_id(
        self,
        user_id: UUID,
    ) -> UserIdentity | None:
        """Find a user by UUID."""
        ...

    # =========================================================================
    # Administrative Listing
    # =========================================================================

    @abstractmethod
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
        limit: int = DEFAULT_USER_LIST_LIMIT,
        offset: int = DEFAULT_USER_LIST_OFFSET,
    ) -> list[UserIdentity]:
        """List users with filtering and pagination."""
        ...

    @abstractmethod
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
        """Count users using the same filters as list_users()."""
        ...

    # =========================================================================
    # Creation / Profile
    # =========================================================================

    @abstractmethod
    async def create_user(
        self,
        user: UserIdentity,
        *,
        role: str,
    ) -> UserIdentity:
        """Persist a new user."""
        ...

    @abstractmethod
    async def update_user(
        self,
        user: UserIdentity,
    ) -> UserIdentity | None:
        """Update editable user profile state."""
        ...

    # =========================================================================
    # Role / Account State
    # =========================================================================

    @abstractmethod
    async def set_role(
        self,
        user_id: UUID,
        role: str,
    ) -> UserIdentity | None:
        """Replace the user's role."""
        ...

    @abstractmethod
    async def set_active(
        self,
        user_id: UUID,
        is_active: bool,
    ) -> UserIdentity | None:
        """Enable or disable a user."""
        ...

    @abstractmethod
    async def set_locked(
        self,
        user_id: UUID,
        is_locked: bool,
    ) -> UserIdentity | None:
        """Lock or unlock a user."""
        ...

    # =========================================================================
    # Authentication Failure State
    # =========================================================================

    @abstractmethod
    async def record_failed_login(
        self,
        user_id: UUID,
        *,
        max_attempts: int = DEFAULT_MAX_LOGIN_ATTEMPTS,
    ) -> UserIdentity | None:
        """Atomically record a failed login attempt."""
        ...

    @abstractmethod
    async def reset_failed_login_count(
        self,
        user_id: UUID,
    ) -> UserIdentity | None:
        """Reset failed-login count without unlocking."""
        ...

    @abstractmethod
    async def record_successful_login(
        self,
        user_id: UUID,
    ) -> UserIdentity | None:
        """Record successful authentication state."""
        ...

    @abstractmethod
    async def set_last_login_at(
        self,
        user_id: UUID,
        last_login_at: datetime,
    ) -> UserIdentity | None:
        """Update last successful login timestamp."""
        ...

    # =========================================================================
    # Password Change State
    # =========================================================================

    @abstractmethod
    async def set_force_password_change(
        self,
        user_id: UUID,
        force_password_change: bool,
    ) -> UserIdentity | None:
        """Set or clear force-password-change state."""
        ...

    # =========================================================================
    # Password Lifecycle
    # =========================================================================

    @abstractmethod
    async def reset_password(
        self,
        user_id: UUID,
        password_hash: str,
    ) -> bool:
        """Replace password hash."""
        ...

    @abstractmethod
    async def set_password_state(
        self,
        user_id: UUID,
        password_hash: str,
        *,
        password_changed_at: datetime,
        force_password_change: bool = False,
    ) -> UserIdentity | None:
        """Atomically replace password security state."""
        ...

    # =========================================================================
    # Deletion
    # =========================================================================

    @abstractmethod
    async def delete_user(
        self,
        user_id: UUID,
    ) -> bool:
        """Permanently delete a user."""
        ...


# =============================================================================
# Abstract Session Repository
# =============================================================================


class AbstractSessionRepository(ABC):
    """
    Optional explicit ABC contract for session repositories.
    """

    @abstractmethod
    async def create(
        self,
        session: SessionRecord,
    ) -> SessionRecord:
        """Persist a new authentication session."""
        ...

    @abstractmethod
    async def get_active(
        self,
        session_id: UUID,
    ) -> SessionRecord | None:
        """Return an active authentication session."""
        ...

    @abstractmethod
    async def list_active_user_sessions(
        self,
        user_id: UUID,
    ) -> list[SessionRecord]:
        """Return active sessions belonging to one user."""
        ...

    @abstractmethod
    async def bind_token(
        self,
        session_id: UUID,
        token_id: str,
    ) -> SessionRecord:
        """Bind an internal JWT JTI to an active session."""
        ...

    @abstractmethod
    async def revoke(
        self,
        session_id: UUID,
    ) -> bool:
        """Revoke one authentication session."""
        ...

    @abstractmethod
    async def revoke_user_sessions(
        self,
        user_id: UUID,
    ) -> int:
        """Revoke all active sessions belonging to a user."""
        ...

    @abstractmethod
    async def purge_expired(
        self,
    ) -> int:
        """Remove expired authentication sessions."""
        ...


# =============================================================================
# Abstract Authentication Audit Repository
# =============================================================================


class AbstractAuthAuditRepository(ABC):
    """
    Optional explicit ABC contract for authentication audit repositories.

    All audit data belongs to the canonical authentication audit stream.
    """

    @abstractmethod
    async def record(
        self,
        record: AuditRecord,
    ) -> None:
        """
        Persist one immutable audit event.
        """
        ...

    @abstractmethod
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
        limit: int = DEFAULT_AUDIT_LIST_LIMIT,
        offset: int = DEFAULT_AUDIT_LIST_OFFSET,
    ) -> list[AuditRecord]:
        """
        Retrieve user-related audit events.
        """
        ...

    @abstractmethod
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
        Count user-related audit events using the exact same
        filtering semantics as list_user_audit().
        """
        ...


# =============================================================================
# Public Exports
# =============================================================================

__all__ = [
    # -------------------------------------------------------------------------
    # Constants
    # -------------------------------------------------------------------------
    "DEFAULT_USER_LIST_LIMIT",
    "DEFAULT_USER_LIST_OFFSET",
    "DEFAULT_AUDIT_LIST_LIMIT",
    "DEFAULT_AUDIT_LIST_OFFSET",
    "DEFAULT_MAX_LOGIN_ATTEMPTS",

    # -------------------------------------------------------------------------
    # Validation helpers
    # -------------------------------------------------------------------------
    "_validate_utc_timestamp",
    "_validate_positive_limit",
    "_validate_non_negative_offset",
    "_validate_login_attempt_limit",

    # -------------------------------------------------------------------------
    # Protocol contracts
    # -------------------------------------------------------------------------
    "UserRepository",
    "SessionRepository",
    "AuthAuditRepository",

    # -------------------------------------------------------------------------
    # Repository errors
    # -------------------------------------------------------------------------
    "AuthenticationRepositoryError",
    "UserRepositoryError",
    "SessionRepositoryError",
    "AuthAuditRepositoryError",

    # -------------------------------------------------------------------------
    # Optional ABC contracts
    # -------------------------------------------------------------------------
    "AbstractUserRepository",
    "AbstractSessionRepository",
    "AbstractAuthAuditRepository",
]