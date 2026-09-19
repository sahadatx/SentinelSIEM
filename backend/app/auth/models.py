"""
SentinelSIEM Authentication Domain Models
==========================================

Authentication and user-management domain contracts.

Responsibilities
----------------
- User identity representation
- Authenticated principal representation
- Server-side authentication session representation
- Domain-level audit event representation
- Canonical audit action constants
- Canonical audit outcome constants

Architecture
------------

    Authentication / User Management
                  |
                  v
          Authentication Domain
                  |
        +---------+---------+
        |                   |
        v                   v
    UserIdentity       UserPrincipal
                            |
                            v
                       AuditService
                            |
                            v
                    AuditRepository
                            |
                            v
                    siem_auth_audit

Important
---------
This module does NOT define a database audit table.

The authoritative audit persistence source is:

    siem_auth_audit

Audit persistence belongs to:

    app.audit

Security
--------
This module MUST NOT expose credential material through:

- API responses
- authenticated principals
- audit metadata
- frontend payloads
- logs
- error messages

Sensitive credential material includes:

- plaintext passwords
- password hashes
- JWTs
- access tokens
- refresh tokens
- session tokens
- API keys
- private keys
- secrets
- authorization headers
- cookies
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4


# ============================================================================
# Time Helpers
# ============================================================================


def utcnow() -> datetime:
    """
    Return the current timezone-aware UTC datetime.

    SentinelSIEM authentication, user-management and audit domain timestamps
    use UTC consistently.
    """
    return datetime.now(UTC)


# ============================================================================
# User Identity
# ============================================================================


@dataclass(frozen=True, slots=True)
class UserIdentity:
    """
    Internal authentication-domain representation of a user.

    This object represents the complete internal identity required by
    authentication and user-management services.

    Security
    --------
    ``password_hash`` is credential material.

    It is intentionally present because password verification requires
    access to the stored password hash.

    ``password_hash`` MUST NEVER be exposed through:

    - API responses
    - UserPrincipal
    - AuditRecord
    - audit metadata
    - frontend payloads
    - logs
    - exceptions
    """

    # ------------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------------

    user_id: UUID

    username: str

    email: str

    # ------------------------------------------------------------------------
    # Credential
    # ------------------------------------------------------------------------

    password_hash: str

    # ------------------------------------------------------------------------
    # Authorization
    # ------------------------------------------------------------------------

    roles: frozenset[str] = field(
        default_factory=frozenset,
    )

    # ------------------------------------------------------------------------
    # Account State
    # ------------------------------------------------------------------------

    is_active: bool = True

    is_locked: bool = False

    failed_login_count: int = 0

    force_password_change: bool = False

    # ------------------------------------------------------------------------
    # Profile
    # ------------------------------------------------------------------------

    display_name: str | None = None

    # ------------------------------------------------------------------------
    # Security Timestamps
    # ------------------------------------------------------------------------

    password_changed_at: datetime | None = None

    last_login_at: datetime | None = None

    # ------------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------------

    created_at: datetime = field(
        default_factory=utcnow,
    )

    updated_at: datetime = field(
        default_factory=utcnow,
    )


# ============================================================================
# Authenticated Principal
# ============================================================================


@dataclass(frozen=True, slots=True)
class UserPrincipal:
    """
    Authenticated request principal.

    This is the identity representation used after authentication has
    succeeded.

    The principal contains only information required by:

    - request processing
    - authorization
    - permission checks
    - role checks
    - audit actor identification

    Security
    --------
    Credential material MUST NEVER be stored here.

    In particular, this object MUST NOT contain:

    - password
    - password_hash
    - JWT
    - access token
    - refresh token
    - session token
    - API key
    - secret
    - private key
    """

    # ------------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------------

    user_id: UUID

    username: str

    # ------------------------------------------------------------------------
    # Authorization
    # ------------------------------------------------------------------------

    roles: frozenset[str] = field(
        default_factory=frozenset,
    )

    permissions: frozenset[str] = field(
        default_factory=frozenset,
    )

    # ------------------------------------------------------------------------
    # Authentication Session
    # ------------------------------------------------------------------------

    session_id: UUID = field(
        default_factory=uuid4,
    )


# ============================================================================
# Authentication Session
# ============================================================================


@dataclass(frozen=True, slots=True)
class SessionRecord:
    """
    Server-side authentication session.

    The server-side session represents the authoritative authentication
    session associated with a user.

    ``token_id`` represents the internal JWT/JTI binding value.

    Security
    --------
    ``token_id`` is credential-related internal state.

    It MUST NEVER be exposed through:

    - API responses
    - frontend payloads
    - audit metadata
    - application logs
    - exception messages
    """

    # ------------------------------------------------------------------------
    # Session Identity
    # ------------------------------------------------------------------------

    session_id: UUID = field(
        default_factory=uuid4,
    )

    user_id: UUID = field(
        default_factory=uuid4,
    )

    # ------------------------------------------------------------------------
    # Internal Authentication Binding
    # ------------------------------------------------------------------------

    token_id: str = ""

    # ------------------------------------------------------------------------
    # Session Lifecycle
    # ------------------------------------------------------------------------

    created_at: datetime = field(
        default_factory=utcnow,
    )

    expires_at: datetime = field(
        default_factory=utcnow,
    )

    revoked_at: datetime | None = None

    # ------------------------------------------------------------------------
    # Request Context
    # ------------------------------------------------------------------------

    ip_address: str | None = None

    user_agent: str | None = None

    # ------------------------------------------------------------------------
    # Session State
    # ------------------------------------------------------------------------

    @property
    def is_active(self) -> bool:
        """
        Return whether the session is currently active.

        A session is active only when:

        1. It has not been revoked.
        2. Its expiration time has not passed.
        """
        return (
            self.revoked_at is None
            and utcnow() < self.expires_at
        )


# ============================================================================
# Authentication / Audit Domain Record
# ============================================================================


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """
    Domain-level SentinelSIEM audit event.

    This is NOT a database model.

    It represents an audit event generated by:

    - authentication
    - authorization
    - user management
    - session management
    - security operations

    before the event is persisted by the centralized audit subsystem.

    Canonical persistence
    ---------------------
    Audit persistence is owned by:

        app.audit

    Canonical persistence source:

        siem_auth_audit

    Security
    --------
    ``metadata`` must contain only sanitized, non-sensitive context.

    Never place the following into metadata:

    - plaintext passwords
    - password hashes
    - JWTs
    - access tokens
    - refresh tokens
    - session tokens
    - API keys
    - secrets
    - private keys
    - authorization headers
    - cookies
    """

    # ------------------------------------------------------------------------
    # Event Classification
    # ------------------------------------------------------------------------

    action: str

    outcome: str

    # ------------------------------------------------------------------------
    # Event Identity
    # ------------------------------------------------------------------------

    actor_user_id: UUID | None = None

    target_user_id: UUID | None = None

    # ------------------------------------------------------------------------
    # Correlation
    # ------------------------------------------------------------------------

    request_id: str | None = None

    session_id: UUID | None = None

    # ------------------------------------------------------------------------
    # Source
    # ------------------------------------------------------------------------

    source_ip: str | None = None

    # ------------------------------------------------------------------------
    # Sanitized Context
    # ------------------------------------------------------------------------

    metadata: dict[str, Any] = field(
        default_factory=dict,
    )

    # ------------------------------------------------------------------------
    # Timestamp
    # ------------------------------------------------------------------------

    timestamp: datetime = field(
        default_factory=utcnow,
    )


# ============================================================================
# Audit Action Constants
# ============================================================================


class AuditAction:
    """
    Canonical SentinelSIEM audit action names.

    Naming convention
    -----------------

    Authentication:

        authentication.*

    User management:

        users.*

    Authorization:

        authorization.*

    Role administration:

        role.*

    These values are part of the application audit contract.
    """

    # ========================================================================
    # Authentication
    # ========================================================================

    LOGIN_SUCCESS = (
        "authentication.login_success"
    )

    LOGIN_FAILURE = (
        "authentication.login_failure"
    )

    LOGOUT = (
        "authentication.logout"
    )

    # ========================================================================
    # Token Validation
    # ========================================================================

    TOKEN_VALIDATION_FAILURE = (
        "authentication.token_validation"
    )

    # ========================================================================
    # Session Lifecycle
    # ========================================================================

    SESSION_CREATED = (
        "authentication.session_created"
    )

    SESSION_REVOKED = (
        "authentication.session_revoked"
    )

    SESSIONS_REVOKED = (
        "authentication.sessions_revoked"
    )

    # ========================================================================
    # Password Lifecycle
    # ========================================================================

    PASSWORD_CHANGED = (
        "authentication.password_changed"
    )

    PASSWORD_CHANGE_FAILURE = (
        "authentication.password_change_failure"
    )

    PASSWORD_RESET = (
        "users.password_reset"
    )

    PASSWORD_RESET_FAILURE = (
        "authentication.password_reset_failure"
    )

    FORCE_PASSWORD_CHANGE = (
        "authentication.force_password_change"
    )

    # ========================================================================
    # User Lifecycle
    # ========================================================================

    USER_CREATED = (
        "users.created"
    )

    USER_UPDATED = (
        "users.updated"
    )

    USER_ENABLED = (
        "users.enabled"
    )

    USER_DISABLED = (
        "users.disabled"
    )

    USER_LOCKED = (
        "users.locked"
    )

    USER_UNLOCKED = (
        "users.unlocked"
    )

    USER_DELETED = (
        "users.deleted"
    )

    # ========================================================================
    # Role / Authorization Administration
    # ========================================================================

    ROLE_CHANGED = (
        "users.role_changed"
    )

    ROLE_CREATED = (
        "role.created"
    )

    ROLE_UPDATED = (
        "role.updated"
    )

    ROLE_DELETED = (
        "role.deleted"
    )

    PERMISSIONS_CHANGED = (
        "role.permissions_changed"
    )

    # ========================================================================
    # User Management Read / Investigation
    # ========================================================================

    USERS_LISTED = (
        "users.listed"
    )

    USER_VIEWED = (
        "users.viewed"
    )

    USER_STATISTICS_VIEWED = (
        "users.statistics_viewed"
    )

    # ========================================================================
    # Authorization
    # ========================================================================

    PERMISSION_DENIED = (
        "authorization.permission_denied"
    )

    AUTHORIZATION_DENIED = (
        "authorization.denied"
    )


# ============================================================================
# Audit Outcome Constants
# ============================================================================


class AuditOutcome:
    """
    Canonical SentinelSIEM audit outcomes.

    SUCCESS
        Operation completed successfully.

    FAILURE
        Operation failed.

    DENIED
        Operation was rejected by authorization or security policy.
    """

    SUCCESS = "success"

    FAILURE = "failure"

    DENIED = "denied"


# ============================================================================
# Public Exports
# ============================================================================


__all__ = [
    "AuditAction",
    "AuditOutcome",
    "AuditRecord",
    "SessionRecord",
    "UserIdentity",
    "UserPrincipal",
    "utcnow",
]