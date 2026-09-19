"""
SentinelSIEM User Management Service.

===============================================================================
RESPONSIBILITY
===============================================================================

Business and security service for administrative and self-service
user-management operations.

The service owns:

    - business validation
    - authorization boundary
    - account security invariants
    - password hashing orchestration
    - session-revocation orchestration
    - audit orchestration
    - pagination validation
    - last-active-ADMIN protection

The service does NOT own:

    - database transactions
    - database commits / rollbacks
    - direct SQL
    - ORM persistence details
    - direct audit-table access
    - password hashing implementation
    - API serialization

===============================================================================
AUDIT ARCHITECTURE
===============================================================================

UserManagementService
        |
        v
   AuditService
        |
        v
 AuditRepository
        |
        v
 siem_auth_audit

There is one canonical authentication/identity audit stream.

User Audit is a filtered view of the same canonical stream.

UserManagementService MUST NOT:

    - import AuthAuditRepository
    - query siem_auth_audit directly
    - create a second audit table
    - persist duplicate user-audit records
    - serialize ORM audit objects

===============================================================================
SECURITY INVARIANTS
===============================================================================

    - public signup is unsupported
    - usernames are normalized
    - emails are normalized
    - roles must exist in RoleRegistry
    - inactive actors cannot perform operations
    - locked actors cannot perform operations
    - non-admin users may operate only on themselves
    - ADMIN users may manage other users
    - self-delete is always forbidden
    - the last active ADMIN cannot be:
        * disabled
        * demoted
        * deleted
    - disabling a user revokes active sessions
    - locking a user revokes active sessions
    - forcing password change revokes active sessions
    - password changes revoke active sessions
    - role changes revoke active sessions
    - audit metadata cannot contain credential material

===============================================================================
PASSWORD SECURITY
===============================================================================

Plaintext passwords may enter this service only as transient input to
PasswordHasher.

Plaintext passwords MUST NOT:

    - reach repositories
    - enter audit metadata
    - enter logs
    - enter exceptions
    - enter response objects

Repositories receive password hashes only.

===============================================================================
TRANSACTION POLICY
===============================================================================

This service never commits or rolls back.

The application/request transaction owns:

    BEGIN
        service operations
    COMMIT / ROLLBACK

Repository implementations may flush but must not commit independently.

===============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from app.audit.models import AuditEvent
from app.audit.schemas import AuditCreate
from app.audit.service import AuditService
from app.auth.models import AuditAction, AuditOutcome, UserIdentity
from app.auth.password import PasswordHashError, PasswordHasher
from app.auth.repositories import (
    AuthenticationRepositoryError,
    SessionRepository,
    UserRepository,
    UserRepositoryError,
)
from app.auth.roles import Role, RoleRegistry


# =============================================================================
# Constants
# =============================================================================

DEFAULT_USER_LIST_LIMIT = 50
DEFAULT_USER_LIST_OFFSET = 0

DEFAULT_AUDIT_PAGE = 1
DEFAULT_AUDIT_PAGE_SIZE = 50

MAX_PAGE_SIZE = 200

MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 100

MIN_EMAIL_LENGTH = 3
MAX_EMAIL_LENGTH = 320

MIN_DISPLAY_NAME_LENGTH = 1
MAX_DISPLAY_NAME_LENGTH = 200


# =============================================================================
# Errors
# =============================================================================


class UserManagementError(RuntimeError):
    """Base exception for user-management failures."""


class UserManagementValidationError(UserManagementError):
    """Raised when user-management input is invalid."""


class UserNotFoundError(UserManagementError):
    """Raised when a requested user does not exist."""


class UserAlreadyExistsError(UserManagementError):
    """Raised when username or email already exists."""


class InvalidRoleError(UserManagementError):
    """Raised when an unsupported role is requested."""


class SelfServiceDeniedError(UserManagementError):
    """Raised when the caller is outside the allowed target scope."""


class LastAdminProtectionError(UserManagementError):
    """Raised when an operation would remove the last active ADMIN."""


# =============================================================================
# DTOs
# =============================================================================


@dataclass(frozen=True, slots=True)
class UserListResult:
    """
    Paginated administrative user listing.

    total:
        Total number of users matching the supplied filters.

    users:
        Current page of users.

    limit:
        Requested page size.

    offset:
        Number of records skipped.
    """

    users: tuple[UserIdentity, ...]
    total: int
    limit: int
    offset: int


@dataclass(frozen=True, slots=True)
class UserStatistics:
    """Administrative user statistics."""

    total: int
    active: int
    disabled: int
    locked: int


@dataclass(frozen=True, slots=True)
class UserAuditHistoryResult:
    """
    Paginated user audit history.

    Audit events originate from the canonical authentication audit stream
    through AuditService.
    """

    events: tuple[AuditEvent, ...]
    total: int
    page: int
    page_size: int


# =============================================================================
# Service
# =============================================================================


class UserManagementService:
    """
    SentinelSIEM User Management business/security service.
    """

    MAX_PAGE_SIZE = MAX_PAGE_SIZE

    # -------------------------------------------------------------------------
    # Informational audit actions
    # -------------------------------------------------------------------------

    _INFORMATIONAL_AUDIT_ACTIONS = frozenset(
        {
            AuditAction.USERS_LISTED,
            AuditAction.USER_VIEWED,
            AuditAction.USER_STATISTICS_VIEWED,
        }
    )

    # -------------------------------------------------------------------------
    # Canonical user-management actions
    # -------------------------------------------------------------------------

    _CANONICAL_USER_AUDIT_ACTIONS = frozenset(
        {
            AuditAction.USER_CREATED,
            AuditAction.USER_UPDATED,
            AuditAction.USER_ENABLED,
            AuditAction.USER_DISABLED,
            AuditAction.USER_LOCKED,
            AuditAction.USER_UNLOCKED,
            AuditAction.USER_DELETED,
            AuditAction.ROLE_CHANGED,
            AuditAction.PASSWORD_RESET,
            AuditAction.SESSIONS_REVOKED,
            AuditAction.FORCE_PASSWORD_CHANGE,
        }
    )

    # -------------------------------------------------------------------------
    # Audit metadata forbidden keys
    # -------------------------------------------------------------------------

    _FORBIDDEN_AUDIT_KEYS = frozenset(
        {
            "password",
            "password_hash",
            "new_password",
            "current_password",
            "old_password",
            "plaintext_password",
            "passwd",
            "pass",
            "token",
            "access_token",
            "refresh_token",
            "session_token",
            "jwt",
            "jwt_token",
            "jti",
            "token_id",
            "api_key",
            "apikey",
            "secret",
            "client_secret",
            "private_key",
            "authorization",
            "cookie",
            "set_cookie",
            "credentials",
            "credential",
        }
    )

    # =========================================================================
    # Initialization
    # =========================================================================

    def __init__(
        self,
        *,
        users: UserRepository,
        sessions: SessionRepository,
        audit: AuditService,
        password_hasher: PasswordHasher,
        roles: RoleRegistry | None = None,
    ) -> None:
        if users is None:
            raise ValueError("UserRepository is required.")

        if sessions is None:
            raise ValueError("SessionRepository is required.")

        if audit is None:
            raise ValueError("AuditService is required.")

        if password_hasher is None:
            raise ValueError("PasswordHasher is required.")

        self._users = users
        self._sessions = sessions
        self._audit = audit
        self._passwords = password_hasher
        self._roles = roles or RoleRegistry()

    # =========================================================================
    # Authorization
    # =========================================================================

    async def _require_actor(
        self,
        actor_user_id: UUID,
    ) -> UserIdentity:
        """
        Resolve and validate the current actor.

        Unknown, inactive, or locked users are denied.
        """

        self._validate_uuid(
            actor_user_id,
            field_name="actor_user_id",
        )

        try:
            actor = await self._users.get_by_id(actor_user_id)
        except UserRepositoryError as exc:
            raise UserManagementError(
                "Unable to retrieve actor."
            ) from exc

        if actor is None:
            raise SelfServiceDeniedError(
                "Actor is not authorized."
            )

        if not actor.is_active:
            raise SelfServiceDeniedError(
                "Actor is not authorized."
            )

        if actor.is_locked:
            raise SelfServiceDeniedError(
                "Actor is not authorized."
            )

        return actor

    @staticmethod
    def _is_admin(
        user: UserIdentity,
    ) -> bool:
        """Return True when the user has the ADMIN role."""

        return Role.ADMIN.value in user.roles

    async def _require_admin(
        self,
        actor_user_id: UUID,
    ) -> UserIdentity:
        """Require an active and unlocked ADMIN actor."""

        actor = await self._require_actor(actor_user_id)

        if not self._is_admin(actor):
            raise SelfServiceDeniedError(
                "Administrator privileges are required."
            )

        return actor

    async def _require_self_or_admin(
        self,
        *,
        actor_user_id: UUID,
        target_user_id: UUID,
    ) -> tuple[UserIdentity, UserIdentity]:
        """
        ADMIN:
            any target

        NON-ADMIN:
            own target only
        """

        actor = await self._require_actor(actor_user_id)
        target = await self._require_user(target_user_id)

        if self._is_admin(actor):
            return actor, target

        if actor.user_id != target.user_id:
            raise SelfServiceDeniedError(
                "You are not authorized to access or modify another user's account."
            )

        return actor, target

    async def _require_admin_target(
        self,
        *,
        actor_user_id: UUID,
        target_user_id: UUID,
    ) -> tuple[UserIdentity, UserIdentity]:
        """Require ADMIN actor and resolve target."""

        actor = await self._require_admin(actor_user_id)
        target = await self._require_user(target_user_id)

        return actor, target

    # =========================================================================
    # User Listing
    # =========================================================================

    async def list_users(
        self,
        *,
        actor_user_id: UUID,
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
        request_id: str | None = None,
        source_ip: str | None = None,
    ) -> UserListResult:
        """
        List users with complete repository-contract filtering.

        ADMIN only.
        """

        actor = await self._require_admin(actor_user_id)

        self._validate_page(
            limit=limit,
            offset=offset,
        )

        self._validate_optional_bool(
            is_active,
            field_name="is_active",
        )

        self._validate_optional_bool(
            is_locked,
            field_name="is_locked",
        )

        self._validate_optional_bool(
            force_password_change,
            field_name="force_password_change",
        )

        normalized_search = self._normalize_search(search)

        normalized_role = None

        if role is not None:
            normalized_role = self._normalize_role(role)
            self._validate_role(normalized_role)

        normalized_created_from = self._normalize_timestamp(
            created_from,
            field_name="created_from",
        )

        normalized_created_to = self._normalize_timestamp(
            created_to,
            field_name="created_to",
        )

        normalized_last_login_from = self._normalize_timestamp(
            last_login_from,
            field_name="last_login_from",
        )

        normalized_last_login_to = self._normalize_timestamp(
            last_login_to,
            field_name="last_login_to",
        )

        self._validate_date_range(
            date_from=normalized_created_from,
            date_to=normalized_created_to,
            from_field="created_from",
            to_field="created_to",
        )

        self._validate_date_range(
            date_from=normalized_last_login_from,
            date_to=normalized_last_login_to,
            from_field="last_login_from",
            to_field="last_login_to",
        )

        try:
            users = await self._users.list_users(
                search=normalized_search,
                role=normalized_role,
                is_active=is_active,
                is_locked=is_locked,
                force_password_change=force_password_change,
                created_from=normalized_created_from,
                created_to=normalized_created_to,
                last_login_from=normalized_last_login_from,
                last_login_to=normalized_last_login_to,
                limit=limit,
                offset=offset,
            )

            total = await self._users.count_users(
                search=normalized_search,
                role=normalized_role,
                is_active=is_active,
                is_locked=is_locked,
                force_password_change=force_password_change,
                created_from=normalized_created_from,
                created_to=normalized_created_to,
                last_login_from=normalized_last_login_from,
                last_login_to=normalized_last_login_to,
            )

        except UserRepositoryError as exc:
            raise UserManagementError(
                "Unable to list users."
            ) from exc

        await self._audit_event(
            action=AuditAction.USERS_LISTED,
            actor_user_id=actor.user_id,
            request_id=request_id,
            source_ip=source_ip,
            metadata={
                "search": bool(normalized_search),
                "role": normalized_role,
                "is_active": is_active,
                "is_locked": is_locked,
                "created_from": normalized_created_from.isoformat()
                if normalized_created_from
                else None,
                "created_to": normalized_created_to.isoformat()
                if normalized_created_to
                else None,
                "last_login_from": normalized_last_login_from.isoformat()
                if normalized_last_login_from
                else None,
                "last_login_to": normalized_last_login_to.isoformat()
                if normalized_last_login_to
                else None,
                "limit": limit,
                "offset": offset,
                "count": len(users),
                "total": total,
            },
            canonical=False,
        )

        return UserListResult(
            users=tuple(users),
            total=total,
            limit=limit,
            offset=offset,
        )

    # =========================================================================
    # User Details
    # =========================================================================

    async def get_user(
        self,
        *,
        actor_user_id: UUID,
        user_id: UUID,
        request_id: str | None = None,
        source_ip: str | None = None,
    ) -> UserIdentity:
        """
        Retrieve user details.

        ADMIN:
            any user

        NON-ADMIN:
            own profile only
        """

        actor, target = await self._require_self_or_admin(
            actor_user_id=actor_user_id,
            target_user_id=user_id,
        )

        await self._audit_event(
            action=AuditAction.USER_VIEWED,
            actor_user_id=actor.user_id,
            target_user_id=target.user_id,
            request_id=request_id,
            source_ip=source_ip,
            metadata={},
            canonical=False,
        )

        return target

    # =========================================================================
    # Statistics
    # =========================================================================

    async def statistics(
        self,
        *,
        actor_user_id: UUID,
        request_id: str | None = None,
        source_ip: str | None = None,
    ) -> UserStatistics:
        """Return administrative user statistics."""

        actor = await self._require_admin(actor_user_id)

        try:
            total = await self._users.count_users()

            active = await self._users.count_users(
                is_active=True,
            )

            disabled = await self._users.count_users(
                is_active=False,
            )

            locked = await self._users.count_users(
                is_locked=True,
            )

        except UserRepositoryError as exc:
            raise UserManagementError(
                "Unable to retrieve user statistics."
            ) from exc

        result = UserStatistics(
            total=total,
            active=active,
            disabled=disabled,
            locked=locked,
        )

        await self._audit_event(
            action=AuditAction.USER_STATISTICS_VIEWED,
            actor_user_id=actor.user_id,
            request_id=request_id,
            source_ip=source_ip,
            metadata={
                "total": total,
                "active": active,
                "disabled": disabled,
                "locked": locked,
            },
            canonical=False,
        )

        return result

    # =========================================================================
    # User Audit History
    # =========================================================================

    async def get_user_audit_history(
        self,
        *,
        actor_user_id: UUID,
        user_id: UUID,
        page: int = DEFAULT_AUDIT_PAGE,
        page_size: int = DEFAULT_AUDIT_PAGE_SIZE,
        action: str | None = None,
        outcome: str | None = None,
        category: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        search: str | None = None,
        request_id: str | None = None,
        source_ip: str | None = None,
    ) -> UserAuditHistoryResult:
        """
        Retrieve user-related audit history through AuditService.

        The current audit-view event is written AFTER retrieval so that the
        current request does not recursively appear in its own result.
        """

        actor, target = await self._require_self_or_admin(
            actor_user_id=actor_user_id,
            target_user_id=user_id,
        )

        self._validate_audit_page(
            page=page,
            page_size=page_size,
        )

        normalized_action = self._normalize_optional_text(action)
        normalized_outcome = self._normalize_outcome(outcome)
        normalized_category = self._normalize_optional_text(category)
        normalized_search = self._normalize_optional_text(search)

        normalized_date_from = self._normalize_timestamp(
            date_from,
            field_name="date_from",
        )

        normalized_date_to = self._normalize_timestamp(
            date_to,
            field_name="date_to",
        )

        self._validate_date_range(
            date_from=normalized_date_from,
            date_to=normalized_date_to,
            from_field="date_from",
            to_field="date_to",
        )

        try:
            events, total = await self._audit.list_user_activity(
                user_id=target.user_id,
                page=page,
                page_size=page_size,
                action=normalized_action,
                result=normalized_outcome,
                category=normalized_category,
                date_from=normalized_date_from,
                date_to=normalized_date_to,
                search=normalized_search,
            )
        except Exception as exc:
            raise UserManagementError(
                "Unable to retrieve user audit history."
            ) from exc

        await self._audit_event(
            action=AuditAction.USER_VIEWED,
            actor_user_id=actor.user_id,
            target_user_id=target.user_id,
            request_id=request_id,
            source_ip=source_ip,
            metadata={
                "view": "audit_history",
                "page": page,
                "page_size": page_size,
                "returned": len(events),
            },
            canonical=False,
        )

        return UserAuditHistoryResult(
            events=tuple(events),
            total=total,
            page=page,
            page_size=page_size,
        )

    # =========================================================================
    # Create User
    # =========================================================================

    async def create_user(
        self,
        *,
        actor_user_id: UUID,
        username: str,
        email: str,
        password: str,
        role: str,
        is_active: bool = True,
        display_name: str | None = None,
        request_id: str | None = None,
        source_ip: str | None = None,
    ) -> UserIdentity:
        """
        Create an administrator-provisioned user.

        Public signup is not supported.
        """

        actor = await self._require_admin(actor_user_id)

        normalized_username = self._normalize_username(username)
        normalized_email = self._normalize_email(email)
        normalized_role = self._normalize_role(role)

        self._validate_username(normalized_username)
        self._validate_email(normalized_email)
        self._validate_role(normalized_role)

        if not isinstance(is_active, bool):
            raise UserManagementValidationError(
                "is_active must be a boolean."
            )

        normalized_display_name = None

        if display_name is not None:
            normalized_display_name = self._normalize_display_name(
                display_name
            )

            self._validate_display_name(
                normalized_display_name
            )

        await self._ensure_unique_login(
            username=normalized_username,
            email=normalized_email,
        )

        try:
            password_hash = self._passwords.hash(password)
        except (
            PasswordHashError,
            TypeError,
            ValueError,
        ) as exc:
            raise UserManagementValidationError(
                "Password does not satisfy the required security policy."
            ) from exc

        user = UserIdentity(
            user_id=uuid4(),
            username=normalized_username,
            email=normalized_email,
            password_hash=password_hash,
            roles=frozenset(),
            is_active=is_active,
            is_locked=False,
            failed_login_count=0,
            display_name=normalized_display_name,
            force_password_change=False,
            password_changed_at=None,
            last_login_at=None,
        )

        try:
            created = await self._users.create_user(
                user,
                role=normalized_role,
            )
        except UserRepositoryError as exc:
            self._raise_repository_error(
                exc,
                operation="create user",
                duplicate_error=True,
            )

        await self._audit_event(
            action=AuditAction.USER_CREATED,
            actor_user_id=actor.user_id,
            target_user_id=created.user_id,
            request_id=request_id,
            source_ip=source_ip,
            metadata={
                "username": created.username,
                "role": normalized_role,
                "is_active": created.is_active,
            },
        )

        return created

    # =========================================================================
    # Profile Update
    # =========================================================================

    async def update_profile(
        self,
        *,
        actor_user_id: UUID,
        user_id: UUID,
        username: str,
        email: str,
        display_name: str | None = None,
        request_id: str | None = None,
        source_ip: str | None = None,
    ) -> UserIdentity:
        """
        Update editable profile fields.

        Security state is preserved.
        """

        actor, existing = await self._require_self_or_admin(
            actor_user_id=actor_user_id,
            target_user_id=user_id,
        )

        normalized_username = self._normalize_username(username)
        normalized_email = self._normalize_email(email)

        self._validate_username(normalized_username)
        self._validate_email(normalized_email)

        if normalized_username != existing.username:
            await self._ensure_unique_username(
                username=normalized_username,
                exclude_user_id=user_id,
            )

        if normalized_email != existing.email:
            await self._ensure_unique_email(
                email=normalized_email,
                exclude_user_id=user_id,
            )

        if display_name is None:
            effective_display_name = existing.display_name
        else:
            effective_display_name = self._normalize_display_name(
                display_name
            )
            self._validate_display_name(
                effective_display_name
            )

        updated_user = self._copy_user(
            existing,
            username=normalized_username,
            email=normalized_email,
            display_name=effective_display_name,
        )

        try:
            result = await self._users.update_user(
                updated_user
            )
        except UserRepositoryError as exc:
            self._raise_repository_error(
                exc,
                operation="update user profile",
                duplicate_error=True,
            )

        if result is None:
            raise UserNotFoundError(
                "User does not exist."
            )

        changed_fields: list[str] = []

        if existing.username != result.username:
            changed_fields.append("username")

        if existing.email != result.email:
            changed_fields.append("email")

        if existing.display_name != result.display_name:
            changed_fields.append("display_name")

        await self._audit_event(
            action=AuditAction.USER_UPDATED,
            actor_user_id=actor.user_id,
            target_user_id=result.user_id,
            request_id=request_id,
            source_ip=source_ip,
            metadata={
                "changed_fields": changed_fields,
            },
        )

        return result

    # =========================================================================
    # Role Management
    # =========================================================================

    async def change_role(
        self,
        *,
        actor_user_id: UUID,
        user_id: UUID,
        role: str,
        request_id: str | None = None,
        source_ip: str | None = None,
    ) -> UserIdentity:
        """Replace target user's role. ADMIN only."""

        actor, target = await self._require_admin_target(
            actor_user_id=actor_user_id,
            target_user_id=user_id,
        )

        normalized_role = self._normalize_role(role)
        self._validate_role(normalized_role)

        current_roles = tuple(sorted(target.roles))

        if current_roles == (normalized_role,):
            return target

        if (
            self._is_admin(target)
            and normalized_role != Role.ADMIN.value
            and target.is_active
        ):
            await self._protect_last_admin(
                target_user_id=target.user_id,
            )

        try:
            updated = await self._users.set_role(
                user_id,
                normalized_role,
            )
        except UserRepositoryError as exc:
            raise UserManagementError(
                "Unable to change user role."
            ) from exc

        if updated is None:
            raise UserNotFoundError(
                "User does not exist."
            )

        revoked_sessions = await self._revoke_sessions_safely(
            user_id,
            failure_message=(
                "User role was changed, but active sessions could not "
                "be revoked safely."
            ),
        )

        await self._audit_event(
            action=AuditAction.ROLE_CHANGED,
            actor_user_id=actor.user_id,
            target_user_id=target.user_id,
            request_id=request_id,
            source_ip=source_ip,
            metadata={
                "previous_roles": list(current_roles),
                "new_role": normalized_role,
                "sessions_revoked": revoked_sessions,
            },
        )

        return updated

    # =========================================================================
    # Active State
    # =========================================================================

    async def set_active(
        self,
        *,
        actor_user_id: UUID,
        user_id: UUID,
        is_active: bool,
        request_id: str | None = None,
        source_ip: str | None = None,
    ) -> UserIdentity:
        """Enable or disable a user."""

        if not isinstance(is_active, bool):
            raise UserManagementValidationError(
                "is_active must be a boolean."
            )

        actor, target = await self._require_admin_target(
            actor_user_id=actor_user_id,
            target_user_id=user_id,
        )

        if target.is_active == is_active:
            return target

        if not is_active and self._is_admin(target):
            await self._protect_last_admin(
                target_user_id=target.user_id,
            )

        try:
            updated = await self._users.set_active(
                user_id,
                is_active,
            )
        except UserRepositoryError as exc:
            raise UserManagementError(
                "Unable to update user active state."
            ) from exc

        if updated is None:
            raise UserNotFoundError(
                "User does not exist."
            )

        revoked_sessions = 0

        if not is_active:
            revoked_sessions = await self._revoke_sessions_safely(
                user_id,
                failure_message=(
                    "User was disabled, but active sessions could not "
                    "be revoked safely."
                ),
            )

        action = (
            AuditAction.USER_ENABLED
            if is_active
            else AuditAction.USER_DISABLED
        )

        await self._audit_event(
            action=action,
            actor_user_id=actor.user_id,
            target_user_id=target.user_id,
            request_id=request_id,
            source_ip=source_ip,
            metadata={
                "is_active": is_active,
                "sessions_revoked": revoked_sessions,
            },
        )

        return updated

    # =========================================================================
    # Lock State
    # =========================================================================

    async def set_locked(
        self,
        *,
        actor_user_id: UUID,
        user_id: UUID,
        is_locked: bool,
        request_id: str | None = None,
        source_ip: str | None = None,
    ) -> UserIdentity:
        """Lock or unlock a user."""

        if not isinstance(is_locked, bool):
            raise UserManagementValidationError(
                "is_locked must be a boolean."
            )

        actor, target = await self._require_admin_target(
            actor_user_id=actor_user_id,
            target_user_id=user_id,
        )

        if target.is_locked == is_locked:
            return target

        try:
            updated = await self._users.set_locked(
                user_id,
                is_locked,
            )
        except UserRepositoryError as exc:
            raise UserManagementError(
                "Unable to update user lock state."
            ) from exc

        if updated is None:
            raise UserNotFoundError(
                "User does not exist."
            )

        revoked_sessions = 0

        if is_locked:
            revoked_sessions = await self._revoke_sessions_safely(
                user_id,
                failure_message=(
                    "User was locked, but active sessions could not "
                    "be revoked safely."
                ),
            )

        action = (
            AuditAction.USER_LOCKED
            if is_locked
            else AuditAction.USER_UNLOCKED
        )

        await self._audit_event(
            action=action,
            actor_user_id=actor.user_id,
            target_user_id=target.user_id,
            request_id=request_id,
            source_ip=source_ip,
            metadata={
                "is_locked": is_locked,
                "sessions_revoked": revoked_sessions,
            },
        )

        return updated

    # =========================================================================
    # Force Password Change
    # =========================================================================

    async def set_force_password_change(
        self,
        *,
        actor_user_id: UUID,
        user_id: UUID,
        force_password_change: bool,
        request_id: str | None = None,
        source_ip: str | None = None,
    ) -> UserIdentity:
        """Set or clear forced-password-change state."""

        if not isinstance(force_password_change, bool):
            raise UserManagementValidationError(
                "force_password_change must be a boolean."
            )

        actor, target = await self._require_admin_target(
            actor_user_id=actor_user_id,
            target_user_id=user_id,
        )

        if target.force_password_change == force_password_change:
            return target

        try:
            updated = await self._users.set_force_password_change(
                user_id,
                force_password_change,
            )
        except UserRepositoryError as exc:
            raise UserManagementError(
                "Unable to update force-password-change state."
            ) from exc

        if updated is None:
            raise UserNotFoundError(
                "User does not exist."
            )

        revoked_sessions = 0

        if force_password_change:
            revoked_sessions = await self._revoke_sessions_safely(
                user_id,
                failure_message=(
                    "Force-password-change state was updated, but "
                    "active sessions could not be revoked safely."
                ),
            )

        await self._audit_event(
            action=AuditAction.FORCE_PASSWORD_CHANGE,
            actor_user_id=actor.user_id,
            target_user_id=target.user_id,
            request_id=request_id,
            source_ip=source_ip,
            metadata={
                "force_password_change": force_password_change,
                "sessions_revoked": revoked_sessions,
            },
        )

        return updated

    # =========================================================================
    # Password Reset / Change
    # =========================================================================

    async def reset_password(
        self,
        *,
        actor_user_id: UUID,
        user_id: UUID,
        new_password: str,
        request_id: str | None = None,
        source_ip: str | None = None,
    ) -> int:
        """
        Reset/change a user's password.

        ADMIN:
            may change another user's password.

        NON-ADMIN:
            may change only own password.

        Every successful password change revokes active sessions.
        """

        actor, target = await self._require_self_or_admin(
            actor_user_id=actor_user_id,
            target_user_id=user_id,
        )

        try:
            password_hash = self._passwords.hash(
                new_password
            )
        except (
            PasswordHashError,
            TypeError,
            ValueError,
        ) as exc:
            raise UserManagementValidationError(
                "Password does not satisfy the required security policy."
            ) from exc

        try:
            changed = await self._users.reset_password(
                user_id,
                password_hash,
            )
        except UserRepositoryError as exc:
            raise UserManagementError(
                "Unable to reset user password."
            ) from exc

        if not changed:
            raise UserNotFoundError(
                "User does not exist."
            )

        revoked_sessions = await self._revoke_sessions_safely(
            user_id,
            failure_message=(
                "Password was changed, but active sessions could not "
                "be revoked safely."
            ),
        )

        await self._audit_event(
            action=AuditAction.PASSWORD_RESET,
            actor_user_id=actor.user_id,
            target_user_id=target.user_id,
            request_id=request_id,
            source_ip=source_ip,
            metadata={
                "sessions_revoked": revoked_sessions,
            },
        )

        return revoked_sessions

    # =========================================================================
    # Session Management
    # =========================================================================

    async def revoke_sessions(
        self,
        *,
        actor_user_id: UUID,
        user_id: UUID,
        request_id: str | None = None,
        source_ip: str | None = None,
    ) -> int:
        """
        Revoke all active sessions for a user.

        ADMIN:
            any user

        NON-ADMIN:
            own sessions only
        """

        actor, target = await self._require_self_or_admin(
            actor_user_id=actor_user_id,
            target_user_id=user_id,
        )

        count = await self._revoke_sessions_safely(
            target.user_id,
            failure_message="Unable to revoke user sessions.",
        )

        await self._audit_event(
            action=AuditAction.SESSIONS_REVOKED,
            actor_user_id=actor.user_id,
            target_user_id=target.user_id,
            request_id=request_id,
            source_ip=source_ip,
            metadata={
                "count": count,
            },
        )

        return count

    # =========================================================================
    # Delete User
    # =========================================================================

    async def delete_user(
        self,
        *,
        actor_user_id: UUID,
        user_id: UUID,
        request_id: str | None = None,
        source_ip: str | None = None,
    ) -> None:
        self._validate_uuid(
            actor_user_id,
            field_name="actor_user_id",
        )
        self._validate_uuid(
            user_id,
            field_name="user_id",
        )

        if actor_user_id == user_id:
            raise SelfServiceDeniedError(
                "Users cannot delete their own account."
            )

        actor = await self._require_admin(actor_user_id)
        target = await self._require_user(user_id)

        if target.is_active and self._is_admin(target):
            await self._protect_last_admin(
                target_user_id=target.user_id,
            )

        revoked_sessions = await self._revoke_sessions_safely(
            user_id,
            failure_message=(
                "User could not be deleted because active sessions "
                "could not be revoked safely."
            ),
        )

        target_username = target.username
        target_roles = tuple(sorted(target.roles))

        # Persist the deletion audit event BEFORE deleting the target user.
        #
        # The audit table references siem_users.target_user_id with
        # ON DELETE SET NULL. Therefore the target UUID must still exist
        # when this audit event is inserted. Once the user is deleted,
        # PostgreSQL will automatically NULL the target_user_id while
        # preserving the historical audit event.
        await self._audit_event(
            action=AuditAction.USER_DELETED,
            actor_user_id=actor.user_id,
            target_user_id=user_id,
            request_id=request_id,
            source_ip=source_ip,
            metadata={
                "username": target_username,
                "roles": list(target_roles),
                "sessions_revoked": revoked_sessions,
            },
        )

        try:
            deleted = await self._users.delete_user(user_id)
        except UserRepositoryError as exc:
            raise UserManagementError(
                "Unable to delete user."
            ) from exc

        if not deleted:
            raise UserNotFoundError(
                "User does not exist."
            )

    async def _require_user(
        self,
        user_id: UUID,
    ) -> UserIdentity:
        """Resolve user or raise UserNotFoundError."""

        self._validate_uuid(
            user_id,
            field_name="user_id",
        )

        try:
            user = await self._users.get_by_id(user_id)
        except UserRepositoryError as exc:
            raise UserManagementError(
                "Unable to retrieve user."
            ) from exc

        if user is None:
            raise UserNotFoundError(
                "User does not exist."
            )

        return user

    async def _ensure_unique_login(
        self,
        *,
        username: str,
        email: str,
        exclude_user_id: UUID | None = None,
    ) -> None:
        """
        Check username and email uniqueness.

        Database uniqueness constraints remain authoritative for races.
        """

        await self._ensure_unique_username(
            username=username,
            exclude_user_id=exclude_user_id,
        )

        await self._ensure_unique_email(
            email=email,
            exclude_user_id=exclude_user_id,
        )

    async def _ensure_unique_username(
        self,
        *,
        username: str,
        exclude_user_id: UUID | None = None,
    ) -> None:
        """Check username uniqueness."""

        try:
            existing = await self._users.get_by_login(username)
        except UserRepositoryError as exc:
            raise UserManagementError(
                "Unable to verify username uniqueness."
            ) from exc

        if existing is not None and existing.user_id != exclude_user_id:
            raise UserAlreadyExistsError(
                "Username is already registered."
            )

    async def _ensure_unique_email(
        self,
        *,
        email: str,
        exclude_user_id: UUID | None = None,
    ) -> None:
        """Check email uniqueness."""

        try:
            existing = await self._users.get_by_login(email)
        except UserRepositoryError as exc:
            raise UserManagementError(
                "Unable to verify email uniqueness."
            ) from exc

        if existing is not None and existing.user_id != exclude_user_id:
            raise UserAlreadyExistsError(
                "Email is already registered."
            )

    # =========================================================================
    # Last Active ADMIN Protection
    # =========================================================================

    async def _protect_last_admin(
        self,
        *,
        target_user_id: UUID,
    ) -> None:
        """
        Prevent disabling, deleting, or demoting the last active ADMIN.

        Because the repository contract does not expose an atomic
        count-active-admin operation, this service uses paginated scanning.

        Database-level constraints should additionally protect this invariant
        if strict concurrent-operation guarantees are required.
        """

        self._validate_uuid(
            target_user_id,
            field_name="target_user_id",
        )

        offset = 0
        active_admin_count = 0
        target_is_active_admin = False

        while True:
            try:
                users = await self._users.list_users(
                    is_active=True,
                    limit=self.MAX_PAGE_SIZE,
                    offset=offset,
                )
            except UserRepositoryError as exc:
                raise UserManagementError(
                    "Unable to verify active administrator protection."
                ) from exc

            if not users:
                break

            for user in users:
                if not self._is_admin(user):
                    continue

                active_admin_count += 1

                if user.user_id == target_user_id:
                    target_is_active_admin = True

            if len(users) < self.MAX_PAGE_SIZE:
                break

            offset += len(users)

        if target_is_active_admin and active_admin_count <= 1:
            raise LastAdminProtectionError(
                "The last active ADMIN account cannot be disabled, "
                "deleted, or demoted."
            )

    # =========================================================================
    # Session Safety
    # =========================================================================

    async def _revoke_sessions_safely(
        self,
        user_id: UUID,
        *,
        failure_message: str,
    ) -> int:
        """
        Revoke all active sessions.

        Security-sensitive callers fail closed if revocation fails.
        """

        self._validate_uuid(
            user_id,
            field_name="user_id",
        )

        try:
            return await self._sessions.revoke_user_sessions(
                user_id
            )
        except AuthenticationRepositoryError as exc:
            raise UserManagementError(
                failure_message
            ) from exc

    # =========================================================================
    # User Copy Helper
    # =========================================================================

    @staticmethod
    def _copy_user(
        user: UserIdentity,
        *,
        username: str | None = None,
        email: str | None = None,
        display_name: str | None = None,
    ) -> UserIdentity:
        """
        Create a UserIdentity while preserving all security state.

        This helper intentionally does not change:

            password_hash
            roles
            is_active
            is_locked
            failed_login_count
            force_password_change
            password_changed_at
            last_login_at
        """

        return UserIdentity(
            user_id=user.user_id,
            username=user.username if username is None else username,
            email=user.email if email is None else email,
            password_hash=user.password_hash,
            roles=user.roles,
            is_active=user.is_active,
            is_locked=user.is_locked,
            failed_login_count=user.failed_login_count,
            display_name=(
                user.display_name
                if display_name is None
                else display_name
            ),
            force_password_change=user.force_password_change,
            password_changed_at=user.password_changed_at,
            last_login_at=user.last_login_at,
            created_at=user.created_at,
            updated_at=user.updated_at,
        )

    # =========================================================================
    # Validation
    # =========================================================================

    @staticmethod
    def _validate_uuid(
        value: UUID,
        *,
        field_name: str,
    ) -> None:
        """Validate UUID."""

        if not isinstance(value, UUID):
            raise UserManagementValidationError(
                f"{field_name} must be a UUID."
            )

    @staticmethod
    def _validate_optional_bool(
        value: bool | None,
        *,
        field_name: str,
    ) -> None:
        """Validate optional boolean."""

        if value is not None and not isinstance(value, bool):
            raise UserManagementValidationError(
                f"{field_name} must be a boolean."
            )

    @staticmethod
    def _normalize_username(
        username: str,
    ) -> str:
        """Normalize username."""

        if not isinstance(username, str):
            raise UserManagementValidationError(
                "Username must be a string."
            )

        return username.strip().lower()

    @staticmethod
    def _normalize_email(
        email: str,
    ) -> str:
        """Normalize email."""

        if not isinstance(email, str):
            raise UserManagementValidationError(
                "Email must be a string."
            )

        return email.strip().lower()

    @staticmethod
    def _normalize_display_name(
        display_name: str,
    ) -> str:
        """Normalize display name."""

        if not isinstance(display_name, str):
            raise UserManagementValidationError(
                "Display name must be a string."
            )

        return display_name.strip()

    @staticmethod
    def _normalize_search(
        search: str | None,
    ) -> str | None:
        """Normalize user search text."""

        if search is None:
            return None

        if not isinstance(search, str):
            raise UserManagementValidationError(
                "Search must be a string."
            )

        normalized = search.strip().lower()

        return normalized or None

    @staticmethod
    def _normalize_optional_text(
        value: str | None,
    ) -> str | None:
        """Normalize optional text."""

        if value is None:
            return None

        if not isinstance(value, str):
            raise UserManagementValidationError(
                "Filter value must be a string."
            )

        normalized = value.strip()

        return normalized or None

    @staticmethod
    def _normalize_role(
        role: str,
    ) -> str:
        """Normalize role to canonical uppercase representation."""

        if not isinstance(role, str):
            raise InvalidRoleError(
                "Role must be a string."
            )

        normalized = role.strip().upper()

        if not normalized:
            raise InvalidRoleError(
                "Role cannot be empty."
            )

        return normalized

    def _validate_role(
        self,
        role: str,
    ) -> None:
        """Validate role against RoleRegistry."""

        try:
            role_enum = Role(role)
        except ValueError as exc:
            raise InvalidRoleError(
                f"Unsupported role: {role}."
            ) from exc

        if self._roles.get(role_enum) is None:
            raise InvalidRoleError(
                f"Unsupported role: {role}."
            )

    @staticmethod
    def _validate_username(
        username: str,
    ) -> None:
        """Validate username length."""

        if not (
            MIN_USERNAME_LENGTH
            <= len(username)
            <= MAX_USERNAME_LENGTH
        ):
            raise UserManagementValidationError(
                "Username must be between "
                f"{MIN_USERNAME_LENGTH} and {MAX_USERNAME_LENGTH} characters."
            )

    @staticmethod
    def _validate_email(
        email: str,
    ) -> None:
        """
        Validate basic email structure.

        Detailed email policy remains a schema/domain responsibility.
        """

        if not (
            MIN_EMAIL_LENGTH
            <= len(email)
            <= MAX_EMAIL_LENGTH
        ):
            raise UserManagementValidationError(
                "Email address is invalid."
            )

        local_part, separator, domain = email.partition("@")

        if (
            not separator
            or not local_part
            or not domain
            or domain.startswith(".")
            or domain.endswith(".")
            or "." not in domain
        ):
            raise UserManagementValidationError(
                "Email address is invalid."
            )

    @staticmethod
    def _validate_display_name(
        display_name: str,
    ) -> None:
        """Validate display name."""

        if not (
            MIN_DISPLAY_NAME_LENGTH
            <= len(display_name)
            <= MAX_DISPLAY_NAME_LENGTH
        ):
            raise UserManagementValidationError(
                "Display name is invalid."
            )

    @staticmethod
    def _normalize_timestamp(
        value: datetime | None,
        *,
        field_name: str,
    ) -> datetime | None:
        """
        Normalize timezone-aware timestamp to UTC.
        """

        if value is None:
            return None

        if not isinstance(value, datetime):
            raise UserManagementValidationError(
                f"{field_name} must be a datetime."
            )

        if value.tzinfo is None:
            raise UserManagementValidationError(
                f"{field_name} must be timezone-aware."
            )

        return value.astimezone(UTC)

    @staticmethod
    def _validate_date_range(
        *,
        date_from: datetime | None,
        date_to: datetime | None,
        from_field: str,
        to_field: str,
    ) -> None:
        """Validate inclusive datetime range."""

        if (
            date_from is not None
            and date_to is not None
            and date_from > date_to
        ):
            raise UserManagementValidationError(
                f"{from_field} must not be later than {to_field}."
            )

    @classmethod
    def _validate_page(
        cls,
        *,
        limit: int,
        offset: int,
    ) -> None:
        """Validate offset pagination."""

        if isinstance(limit, bool) or not isinstance(limit, int):
            raise UserManagementValidationError(
                "Pagination limit must be an integer."
            )

        if isinstance(offset, bool) or not isinstance(offset, int):
            raise UserManagementValidationError(
                "Pagination offset must be an integer."
            )

        if limit < 1 or limit > cls.MAX_PAGE_SIZE:
            raise UserManagementValidationError(
                "Invalid pagination limit."
            )

        if offset < 0:
            raise UserManagementValidationError(
                "Pagination offset cannot be negative."
            )

    @classmethod
    def _validate_audit_page(
        cls,
        *,
        page: int,
        page_size: int,
    ) -> None:
        """Validate audit page-number pagination."""

        if isinstance(page, bool) or not isinstance(page, int):
            raise UserManagementValidationError(
                "Audit page must be an integer."
            )

        if page < 1:
            raise UserManagementValidationError(
                "Audit page must be greater than zero."
            )

        if isinstance(page_size, bool) or not isinstance(page_size, int):
            raise UserManagementValidationError(
                "Audit page_size must be an integer."
            )

        if page_size < 1 or page_size > cls.MAX_PAGE_SIZE:
            raise UserManagementValidationError(
                "Invalid audit page_size."
            )

    @staticmethod
    def _normalize_outcome(
        outcome: str | None,
    ) -> str | None:
        """Normalize and validate audit outcome."""

        normalized = UserManagementService._normalize_optional_text(
            outcome
        )

        if normalized is None:
            return None

        normalized = normalized.lower()

        allowed = {
            AuditOutcome.SUCCESS,
            AuditOutcome.FAILURE,
            AuditOutcome.DENIED,
        }

        if normalized not in allowed:
            raise UserManagementValidationError(
                "Invalid audit outcome."
            )

        return normalized

    # =========================================================================
    # Audit
    # =========================================================================

    async def _audit_event(
        self,
        *,
        action: str,
        actor_user_id: UUID | None = None,
        target_user_id: UUID | None = None,
        request_id: str | None = None,
        source_ip: str | None = None,
        metadata: dict[str, Any] | None = None,
        canonical: bool = True,
    ) -> None:
        """
        Write an audit event through AuditService only.
        """

        if canonical:
            if action not in self._CANONICAL_USER_AUDIT_ACTIONS:
                raise UserManagementError(
                    f"Invalid canonical user-management audit action: {action}"
                )
        else:
            if action not in self._INFORMATIONAL_AUDIT_ACTIONS:
                raise UserManagementError(
                    f"Invalid informational user-management audit action: {action}"
                )

        self._validate_optional_uuid(
            actor_user_id,
            field_name="actor_user_id",
        )

        self._validate_optional_uuid(
            target_user_id,
            field_name="target_user_id",
        )

        safe_metadata = self._sanitize_audit_metadata(
            metadata or {}
        )

        audit = AuditCreate(
            action=action,
            outcome=AuditOutcome.SUCCESS,
            actor_user_id=actor_user_id,
            target_user_id=target_user_id,
            request_id=request_id,
            source_ip=source_ip,
            metadata_json=safe_metadata or None,
        )

        try:
            await self._audit.log(audit)
        except Exception as exc:
            raise UserManagementError(
                "Unable to persist user-management audit event."
            ) from exc

    @classmethod
    def _sanitize_audit_metadata(
        cls,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Recursively reject credential-bearing audit metadata.
        """

        if not isinstance(metadata, dict):
            raise UserManagementError(
                "Audit metadata must be a dictionary."
            )

        def normalize_key(key: Any) -> str:
            return (
                str(key)
                .strip()
                .lower()
                .replace("-", "_")
                .replace(" ", "_")
                .replace(".", "_")
                .replace("/", "_")
            )

        def walk(value: Any) -> Any:
            if isinstance(value, dict):
                result: dict[str, Any] = {}

                for key, nested_value in value.items():
                    normalized_key = normalize_key(key)

                    if normalized_key in cls._FORBIDDEN_AUDIT_KEYS:
                        raise UserManagementError(
                            "Sensitive credential material cannot be stored "
                            "in audit metadata."
                        )

                    result[str(key)] = walk(nested_value)

                return result

            if isinstance(value, list):
                return [walk(item) for item in value]

            if isinstance(value, tuple):
                return tuple(walk(item) for item in value)

            if isinstance(value, set):
                return {walk(item) for item in value}

            if isinstance(value, frozenset):
                return frozenset(walk(item) for item in value)

            return value

        result = walk(metadata)

        if not isinstance(result, dict):
            raise UserManagementError(
                "Audit metadata must be a dictionary."
            )

        return result

    # =========================================================================
    # Optional UUID Validation
    # =========================================================================

    @staticmethod
    def _validate_optional_uuid(
        value: UUID | None,
        *,
        field_name: str,
    ) -> None:
        """Validate optional UUID."""

        if value is not None and not isinstance(value, UUID):
            raise UserManagementValidationError(
                f"{field_name} must be a UUID."
            )

    # =========================================================================
    # Repository Error Conversion
    # =========================================================================

    @staticmethod
    def _raise_repository_error(
        exc: UserRepositoryError,
        *,
        operation: str,
        duplicate_error: bool = False,
    ) -> None:
        """
        Convert repository failures into service-level failures.

        Database uniqueness constraints remain authoritative under races.
        """

        message = str(exc).lower()

        if duplicate_error and any(
            marker in message
            for marker in (
                "duplicate",
                "unique",
                "already exists",
                "conflicts with existing data",
            )
        ):
            raise UserAlreadyExistsError(
                "Username or email is already registered."
            ) from exc

        raise UserManagementError(
            f"Unable to {operation}."
        ) from exc


# =============================================================================
# Public Exports
# =============================================================================

__all__ = [
    "InvalidRoleError",
    "LastAdminProtectionError",
    "SelfServiceDeniedError",
    "UserAlreadyExistsError",
    "UserAuditHistoryResult",
    "UserListResult",
    "UserManagementError",
    "UserManagementService",
    "UserManagementValidationError",
    "UserNotFoundError",
    "UserStatistics",
]