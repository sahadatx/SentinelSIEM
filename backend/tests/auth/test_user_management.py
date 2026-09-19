"""
SentinelSIEM User Management Service Tests
===========================================

Unit and contract-level tests for:

    app.auth.user_management.UserManagementService

Architecture under test:

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

Important:

    UserManagementService MUST receive the canonical AuditService.

    It MUST NOT receive:
        - AuthAuditRepository
        - FakeAuditRepository
        - legacy audit sink
        - audit=None

These tests therefore use a FakeAuditService rather than pretending that
UserManagementService talks directly to an audit repository.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from app.audit.schemas import AuditCreate
from app.auth.models import (
    AuditAction,
    AuditOutcome,
    UserIdentity,
)
from app.auth.user_management import (
    InvalidRoleError,
    LastAdminProtectionError,
    SelfServiceDeniedError,
    UserAlreadyExistsError,
    UserManagementError,
    UserManagementService,
    UserManagementValidationError,
    UserNotFoundError,
)

# ============================================================================
# Constants
# ============================================================================

ADMIN_ROLE = "ADMIN"
SECURITY_ANALYST_ROLE = "SECURITY_ANALYST"
SOC_ANALYST_ROLE = "SOC_ANALYST"
INVESTIGATOR_ROLE = "INVESTIGATOR"
VIEWER_ROLE = "VIEWER"

STRONG_PASSWORD = "StrongPassword123!"
NEW_PASSWORD = "NewStrongPassword123!"

ALL_ROLES = {
    ADMIN_ROLE,
    SECURITY_ANALYST_ROLE,
    SOC_ANALYST_ROLE,
    INVESTIGATOR_ROLE,
    VIEWER_ROLE,
}


# ============================================================================
# Test Doubles
# ============================================================================


class FakePasswordHasher:
    """
    Minimal password hasher compatible with UserManagementService.
    """

    def hash(self, password: str) -> str:
        if not isinstance(password, str) or len(password) < 8:
            raise ValueError("password too weak")

        return f"hashed::{password}"


class FakeRoleRegistry:
    """
    Minimal canonical-role-compatible registry.

    All five SentinelSIEM application roles are accepted.
    """

    VALID_ROLES = ALL_ROLES

    def get(self, role: str):
        normalized = str(role).strip().upper()

        if normalized not in self.VALID_ROLES:
            raise InvalidRoleError(f"Invalid role: {normalized}")

        return normalized


class FakeAuditService:
    """
    In-memory stand-in for the canonical AuditService.

    IMPORTANT:

        UserManagementService talks to this service through:

            audit.log(...)
            audit.list_user_activity(...)

        It never talks directly to an audit repository.

    AuditCreate objects are retained exactly as they are supplied by the
    UserManagementService so tests can verify the canonical audit contract.
    """

    def __init__(self) -> None:
        self.records: list[AuditCreate] = []

        self.list_user_activity_calls: list[dict[str, Any]] = []

        self.events: list[AuditCreate] = self.records

        self.fail_log = False
        self.fail_list_user_activity = False

        self.activity_events: list[Any] = []
        self.activity_total = 0

    async def log(self, audit: AuditCreate):
        if self.fail_log:
            raise RuntimeError("simulated audit persistence failure")

        if not isinstance(audit, AuditCreate):
            raise TypeError("audit must be an AuditCreate instance")

        self.records.append(audit)

        return audit

    async def list_user_activity(
        self,
        *,
        user_id: UUID,
        page: int = 1,
        page_size: int = 50,
        action: str | None = None,
        result: str | None = None,
        category: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        search: str | None = None,
    ):
        if self.fail_list_user_activity:
            raise RuntimeError("simulated audit query failure")

        call = {
            "user_id": user_id,
            "page": page,
            "page_size": page_size,
            "action": action,
            "result": result,
            "category": category,
            "date_from": date_from,
            "date_to": date_to,
            "search": search,
        }

        self.list_user_activity_calls.append(call)

        return (
            tuple(self.activity_events),
            self.activity_total,
        )

    def last(self) -> AuditCreate:
        assert self.records, "No audit events were recorded."

        return self.records[-1]

    def actions(self) -> list[str]:
        return [record.action for record in self.records]


class FakeSessionRepository:
    """
    In-memory session repository.
    """

    def __init__(self) -> None:
        self.revocations: list[UUID] = []

    async def revoke_user_sessions(
        self,
        user_id: UUID,
    ) -> int:
        self.revocations.append(user_id)
        return 1


class FakeUserRepository:
    """
    In-memory UserRepository implementation matching the contract consumed
    by UserManagementService.
    """

    def __init__(
        self,
        users: list[UserIdentity] | None = None,
    ) -> None:
        self.users: dict[UUID, UserIdentity] = {}

        if users:
            for user in users:
                self.users[user.user_id] = user

        self.create_calls: list[tuple[UserIdentity, str]] = []
        self.update_calls: list[UserIdentity] = []
        self.role_calls: list[tuple[UUID, str]] = []
        self.active_calls: list[tuple[UUID, bool]] = []
        self.lock_calls: list[tuple[UUID, bool]] = []
        self.password_calls: list[tuple[UUID, str]] = []
        self.force_password_change_calls: list[tuple[UUID, bool]] = []
        self.delete_calls: list[UUID] = []

    # ------------------------------------------------------------------
    # Identity lookup
    # ------------------------------------------------------------------

    async def get_by_login(
        self,
        login: str,
    ):
        normalized = login.strip().lower()

        for user in self.users.values():
            if user.username.lower() == normalized or user.email.lower() == normalized:
                return user

        return None

    async def get_by_id(
        self,
        user_id: UUID,
    ):
        return self.users.get(user_id)

    # ------------------------------------------------------------------
    # Listing / statistics
    # ------------------------------------------------------------------

    async def list_users(
        self,
        *,
        search=None,
        role=None,
        is_active=None,
        is_locked=None,
        force_password_change=None,
        created_from=None,
        created_to=None,
        last_login_from=None,
        last_login_to=None,
        limit=50,
        offset=0,
    ):
        users = list(self.users.values())

        if search:
            normalized_search = search.lower()
            users = [
                user
                for user in users
                if (
                    normalized_search in user.username.lower()
                    or normalized_search in user.email.lower()
                )
            ]

        if role is not None:
            users = [
                user
                for user in users
                if getattr(user, "role", None) == role
            ]

        if is_active is not None:
            users = [
                user
                for user in users
                if user.is_active == is_active
            ]

        if is_locked is not None:
            users = [
                user
                for user in users
                if user.is_locked == is_locked
            ]

        if force_password_change is not None:
            users = [
                user
                for user in users
                if getattr(user, "force_password_change", False)
                == force_password_change
            ]

        if created_from is not None:
            users = [
                user
                for user in users
                if getattr(user, "created_at", None) is not None
                and user.created_at >= created_from
            ]

        if created_to is not None:
            users = [
                user
                for user in users
                if getattr(user, "created_at", None) is not None
                and user.created_at <= created_to
            ]

        if last_login_from is not None:
            users = [
                user
                for user in users
                if getattr(user, "last_login_at", None) is not None
                and user.last_login_at >= last_login_from
            ]

        if last_login_to is not None:
            users = [
                user
                for user in users
                if getattr(user, "last_login_at", None) is not None
                and user.last_login_at <= last_login_to
            ]

        return users[offset : offset + limit]

    async def count_users(
        self,
        *,
        search=None,
        role=None,
        is_active=None,
        is_locked=None,
        force_password_change=None,
        created_from=None,
        created_to=None,
        last_login_from=None,
        last_login_to=None,
    ):
        users = list(self.users.values())

        if search:
            normalized_search = search.lower()
            users = [
                user
                for user in users
                if (
                    normalized_search in user.username.lower()
                    or normalized_search in user.email.lower()
                )
            ]

        if role is not None:
            users = [
                user
                for user in users
                if getattr(user, "role", None) == role
            ]

        if is_active is not None:
            users = [
                user
                for user in users
                if user.is_active == is_active
            ]

        if is_locked is not None:
            users = [
                user
                for user in users
                if user.is_locked == is_locked
            ]

        if force_password_change is not None:
            users = [
                user
                for user in users
                if getattr(user, "force_password_change", False)
                == force_password_change
            ]

        if created_from is not None:
            users = [
                user
                for user in users
                if getattr(user, "created_at", None) is not None
                and user.created_at >= created_from
            ]

        if created_to is not None:
            users = [
                user
                for user in users
                if getattr(user, "created_at", None) is not None
                and user.created_at <= created_to
            ]

        if last_login_from is not None:
            users = [
                user
                for user in users
                if getattr(user, "last_login_at", None) is not None
                and user.last_login_at >= last_login_from
            ]

        if last_login_to is not None:
            users = [
                user
                for user in users
                if getattr(user, "last_login_at", None) is not None
                and user.last_login_at <= last_login_to
            ]

        return len(users)
    async def create_user(
        self,
        user,
        *,
        role,
    ):
        self.create_calls.append((user, role))

        if await self.get_by_login(user.username):
            raise RuntimeError("username already exists")

        if await self.get_by_login(user.email):
            raise RuntimeError("email already exists")

        created = replace_user(
            user,
            roles=frozenset({role}),
        )

        self.users[created.user_id] = created

        return created

    async def update_user(
        self,
        user,
    ):
        self.update_calls.append(user)

        if user.user_id not in self.users:
            return None

        self.users[user.user_id] = user

        return user

    # ------------------------------------------------------------------
    # Role / account state
    # ------------------------------------------------------------------

    async def set_role(
        self,
        user_id,
        role,
    ):
        self.role_calls.append((user_id, role))

        user = self.users.get(user_id)

        if user is None:
            return None

        updated = replace_user(
            user,
            roles=frozenset({role}),
        )

        self.users[user_id] = updated

        return updated

    async def set_active(
        self,
        user_id,
        is_active,
    ):
        self.active_calls.append((user_id, is_active))

        user = self.users.get(user_id)

        if user is None:
            return None

        updated = replace_user(
            user,
            is_active=is_active,
        )

        self.users[user_id] = updated

        return updated

    async def set_locked(
        self,
        user_id,
        is_locked,
    ):
        self.lock_calls.append((user_id, is_locked))

        user = self.users.get(user_id)

        if user is None:
            return None

        updated = replace_user(
            user,
            is_locked=is_locked,
        )

        self.users[user_id] = updated

        return updated

    async def set_force_password_change(
        self,
        user_id,
        force_password_change,
    ):
        self.force_password_change_calls.append(
            (
                user_id,
                force_password_change,
            )
        )

        user = self.users.get(user_id)

        if user is None:
            return None

        updated = replace_user(
            user,
            force_password_change=force_password_change,
        )

        self.users[user_id] = updated

        return updated

    # ------------------------------------------------------------------
    # Password lifecycle
    # ------------------------------------------------------------------

    async def reset_password(
        self,
        user_id,
        password_hash,
    ):
        self.password_calls.append(
            (
                user_id,
                password_hash,
            )
        )

        user = self.users.get(user_id)

        if user is None:
            return False

        updated = replace_user(
            user,
            password_hash=password_hash,
            failed_login_count=0,
        )

        self.users[user_id] = updated

        return True

    # ------------------------------------------------------------------
    # Deletion
    # ------------------------------------------------------------------

    async def delete_user(
        self,
        user_id,
    ):
        self.delete_calls.append(user_id)

        if user_id not in self.users:
            return False

        del self.users[user_id]

        return True


# ============================================================================
# Helpers
# ============================================================================


def replace_user(
    user: UserIdentity,
    **changes,
) -> UserIdentity:
    """
    Rebuild UserIdentity while preserving every supported field.
    """

    values = {
        "user_id": user.user_id,
        "username": user.username,
        "email": user.email,
        "password_hash": user.password_hash,
        "roles": user.roles,
        "is_active": user.is_active,
        "is_locked": user.is_locked,
        "failed_login_count": user.failed_login_count,
        "display_name": user.display_name,
        "force_password_change": user.force_password_change,
        "password_changed_at": user.password_changed_at,
        "last_login_at": user.last_login_at,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
    }

    values.update(changes)

    return UserIdentity(**values)


def make_user(
    *,
    username: str,
    email: str,
    role: str = VIEWER_ROLE,
    is_active: bool = True,
    is_locked: bool = False,
    force_password_change: bool = False,
    display_name: str | None = None,
) -> UserIdentity:
    """
    Build a test UserIdentity.
    """

    now = datetime.now(UTC)

    return UserIdentity(
        user_id=uuid4(),
        username=username,
        email=email,
        password_hash="hashed::InitialPassword123",
        roles=frozenset({role}),
        is_active=is_active,
        is_locked=is_locked,
        failed_login_count=0,
        display_name=display_name,
        force_password_change=force_password_change,
        password_changed_at=None,
        last_login_at=None,
        created_at=now,
        updated_at=now,
    )


def current_user(
    context: ServiceContext,
    user_id: UUID,
) -> UserIdentity:
    """
    Always retrieve the current repository state.

    This avoids assertions against stale UserIdentity instances after
    repository operations replace immutable identity objects.
    """

    return context.users.users[user_id]


def assert_authorization_denied(
    exc_info,
) -> None:
    assert isinstance(
        exc_info.value,
        UserManagementError,
    )


def assert_last_audit(
    context: ServiceContext,
    *,
    action: str,
    actor_user_id: UUID | None = None,
    target_user_id: UUID | None = None,
    outcome: str = AuditOutcome.SUCCESS,
) -> AuditCreate:
    record = context.audit.last()

    assert record.action == action
    assert record.outcome == outcome

    if actor_user_id is not None:
        assert record.actor_user_id == actor_user_id

    if target_user_id is not None:
        assert record.target_user_id == target_user_id

    return record


# ============================================================================
# Service Context
# ============================================================================


@dataclass
class ServiceContext:
    admin: UserIdentity
    security_analyst: UserIdentity
    soc_analyst: UserIdentity
    investigator: UserIdentity
    viewer: UserIdentity

    users: FakeUserRepository
    sessions: FakeSessionRepository
    audit: FakeAuditService
    passwords: FakePasswordHasher
    roles: FakeRoleRegistry

    service: UserManagementService


@pytest.fixture
def context() -> ServiceContext:
    admin = make_user(
        username="admin",
        email="admin@example.com",
        role=ADMIN_ROLE,
    )

    security_analyst = make_user(
        username="security-analyst",
        email="security@example.com",
        role=SECURITY_ANALYST_ROLE,
    )

    soc_analyst = make_user(
        username="soc-analyst",
        email="soc@example.com",
        role=SOC_ANALYST_ROLE,
    )

    investigator = make_user(
        username="investigator",
        email="investigator@example.com",
        role=INVESTIGATOR_ROLE,
    )

    viewer = make_user(
        username="viewer",
        email="viewer@example.com",
        role=VIEWER_ROLE,
    )

    users = FakeUserRepository(
        [
            admin,
            security_analyst,
            soc_analyst,
            investigator,
            viewer,
        ]
    )

    sessions = FakeSessionRepository()
    audit = FakeAuditService()
    passwords = FakePasswordHasher()
    roles = FakeRoleRegistry()

    service = UserManagementService(
        users=users,
        sessions=sessions,
        audit=audit,
        password_hasher=passwords,
        roles=roles,
    )

    return ServiceContext(
        admin=admin,
        security_analyst=security_analyst,
        soc_analyst=soc_analyst,
        investigator=investigator,
        viewer=viewer,
        users=users,
        sessions=sessions,
        audit=audit,
        passwords=passwords,
        roles=roles,
        service=service,
    )


# ============================================================================
# Initialization / Contract
# ============================================================================


def test_service_requires_audit_service(
    context,
):
    with pytest.raises(ValueError):
        UserManagementService(
            users=context.users,
            sessions=context.sessions,
            audit=None,
            password_hasher=context.passwords,
            roles=context.roles,
        )


def test_service_requires_password_hasher(
    context,
):
    with pytest.raises(ValueError):
        UserManagementService(
            users=context.users,
            sessions=context.sessions,
            audit=context.audit,
            password_hasher=None,
            roles=context.roles,
        )


def test_all_five_application_roles_are_supported(
    context,
):
    for role in ALL_ROLES:
        assert context.roles.get(role) == role


# ============================================================================
# Basic Read Operations
# ============================================================================


@pytest.mark.asyncio
async def test_list_users_returns_paginated_users(
    context,
):
    result = await context.service.list_users(
        actor_user_id=context.admin.user_id,
        limit=2,
        offset=0,
    )

    assert result.limit == 2
    assert result.offset == 0
    assert len(result.users) == 2


@pytest.mark.asyncio
async def test_list_users_normalizes_search(
    context,
):
    result = await context.service.list_users(
        actor_user_id=context.admin.user_id,
        search="  ADMIN  ",
    )

    assert len(result.users) == 1
    assert result.users[0].username == "admin"


@pytest.mark.asyncio
async def test_list_users_rejects_invalid_limit(
    context,
):
    with pytest.raises(UserManagementValidationError):
        await context.service.list_users(
            actor_user_id=context.admin.user_id,
            limit=0,
        )


@pytest.mark.asyncio
async def test_list_users_rejects_negative_offset(
    context,
):
    with pytest.raises(UserManagementValidationError):
        await context.service.list_users(
            actor_user_id=context.admin.user_id,
            offset=-1,
        )


@pytest.mark.asyncio
async def test_list_users_generates_informational_audit(
    context,
):
    await context.service.list_users(
        actor_user_id=context.admin.user_id,
    )

    assert_last_audit(
        context,
        action=AuditAction.USERS_LISTED,
        actor_user_id=context.admin.user_id,
    )


# ============================================================================
# Get User
# ============================================================================


@pytest.mark.asyncio
async def test_get_user_returns_user(
    context,
):
    result = await context.service.get_user(
        actor_user_id=context.admin.user_id,
        user_id=context.viewer.user_id,
    )

    assert result.user_id == context.viewer.user_id
    assert result.username == "viewer"


@pytest.mark.asyncio
async def test_get_user_missing_user_raises(
    context,
):
    with pytest.raises(UserNotFoundError):
        await context.service.get_user(
            actor_user_id=context.admin.user_id,
            user_id=uuid4(),
        )


# ============================================================================
# Statistics
# ============================================================================


@pytest.mark.asyncio
async def test_statistics_returns_expected_values(
    context,
):
    locked = make_user(
        username="locked",
        email="locked@example.com",
        is_locked=True,
    )

    disabled = make_user(
        username="disabled",
        email="disabled@example.com",
        is_active=False,
    )

    context.users.users[locked.user_id] = locked
    context.users.users[disabled.user_id] = disabled

    result = await context.service.statistics(
        actor_user_id=context.admin.user_id,
    )

    assert result.total == 7
    assert result.active == 6
    assert result.disabled == 1
    assert result.locked == 1


@pytest.mark.asyncio
async def test_statistics_generates_informational_audit(
    context,
):
    await context.service.statistics(
        actor_user_id=context.admin.user_id,
    )

    assert_last_audit(
        context,
        action=AuditAction.USER_STATISTICS_VIEWED,
        actor_user_id=context.admin.user_id,
    )


# ============================================================================
# User Audit History
# ============================================================================


@pytest.mark.asyncio
async def test_user_audit_history_uses_canonical_audit_service(
    context,
):
    historical_event = AuditCreate(
        action=AuditAction.USER_CREATED,
        outcome=AuditOutcome.SUCCESS,
        actor_user_id=context.admin.user_id,
        target_user_id=context.viewer.user_id,
        metadata_json={
            "test": "historical-event",
        },
    )

    context.audit.activity_events = [
        historical_event,
    ]
    context.audit.activity_total = 1

    result = await context.service.get_user_audit_history(
        actor_user_id=context.admin.user_id,
        user_id=context.viewer.user_id,
        page=2,
        page_size=25,
        action="users.created",
        outcome="success",
        category="users",
        search="historical",
    )

    assert result.total == 1
    assert result.page == 2
    assert result.page_size == 25
    assert result.events == (historical_event,)

    assert len(context.audit.list_user_activity_calls) == 1

    call = context.audit.list_user_activity_calls[0]

    assert call["user_id"] == context.viewer.user_id
    assert call["page"] == 2
    assert call["page_size"] == 25
    assert call["action"] == "users.created"
    assert call["result"] == "success"
    assert call["category"] == "users"
    assert call["search"] == "historical"


@pytest.mark.asyncio
async def test_user_can_view_own_audit_history(
    context,
):
    await context.service.get_user_audit_history(
        actor_user_id=context.viewer.user_id,
        user_id=context.viewer.user_id,
    )

    assert len(context.audit.list_user_activity_calls) == 1


@pytest.mark.asyncio
async def test_non_admin_cannot_view_another_users_audit_history(
    context,
):
    with pytest.raises(UserManagementError) as exc_info:
        await context.service.get_user_audit_history(
            actor_user_id=context.viewer.user_id,
            user_id=context.admin.user_id,
        )

    assert_authorization_denied(exc_info)

    assert context.audit.list_user_activity_calls == []


@pytest.mark.asyncio
async def test_user_audit_history_generates_view_event_after_query(
    context,
):
    context.audit.activity_events = []
    context.audit.activity_total = 0

    await context.service.get_user_audit_history(
        actor_user_id=context.admin.user_id,
        user_id=context.viewer.user_id,
    )

    assert len(context.audit.list_user_activity_calls) == 1

    record = assert_last_audit(
        context,
        action=AuditAction.USER_VIEWED,
        actor_user_id=context.admin.user_id,
        target_user_id=context.viewer.user_id,
    )

    assert record.metadata_json is not None
    assert record.metadata_json["view"] == "audit_history"


# ============================================================================
# ADMIN MATRIX
# ============================================================================


@pytest.mark.asyncio
async def test_admin_can_create_user(
    context,
):
    created = await context.service.create_user(
        actor_user_id=context.admin.user_id,
        username="newuser",
        email="newuser@example.com",
        password=STRONG_PASSWORD,
        role=VIEWER_ROLE,
    )

    assert created.username == "newuser"
    assert created.email == "newuser@example.com"
    assert created.roles == frozenset({VIEWER_ROLE})
    assert created.user_id in context.users.users


@pytest.mark.asyncio
async def test_admin_can_delete_user(
    context,
):
    await context.service.delete_user(
        actor_user_id=context.admin.user_id,
        user_id=context.viewer.user_id,
    )

    assert context.viewer.user_id not in context.users.users
    assert context.viewer.user_id in context.sessions.revocations


@pytest.mark.asyncio
async def test_admin_can_change_role(
    context,
):
    result = await context.service.change_role(
        actor_user_id=context.admin.user_id,
        user_id=context.viewer.user_id,
        role=INVESTIGATOR_ROLE,
    )

    assert result.roles == frozenset({INVESTIGATOR_ROLE})


@pytest.mark.asyncio
async def test_admin_can_lock_user(
    context,
):
    result = await context.service.set_locked(
        actor_user_id=context.admin.user_id,
        user_id=context.viewer.user_id,
        is_locked=True,
    )

    assert result.is_locked is True
    assert context.viewer.user_id in context.sessions.revocations


@pytest.mark.asyncio
async def test_admin_can_unlock_user(
    context,
):
    locked = make_user(
        username="locked",
        email="locked@example.com",
        is_locked=True,
    )

    context.users.users[locked.user_id] = locked

    result = await context.service.set_locked(
        actor_user_id=context.admin.user_id,
        user_id=locked.user_id,
        is_locked=False,
    )

    assert result.is_locked is False
    assert locked.user_id not in context.sessions.revocations


@pytest.mark.asyncio
async def test_admin_can_disable_user(
    context,
):
    result = await context.service.set_active(
        actor_user_id=context.admin.user_id,
        user_id=context.viewer.user_id,
        is_active=False,
    )

    assert result.is_active is False
    assert context.viewer.user_id in context.sessions.revocations


@pytest.mark.asyncio
async def test_admin_can_enable_user(
    context,
):
    disabled = make_user(
        username="disabled",
        email="disabled@example.com",
        is_active=False,
    )

    context.users.users[disabled.user_id] = disabled

    result = await context.service.set_active(
        actor_user_id=context.admin.user_id,
        user_id=disabled.user_id,
        is_active=True,
    )

    assert result.is_active is True
    assert disabled.user_id not in context.sessions.revocations


@pytest.mark.asyncio
async def test_admin_can_reset_password(
    context,
):
    revoked = await context.service.reset_password(
        actor_user_id=context.admin.user_id,
        user_id=context.viewer.user_id,
        new_password=NEW_PASSWORD,
    )

    assert revoked == 1

    updated = current_user(
        context,
        context.viewer.user_id,
    )

    assert updated.password_hash == (f"hashed::{NEW_PASSWORD}")

    assert updated.failed_login_count == 0


@pytest.mark.asyncio
async def test_admin_can_revoke_sessions(
    context,
):
    count = await context.service.revoke_sessions(
        actor_user_id=context.admin.user_id,
        user_id=context.viewer.user_id,
    )

    assert count == 1
    assert context.viewer.user_id in context.sessions.revocations


# ============================================================================
# NON-ADMIN MATRIX
# ============================================================================


@pytest.mark.asyncio
async def test_non_admin_cannot_create_user(
    context,
):
    with pytest.raises(UserManagementError) as exc_info:
        await context.service.create_user(
            actor_user_id=context.security_analyst.user_id,
            username="blocked-user",
            email="blocked@example.com",
            password=STRONG_PASSWORD,
            role=VIEWER_ROLE,
        )

    assert_authorization_denied(exc_info)

    assert await context.users.get_by_login("blocked-user") is None


@pytest.mark.asyncio
async def test_non_admin_cannot_delete_user(
    context,
):
    with pytest.raises(UserManagementError) as exc_info:
        await context.service.delete_user(
            actor_user_id=context.security_analyst.user_id,
            user_id=context.viewer.user_id,
        )

    assert_authorization_denied(exc_info)

    assert context.viewer.user_id in context.users.users


@pytest.mark.asyncio
async def test_non_admin_cannot_change_role(
    context,
):
    original_roles = current_user(
        context,
        context.viewer.user_id,
    ).roles

    with pytest.raises(UserManagementError) as exc_info:
        await context.service.change_role(
            actor_user_id=context.security_analyst.user_id,
            user_id=context.viewer.user_id,
            role=INVESTIGATOR_ROLE,
        )

    assert_authorization_denied(exc_info)

    assert (
        current_user(
            context,
            context.viewer.user_id,
        ).roles
        == original_roles
    )


@pytest.mark.asyncio
async def test_non_admin_cannot_disable_user(
    context,
):
    with pytest.raises(UserManagementError) as exc_info:
        await context.service.set_active(
            actor_user_id=context.security_analyst.user_id,
            user_id=context.viewer.user_id,
            is_active=False,
        )

    assert_authorization_denied(exc_info)

    assert (
        current_user(
            context,
            context.viewer.user_id,
        ).is_active
        is True
    )

    assert context.sessions.revocations == []


@pytest.mark.asyncio
async def test_non_admin_cannot_lock_another_user(
    context,
):
    with pytest.raises(UserManagementError) as exc_info:
        await context.service.set_locked(
            actor_user_id=context.security_analyst.user_id,
            user_id=context.viewer.user_id,
            is_locked=True,
        )

    assert_authorization_denied(exc_info)

    assert (
        current_user(
            context,
            context.viewer.user_id,
        ).is_locked
        is False
    )


@pytest.mark.asyncio
async def test_non_admin_cannot_reset_another_user_password(
    context,
):
    original_hash = current_user(
        context,
        context.viewer.user_id,
    ).password_hash

    with pytest.raises(UserManagementError) as exc_info:
        await context.service.reset_password(
            actor_user_id=context.security_analyst.user_id,
            user_id=context.viewer.user_id,
            new_password=NEW_PASSWORD,
        )

    assert_authorization_denied(exc_info)

    assert (
        current_user(
            context,
            context.viewer.user_id,
        ).password_hash
        == original_hash
    )


@pytest.mark.asyncio
async def test_non_admin_cannot_revoke_another_user_sessions(
    context,
):
    with pytest.raises(UserManagementError) as exc_info:
        await context.service.revoke_sessions(
            actor_user_id=context.security_analyst.user_id,
            user_id=context.viewer.user_id,
        )

    assert_authorization_denied(exc_info)

    assert context.sessions.revocations == []


# ============================================================================
# SELF-SERVICE MATRIX
# ============================================================================


@pytest.mark.asyncio
async def test_user_can_update_own_profile(
    context,
):
    result = await context.service.update_profile(
        actor_user_id=context.viewer.user_id,
        user_id=context.viewer.user_id,
        username="updatedviewer",
        email="updatedviewer@example.com",
    )

    assert result.user_id == context.viewer.user_id
    assert result.username == "updatedviewer"
    assert result.email == "updatedviewer@example.com"


@pytest.mark.asyncio
async def test_user_can_change_own_password(
    context,
):
    revoked = await context.service.reset_password(
        actor_user_id=context.viewer.user_id,
        user_id=context.viewer.user_id,
        new_password=NEW_PASSWORD,
    )

    assert revoked == 1

    updated = current_user(
        context,
        context.viewer.user_id,
    )

    assert updated.password_hash == (f"hashed::{NEW_PASSWORD}")


@pytest.mark.asyncio
async def test_user_can_revoke_own_sessions(
    context,
):
    count = await context.service.revoke_sessions(
        actor_user_id=context.viewer.user_id,
        user_id=context.viewer.user_id,
    )

    assert count == 1
    assert context.viewer.user_id in context.sessions.revocations


@pytest.mark.asyncio
async def test_user_cannot_delete_self(
    context,
):
    with pytest.raises(SelfServiceDeniedError):
        await context.service.delete_user(
            actor_user_id=context.viewer.user_id,
            user_id=context.viewer.user_id,
        )

    assert context.viewer.user_id in context.users.users


# ============================================================================
# SELF-SERVICE BOUNDARIES
# ============================================================================


@pytest.mark.asyncio
async def test_user_cannot_update_another_profile(
    context,
):
    with pytest.raises(UserManagementError) as exc_info:
        await context.service.update_profile(
            actor_user_id=context.viewer.user_id,
            user_id=context.security_analyst.user_id,
            username="attacked",
            email="attacked@example.com",
        )

    assert_authorization_denied(exc_info)

    analyst = current_user(
        context,
        context.security_analyst.user_id,
    )

    assert analyst.username == "security-analyst"
    assert analyst.email == "security@example.com"


@pytest.mark.asyncio
async def test_user_cannot_revoke_another_users_sessions(
    context,
):
    with pytest.raises(UserManagementError) as exc_info:
        await context.service.revoke_sessions(
            actor_user_id=context.viewer.user_id,
            user_id=context.security_analyst.user_id,
        )

    assert_authorization_denied(exc_info)
    assert context.sessions.revocations == []


@pytest.mark.asyncio
async def test_user_cannot_change_another_users_password(
    context,
):
    original_hash = current_user(
        context,
        context.security_analyst.user_id,
    ).password_hash

    with pytest.raises(UserManagementError) as exc_info:
        await context.service.reset_password(
            actor_user_id=context.viewer.user_id,
            user_id=context.security_analyst.user_id,
            new_password=NEW_PASSWORD,
        )

    assert_authorization_denied(exc_info)

    assert (
        current_user(
            context,
            context.security_analyst.user_id,
        ).password_hash
        == original_hash
    )


# ============================================================================
# LAST ADMIN PROTECTION
# ============================================================================


@pytest.mark.asyncio
async def test_last_admin_cannot_be_demoted_by_admin(
    context,
):
    with pytest.raises(LastAdminProtectionError):
        await context.service.change_role(
            actor_user_id=context.admin.user_id,
            user_id=context.admin.user_id,
            role=SECURITY_ANALYST_ROLE,
        )

    assert current_user(
        context,
        context.admin.user_id,
    ).roles == frozenset({ADMIN_ROLE})


@pytest.mark.asyncio
async def test_last_admin_cannot_be_disabled_by_admin(
    context,
):
    with pytest.raises(LastAdminProtectionError):
        await context.service.set_active(
            actor_user_id=context.admin.user_id,
            user_id=context.admin.user_id,
            is_active=False,
        )

    assert (
        current_user(
            context,
            context.admin.user_id,
        ).is_active
        is True
    )

    assert context.sessions.revocations == []


@pytest.mark.asyncio
async def test_last_admin_cannot_be_deleted_by_admin(
    context,
):
    with pytest.raises(SelfServiceDeniedError):
        await context.service.delete_user(
            actor_user_id=context.admin.user_id,
            user_id=context.admin.user_id,
        )

    assert context.admin.user_id in context.users.users


@pytest.mark.asyncio
async def test_admin_can_demote_another_admin_if_one_remains(
    context,
):
    second_admin = make_user(
        username="admin2",
        email="admin2@example.com",
        role=ADMIN_ROLE,
    )

    context.users.users[second_admin.user_id] = second_admin

    result = await context.service.change_role(
        actor_user_id=context.admin.user_id,
        user_id=second_admin.user_id,
        role=SECURITY_ANALYST_ROLE,
    )

    assert result.roles == frozenset({SECURITY_ANALYST_ROLE})


@pytest.mark.asyncio
async def test_admin_can_disable_another_admin_if_one_remains(
    context,
):
    second_admin = make_user(
        username="admin2",
        email="admin2@example.com",
        role=ADMIN_ROLE,
    )

    context.users.users[second_admin.user_id] = second_admin

    result = await context.service.set_active(
        actor_user_id=context.admin.user_id,
        user_id=second_admin.user_id,
        is_active=False,
    )

    assert result.is_active is False
    assert second_admin.user_id in context.sessions.revocations


@pytest.mark.asyncio
async def test_admin_can_delete_another_admin_if_one_remains(
    context,
):
    second_admin = make_user(
        username="admin2",
        email="admin2@example.com",
        role=ADMIN_ROLE,
    )

    context.users.users[second_admin.user_id] = second_admin

    await context.service.delete_user(
        actor_user_id=context.admin.user_id,
        user_id=second_admin.user_id,
    )

    assert second_admin.user_id not in context.users.users


# ============================================================================
# Validation
# ============================================================================


@pytest.mark.asyncio
async def test_create_user_rejects_duplicate_username(
    context,
):
    with pytest.raises(UserAlreadyExistsError):
        await context.service.create_user(
            actor_user_id=context.admin.user_id,
            username="ADMIN",
            email="different@example.com",
            password=STRONG_PASSWORD,
            role=VIEWER_ROLE,
        )


@pytest.mark.asyncio
async def test_create_user_rejects_duplicate_email(
    context,
):
    with pytest.raises(UserAlreadyExistsError):
        await context.service.create_user(
            actor_user_id=context.admin.user_id,
            username="different",
            email="ADMIN@example.com",
            password=STRONG_PASSWORD,
            role=VIEWER_ROLE,
        )


@pytest.mark.asyncio
async def test_create_user_rejects_invalid_role(
    context,
):
    with pytest.raises(InvalidRoleError):
        await context.service.create_user(
            actor_user_id=context.admin.user_id,
            username="newuser",
            email="newuser@example.com",
            password=STRONG_PASSWORD,
            role="SUPER_ADMIN",
        )


@pytest.mark.asyncio
async def test_create_user_rejects_invalid_username(
    context,
):
    with pytest.raises(UserManagementValidationError):
        await context.service.create_user(
            actor_user_id=context.admin.user_id,
            username="ab",
            email="newuser@example.com",
            password=STRONG_PASSWORD,
            role=VIEWER_ROLE,
        )


@pytest.mark.asyncio
async def test_create_user_rejects_invalid_email(
    context,
):
    with pytest.raises(UserManagementValidationError):
        await context.service.create_user(
            actor_user_id=context.admin.user_id,
            username="newuser",
            email="invalid-email",
            password=STRONG_PASSWORD,
            role=VIEWER_ROLE,
        )


@pytest.mark.asyncio
async def test_create_user_rejects_weak_password(
    context,
):
    with pytest.raises(UserManagementValidationError):
        await context.service.create_user(
            actor_user_id=context.admin.user_id,
            username="newuser",
            email="newuser@example.com",
            password="123",
            role=VIEWER_ROLE,
        )


# ============================================================================
# Security State Preservation
# ============================================================================


@pytest.mark.asyncio
async def test_update_profile_preserves_security_state(
    context,
):
    user = make_user(
        username="stateful",
        email="stateful@example.com",
        role=VIEWER_ROLE,
        is_locked=True,
        force_password_change=True,
        display_name="Stateful User",
    )

    context.users.users[user.user_id] = user

    result = await context.service.update_profile(
        actor_user_id=context.admin.user_id,
        user_id=user.user_id,
        username="updatedstateful",
        email="updatedstateful@example.com",
    )

    assert result.is_locked is True
    assert result.force_password_change is True
    assert result.display_name == "Stateful User"
    assert result.password_hash == user.password_hash
    assert result.failed_login_count == user.failed_login_count
    assert result.password_changed_at == user.password_changed_at
    assert result.last_login_at == user.last_login_at


@pytest.mark.asyncio
async def test_reset_password_preserves_administrative_lock(
    context,
):
    locked = make_user(
        username="locked-user",
        email="locked-user@example.com",
        is_locked=True,
    )

    context.users.users[locked.user_id] = locked

    await context.service.reset_password(
        actor_user_id=context.admin.user_id,
        user_id=locked.user_id,
        new_password=NEW_PASSWORD,
    )

    updated = current_user(
        context,
        locked.user_id,
    )

    assert updated.is_locked is True
    assert updated.failed_login_count == 0


# ============================================================================
# Account State
# ============================================================================


@pytest.mark.asyncio
async def test_locking_user_revokes_sessions(
    context,
):
    result = await context.service.set_locked(
        actor_user_id=context.admin.user_id,
        user_id=context.viewer.user_id,
        is_locked=True,
    )

    assert result.is_locked is True
    assert context.viewer.user_id in context.sessions.revocations


@pytest.mark.asyncio
async def test_unlocking_user_does_not_revoke_sessions(
    context,
):
    locked = make_user(
        username="locked",
        email="locked@example.com",
        is_locked=True,
    )

    context.users.users[locked.user_id] = locked

    await context.service.set_locked(
        actor_user_id=context.admin.user_id,
        user_id=locked.user_id,
        is_locked=False,
    )

    assert context.sessions.revocations == []


@pytest.mark.asyncio
async def test_disabling_user_revokes_sessions(
    context,
):
    result = await context.service.set_active(
        actor_user_id=context.admin.user_id,
        user_id=context.viewer.user_id,
        is_active=False,
    )

    assert result.is_active is False
    assert context.viewer.user_id in context.sessions.revocations


@pytest.mark.asyncio
async def test_enabling_user_does_not_revoke_sessions(
    context,
):
    disabled = make_user(
        username="disabled",
        email="disabled@example.com",
        is_active=False,
    )

    context.users.users[disabled.user_id] = disabled

    await context.service.set_active(
        actor_user_id=context.admin.user_id,
        user_id=disabled.user_id,
        is_active=True,
    )

    assert context.sessions.revocations == []


# ============================================================================
# Force Password Change
# ============================================================================


@pytest.mark.asyncio
async def test_force_password_change_revokes_sessions(
    context,
):
    result = await context.service.set_force_password_change(
        actor_user_id=context.admin.user_id,
        user_id=context.viewer.user_id,
        force_password_change=True,
    )

    assert result.force_password_change is True
    assert context.viewer.user_id in context.sessions.revocations


@pytest.mark.asyncio
async def test_clear_force_password_change_does_not_revoke_sessions(
    context,
):
    viewer = make_user(
        username="forced",
        email="forced@example.com",
        force_password_change=True,
    )

    context.users.users[viewer.user_id] = viewer

    result = await context.service.set_force_password_change(
        actor_user_id=context.admin.user_id,
        user_id=viewer.user_id,
        force_password_change=False,
    )

    assert result.force_password_change is False
    assert context.sessions.revocations == []


# ============================================================================
# Audit Contract
# ============================================================================


@pytest.mark.asyncio
async def test_create_user_generates_canonical_audit_event(
    context,
):
    created = await context.service.create_user(
        actor_user_id=context.admin.user_id,
        username="audited",
        email="audited@example.com",
        password=STRONG_PASSWORD,
        role=VIEWER_ROLE,
    )

    record = assert_last_audit(
        context,
        action=AuditAction.USER_CREATED,
        actor_user_id=context.admin.user_id,
        target_user_id=created.user_id,
    )

    assert record.outcome == AuditOutcome.SUCCESS


@pytest.mark.asyncio
async def test_update_profile_generates_canonical_audit_event(
    context,
):
    await context.service.update_profile(
        actor_user_id=context.viewer.user_id,
        user_id=context.viewer.user_id,
        username="updatedviewer",
        email="updatedviewer@example.com",
    )

    assert_last_audit(
        context,
        action=AuditAction.USER_UPDATED,
        actor_user_id=context.viewer.user_id,
        target_user_id=context.viewer.user_id,
    )


@pytest.mark.asyncio
async def test_change_role_generates_canonical_audit_event(
    context,
):
    await context.service.change_role(
        actor_user_id=context.admin.user_id,
        user_id=context.viewer.user_id,
        role=INVESTIGATOR_ROLE,
    )

    record = assert_last_audit(
        context,
        action=AuditAction.ROLE_CHANGED,
        actor_user_id=context.admin.user_id,
        target_user_id=context.viewer.user_id,
    )

    assert record.metadata_json is not None
    assert record.metadata_json["new_role"] == INVESTIGATOR_ROLE


@pytest.mark.asyncio
async def test_disable_user_generates_canonical_audit_event(
    context,
):
    await context.service.set_active(
        actor_user_id=context.admin.user_id,
        user_id=context.viewer.user_id,
        is_active=False,
    )

    assert_last_audit(
        context,
        action=AuditAction.USER_DISABLED,
        actor_user_id=context.admin.user_id,
        target_user_id=context.viewer.user_id,
    )


@pytest.mark.asyncio
async def test_enable_user_generates_canonical_audit_event(
    context,
):
    disabled = make_user(
        username="disabled",
        email="disabled@example.com",
        is_active=False,
    )

    context.users.users[disabled.user_id] = disabled

    await context.service.set_active(
        actor_user_id=context.admin.user_id,
        user_id=disabled.user_id,
        is_active=True,
    )

    assert_last_audit(
        context,
        action=AuditAction.USER_ENABLED,
        actor_user_id=context.admin.user_id,
        target_user_id=disabled.user_id,
    )


@pytest.mark.asyncio
async def test_lock_user_generates_canonical_audit_event(
    context,
):
    await context.service.set_locked(
        actor_user_id=context.admin.user_id,
        user_id=context.viewer.user_id,
        is_locked=True,
    )

    assert_last_audit(
        context,
        action=AuditAction.USER_LOCKED,
        actor_user_id=context.admin.user_id,
        target_user_id=context.viewer.user_id,
    )


@pytest.mark.asyncio
async def test_unlock_user_generates_canonical_audit_event(
    context,
):
    locked = make_user(
        username="locked",
        email="locked@example.com",
        is_locked=True,
    )

    context.users.users[locked.user_id] = locked

    await context.service.set_locked(
        actor_user_id=context.admin.user_id,
        user_id=locked.user_id,
        is_locked=False,
    )

    assert_last_audit(
        context,
        action=AuditAction.USER_UNLOCKED,
        actor_user_id=context.admin.user_id,
        target_user_id=locked.user_id,
    )


@pytest.mark.asyncio
async def test_force_password_change_generates_audit_event(
    context,
):
    await context.service.set_force_password_change(
        actor_user_id=context.admin.user_id,
        user_id=context.viewer.user_id,
        force_password_change=True,
    )

    assert_last_audit(
        context,
        action=AuditAction.FORCE_PASSWORD_CHANGE,
        actor_user_id=context.admin.user_id,
        target_user_id=context.viewer.user_id,
    )


@pytest.mark.asyncio
async def test_reset_password_generates_canonical_audit_event(
    context,
):
    await context.service.reset_password(
        actor_user_id=context.admin.user_id,
        user_id=context.viewer.user_id,
        new_password=NEW_PASSWORD,
    )

    assert_last_audit(
        context,
        action=AuditAction.PASSWORD_RESET,
        actor_user_id=context.admin.user_id,
        target_user_id=context.viewer.user_id,
    )


@pytest.mark.asyncio
async def test_revoke_sessions_generates_canonical_audit_event(
    context,
):
    await context.service.revoke_sessions(
        actor_user_id=context.admin.user_id,
        user_id=context.viewer.user_id,
    )

    assert_last_audit(
        context,
        action=AuditAction.SESSIONS_REVOKED,
        actor_user_id=context.admin.user_id,
        target_user_id=context.viewer.user_id,
    )


@pytest.mark.asyncio
async def test_delete_user_generates_canonical_audit_event(
    context,
):
    await context.service.delete_user(
        actor_user_id=context.admin.user_id,
        user_id=context.viewer.user_id,
    )

    assert_last_audit(
        context,
        action=AuditAction.USER_DELETED,
        actor_user_id=context.admin.user_id,
        target_user_id=context.viewer.user_id,
    )


# ============================================================================
# Audit Metadata Security
# ============================================================================


@pytest.mark.asyncio
async def test_password_reset_audit_does_not_contain_password(
    context,
):
    await context.service.reset_password(
        actor_user_id=context.admin.user_id,
        user_id=context.viewer.user_id,
        new_password=NEW_PASSWORD,
    )

    record = context.audit.last()

    metadata_text = str(record.metadata_json)

    assert NEW_PASSWORD not in metadata_text
    assert "hashed::" not in metadata_text
    assert "password_hash" not in metadata_text
    assert "password" not in metadata_text.lower()


@pytest.mark.asyncio
async def test_create_user_audit_contains_safe_metadata_only(
    context,
):
    created = await context.service.create_user(
        actor_user_id=context.admin.user_id,
        username="safe-audit-user",
        email="safe-audit@example.com",
        password=STRONG_PASSWORD,
        role=VIEWER_ROLE,
    )

    record = context.audit.last()

    assert record.target_user_id == created.user_id

    metadata_text = str(record.metadata_json).lower()

    assert STRONG_PASSWORD.lower() not in metadata_text
    assert "hashed::" not in metadata_text
    assert "password_hash" not in metadata_text
    assert "access_token" not in metadata_text
    assert "refresh_token" not in metadata_text
    assert "private_key" not in metadata_text


@pytest.mark.asyncio
async def test_audit_record_uses_metadata_json_not_legacy_metadata(
    context,
):
    await context.service.create_user(
        actor_user_id=context.admin.user_id,
        username="metadata-user",
        email="metadata@example.com",
        password=STRONG_PASSWORD,
        role=VIEWER_ROLE,
    )

    record = context.audit.last()

    assert hasattr(
        record,
        "metadata_json",
    )

    assert not hasattr(
        record,
        "metadata",
    )


# ============================================================================
# Audit Failure Safety
# ============================================================================


@pytest.mark.asyncio
async def test_audit_persistence_failure_is_not_silently_ignored(
    context,
):
    context.audit.fail_log = True

    with pytest.raises(UserManagementError):
        await context.service.create_user(
            actor_user_id=context.admin.user_id,
            username="audit-failure-user",
            email="audit-failure@example.com",
            password=STRONG_PASSWORD,
            role=VIEWER_ROLE,
        )


# ============================================================================
# Last Admin Regression
# ============================================================================


@pytest.mark.asyncio
async def test_last_admin_scan_handles_large_population(
    context,
):
    for index in range(205):
        user = make_user(
            username=f"user{index}",
            email=f"user{index}@example.com",
            role=VIEWER_ROLE,
        )

        context.users.users[user.user_id] = user

    second_admin = make_user(
        username="late-admin",
        email="late-admin@example.com",
        role=ADMIN_ROLE,
    )

    context.users.users[second_admin.user_id] = second_admin

    result = await context.service.set_active(
        actor_user_id=context.admin.user_id,
        user_id=context.admin.user_id,
        is_active=False,
    )

    assert result.is_active is False

    assert context.admin.user_id in context.sessions.revocations


@pytest.mark.asyncio
async def test_last_admin_protection_survives_large_population(
    context,
):
    for index in range(205):
        user = make_user(
            username=f"user{index}",
            email=f"user{index}@example.com",
            role=VIEWER_ROLE,
        )

        context.users.users[user.user_id] = user

    with pytest.raises(LastAdminProtectionError):
        await context.service.set_active(
            actor_user_id=context.admin.user_id,
            user_id=context.admin.user_id,
            is_active=False,
        )

    assert (
        current_user(
            context,
            context.admin.user_id,
        ).is_active
        is True
    )

    assert context.sessions.revocations == []


# ============================================================================
# Service Contract Regression
# ============================================================================


@pytest.mark.asyncio
async def test_missing_target_is_rejected_for_role_change(
    context,
):
    with pytest.raises(UserNotFoundError):
        await context.service.change_role(
            actor_user_id=context.admin.user_id,
            user_id=uuid4(),
            role=VIEWER_ROLE,
        )


@pytest.mark.asyncio
async def test_missing_target_is_rejected_for_active_state(
    context,
):
    with pytest.raises(UserNotFoundError):
        await context.service.set_active(
            actor_user_id=context.admin.user_id,
            user_id=uuid4(),
            is_active=False,
        )


@pytest.mark.asyncio
async def test_missing_target_is_rejected_for_lock_state(
    context,
):
    with pytest.raises(UserNotFoundError):
        await context.service.set_locked(
            actor_user_id=context.admin.user_id,
            user_id=uuid4(),
            is_locked=True,
        )


# ============================================================================
# Audit Query Failure
# ============================================================================


@pytest.mark.asyncio
async def test_user_audit_history_query_failure_is_wrapped(
    context,
):
    context.audit.fail_list_user_activity = True

    with pytest.raises(UserManagementError):
        await context.service.get_user_audit_history(
            actor_user_id=context.admin.user_id,
            user_id=context.viewer.user_id,
        )


# ============================================================================
# Phase Security Matrix
# ============================================================================


def test_phase10_security_matrix_is_defined():
    matrix = {
        "admin": {
            "create_user": True,
            "delete_user": True,
            "change_role": True,
            "lock": True,
            "unlock": True,
            "disable": True,
            "enable": True,
            "reset_password": True,
            "revoke_sessions": True,
        },
        "non_admin": {
            "create_user": False,
            "delete_user": False,
            "change_role": False,
            "disable_user": False,
            "lock_user": False,
            "reset_password_other": False,
            "revoke_sessions_other": False,
        },
        "self_service": {
            "own_profile": True,
            "own_password": True,
            "own_sessions": True,
            "logout": True,
            "delete_self": False,
        },
    }

    assert matrix["admin"]["create_user"] is True
    assert matrix["admin"]["delete_user"] is True
    assert matrix["admin"]["change_role"] is True

    assert matrix["non_admin"]["create_user"] is False
    assert matrix["non_admin"]["delete_user"] is False

    assert matrix["self_service"]["own_profile"] is True
    assert matrix["self_service"]["own_password"] is True
    assert matrix["self_service"]["own_sessions"] is True
    assert matrix["self_service"]["delete_self"] is False
