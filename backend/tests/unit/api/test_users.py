"""
SentinelSIEM User Management API Route Tests
============================================

API-level tests for:

    app.api.routes.users

Test Scope
----------

These tests verify:

    - canonical route contract
    - HTTP methods and paths
    - authentication dependency wiring
    - permission dependency wiring
    - request validation
    - service invocation
    - request metadata propagation
    - HTTP exception mapping
    - safe response serialization
    - credential/secret non-disclosure
    - user filtering
    - pagination
    - user creation
    - profile updates
    - role changes
    - enable/disable
    - lock/unlock
    - password reset
    - session revocation
    - user deletion
    - public signup absence

Business rules such as:

    - last-admin protection
    - self-action protection
    - password policy
    - role validity

are represented here only through service exceptions.

Their complete business behavior belongs to the service-layer tests.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.api.dependencies import (
    get_current_principal,
    get_user_management_service,
)

from app.api.routes.users import (
    roles_manage_permission,
    router as users_router,
    users_manage_permission,
    users_read_permission,
)

from app.auth.permissions import Permission

from app.auth.user_management import (
    InvalidRoleError,
    LastAdminProtectionError,
    SelfServiceDeniedError,
    UserAlreadyExistsError,
    UserNotFoundError,
)


# =============================================================================
# Constants
# =============================================================================


READ_PERMISSION = Permission.USERS_READ.value
MANAGE_PERMISSION = Permission.USERS_MANAGE.value

NOW = datetime.now(UTC)


FORBIDDEN_RESPONSE_FIELDS = frozenset(
    {
        "password",
        "password_hash",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "secret",
        "session_token",
        "jwt",
        "jti",
        "token_id",
        "private_key",
    }
)


EXPECTED_READ_ROUTES = {
    ("GET", "/users"),
    ("GET", "/users/statistics"),
    ("GET", "/users/{user_id}"),
    ("GET", "/users/{user_id}/audit"),
}


EXPECTED_MANAGE_ROUTES = {
    ("POST", "/users"),
    ("PATCH", "/users/{user_id}"),
    ("PATCH", "/users/{user_id}/role"),
    ("PATCH", "/users/{user_id}/active"),
    ("PATCH", "/users/{user_id}/lock"),
    ("POST", "/users/{user_id}/password/reset"),
    ("POST", "/users/{user_id}/sessions/revoke"),
    ("DELETE", "/users/{user_id}"),
}


EXPECTED_ALL_ROUTES = (
    EXPECTED_READ_ROUTES
    | EXPECTED_MANAGE_ROUTES
)


# =============================================================================
# User Factory
# =============================================================================


def make_user(
    *,
    user_id: UUID | None = None,
    username: str = "alice",
    email: str = "alice@example.com",
    roles: frozenset[str] | None = None,
    is_active: bool = True,
    is_locked: bool = False,
    failed_login_count: int = 0,
    display_name: str | None = None,
    force_password_change: bool = False,
):
    """
    Build a minimal UserIdentity-like object.

    Sensitive fields are intentionally attached so that API response
    serialization is tested against accidental credential leakage.
    """

    return SimpleNamespace(
        user_id=user_id or uuid4(),
        username=username,
        email=email,
        roles=roles or frozenset({"VIEWER"}),
        is_active=is_active,
        is_locked=is_locked,
        failed_login_count=failed_login_count,
        display_name=display_name,
        force_password_change=force_password_change,
        password_changed_at=NOW,
        last_login_at=NOW,
        created_at=NOW,
        updated_at=NOW,

        # ------------------------------------------------------------------
        # Sensitive fields intentionally present.
        # ------------------------------------------------------------------

        password_hash="MUST_NEVER_BE_RETURNED",
        password="MUST_NEVER_BE_RETURNED",
        token="MUST_NEVER_BE_RETURNED",
        access_token="MUST_NEVER_BE_RETURNED",
        refresh_token="MUST_NEVER_BE_RETURNED",
        api_key="MUST_NEVER_BE_RETURNED",
        secret="MUST_NEVER_BE_RETURNED",
        session_token="MUST_NEVER_BE_RETURNED",
        jwt="MUST_NEVER_BE_RETURNED",
        jti="MUST_NEVER_BE_RETURNED",
        token_id="MUST_NEVER_BE_RETURNED",
        private_key="MUST_NEVER_BE_RETURNED",
    )


# =============================================================================
# Route Helpers
# =============================================================================


def canonical_path(path: str) -> str:
    """
    Normalize route paths while preserving root '/'.
    """

    if path == "/":
        return "/"

    return path.rstrip("/")


def get_router_routes() -> list[APIRoute]:
    """
    Return concrete APIRoute instances registered directly on users_router.
    """

    return [
        route
        for route in users_router.routes
        if isinstance(route, APIRoute)
    ]


def router_route_keys() -> set[tuple[str, str]]:
    """
    Return all concrete (METHOD, PATH) pairs registered on users_router.
    """

    discovered: set[tuple[str, str]] = set()

    for route in get_router_routes():
        path = canonical_path(route.path)

        for method in route.methods:
            discovered.add(
                (
                    method.upper(),
                    path,
                )
            )

    return discovered


def route_by_router_path(
    path: str,
    method: str,
) -> APIRoute:
    """
    Resolve a concrete route directly from users_router.
    """

    normalized_method = method.upper()
    normalized_path = canonical_path(path)

    for route in get_router_routes():
        if normalized_method not in route.methods:
            continue

        if canonical_path(route.path) == normalized_path:
            return route

    raise AssertionError(
        f"Route not found: "
        f"{normalized_method} {normalized_path}. "
        f"Discovered routes: {sorted(router_route_keys())}",
    )


# =============================================================================
# Response Security Helpers
# =============================================================================


def assert_safe_response(
    body: dict,
) -> None:
    """
    Assert that security-sensitive fields are absent.
    """

    assert FORBIDDEN_RESPONSE_FIELDS.isdisjoint(
        body.keys(),
    )


def assert_safe_user_response(
    body: dict,
) -> None:
    """
    Assert that a serialized user contains no forbidden credential fields.
    """

    assert_safe_response(body)


def assert_safe_user_list_response(
    body: dict,
) -> None:
    """
    Assert that every serialized user is safe.
    """

    for user in body.get("users", []):
        assert_safe_user_response(user)


# =============================================================================
# Dependency Helpers
# =============================================================================


def dependency_tree_contains(
    dependant,
    target_callable,
) -> bool:
    """
    Recursively search a FastAPI dependency tree.
    """

    for dependency in dependant.dependencies:
        if dependency.call is target_callable:
            return True

        if dependency_tree_contains(
            dependency,
            target_callable,
        ):
            return True

    return False


def assert_route_has_dependency(
    route: APIRoute,
    dependency_callable,
) -> None:
    """
    Assert that a route contains the expected dependency.
    """

    assert dependency_tree_contains(
        route.dependant,
        dependency_callable,
    ), (
        f"{route.path} is missing dependency "
        f"{dependency_callable!r}"
    )


# =============================================================================
# Fake User Management Service
# =============================================================================


class FakeUserManagementService:
    """
    API-level UserManagementService test double.

    The fake intentionally mirrors the public method signatures consumed
    by the User Management routes.

    These tests do not replace service-layer business-rule tests.
    """

    def __init__(self):
        self.actor_user_id = uuid4()

        self.target_user = make_user(
            user_id=uuid4(),
            username="alice",
            email="alice@example.com",
            roles=frozenset({"VIEWER"}),
            display_name="Alice",
        )

        self.users = [
            self.target_user,
            make_user(
                user_id=uuid4(),
                username="bob",
                email="bob@example.com",
                roles=frozenset({"SOC_ANALYST"}),
                display_name="Bob",
            ),
        ]

        # ------------------------------------------------------------------
        # Captured calls
        # ------------------------------------------------------------------

        self.list_calls: list[dict] = []
        self.statistics_calls: list[dict] = []
        self.get_calls: list[dict] = []
        self.created_users: list[dict] = []
        self.updated_users: list[dict] = []
        self.role_changes: list[dict] = []
        self.active_changes: list[dict] = []
        self.lock_changes: list[dict] = []
        self.password_resets: list[dict] = []
        self.session_revocations: list[dict] = []
        self.deleted_users: list[dict] = []

        # ------------------------------------------------------------------
        # Configurable exceptions
        # ------------------------------------------------------------------

        self.raise_list: Exception | None = None
        self.raise_statistics: Exception | None = None
        self.raise_get: Exception | None = None
        self.raise_create: Exception | None = None
        self.raise_update: Exception | None = None
        self.raise_role: Exception | None = None
        self.raise_active: Exception | None = None
        self.raise_locked: Exception | None = None
        self.raise_password_reset: Exception | None = None
        self.raise_revoke: Exception | None = None
        self.raise_delete: Exception | None = None

    # =========================================================================
    # Read Operations
    # =========================================================================

    async def list_users(
        self,
        *,
        actor_user_id=None,
        search=None,
        role=None,
        is_active=None,
        is_locked=None,
        force_password_change=None,
        created_from=None,
        created_to=None,
        last_login_from=None,
        last_login_to=None,
        limit=30,
        offset=0,
        request_id=None,
        source_ip=None,
    ):
        if self.raise_list:
            raise self.raise_list

        self.list_calls.append(
            {
                "actor_user_id": actor_user_id,
                "search": search,
                "role": role,
                "is_active": is_active,
                "is_locked": is_locked,
                "force_password_change": force_password_change,
                "created_from": created_from,
                "created_to": created_to,
                "last_login_from": last_login_from,
                "last_login_to": last_login_to,
                "limit": limit,
                "offset": offset,
                "request_id": request_id,
                "source_ip": source_ip,
            }
        )

        filtered = list(self.users)

        if search:
            needle = search.lower()

            filtered = [
                user
                for user in filtered
                if (
                    needle in user.username.lower()
                    or needle in user.email.lower()
                    or needle
                    in (
                        getattr(
                            user,
                            "display_name",
                            None,
                        )
                        or ""
                    ).lower()
                )
            ]

        if role is not None:
            filtered = [
                user
                for user in filtered
                if role in user.roles
            ]

        if is_active is not None:
            filtered = [
                user
                for user in filtered
                if user.is_active == is_active
            ]

        if is_locked is not None:
            filtered = [
                user
                for user in filtered
                if user.is_locked == is_locked
            ]

        if force_password_change is not None:
            filtered = [
                user
                for user in filtered
                if user.force_password_change
                == force_password_change
            ]

        if created_from is not None:
            filtered = [
                user
                for user in filtered
                if user.created_at >= created_from
            ]

        if created_to is not None:
            filtered = [
                user
                for user in filtered
                if user.created_at <= created_to
            ]

        if last_login_from is not None:
            filtered = [
                user
                for user in filtered
                if user.last_login_at >= last_login_from
            ]

        if last_login_to is not None:
            filtered = [
                user
                for user in filtered
                if user.last_login_at <= last_login_to
            ]

        paginated = filtered[
            offset : offset + limit
        ]

        total = len(filtered)
        total_pages = (
            (total + limit - 1) // limit
            if total > 0
            else 0
        )

        return SimpleNamespace(
            users=paginated,
            total=total,
            total_pages=total_pages,
            limit=limit,
            offset=offset,
        )

    async def statistics(
        self,
        *,
        actor_user_id=None,
        request_id=None,
        source_ip=None,
    ):
        if self.raise_statistics:
            raise self.raise_statistics

        self.statistics_calls.append(
            {
                "actor_user_id": actor_user_id,
                "request_id": request_id,
                "source_ip": source_ip,
            }
        )

        return SimpleNamespace(
            total=len(self.users),
            active=sum(
                user.is_active
                for user in self.users
            ),
            disabled=sum(
                not user.is_active
                for user in self.users
            ),
            locked=sum(
                user.is_locked
                for user in self.users
            ),
        )

    async def get_user(
        self,
        *,
        actor_user_id=None,
        user_id: UUID,
        request_id=None,
        source_ip=None,
    ):
        if self.raise_get:
            raise self.raise_get

        self.get_calls.append(
            {
                "actor_user_id": actor_user_id,
                "user_id": user_id,
                "request_id": request_id,
                "source_ip": source_ip,
            }
        )

        for user in self.users:
            if user.user_id == user_id:
                return user

        raise UserNotFoundError(
            "User does not exist.",
        )

    # =========================================================================
    # Create
    # =========================================================================

    async def create_user(
        self,
        *,
        actor_user_id,
        username,
        email,
        password,
        role,
        is_active=True,
        display_name=None,
        request_id=None,
        source_ip=None,
    ):
        """
        Match the production create_user() contract.

        IMPORTANT:

        display_name is intentionally accepted here because the route
        forwards it to the service.
        """

        if self.raise_create:
            raise self.raise_create

        user = make_user(
            username=username,
            email=email,
            roles=frozenset({role}),
            is_active=is_active,
            display_name=display_name,
        )

        self.created_users.append(
            {
                "actor_user_id": actor_user_id,
                "username": username,
                "email": email,
                "password": password,
                "role": role,
                "is_active": is_active,
                "display_name": display_name,
                "request_id": request_id,
                "source_ip": source_ip,
            }
        )

        self.users.append(user)

        return user

    # =========================================================================
    # Profile Update
    # =========================================================================

    async def update_profile(
        self,
        *,
        actor_user_id,
        user_id,
        username,
        email,
        display_name=None,
        request_id=None,
        source_ip=None,
    ):
        if self.raise_update:
            raise self.raise_update

        user = await self.get_user(
            actor_user_id=actor_user_id,
            user_id=user_id,
            request_id=request_id,
            source_ip=source_ip,
        )

        updated = make_user(
            user_id=user.user_id,
            username=username,
            email=email,
            roles=user.roles,
            is_active=user.is_active,
            is_locked=user.is_locked,
            failed_login_count=user.failed_login_count,
            display_name=display_name,
            force_password_change=user.force_password_change,
        )

        self.updated_users.append(
            {
                "actor_user_id": actor_user_id,
                "user_id": user_id,
                "username": username,
                "email": email,
                "display_name": display_name,
                "request_id": request_id,
                "source_ip": source_ip,
            }
        )

        self.users = [
            updated
            if item.user_id == user_id
            else item
            for item in self.users
        ]

        return updated

    # =========================================================================
    # Role
    # =========================================================================

    async def change_role(
        self,
        *,
        actor_user_id,
        user_id,
        role,
        request_id=None,
        source_ip=None,
    ):
        if self.raise_role:
            raise self.raise_role

        user = await self.get_user(
            actor_user_id=actor_user_id,
            user_id=user_id,
            request_id=request_id,
            source_ip=source_ip,
        )

        updated = make_user(
            user_id=user.user_id,
            username=user.username,
            email=user.email,
            roles=frozenset({role}),
            is_active=user.is_active,
            is_locked=user.is_locked,
            failed_login_count=user.failed_login_count,
            display_name=user.display_name,
            force_password_change=user.force_password_change,
        )

        self.role_changes.append(
            {
                "actor_user_id": actor_user_id,
                "user_id": user_id,
                "role": role,
                "request_id": request_id,
                "source_ip": source_ip,
            }
        )

        self.users = [
            updated
            if item.user_id == user_id
            else item
            for item in self.users
        ]

        return updated

    # =========================================================================
    # Active State
    # =========================================================================

    async def set_active(
        self,
        *,
        actor_user_id,
        user_id,
        is_active,
        request_id=None,
        source_ip=None,
    ):
        if self.raise_active:
            raise self.raise_active

        user = await self.get_user(
            actor_user_id=actor_user_id,
            user_id=user_id,
            request_id=request_id,
            source_ip=source_ip,
        )

        updated = make_user(
            user_id=user.user_id,
            username=user.username,
            email=user.email,
            roles=user.roles,
            is_active=is_active,
            is_locked=user.is_locked,
            failed_login_count=user.failed_login_count,
            display_name=user.display_name,
            force_password_change=user.force_password_change,
        )

        self.active_changes.append(
            {
                "actor_user_id": actor_user_id,
                "user_id": user_id,
                "is_active": is_active,
                "request_id": request_id,
                "source_ip": source_ip,
            }
        )

        self.users = [
            updated
            if item.user_id == user_id
            else item
            for item in self.users
        ]

        return updated

    # =========================================================================
    # Lock State
    # =========================================================================

    async def set_locked(
        self,
        *,
        actor_user_id,
        user_id,
        is_locked,
        request_id=None,
        source_ip=None,
    ):
        if self.raise_locked:
            raise self.raise_locked

        user = await self.get_user(
            actor_user_id=actor_user_id,
            user_id=user_id,
            request_id=request_id,
            source_ip=source_ip,
        )

        updated = make_user(
            user_id=user.user_id,
            username=user.username,
            email=user.email,
            roles=user.roles,
            is_active=user.is_active,
            is_locked=is_locked,
            failed_login_count=user.failed_login_count,
            display_name=user.display_name,
            force_password_change=user.force_password_change,
        )

        self.lock_changes.append(
            {
                "actor_user_id": actor_user_id,
                "user_id": user_id,
                "is_locked": is_locked,
                "request_id": request_id,
                "source_ip": source_ip,
            }
        )

        self.users = [
            updated
            if item.user_id == user_id
            else item
            for item in self.users
        ]

        return updated

    # =========================================================================
    # Password Reset
    # =========================================================================

    async def reset_password(
        self,
        *,
        actor_user_id,
        user_id,
        new_password,
        request_id=None,
        source_ip=None,
    ):
        if self.raise_password_reset:
            raise self.raise_password_reset

        await self.get_user(
            actor_user_id=actor_user_id,
            user_id=user_id,
            request_id=request_id,
            source_ip=source_ip,
        )

        self.password_resets.append(
            {
                "actor_user_id": actor_user_id,
                "user_id": user_id,
                "new_password": new_password,
                "request_id": request_id,
                "source_ip": source_ip,
            }
        )

        return 3

    # =========================================================================
    # Session Revocation
    # =========================================================================

    async def revoke_sessions(
        self,
        *,
        actor_user_id,
        user_id,
        request_id=None,
        source_ip=None,
    ):
        if self.raise_revoke:
            raise self.raise_revoke

        await self.get_user(
            actor_user_id=actor_user_id,
            user_id=user_id,
            request_id=request_id,
            source_ip=source_ip,
        )

        self.session_revocations.append(
            {
                "actor_user_id": actor_user_id,
                "user_id": user_id,
                "request_id": request_id,
                "source_ip": source_ip,
            }
        )

        return 4

    # =========================================================================
    # Delete
    # =========================================================================

    async def delete_user(
        self,
        *,
        actor_user_id,
        user_id,
        request_id=None,
        source_ip=None,
    ):
        if self.raise_delete:
            raise self.raise_delete

        await self.get_user(
            actor_user_id=actor_user_id,
            user_id=user_id,
            request_id=request_id,
            source_ip=source_ip,
        )

        self.deleted_users.append(
            {
                "actor_user_id": actor_user_id,
                "user_id": user_id,
                "request_id": request_id,
                "source_ip": source_ip,
            }
        )

        self.users = [
            user
            for user in self.users
            if user.user_id != user_id
        ]


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def fake_service():
    return FakeUserManagementService()


@pytest.fixture
def allowed_permissions():
    return {
        READ_PERMISSION,
        MANAGE_PERMISSION,
    }


@pytest.fixture
def app(
    fake_service,
    allowed_permissions,
):
    app = FastAPI()

    app.include_router(users_router)

    # -------------------------------------------------------------------------
    # User Management Service
    # -------------------------------------------------------------------------

    async def override_service():
        return fake_service

    app.dependency_overrides[
        get_user_management_service
    ] = override_service

    # -------------------------------------------------------------------------
    # Current Principal
    # -------------------------------------------------------------------------

    async def override_principal():
        return SimpleNamespace(
            user_id=fake_service.actor_user_id,
            username="admin",
            roles=frozenset({"ADMIN"}),
        )

    app.dependency_overrides[
        get_current_principal
    ] = override_principal

    # -------------------------------------------------------------------------
    # users:read
    # -------------------------------------------------------------------------

    async def override_users_read_permission():
        if READ_PERMISSION not in allowed_permissions:
            raise HTTPException(
                status_code=403,
                detail="Permission denied.",
            )

        return True

    app.dependency_overrides[
        users_read_permission
    ] = override_users_read_permission

    # -------------------------------------------------------------------------
    # users:manage
    # -------------------------------------------------------------------------

    async def override_users_manage_permission():
        if MANAGE_PERMISSION not in allowed_permissions:
            raise HTTPException(
                status_code=403,
                detail="Permission denied.",
            )

        return True

    app.dependency_overrides[
        users_manage_permission
    ] = override_users_manage_permission

    # -------------------------------------------------------------------------
    # roles:manage
    #
    # The test contract intentionally treats manage permission as sufficient
    # for this API-level dependency override. Dedicated permission semantics
    # remain outside these route tests.
    # -------------------------------------------------------------------------

    async def override_roles_manage_permission():
        if MANAGE_PERMISSION not in allowed_permissions:
            raise HTTPException(
                status_code=403,
                detail="Permission denied.",
            )

        return True

    app.dependency_overrides[
        roles_manage_permission
    ] = override_roles_manage_permission

    return app


@pytest.fixture
def client(app):
    return TestClient(app)


# =============================================================================
# Read Endpoints
# =============================================================================


def test_list_users(
    client,
    fake_service,
):
    response = client.get("/users")

    assert response.status_code == 200

    body = response.json()

    assert body["limit"] == 30
    assert body["offset"] == 0
    assert body["total"] == 2
    assert body["total_pages"] == 1

    assert len(body["users"]) == 2

    assert body["users"][0]["username"] == "alice"
    assert body["users"][0]["email"] == "alice@example.com"
    assert body["users"][0]["display_name"] == "Alice"

    assert_safe_user_list_response(body)

    assert (
        fake_service.list_calls[0]["actor_user_id"]
        == fake_service.actor_user_id
    )


def test_list_users_uses_canonical_default_page_size(
    client,
    fake_service,
):
    response = client.get("/users")

    assert response.status_code == 200

    call = fake_service.list_calls[0]

    assert call["limit"] == 30
    assert call["offset"] == 0

    body = response.json()

    assert body["limit"] == 30
    assert body["offset"] == 0
    assert body["total"] == 2
    assert body["total_pages"] == 1


def test_list_users_filters_by_search(
    client,
    fake_service,
):
    response = client.get(
        "/users",
        params={
            "search": "alice",
            "limit": 10,
            "offset": 0,
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["total"] == 1
    assert len(body["users"]) == 1
    assert body["users"][0]["username"] == "alice"

    call = fake_service.list_calls[0]

    assert call["search"] == "alice"
    assert call["limit"] == 10
    assert call["offset"] == 0


def test_list_users_filters_by_display_name(
    client,
):
    response = client.get(
        "/users",
        params={
            "search": "Alice",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["total"] == 1
    assert body["users"][0]["username"] == "alice"


def test_list_users_filters_by_role(
    client,
):
    response = client.get(
        "/users",
        params={
            "role": "SOC_ANALYST",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["total"] == 1
    assert body["users"][0]["username"] == "bob"


def test_list_users_filters_by_active_state(
    client,
    fake_service,
):
    fake_service.users.append(
        make_user(
            username="disabled",
            email="disabled@example.com",
            is_active=False,
        )
    )

    response = client.get(
        "/users",
        params={
            "is_active": "false",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["total"] == 1
    assert body["users"][0]["username"] == "disabled"


def test_list_users_filters_by_locked_state(
    client,
    fake_service,
):
    fake_service.users.append(
        make_user(
            username="locked",
            email="locked@example.com",
            is_locked=True,
        )
    )

    response = client.get(
        "/users",
        params={
            "is_locked": "true",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["total"] == 1
    assert body["users"][0]["username"] == "locked"


def test_list_users_filters_by_force_password_change(
    client,
    fake_service,
):
    fake_service.users[0].force_password_change = True

    response = client.get(
        "/users",
        params={
            "force_password_change": "true",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["total"] == 1
    assert body["users"][0]["username"] == "alice"


def test_list_users_filters_by_created_from(
    client,
):
    response = client.get(
        "/users",
        params={
            "created_from": NOW.isoformat(),
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["total"] == 2


def test_list_users_filters_by_created_to(
    client,
):
    response = client.get(
        "/users",
        params={
            "created_to": NOW.isoformat(),
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["total"] == 2


def test_list_users_filters_by_last_login_from(
    client,
):
    response = client.get(
        "/users",
        params={
            "last_login_from": NOW.isoformat(),
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["total"] == 2


def test_list_users_filters_by_last_login_to(
    client,
):
    response = client.get(
        "/users",
        params={
            "last_login_to": NOW.isoformat(),
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["total"] == 2


def test_list_users_pagination(client):
    response = client.get(
        "/users",
        params={
            "limit": 1,
            "offset": 1,
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["total"] == 2
    assert body["limit"] == 1
    assert body["offset"] == 1
    assert body["total_pages"] == 2

    assert len(body["users"]) == 1
    assert body["users"][0]["username"] == "bob"


def test_list_users_calculates_total_pages_from_backend_total(
    client,
    fake_service,
):
    # 61 users with a fixed page size of 30 must produce 3 pages.
    fake_service.users = [
        make_user(
            username=f"user{i}",
            email=f"user{i}@example.com",
        )
        for i in range(61)
    ]

    response = client.get("/users")

    assert response.status_code == 200

    body = response.json()

    assert body["total"] == 61
    assert body["limit"] == 30
    assert body["offset"] == 0
    assert body["total_pages"] == 3
    assert len(body["users"]) == 30


def test_list_users_returns_fewer_users_on_final_page(
    client,
    fake_service,
):
    fake_service.users = [
        make_user(
            username=f"user{i}",
            email=f"user{i}@example.com",
        )
        for i in range(61)
    ]

    response = client.get(
        "/users",
        params={
            "limit": 30,
            "offset": 60,
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["total"] == 61
    assert body["limit"] == 30
    assert body["offset"] == 60
    assert body["total_pages"] == 3
    assert len(body["users"]) == 1
    assert body["users"][0]["username"] == "user60"


def test_list_users_rejects_invalid_limit(client):
    response = client.get(
        "/users",
        params={
            "limit": 0,
        },
    )

    assert response.status_code == 422


def test_list_users_rejects_limit_above_maximum(client):
    response = client.get(
        "/users",
        params={
            "limit": 201,
        },
    )

    assert response.status_code == 422


def test_list_users_rejects_negative_offset(client):
    response = client.get(
        "/users",
        params={
            "offset": -1,
        },
    )

    assert response.status_code == 422


# =============================================================================
# Date Validation
# =============================================================================


def test_list_users_rejects_invalid_created_date_range(client):
    response = client.get(
        "/users",
        params={
            "created_from": NOW.isoformat(),
            "created_to": (
                NOW.replace(
                    year=NOW.year - 1,
                ).isoformat()
            ),
        },
    )

    assert response.status_code == 422


def test_list_users_rejects_invalid_last_login_date_range(client):
    response = client.get(
        "/users",
        params={
            "last_login_from": NOW.isoformat(),
            "last_login_to": (
                NOW.replace(
                    year=NOW.year - 1,
                ).isoformat()
            ),
        },
    )

    assert response.status_code == 422


# =============================================================================
# Statistics
# =============================================================================


def test_user_statistics(
    client,
    fake_service,
):
    response = client.get(
        "/users/statistics",
    )

    assert response.status_code == 200

    assert response.json() == {
        "total": 2,
        "active": 2,
        "disabled": 0,
        "locked": 0,
    }

    assert (
        fake_service.statistics_calls[0]["actor_user_id"]
        == fake_service.actor_user_id
    )


# =============================================================================
# Get User
# =============================================================================


def test_get_user(
    client,
    fake_service,
):
    user_id = fake_service.target_user.user_id

    response = client.get(
        f"/users/{user_id}",
    )

    assert response.status_code == 200

    body = response.json()

    assert body["user_id"] == str(user_id)
    assert body["username"] == "alice"
    assert body["email"] == "alice@example.com"
    assert body["display_name"] == "Alice"

    assert_safe_user_response(body)

    call = fake_service.get_calls[0]

    assert call["actor_user_id"] == fake_service.actor_user_id
    assert call["user_id"] == user_id


def test_get_missing_user_returns_404(client):
    response = client.get(
        f"/users/{uuid4()}",
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "User not found."


def test_get_user_invalid_uuid_returns_422(client):
    response = client.get(
        "/users/not-a-uuid",
    )

    assert response.status_code == 422


# =============================================================================
# Request Metadata
# =============================================================================


def test_list_users_propagates_request_id(
    client,
    fake_service,
):
    response = client.get(
        "/users",
        headers={
            "X-Request-ID": "req-users-list-001",
        },
    )

    assert response.status_code == 200

    assert (
        fake_service.list_calls[0]["request_id"]
        == "req-users-list-001"
    )


def test_request_id_is_stripped(
    client,
    fake_service,
):
    response = client.get(
        "/users",
        headers={
            "X-Request-ID": "   request-123   ",
        },
    )

    assert response.status_code == 200

    assert (
        fake_service.list_calls[0]["request_id"]
        == "request-123"
    )


def test_empty_request_id_becomes_none(
    client,
    fake_service,
):
    response = client.get(
        "/users",
        headers={
            "X-Request-ID": "   ",
        },
    )

    assert response.status_code == 200

    assert (
        fake_service.list_calls[0]["request_id"]
        is None
    )


def test_x_forwarded_for_is_not_trusted(
    client,
    fake_service,
):
    response = client.get(
        "/users",
        headers={
            "X-Forwarded-For": "203.0.113.10",
        },
    )

    assert response.status_code == 200

    assert (
        fake_service.list_calls[0]["source_ip"]
        == "testclient"
    )


# =============================================================================
# Create User
# =============================================================================


def test_create_user(
    client,
    fake_service,
):
    response = client.post(
        "/users",
        json={
            "username": "charlie",
            "email": "charlie@example.com",
            "password": "StrongPassword123!",
            "role": "SOC_ANALYST",
            "is_active": True,
        },
    )

    assert response.status_code == 201

    body = response.json()

    assert body["username"] == "charlie"
    assert body["email"] == "charlie@example.com"
    assert body["roles"] == ["SOC_ANALYST"]
    assert body["is_active"] is True

    assert_safe_user_response(body)

    call = fake_service.created_users[0]

    assert (
        call["actor_user_id"]
        == fake_service.actor_user_id
    )

    assert call["username"] == "charlie"
    assert call["email"] == "charlie@example.com"
    assert call["role"] == "SOC_ANALYST"
    assert call["password"] == "StrongPassword123!"


def test_create_user_with_display_name(
    client,
    fake_service,
):
    response = client.post(
        "/users",
        json={
            "username": "charlie",
            "email": "charlie@example.com",
            "password": "StrongPassword123!",
            "role": "SOC_ANALYST",
            "is_active": True,
            "display_name": "Charlie User",
        },
    )

    assert response.status_code == 201

    body = response.json()

    assert body["display_name"] == "Charlie User"

    assert (
        fake_service.created_users[0]["display_name"]
        == "Charlie User"
    )


def test_create_user_duplicate_returns_409(
    client,
    fake_service,
):
    fake_service.raise_create = UserAlreadyExistsError(
        "Username or email already exists.",
    )

    response = client.post(
        "/users",
        json={
            "username": "alice",
            "email": "alice@example.com",
            "password": "StrongPassword123!",
            "role": "VIEWER",
            "is_active": True,
        },
    )

    assert response.status_code == 409


def test_create_user_invalid_role_returns_422(
    client,
    fake_service,
):
    fake_service.raise_create = InvalidRoleError(
        "Invalid role.",
    )

    response = client.post(
        "/users",
        json={
            "username": "charlie",
            "email": "charlie@example.com",
            "password": "StrongPassword123!",
            "role": "SUPER_ADMIN",
            "is_active": True,
        },
    )

    assert response.status_code == 422


def test_create_user_rejects_password_hash_field(client):
    response = client.post(
        "/users",
        json={
            "username": "charlie",
            "email": "charlie@example.com",
            "password": "StrongPassword123!",
            "role": "VIEWER",
            "is_active": True,
            "password_hash": "must-not-be-accepted",
        },
    )

    assert response.status_code == 422


def test_create_user_rejects_token_field(client):
    response = client.post(
        "/users",
        json={
            "username": "charlie",
            "email": "charlie@example.com",
            "password": "StrongPassword123!",
            "role": "VIEWER",
            "is_active": True,
            "token": "must-not-be-accepted",
        },
    )

    assert response.status_code == 422


# =============================================================================
# Update User
# =============================================================================


def test_update_user(
    client,
    fake_service,
):
    user_id = fake_service.target_user.user_id

    response = client.patch(
        f"/users/{user_id}",
        json={
            "username": "alice-new",
            "email": "alice-new@example.com",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["username"] == "alice-new"
    assert body["email"] == "alice-new@example.com"

    assert_safe_user_response(body)

    call = fake_service.updated_users[0]

    assert call["user_id"] == user_id
    assert call["username"] == "alice-new"
    assert call["email"] == "alice-new@example.com"


def test_update_user_with_display_name(
    client,
    fake_service,
):
    user_id = fake_service.target_user.user_id

    response = client.patch(
        f"/users/{user_id}",
        json={
            "username": "alice-new",
            "email": "alice-new@example.com",
            "display_name": "Alice Updated",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["display_name"] == "Alice Updated"

    assert (
        fake_service.updated_users[0]["display_name"]
        == "Alice Updated"
    )


def test_update_missing_user_returns_404(
    client,
    fake_service,
):
    fake_service.raise_update = UserNotFoundError(
        "User does not exist.",
    )

    response = client.patch(
        f"/users/{uuid4()}",
        json={
            "username": "missing",
            "email": "missing@example.com",
        },
    )

    assert response.status_code == 404


def test_update_user_rejects_password_field(client):
    response = client.patch(
        f"/users/{uuid4()}",
        json={
            "username": "alice",
            "email": "alice@example.com",
            "password": "MustNotBeAccepted123!",
        },
    )

    assert response.status_code == 422


def test_update_user_rejects_password_hash_field(client):
    response = client.patch(
        f"/users/{uuid4()}",
        json={
            "username": "alice",
            "email": "alice@example.com",
            "password_hash": "must-not-be-accepted",
        },
    )

    assert response.status_code == 422


# =============================================================================
# Role Management
# =============================================================================


def test_change_user_role(
    client,
    fake_service,
):
    user_id = fake_service.target_user.user_id

    response = client.patch(
        f"/users/{user_id}/role",
        json={
            "role": "SOC_ANALYST",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["roles"] == ["SOC_ANALYST"]

    assert (
        fake_service.role_changes[0]["role"]
        == "SOC_ANALYST"
    )

    assert_safe_user_response(body)


def test_change_role_last_admin_returns_409(
    client,
    fake_service,
):
    fake_service.raise_role = LastAdminProtectionError(
        "At least one active ADMIN must remain.",
    )

    response = client.patch(
        f"/users/{fake_service.target_user.user_id}/role",
        json={
            "role": "VIEWER",
        },
    )

    assert response.status_code == 409


def test_change_role_invalid_role_returns_422(
    client,
    fake_service,
):
    fake_service.raise_role = InvalidRoleError(
        "Invalid role.",
    )

    response = client.patch(
        f"/users/{fake_service.target_user.user_id}/role",
        json={
            "role": "INVALID",
        },
    )

    assert response.status_code == 422


# =============================================================================
# Active State
# =============================================================================


def test_disable_user(
    client,
    fake_service,
):
    user_id = fake_service.target_user.user_id

    response = client.patch(
        f"/users/{user_id}/active",
        json={
            "is_active": False,
        },
    )

    assert response.status_code == 200
    assert response.json()["is_active"] is False

    assert (
        fake_service.active_changes[0]["is_active"]
        is False
    )


def test_enable_user(
    client,
    fake_service,
):
    user_id = fake_service.target_user.user_id

    disabled_user = make_user(
        user_id=user_id,
        username=fake_service.target_user.username,
        email=fake_service.target_user.email,
        roles=fake_service.target_user.roles,
        is_active=False,
        is_locked=fake_service.target_user.is_locked,
        failed_login_count=fake_service.target_user.failed_login_count,
        display_name=fake_service.target_user.display_name,
        force_password_change=fake_service.target_user.force_password_change,
    )

    fake_service.users = [
        disabled_user
        if user.user_id == user_id
        else user
        for user in fake_service.users
    ]

    response = client.patch(
        f"/users/{user_id}/active",
        json={
            "is_active": True,
        },
    )

    assert response.status_code == 200
    assert response.json()["is_active"] is True


def test_disable_last_admin_returns_409(
    client,
    fake_service,
):
    fake_service.raise_active = LastAdminProtectionError(
        "At least one active ADMIN must remain.",
    )

    response = client.patch(
        f"/users/{fake_service.target_user.user_id}/active",
        json={
            "is_active": False,
        },
    )

    assert response.status_code == 409


def test_set_active_rejects_invalid_boolean(
    client,
    fake_service,
):
    response = client.patch(
        f"/users/{fake_service.target_user.user_id}/active",
        json={
            "is_active": "not-a-boolean",
        },
    )

    assert response.status_code == 422


# =============================================================================
# Lock State
# =============================================================================


def test_lock_user(
    client,
    fake_service,
):
    user_id = fake_service.target_user.user_id

    response = client.patch(
        f"/users/{user_id}/lock",
        json={
            "is_locked": True,
        },
    )

    assert response.status_code == 200
    assert response.json()["is_locked"] is True

    assert (
        fake_service.lock_changes[0]["is_locked"]
        is True
    )


def test_unlock_user(
    client,
    fake_service,
):
    user_id = fake_service.target_user.user_id

    locked_user = make_user(
        user_id=user_id,
        username=fake_service.target_user.username,
        email=fake_service.target_user.email,
        roles=fake_service.target_user.roles,
        is_active=fake_service.target_user.is_active,
        is_locked=True,
        failed_login_count=fake_service.target_user.failed_login_count,
        display_name=fake_service.target_user.display_name,
        force_password_change=fake_service.target_user.force_password_change,
    )

    fake_service.users = [
        locked_user
        if user.user_id == user_id
        else user
        for user in fake_service.users
    ]

    response = client.patch(
        f"/users/{user_id}/lock",
        json={
            "is_locked": False,
        },
    )

    assert response.status_code == 200
    assert response.json()["is_locked"] is False


def test_set_locked_rejects_invalid_boolean(
    client,
    fake_service,
):
    response = client.patch(
        f"/users/{fake_service.target_user.user_id}/lock",
        json={
            "is_locked": "not-a-boolean",
        },
    )

    assert response.status_code == 422


# =============================================================================
# Password Reset
# =============================================================================


def test_reset_password(
    client,
    fake_service,
):
    user_id = fake_service.target_user.user_id

    response = client.post(
        f"/users/{user_id}/password/reset",
        json={
            "new_password": "NewStrongPassword123!",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["success"] is True
    assert body["sessions_revoked"] == 3

    assert (
        fake_service.password_resets[0]["user_id"]
        == user_id
    )

    assert_safe_response(body)


def test_password_reset_does_not_return_password(
    client,
    fake_service,
):
    password = "UltraSecretPassword123!"

    response = client.post(
        f"/users/{fake_service.target_user.user_id}/password/reset",
        json={
            "new_password": password,
        },
    )

    assert response.status_code == 200

    response_text = response.text

    assert password not in response_text
    assert "password_hash" not in response_text


def test_password_reset_exception_is_mapped_to_404(
    client,
    fake_service,
):
    fake_service.raise_password_reset = UserNotFoundError(
        "User does not exist.",
    )

    response = client.post(
        f"/users/{uuid4()}/password/reset",
        json={
            "new_password": "NewStrongPassword123!",
        },
    )

    assert response.status_code == 404


# =============================================================================
# Session Revocation
# =============================================================================


def test_revoke_user_sessions(
    client,
    fake_service,
):
    user_id = fake_service.target_user.user_id

    response = client.post(
        f"/users/{user_id}/sessions/revoke",
    )

    assert response.status_code == 200

    body = response.json()

    assert body["success"] is True
    assert body["revoked_count"] == 4

    call = fake_service.session_revocations[0]

    assert call["user_id"] == user_id


# =============================================================================
# Delete User
# =============================================================================


def test_delete_user(
    client,
    fake_service,
):
    user_id = fake_service.target_user.user_id

    response = client.delete(
        f"/users/{user_id}",
    )

    assert response.status_code == 200

    body = response.json()

    assert body["success"] is True
    assert body["message"] == "User deleted successfully."

    assert (
        fake_service.deleted_users[0]["user_id"]
        == user_id
    )


def test_delete_self_returns_403(
    client,
    fake_service,
):
    fake_service.raise_delete = SelfServiceDeniedError(
        "Self-delete is not allowed.",
    )

    response = client.delete(
        f"/users/{fake_service.actor_user_id}",
    )

    assert response.status_code == 403


def test_delete_last_admin_returns_409(
    client,
    fake_service,
):
    fake_service.raise_delete = LastAdminProtectionError(
        "At least one active ADMIN must remain.",
    )

    response = client.delete(
        f"/users/{fake_service.target_user.user_id}",
    )

    assert response.status_code == 409


def test_delete_missing_user_returns_404(
    client,
    fake_service,
):
    fake_service.raise_delete = UserNotFoundError(
        "User does not exist.",
    )

    response = client.delete(
        f"/users/{uuid4()}",
    )

    assert response.status_code == 404


# =============================================================================
# Error Mapping
# =============================================================================


def test_service_user_not_found_maps_to_404(
    client,
    fake_service,
):
    fake_service.raise_get = UserNotFoundError(
        "internal user lookup details",
    )

    response = client.get(
        f"/users/{uuid4()}",
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "User not found."

    assert (
        "internal user lookup details"
        not in response.text
    )


def test_service_user_already_exists_maps_to_409(
    client,
    fake_service,
):
    fake_service.raise_create = UserAlreadyExistsError(
        "Username or email already exists.",
    )

    response = client.post(
        "/users",
        json={
            "username": "alice",
            "email": "alice@example.com",
            "password": "StrongPassword123!",
            "role": "VIEWER",
        },
    )

    assert response.status_code == 409


def test_service_self_action_maps_to_403(
    client,
    fake_service,
):
    fake_service.raise_delete = SelfServiceDeniedError(
        "Self-delete is not allowed.",
    )

    response = client.delete(
        f"/users/{fake_service.actor_user_id}",
    )

    assert response.status_code == 403


def test_service_last_admin_maps_to_409(
    client,
    fake_service,
):
    fake_service.raise_active = LastAdminProtectionError(
        "At least one active ADMIN must remain.",
    )

    response = client.patch(
        f"/users/{fake_service.target_user.user_id}/active",
        json={
            "is_active": False,
        },
    )

    assert response.status_code == 409


# =============================================================================
# Response Security
# =============================================================================


def test_user_detail_response_never_exposes_credentials(
    client,
    fake_service,
):
    response = client.get(
        f"/users/{fake_service.target_user.user_id}",
    )

    assert response.status_code == 200

    assert_safe_user_response(
        response.json(),
    )


def test_user_list_response_never_exposes_credentials(
    client,
):
    response = client.get(
        "/users",
    )

    assert response.status_code == 200

    assert_safe_user_list_response(
        response.json(),
    )


def test_create_response_never_exposes_credentials(
    client,
):
    response = client.post(
        "/users",
        json={
            "username": "charlie",
            "email": "charlie@example.com",
            "password": "StrongPassword123!",
            "role": "VIEWER",
        },
    )

    assert response.status_code == 201

    assert_safe_user_response(
        response.json(),
    )


def test_update_response_never_exposes_credentials(
    client,
    fake_service,
):
    response = client.patch(
        f"/users/{fake_service.target_user.user_id}",
        json={
            "username": "alice-new",
            "email": "alice-new@example.com",
        },
    )

    assert response.status_code == 200

    assert_safe_user_response(
        response.json(),
    )


def test_password_reset_response_contains_no_credential_fields(
    client,
    fake_service,
):
    response = client.post(
        f"/users/{fake_service.target_user.user_id}/password/reset",
        json={
            "new_password": "SuperSecret123!",
        },
    )

    assert response.status_code == 200

    assert_safe_response(
        response.json(),
    )


# =============================================================================
# Public Signup / Registration
# =============================================================================


def test_public_signup_endpoint_does_not_exist(
    client,
):
    response = client.post(
        "/users/signup",
        json={
            "username": "attacker",
            "email": "attacker@example.com",
            "password": "StrongPassword123!",
            "role": "ADMIN",
        },
    )

    assert response.status_code in {
        404,
        405,
    }


def test_public_users_register_endpoint_does_not_exist(
    client,
):
    response = client.post(
        "/users/register",
        json={
            "username": "attacker",
            "email": "attacker@example.com",
            "password": "StrongPassword123!",
            "role": "ADMIN",
        },
    )

    assert response.status_code in {
        404,
        405,
    }


def test_public_register_endpoint_does_not_exist(
    client,
):
    response = client.post(
        "/register",
        json={
            "username": "attacker",
            "email": "attacker@example.com",
            "password": "StrongPassword123!",
            "role": "ADMIN",
        },
    )

    assert response.status_code == 404


# =============================================================================
# Route Contract
# =============================================================================


def test_users_router_contains_exact_expected_route_contract():
    discovered = router_route_keys()

    assert discovered == EXPECTED_ALL_ROUTES, (
        "Unexpected User Management route contract.\n"
        f"Expected: {sorted(EXPECTED_ALL_ROUTES)}\n"
        f"Actual:   {sorted(discovered)}"
    )


def test_users_router_contains_expected_read_routes():
    discovered = router_route_keys()

    assert EXPECTED_READ_ROUTES.issubset(
        discovered,
    )


def test_users_router_contains_expected_manage_routes():
    discovered = router_route_keys()

    assert EXPECTED_MANAGE_ROUTES.issubset(
        discovered,
    )


def test_every_expected_route_is_resolvable():
    for method, path in sorted(
        EXPECTED_ALL_ROUTES,
    ):
        route = route_by_router_path(
            path,
            method,
        )

        assert method.upper() in route.methods
        assert canonical_path(route.path) == canonical_path(path)


# =============================================================================
# Permission Metadata
# =============================================================================


def test_users_read_permission_value():
    assert READ_PERMISSION == "users:read"


def test_users_manage_permission_value():
    assert MANAGE_PERMISSION == "users:manage"


def test_users_read_and_manage_are_distinct():
    assert READ_PERMISSION != MANAGE_PERMISSION


def test_users_read_permission_metadata_is_correct():
    assert (
        getattr(
            users_read_permission,
            "__permission__",
            None,
        )
        == READ_PERMISSION
    )


def test_users_manage_permission_metadata_is_correct():
    assert (
        getattr(
            users_manage_permission,
            "__permission__",
            None,
        )
        == MANAGE_PERMISSION
    )


# =============================================================================
# Permission Dependency Wiring
# =============================================================================


def test_read_routes_have_users_read_permission():
    for method, path in EXPECTED_READ_ROUTES:
        route = route_by_router_path(
            path,
            method,
        )

        assert_route_has_dependency(
            route,
            users_read_permission,
        )


def test_manage_routes_have_users_manage_permission():
    for method, path in EXPECTED_MANAGE_ROUTES:
        route = route_by_router_path(
            path,
            method,
        )

        assert_route_has_dependency(
            route,
            users_manage_permission,
        )


def test_role_change_has_roles_manage_permission():
    route = route_by_router_path(
        "/users/{user_id}/role",
        "PATCH",
    )

    assert_route_has_dependency(
        route,
        roles_manage_permission,
    )


def test_read_routes_do_not_require_manage_permission():
    for method, path in EXPECTED_READ_ROUTES:
        route = route_by_router_path(
            path,
            method,
        )

        assert not dependency_tree_contains(
            route.dependant,
            users_manage_permission,
        ), (
            f"{method} {path} unexpectedly requires "
            "users:manage"
        )


# =============================================================================
# Authorization Boundary
# =============================================================================


def test_users_read_denied_without_users_read_permission(
    client,
    allowed_permissions,
):
    allowed_permissions.remove(
        READ_PERMISSION,
    )

    response = client.get(
        "/users",
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Permission denied."


def test_statistics_denied_without_users_read_permission(
    client,
    allowed_permissions,
):
    allowed_permissions.remove(
        READ_PERMISSION,
    )

    response = client.get(
        "/users/statistics",
    )

    assert response.status_code == 403


def test_single_user_denied_without_users_read_permission(
    client,
    fake_service,
    allowed_permissions,
):
    allowed_permissions.remove(
        READ_PERMISSION,
    )

    response = client.get(
        f"/users/{fake_service.target_user.user_id}",
    )

    assert response.status_code == 403


def test_user_audit_denied_without_users_read_permission(
    client,
    allowed_permissions,
):
    allowed_permissions.remove(
        READ_PERMISSION,
    )

    response = client.get(
        f"/users/{uuid4()}/audit",
    )

    assert response.status_code == 403


def test_create_denied_without_users_manage_permission(
    client,
    allowed_permissions,
):
    allowed_permissions.remove(
        MANAGE_PERMISSION,
    )

    response = client.post(
        "/users",
        json={
            "username": "charlie",
            "email": "charlie@example.com",
            "password": "StrongPassword123!",
            "role": "VIEWER",
        },
    )

    assert response.status_code == 403


def test_update_denied_without_users_manage_permission(
    client,
    fake_service,
    allowed_permissions,
):
    allowed_permissions.remove(
        MANAGE_PERMISSION,
    )

    response = client.patch(
        f"/users/{fake_service.target_user.user_id}",
        json={
            "username": "alice-new",
            "email": "alice-new@example.com",
        },
    )

    assert response.status_code == 403


def test_role_change_denied_without_users_manage_permission(
    client,
    fake_service,
    allowed_permissions,
):
    allowed_permissions.remove(
        MANAGE_PERMISSION,
    )

    response = client.patch(
        f"/users/{fake_service.target_user.user_id}/role",
        json={
            "role": "SOC_ANALYST",
        },
    )

    assert response.status_code == 403


def test_active_change_denied_without_users_manage_permission(
    client,
    fake_service,
    allowed_permissions,
):
    allowed_permissions.remove(
        MANAGE_PERMISSION,
    )

    response = client.patch(
        f"/users/{fake_service.target_user.user_id}/active",
        json={
            "is_active": False,
        },
    )

    assert response.status_code == 403


def test_lock_change_denied_without_users_manage_permission(
    client,
    fake_service,
    allowed_permissions,
):
    allowed_permissions.remove(
        MANAGE_PERMISSION,
    )

    response = client.patch(
        f"/users/{fake_service.target_user.user_id}/lock",
        json={
            "is_locked": True,
        },
    )

    assert response.status_code == 403


def test_password_reset_denied_without_users_manage_permission(
    client,
    fake_service,
    allowed_permissions,
):
    allowed_permissions.remove(
        MANAGE_PERMISSION,
    )

    response = client.post(
        f"/users/{fake_service.target_user.user_id}/password/reset",
        json={
            "new_password": "NewStrongPassword123!",
        },
    )

    assert response.status_code == 403


def test_session_revoke_denied_without_users_manage_permission(
    client,
    fake_service,
    allowed_permissions,
):
    allowed_permissions.remove(
        MANAGE_PERMISSION,
    )

    response = client.post(
        f"/users/{fake_service.target_user.user_id}/sessions/revoke",
    )

    assert response.status_code == 403


def test_delete_denied_without_users_manage_permission(
    client,
    fake_service,
    allowed_permissions,
):
    allowed_permissions.remove(
        MANAGE_PERMISSION,
    )

    response = client.delete(
        f"/users/{fake_service.target_user.user_id}",
    )

    assert response.status_code == 403


def test_read_and_manage_permissions_are_independent(
    client,
    allowed_permissions,
):
    allowed_permissions.remove(
        READ_PERMISSION,
    )

    read_response = client.get(
        "/users",
    )

    manage_response = client.post(
        "/users",
        json={
            "username": "charlie",
            "email": "charlie@example.com",
            "password": "StrongPassword123!",
            "role": "VIEWER",
        },
    )

    assert read_response.status_code == 403
    assert manage_response.status_code == 201


def test_manage_denial_does_not_remove_read_access(
    client,
    fake_service,
    allowed_permissions,
):
    allowed_permissions.remove(
        MANAGE_PERMISSION,
    )

    read_response = client.get(
        "/users",
    )

    manage_response = client.delete(
        f"/users/{fake_service.target_user.user_id}",
    )

    assert read_response.status_code == 200
    assert manage_response.status_code == 403


# =============================================================================
# Forbidden Route Contract
# =============================================================================


def test_force_password_change_route_is_not_exposed(
    client,
    fake_service,
):
    response = client.patch(
        f"/users/{fake_service.target_user.user_id}/force-password-change",
        json={
            "force_password_change": True,
        },
    )

    assert response.status_code in {
        404,
        405,
    }


def test_session_listing_route_is_not_exposed(
    client,
    fake_service,
):
    response = client.get(
        f"/users/{fake_service.target_user.user_id}/sessions",
    )

    assert response.status_code in {
        404,
        405,
    }


# =============================================================================
# Dependency Graph Sanity
# =============================================================================


def test_every_expected_route_has_dependencies():
    for method, path in EXPECTED_ALL_ROUTES:
        route = route_by_router_path(
            path,
            method,
        )

        assert route.dependant.dependencies, (
            f"No dependencies found for "
            f"{method} {path}"
        )


def test_every_read_route_has_read_dependency():
    for method, path in EXPECTED_READ_ROUTES:
        route = route_by_router_path(
            path,
            method,
        )

        assert dependency_tree_contains(
            route.dependant,
            users_read_permission,
        )


def test_every_manage_route_has_manage_dependency():
    for method, path in EXPECTED_MANAGE_ROUTES:
        route = route_by_router_path(
            path,
            method,
        )

        assert dependency_tree_contains(
            route.dependant,
            users_manage_permission,
        )


# =============================================================================
# Route Ordering
# =============================================================================


def test_statistics_route_exists_as_static_route():
    route = route_by_router_path(
        "/users/statistics",
        "GET",
    )

    assert route.path == "/users/statistics"


def test_statistics_is_not_uuid_route():
    route = route_by_router_path(
        "/users/statistics",
        "GET",
    )

    assert "{user_id}" not in route.path


def test_nested_user_routes_exist_before_generic_route_contract():
    expected_nested_routes = {
        "/users/{user_id}/audit",
        "/users/{user_id}/role",
        "/users/{user_id}/active",
        "/users/{user_id}/lock",
        "/users/{user_id}/password/reset",
        "/users/{user_id}/sessions/revoke",
    }

    discovered_paths = {
        canonical_path(route.path)
        for route in get_router_routes()
    }

    assert expected_nested_routes.issubset(
        discovered_paths,
    )


# =============================================================================
# Final Contract Assertion
# =============================================================================


def test_users_router_has_exact_expected_route_contract():
    """
    Locked canonical User Management API contract.

    No additional route may silently be introduced.
    """

    assert router_route_keys() == EXPECTED_ALL_ROUTES
