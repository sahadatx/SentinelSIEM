from __future__ import annotations

from uuid import uuid4

import pytest

from app.auth.audit import InMemoryAuditSink
from app.auth.authorization import (
    AuthorizationService,
    PermissionDenied,
    require_authenticated_user,
    require_permission,
    require_role,
)
from app.auth.models import UserPrincipal
from app.auth.permissions import Permission
from app.auth.roles import Role, RoleRegistry

# ==========================================================================
# Test Helpers
# ==========================================================================


def principal(role: Role) -> UserPrincipal:
    """
    Build a test UserPrincipal for a single application role.
    """

    registry = RoleRegistry()
    roles = frozenset({role.value})
    permissions = registry.permissions_for(roles)

    return UserPrincipal(
        uuid4(),
        "analyst",
        roles,
        permissions,
        uuid4(),
    )


# ==========================================================================
# Permission Tests
# ==========================================================================


def test_viewer_can_read_events() -> None:
    """
    VIEWER must have events:read permission.
    """

    service = AuthorizationService()

    user = service.require_permission(
        principal(Role.VIEWER),
        Permission.EVENTS_READ.value,
    )

    assert user.username == "analyst"


def test_viewer_cannot_manage_incidents() -> None:
    """
    VIEWER must not have incidents:manage permission.
    """

    service = AuthorizationService()

    with pytest.raises(PermissionDenied):
        service.require_permission(
            principal(Role.VIEWER),
            Permission.INCIDENTS_MANAGE.value,
        )


# ==========================================================================
# System Permission Tests
# ==========================================================================


def test_security_analyst_can_read_system() -> None:
    """
    SECURITY_ANALYST must have system:read permission.
    """

    service = AuthorizationService()

    user = service.require_permission(
        principal(Role.SECURITY_ANALYST),
        Permission.SYSTEM_READ.value,
    )

    assert user.username == "analyst"


def test_viewer_cannot_read_system() -> None:
    """
    VIEWER must not have system:read permission.
    """

    service = AuthorizationService()

    with pytest.raises(PermissionDenied):
        service.require_permission(
            principal(Role.VIEWER),
            Permission.SYSTEM_READ.value,
        )


# ==========================================================================
# Dependency Guard Tests
# ==========================================================================


def test_dependency_guards() -> None:
    """
    Authentication, permission, and role dependency guards
    must enforce their respective boundaries.
    """

    viewer = principal(Role.VIEWER)

    authenticated_user = require_authenticated_user(viewer)

    assert authenticated_user.username == "analyst"

    permitted_user = require_permission(
        Permission.EVENTS_READ.value,
    )(viewer)

    assert permitted_user.username == "analyst"

    with pytest.raises(PermissionDenied):
        require_role(Role.ADMIN.value)(viewer)


# ==========================================================================
# Authorization Audit Tests
# ==========================================================================


def test_denials_are_audited() -> None:
    """
    Permission denial must produce an authorization audit event.
    """

    audit = InMemoryAuditSink()

    service = AuthorizationService(
        audit=audit,
    )

    with pytest.raises(PermissionDenied):
        service.require_permission(
            None,
            Permission.SYSTEM_READ.value,
        )

    assert audit.all()[-1].action == "authorization.denied"
