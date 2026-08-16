from uuid import uuid4
import pytest
from app.auth.audit import InMemoryAuditSink
from app.auth.authorization import AuthorizationService, PermissionDenied, require_authenticated_user, require_permission, require_role
from app.auth.models import UserPrincipal
from app.auth.permissions import Permission
from app.auth.roles import Role, RoleRegistry


def principal(role: Role) -> UserPrincipal:
    registry = RoleRegistry()
    roles = frozenset({role.value})
    return UserPrincipal(uuid4(), "analyst", roles, registry.permissions_for(roles), uuid4())


def test_viewer_can_read_events() -> None:
    assert AuthorizationService().require_permission(principal(Role.VIEWER), Permission.EVENTS_READ.value).username == "analyst"


def test_viewer_cannot_manage_incidents() -> None:
    with pytest.raises(PermissionDenied):
        AuthorizationService().require_permission(principal(Role.VIEWER), Permission.INCIDENTS_MANAGE.value)


def test_dependency_guards() -> None:
    viewer = principal(Role.VIEWER)
    assert require_authenticated_user(viewer).username == "analyst"
    assert require_permission(Permission.EVENTS_READ.value)(viewer).username == "analyst"
    with pytest.raises(PermissionDenied):
        require_role(Role.ADMIN.value)(viewer)


def test_denials_are_audited() -> None:
    audit = InMemoryAuditSink()
    service = AuthorizationService(audit=audit)
    with pytest.raises(PermissionDenied):
        service.require_permission(None, Permission.SYSTEM_READ.value)
    assert audit.all()[-1].action == "authorization.denied"
