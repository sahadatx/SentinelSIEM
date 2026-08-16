from uuid import uuid4
from app.auth.models import UserPrincipal
from app.auth.permissions import Permission
from app.auth.roles import Role, RoleRegistry


def make_principal(role: Role) -> UserPrincipal:
    roles = frozenset({role.value})
    permissions = RoleRegistry().permissions_for(roles)
    return UserPrincipal(uuid4(), "user", roles, permissions, uuid4())


def test_viewer_is_least_privilege() -> None:
    viewer = make_principal(Role.VIEWER)
    assert Permission.EVENTS_READ.value in viewer.permissions
    assert Permission.INCIDENTS_MANAGE.value not in viewer.permissions
    assert Permission.USERS_MANAGE.value not in viewer.permissions
    assert Permission.ROLES_MANAGE.value not in viewer.permissions


def test_admin_has_all_permissions() -> None:
    admin = make_principal(Role.ADMIN)
    assert admin.permissions == frozenset(p.value for p in Permission)
