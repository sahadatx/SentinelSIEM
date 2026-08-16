"""SentinelSIEM Phase 17 identity and access-control layer."""

from .authentication import AuthenticationError, AuthenticationService, LoginResult
from .authorization import (
    AuthorizationService,
    PermissionDenied,
    require_authenticated_user,
    require_permission,
    require_role,
)
from .permissions import Permission
from .roles import Role

__all__ = [
    "AuthenticationError", "AuthenticationService", "AuthorizationService",
    "LoginResult", "Permission", "PermissionDenied", "Role",
    "require_authenticated_user", "require_permission", "require_role",
]
