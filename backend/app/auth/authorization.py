from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

from .audit import AuditSink
from .models import AuditRecord, UserPrincipal
from .policies import AuthorizationDecision, AuthorizationPolicy
from .roles import RoleRegistry


class PermissionDenied(Exception):
    def __init__(self, permission: str, reason: str = "permission_denied") -> None:
        self.permission = permission
        self.reason = reason
        super().__init__(f"Permission denied: {permission} ({reason})")


class AuthorizationService:
    """Single authorization boundary with default-deny behavior."""

    def __init__(self, role_registry: RoleRegistry | None = None,
                 policy: AuthorizationPolicy | None = None,
                 audit: AuditSink | None = None) -> None:
        self._roles = role_registry or RoleRegistry()
        self._policy = policy or AuthorizationPolicy()
        self._audit = audit

    def permissions_for_roles(self, roles: set[str] | frozenset[str]) -> frozenset[str]:
        return self._roles.permissions_for(roles)

    def decision(self, principal: UserPrincipal | None, permission: str) -> AuthorizationDecision:
        granted = principal.permissions if principal else frozenset()
        decision = self._policy.evaluate(authenticated=principal is not None, permission=permission, granted_permissions=granted)
        if not decision.allowed and self._audit:
            self._audit.record(AuditRecord(
                action="authorization.denied", outcome="failure",
                actor_user_id=principal.user_id if principal else None,
                session_id=principal.session_id if principal else None,
                metadata={"permission": permission, "reason": decision.reason},
            ))
        return decision

    def require_authenticated_user(self, principal: UserPrincipal | None) -> UserPrincipal:
        if principal is None:
            if self._audit:
                self._audit.record(AuditRecord(action="authentication.required", outcome="failure"))
            raise PermissionDenied("authenticated_user", "authentication_required")
        return principal

    def require_permission(self, principal: UserPrincipal | None, permission: str) -> UserPrincipal:
        decision = self.decision(principal, permission)
        if not decision.allowed:
            raise PermissionDenied(permission, decision.reason)
        return principal  # type: ignore[return-value]

    def require_role(self, principal: UserPrincipal | None, role: str) -> UserPrincipal:
        principal = self.require_authenticated_user(principal)
        if role not in principal.roles:
            if self._audit:
                self._audit.record(AuditRecord(
                    action="authorization.denied", outcome="failure",
                    actor_user_id=principal.user_id, session_id=principal.session_id,
                    metadata={"role": role, "reason": "role_required"},
                ))
            raise PermissionDenied(role, "role_required")
        return principal


def require_authenticated_user(principal: UserPrincipal | None, *, service: AuthorizationService | None = None) -> UserPrincipal:
    return (service or AuthorizationService()).require_authenticated_user(principal)


def require_permission(permission: str, *, service: AuthorizationService | None = None) -> Callable[[UserPrincipal | None], UserPrincipal]:
    def guard(principal: UserPrincipal | None) -> UserPrincipal:
        return (service or AuthorizationService()).require_permission(principal, permission)
    return guard


def require_role(role: str, *, service: AuthorizationService | None = None) -> Callable[[UserPrincipal | None], UserPrincipal]:
    def guard(principal: UserPrincipal | None) -> UserPrincipal:
        return (service or AuthorizationService()).require_role(principal, role)
    return guard
