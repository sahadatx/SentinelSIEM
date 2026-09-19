from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends

from .audit import AuditSink
from .models import AuditRecord, UserPrincipal
from .permissions import ALL_PERMISSIONS, Permission
from .policies import (
    AuthorizationDecision,
    AuthorizationPolicy,
    Decision,
)
from .roles import Role, RoleRegistry


# ============================================================================
# Types
# ============================================================================

type PrincipalGuard = Callable[
    [UserPrincipal],
    UserPrincipal,
]


# ============================================================================
# Errors
# ============================================================================


class PermissionDenied(Exception):
    """
    Raised when authentication or authorization fails.

    This exception intentionally does not expose sensitive information.
    """

    def __init__(
        self,
        permission: str,
        reason: str = "permission_denied",
    ) -> None:
        self.permission = permission
        self.reason = reason

        super().__init__(
            f"Permission denied: {permission} ({reason})",
        )


# ============================================================================
# Authorization Service
# ============================================================================


class AuthorizationService:
    """
    Central SentinelSIEM authorization boundary.

    Security guarantees
    -------------------

    - default deny
    - authentication required
    - explicit permission checks
    - centralized role resolution
    - centralized permission resolution
    - unknown permissions are denied
    - unknown roles are denied
    - denied authorization attempts can be audited
    - credentials and secrets are never written to audit metadata
    - decision() never raises for invalid permission identifiers
    - require_* methods provide strict raising behavior

    RBAC contract
    -------------

    The application permission registry is the source of truth.

    Audit access is intentionally NOT represented by a dedicated
    "audit:read" permission.

    Audit routes must use:

        users:read
    """

    def __init__(
        self,
        *,
        role_registry: RoleRegistry | None = None,
        policy: AuthorizationPolicy | None = None,
        audit: AuditSink | None = None,
    ) -> None:
        self._roles = (
            role_registry
            if role_registry is not None
            else RoleRegistry()
        )

        self._policy = (
            policy
            if policy is not None
            else AuthorizationPolicy()
        )

        self._audit = audit

    # ========================================================================
    # Permission Resolution
    # ========================================================================

    def permissions_for_roles(
        self,
        roles: set[str] | frozenset[str],
    ) -> frozenset[str]:
        """
        Resolve effective permissions for a collection of roles.

        RoleRegistry owns the actual role-to-permission mapping.
        """

        return self._roles.permissions_for(
            roles,
        )

    # ========================================================================
    # Decision
    # ========================================================================

    def decision(
        self,
        principal: UserPrincipal | None,
        permission: str | Permission,
    ) -> AuthorizationDecision:
        """
        Evaluate an authorization request without raising.

        Decision rules
        --------------

        Anonymous:
            DENY / authentication_required

        Invalid permission:
            DENY / invalid_permission

        Valid permission but not granted:
            DENY / permission_denied

        Valid permission and granted:
            ALLOW
        """

        # --------------------------------------------------------------------
        # Authentication takes precedence.
        # --------------------------------------------------------------------

        if principal is None:
            normalized_permission = self._permission_for_audit(
                permission,
            )

            decision = self._policy.evaluate(
                authenticated=False,
                permission=normalized_permission,
                granted_permissions=frozenset(),
            )

            # Defensive guarantee:
            # anonymous principals can never be allowed.
            if decision.allowed:
                decision = AuthorizationDecision(
                    Decision.DENY,
                    normalized_permission,
                    "authentication_required",
                )

            self._audit_denial(
                principal=None,
                permission=normalized_permission,
                reason="authentication_required",
            )

            return decision

        # --------------------------------------------------------------------
        # Normalize and validate permission.
        # --------------------------------------------------------------------

        try:
            normalized_permission = self._normalize_permission(
                permission,
            )

        except PermissionDenied as exc:
            self._audit_denial(
                principal=principal,
                permission=exc.permission,
                reason=exc.reason,
            )

            return AuthorizationDecision(
                Decision.DENY,
                exc.permission,
                exc.reason,
            )

        # --------------------------------------------------------------------
        # Evaluate against principal permissions.
        # --------------------------------------------------------------------

        decision = self._policy.evaluate(
            authenticated=True,
            permission=normalized_permission,
            granted_permissions=principal.permissions,
        )

        # --------------------------------------------------------------------
        # Audit denied authorization attempts.
        # --------------------------------------------------------------------

        if not decision.allowed:
            self._audit_denial(
                principal=principal,
                permission=normalized_permission,
                reason=decision.reason,
            )

        return decision

    # ========================================================================
    # Authentication
    # ========================================================================

    def require_authenticated_user(
        self,
        principal: UserPrincipal | None,
    ) -> UserPrincipal:
        """
        Require an authenticated principal.

        Raises
        ------

        PermissionDenied
            When no authenticated principal exists.
        """

        if principal is None:
            self._audit_authentication_required()

            raise PermissionDenied(
                "authenticated_user",
                "authentication_required",
            )

        return principal

    # ========================================================================
    # Permission Requirement
    # ========================================================================

    def require_permission(
        self,
        principal: UserPrincipal | None,
        permission: str | Permission,
    ) -> UserPrincipal:
        """
        Require a specific permission.

        Raises
        ------

        PermissionDenied
            When:

            - authentication is missing
            - permission is invalid
            - permission is not granted
        """

        # --------------------------------------------------------------------
        # Strict validation.
        # --------------------------------------------------------------------

        normalized_permission = self._normalize_permission(
            permission,
        )

        # --------------------------------------------------------------------
        # Evaluate authorization.
        # --------------------------------------------------------------------

        decision = self.decision(
            principal,
            normalized_permission,
        )

        if not decision.allowed:
            raise PermissionDenied(
                normalized_permission,
                decision.reason,
            )

        # --------------------------------------------------------------------
        # Defensive guarantee.
        # --------------------------------------------------------------------

        if principal is None:
            raise PermissionDenied(
                normalized_permission,
                "authentication_required",
            )

        return principal

    # ========================================================================
    # Role Requirement
    # ========================================================================

    def require_role(
        self,
        principal: UserPrincipal | None,
        role: str | Role,
    ) -> UserPrincipal:
        """
        Require an authenticated principal with a specific role.

        Raises
        ------

        PermissionDenied
            When authentication is missing or the role is not assigned.
        """

        principal = self.require_authenticated_user(
            principal,
        )

        normalized_role = self._normalize_role(
            role,
        )

        # --------------------------------------------------------------------
        # Check role membership.
        # --------------------------------------------------------------------

        if normalized_role not in principal.roles:
            self._audit_denial(
                principal=principal,
                permission=normalized_role,
                reason="role_required",
                metadata={
                    "role": normalized_role,
                },
            )

            raise PermissionDenied(
                normalized_role,
                "role_required",
            )

        return principal

    # ========================================================================
    # Internal Permission Normalization
    # ========================================================================

    @staticmethod
    def _normalize_permission(
        permission: str | Permission,
    ) -> str:
        """
        Normalize and validate a permission identifier.

        Raises
        ------

        PermissionDenied
            For invalid or unknown permissions.
        """

        # --------------------------------------------------------------------
        # Enum permission.
        # --------------------------------------------------------------------

        if isinstance(permission, Permission):
            normalized = permission.value

        # --------------------------------------------------------------------
        # String permission.
        # --------------------------------------------------------------------

        elif isinstance(permission, str):
            normalized = permission.strip().lower()

        # --------------------------------------------------------------------
        # Unsupported type.
        # --------------------------------------------------------------------

        else:
            raise PermissionDenied(
                "unknown",
                "invalid_permission",
            )

        # --------------------------------------------------------------------
        # Empty permission.
        # --------------------------------------------------------------------

        if not normalized:
            raise PermissionDenied(
                "unknown",
                "invalid_permission",
            )

        # --------------------------------------------------------------------
        # Dedicated audit permissions are intentionally invalid.
        # --------------------------------------------------------------------

        if normalized in {
            "audit:read",
            "audit:export",
        }:
            raise PermissionDenied(
                normalized,
                "invalid_permission",
            )

        # --------------------------------------------------------------------
        # Canonical permission registry validation.
        # --------------------------------------------------------------------

        if normalized not in ALL_PERMISSIONS:
            raise PermissionDenied(
                normalized,
                "invalid_permission",
            )

        return normalized

    # ========================================================================
    # Internal Role Normalization
    # ========================================================================

    @staticmethod
    def _normalize_role(
        role: str | Role,
    ) -> str:
        """
        Normalize and validate a role identifier.

        Raises
        ------

        PermissionDenied
            For invalid or unknown roles.
        """

        # --------------------------------------------------------------------
        # Enum role.
        # --------------------------------------------------------------------

        if isinstance(role, Role):
            return role.value

        # --------------------------------------------------------------------
        # String role.
        # --------------------------------------------------------------------

        if not isinstance(role, str):
            raise PermissionDenied(
                "unknown",
                "invalid_role",
            )

        normalized = role.strip().upper()

        # --------------------------------------------------------------------
        # Empty role.
        # --------------------------------------------------------------------

        if not normalized:
            raise PermissionDenied(
                "unknown",
                "invalid_role",
            )

        # --------------------------------------------------------------------
        # Canonical role validation.
        # --------------------------------------------------------------------

        try:
            return Role(normalized).value

        except ValueError as exc:
            raise PermissionDenied(
                normalized,
                "invalid_role",
            ) from exc

    # ========================================================================
    # Safe Permission Representation
    # ========================================================================

    @staticmethod
    def _permission_for_audit(
        permission: str | Permission,
    ) -> str:
        """
        Safely obtain a string representation for audit logging.

        This helper must never raise.
        """

        if isinstance(permission, Permission):
            return permission.value

        if isinstance(permission, str):
            normalized = permission.strip().lower()
            return normalized or "unknown"

        return "unknown"

    # ========================================================================
    # Audit Helpers
    # ========================================================================

    def _audit_denial(
        self,
        *,
        principal: UserPrincipal | None,
        permission: str,
        reason: str,
        metadata: dict[str, object] | None = None,
    ) -> None:
        """
        Record a denied authorization attempt.

        Audit metadata intentionally contains only authorization context.

        Never record:

            - password
            - password hash
            - access token
            - refresh token
            - session token
            - API key
            - secret
            - private key
            - credential material
        """

        if self._audit is None:
            return

        audit_metadata: dict[str, object] = {
            "permission": permission,
            "reason": reason,
        }

        if metadata:
            audit_metadata.update(
                metadata,
            )

        self._audit.record(
            AuditRecord(
                action="authorization.denied",
                outcome="failure",
                actor_user_id=(
                    principal.user_id
                    if principal is not None
                    else None
                ),
                session_id=(
                    principal.session_id
                    if principal is not None
                    else None
                ),
                metadata=audit_metadata,
            )
        )

    def _audit_authentication_required(
        self,
    ) -> None:
        """
        Record an unauthenticated access attempt.

        No credential or request-secret information is stored.
        """

        if self._audit is None:
            return

        self._audit.record(
            AuditRecord(
                action="authentication.required",
                outcome="failure",
            )
        )


# ============================================================================
# Functional Authentication Guard
# ============================================================================


def require_authenticated_user(
    principal: UserPrincipal | None,
    *,
    service: AuthorizationService | None = None,
) -> UserPrincipal:
    """
    Functional authentication guard.

    This function is intended for direct Python/service-layer usage.

    FastAPI routes that need authentication should use
    get_current_principal through Depends().
    """

    authorization = (
        service
        if service is not None
        else AuthorizationService()
    )

    return authorization.require_authenticated_user(
        principal,
    )


# ============================================================================
# Functional Permission Guard
# ============================================================================


def require_permission(
    permission: str | Permission,
    *,
    service: AuthorizationService | None = None,
) -> Callable[..., UserPrincipal]:
    """
    Build a reusable FastAPI permission guard.

    Example
    -------

        alerts_read_permission = require_permission(
            Permission.ALERTS_READ,
        )

        @router.get(
            "",
            dependencies=[
                Depends(alerts_read_permission),
            ],
        )
        async def list_alerts():
            ...

    FastAPI dependency flow:

        Request
          |
          v
        guard()
          |
          +--> Depends(get_current_principal)
          |
          v
        UserPrincipal
          |
          v
        AuthorizationService.require_permission()

    IMPORTANT
    ---------

    UserPrincipal is injected through Depends(get_current_principal).

    It is NOT declared as a plain parameter.

    Therefore FastAPI will not interpret UserPrincipal as a request body
    for GET endpoints.
    """

    authorization = (
        service
        if service is not None
        else AuthorizationService()
    )

    # ------------------------------------------------------------------------
    # Validate permission immediately when the guard is created.
    # ------------------------------------------------------------------------

    normalized_permission = authorization._normalize_permission(
        permission,
    )

    # ------------------------------------------------------------------------
    # Local import avoids module-level circular dependency:
    #
    #   app.auth.authorization
    #          ↕
    #   app.api.dependencies
    #
    # The imported function itself is NOT called manually.
    # FastAPI receives it through Depends().
    # ------------------------------------------------------------------------

    from app.api.dependencies import get_current_principal

    # ------------------------------------------------------------------------
    # FastAPI dependency guard.
    # ------------------------------------------------------------------------

    def guard(
        principal: UserPrincipal = Depends(
            get_current_principal,
        ),
    ) -> UserPrincipal:
        return authorization.require_permission(
            principal,
            normalized_permission,
        )

    return guard


# ============================================================================
# Functional Role Guard
# ============================================================================


def require_role(
    role: str | Role,
    *,
    service: AuthorizationService | None = None,
) -> Callable[..., UserPrincipal]:
    """
    Build a reusable FastAPI role guard.

    FastAPI resolves the authenticated principal through
    get_current_principal().
    """

    authorization = (
        service
        if service is not None
        else AuthorizationService()
    )

    # ------------------------------------------------------------------------
    # Validate role immediately.
    # ------------------------------------------------------------------------

    normalized_role = authorization._normalize_role(
        role,
    )

    # ------------------------------------------------------------------------
    # Local import avoids module-level circular dependency.
    # ------------------------------------------------------------------------

    from app.api.dependencies import get_current_principal

    # ------------------------------------------------------------------------
    # FastAPI dependency guard.
    # ------------------------------------------------------------------------

    def guard(
        principal: UserPrincipal = Depends(
            get_current_principal,
        ),
    ) -> UserPrincipal:
        return authorization.require_role(
            principal,
            normalized_role,
        )

    return guard


# ============================================================================
# Public API
# ============================================================================

__all__ = [
    "AuthorizationService",
    "PermissionDenied",
    "PrincipalGuard",
    "require_authenticated_user",
    "require_permission",
    "require_role",
]