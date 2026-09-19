from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .permissions import Permission

# ============================================================================
# Authorization decision
# ============================================================================


class Decision(StrEnum):
    """
    Final authorization decision.
    """

    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    """
    Immutable authorization result.
    """

    decision: Decision
    permission: str
    reason: str

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW


# ============================================================================
# Authorization policy
# ============================================================================


@dataclass(frozen=True, slots=True)
class AuthorizationPolicy:
    """
    Strict default-deny authorization policy.

    Authorization requires BOTH:

        1. an authenticated principal
        2. the requested permission being explicitly granted

    No implicit permissions are granted.
    """

    def evaluate(
        self,
        *,
        authenticated: bool,
        permission: str,
        granted_permissions: frozenset[str],
    ) -> AuthorizationDecision:
        """
        Evaluate one permission request.
        """

        normalized_permission = self._normalize_permission(permission)

        if not authenticated:
            return AuthorizationDecision(
                decision=Decision.DENY,
                permission=normalized_permission,
                reason="authentication_required",
            )

        if normalized_permission not in granted_permissions:
            return AuthorizationDecision(
                decision=Decision.DENY,
                permission=normalized_permission,
                reason="permission_denied",
            )

        return AuthorizationDecision(
            decision=Decision.ALLOW,
            permission=normalized_permission,
            reason="permission_granted",
        )

    @staticmethod
    def _normalize_permission(
        permission: str | Permission,
    ) -> str:
        """
        Normalize and validate a permission identifier.

        Unknown permissions are denied rather than silently accepted.
        """

        if isinstance(permission, Permission):
            return permission.value

        if not isinstance(permission, str):
            return ""

        return permission.strip().lower()
