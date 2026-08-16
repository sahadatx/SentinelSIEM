from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    decision: Decision
    permission: str
    reason: str

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW


@dataclass(frozen=True, slots=True)
class AuthorizationPolicy:
    """Strict default-deny authorization policy."""

    def evaluate(self, *, authenticated: bool, permission: str, granted_permissions: frozenset[str]) -> AuthorizationDecision:
        if not authenticated:
            return AuthorizationDecision(Decision.DENY, permission, "authentication_required")
        if permission not in granted_permissions:
            return AuthorizationDecision(Decision.DENY, permission, "permission_denied")
        return AuthorizationDecision(Decision.ALLOW, permission, "permission_granted")
