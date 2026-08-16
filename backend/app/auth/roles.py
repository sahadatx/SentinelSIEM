from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .permissions import Permission


class Role(StrEnum):
    ADMIN = "ADMIN"
    SOC_ANALYST = "SOC_ANALYST"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    INVESTIGATOR = "INVESTIGATOR"
    VIEWER = "VIEWER"


@dataclass(frozen=True, slots=True)
class RoleDefinition:
    name: Role
    permissions: frozenset[str]


ROLE_DEFINITIONS: dict[Role, RoleDefinition] = {
    Role.ADMIN: RoleDefinition(Role.ADMIN, frozenset(Permission)),
    Role.SOC_ANALYST: RoleDefinition(
        Role.SOC_ANALYST,
        frozenset({
            Permission.EVENTS_READ, Permission.ALERTS_READ, Permission.ALERTS_MANAGE,
            Permission.INCIDENTS_READ, Permission.INCIDENTS_MANAGE, Permission.IOCS_READ,
            Permission.MITRE_READ, Permission.DASHBOARD_READ, Permission.DETECTIONS_READ,
            Permission.ASSETS_READ, Permission.SYSTEM_READ,
        }),
    ),
    Role.SECURITY_ANALYST: RoleDefinition(
        Role.SECURITY_ANALYST,
        frozenset({
            Permission.EVENTS_READ, Permission.ALERTS_READ, Permission.ALERTS_MANAGE,
            Permission.INCIDENTS_READ, Permission.INCIDENTS_MANAGE, Permission.IOCS_READ,
            Permission.IOCS_MANAGE, Permission.MITRE_READ, Permission.DASHBOARD_READ,
            Permission.DETECTIONS_READ, Permission.DETECTIONS_MANAGE, Permission.ASSETS_READ,
            Permission.SYSTEM_READ,
        }),
    ),
    Role.INVESTIGATOR: RoleDefinition(
        Role.INVESTIGATOR,
        frozenset({
            Permission.EVENTS_READ, Permission.ALERTS_READ, Permission.INCIDENTS_READ,
            Permission.INCIDENTS_MANAGE, Permission.IOCS_READ, Permission.IOCS_MANAGE,
            Permission.MITRE_READ, Permission.DASHBOARD_READ, Permission.ASSETS_READ,
        }),
    ),
    Role.VIEWER: RoleDefinition(
        Role.VIEWER,
        frozenset({
            Permission.EVENTS_READ, Permission.ALERTS_READ, Permission.INCIDENTS_READ,
            Permission.IOCS_READ, Permission.MITRE_READ, Permission.DASHBOARD_READ,
            Permission.ASSETS_READ, Permission.SYSTEM_READ,
        }),
    ),
}


class RoleRegistry:
    def __init__(self, definitions: dict[Role, RoleDefinition] | None = None) -> None:
        self._definitions = dict(definitions or ROLE_DEFINITIONS)

    def get(self, role: str | Role) -> RoleDefinition | None:
        try:
            return self._definitions.get(role if isinstance(role, Role) else Role(role))
        except ValueError:
            return None

    def permissions_for(self, roles: set[str] | frozenset[str]) -> frozenset[str]:
        granted: set[str] = set()
        for role in roles:
            definition = self.get(role)
            if definition:
                granted.update(str(permission) for permission in definition.permissions)
        return frozenset(granted)

    def all(self) -> tuple[RoleDefinition, ...]:
        return tuple(self._definitions.values())
