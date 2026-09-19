from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .permissions import Permission


# ============================================================================
# Roles
# ============================================================================


class Role(StrEnum):
    """
    SentinelSIEM security roles.

    These are the only supported application roles.

    Role hierarchy is conceptual only.
    Roles do not inherit from one another.

    Every role has an explicit immutable permission set.
    """

    ADMIN = "ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    SOC_ANALYST = "SOC_ANALYST"
    INVESTIGATOR = "INVESTIGATOR"
    VIEWER = "VIEWER"


# ============================================================================
# Role Definition
# ============================================================================


@dataclass(frozen=True, slots=True)
class RoleDefinition:
    """
    Immutable definition of one SentinelSIEM role.

    Each role contains:

        - role name
        - explicitly granted permissions

    Permissions are stored as normalized strings because the
    authentication and authorization layers operate on permission values.
    """

    name: Role
    permissions: frozenset[str]


# ============================================================================
# Default Role Definitions
# ============================================================================


ROLE_DEFINITIONS: dict[Role, RoleDefinition] = {
    # ------------------------------------------------------------------------
    # ADMIN
    #
    # Full SentinelSIEM platform administration.
    #
    # ADMIN receives every registered permission.
    #
    # Audit access is controlled through:
    #
    #     users:read
    #
    # ------------------------------------------------------------------------

    Role.ADMIN: RoleDefinition(
        name=Role.ADMIN,
        permissions=frozenset(
            permission.value
            for permission in Permission
        ),
    ),

    # ------------------------------------------------------------------------
    # SECURITY_ANALYST
    #
    # Advanced security operations.
    #
    # Can:
    #     - read events
    #     - read/manage alerts
    #     - read/manage incidents
    #     - read/manage IOCs
    #     - read MITRE
    #     - read dashboard
    #     - read/manage detections
    #     - read/manage assets
    #     - read system information
    #
    # Cannot:
    #     - read users
    #     - manage users
    #     - read roles
    #     - manage roles
    #     - access global audit logs
    #
    # ------------------------------------------------------------------------

    Role.SECURITY_ANALYST: RoleDefinition(
        name=Role.SECURITY_ANALYST,
        permissions=frozenset(
            {
                Permission.EVENTS_READ.value,
                Permission.ALERTS_READ.value,
                Permission.ALERTS_MANAGE.value,
                Permission.INCIDENTS_READ.value,
                Permission.INCIDENTS_MANAGE.value,
                Permission.IOCS_READ.value,
                Permission.IOCS_MANAGE.value,
                Permission.MITRE_READ.value,
                Permission.DASHBOARD_READ.value,
                Permission.DETECTIONS_READ.value,
                Permission.DETECTIONS_MANAGE.value,
                Permission.ASSETS_READ.value,
                Permission.ASSETS_MANAGE.value,
                Permission.SYSTEM_READ.value,
            }
        ),
    ),

    # ------------------------------------------------------------------------
    # SOC_ANALYST
    #
    # SOC monitoring and response.
    #
    # Can:
    #     - read events
    #     - read/manage alerts
    #     - read/manage incidents
    #     - read IOCs
    #     - read MITRE
    #     - read dashboard
    #     - read/manage detections
    #     - read assets
    #     - read system information
    #
    # Cannot:
    #     - manage IOCs
    #     - manage assets
    #     - manage users
    #     - manage roles
    #     - access global audit logs
    #
    # ------------------------------------------------------------------------

    Role.SOC_ANALYST: RoleDefinition(
        name=Role.SOC_ANALYST,
        permissions=frozenset(
            {
                Permission.EVENTS_READ.value,
                Permission.ALERTS_READ.value,
                Permission.ALERTS_MANAGE.value,
                Permission.INCIDENTS_READ.value,
                Permission.INCIDENTS_MANAGE.value,
                Permission.IOCS_READ.value,
                Permission.MITRE_READ.value,
                Permission.DASHBOARD_READ.value,
                Permission.DETECTIONS_READ.value,
                Permission.DETECTIONS_MANAGE.value,
                Permission.ASSETS_READ.value,
                Permission.SYSTEM_READ.value,
            }
        ),
    ),

    # ------------------------------------------------------------------------
    # INVESTIGATOR
    #
    # Investigation-focused access.
    #
    # Can:
    #     - read events
    #     - read/manage incidents
    #     - read/manage IOCs
    #     - read MITRE
    #     - read dashboard
    #     - read assets
    #
    # Cannot:
    #     - access alerts
    #     - access detection permissions
    #     - access system permissions
    #     - manage users
    #     - manage roles
    #     - access global audit logs
    #
    # ------------------------------------------------------------------------

    Role.INVESTIGATOR: RoleDefinition(
        name=Role.INVESTIGATOR,
        permissions=frozenset(
            {
                Permission.EVENTS_READ.value,
                Permission.INCIDENTS_READ.value,
                Permission.INCIDENTS_MANAGE.value,
                Permission.IOCS_READ.value,
                Permission.IOCS_MANAGE.value,
                Permission.MITRE_READ.value,
                Permission.DASHBOARD_READ.value,
                Permission.ASSETS_READ.value,
            }
        ),
    ),

    # ------------------------------------------------------------------------
    # VIEWER
    #
    # Strict read-only operational visibility.
    #
    # Can:
    #     - read events
    #     - read incidents
    #     - read IOCs
    #     - read MITRE
    #     - read dashboard
    #     - read assets
    #
    # Cannot:
    #     - access alerts
    #     - manage any resource
    #     - manage users
    #     - manage roles
    #     - access system administration
    #     - access global audit logs
    #
    # ------------------------------------------------------------------------

    Role.VIEWER: RoleDefinition(
        name=Role.VIEWER,
        permissions=frozenset(
            {
                Permission.EVENTS_READ.value,
                Permission.INCIDENTS_READ.value,
                Permission.IOCS_READ.value,
                Permission.MITRE_READ.value,
                Permission.DASHBOARD_READ.value,
                Permission.ASSETS_READ.value,
            }
        ),
    ),
}


# ============================================================================
# Expected Permission Counts
# ============================================================================


EXPECTED_ROLE_PERMISSION_COUNTS: dict[Role, int] = {
    Role.ADMIN: len(Permission),
    Role.SECURITY_ANALYST: 14,
    Role.SOC_ANALYST: 12,
    Role.INVESTIGATOR: 8,
    Role.VIEWER: 6,
}


# ============================================================================
# Role Registry
# ============================================================================


class RoleRegistry:
    """
    Central registry for SentinelSIEM roles.

    Responsibilities:

        - resolve roles
        - determine role existence
        - calculate effective permissions
        - expose registered role definitions
        - validate RBAC configuration

    The registry does not perform authorization itself.

    Authorization remains the responsibility of AuthorizationService.
    """

    def __init__(
        self,
        definitions: dict[Role, RoleDefinition] | None = None,
    ) -> None:
        source = (
            ROLE_DEFINITIONS
            if definitions is None
            else definitions
        )

        self._definitions = dict(source)

        self._validate_definitions()

    # ========================================================================
    # Role Lookup
    # ========================================================================

    def get(
        self,
        role: str | Role,
    ) -> RoleDefinition | None:
        """
        Resolve a role definition.

        String role names are normalized using:

            strip()
            upper()

        Invalid roles return None.
        """

        if isinstance(
            role,
            Role,
        ):
            return self._definitions.get(
                role,
            )

        if not isinstance(
            role,
            str,
        ):
            return None

        normalized = role.strip().upper()

        if not normalized:
            return None

        try:
            normalized_role = Role(
                normalized,
            )

        except ValueError:
            return None

        return self._definitions.get(
            normalized_role,
        )

    # ========================================================================
    # Role Existence
    # ========================================================================

    def contains(
        self,
        role: str | Role,
    ) -> bool:
        """
        Return True when the role is registered.
        """

        return self.get(
            role,
        ) is not None

    # ========================================================================
    # Permission Resolution
    # ========================================================================

    def permissions_for(
        self,
        roles: set[str] | frozenset[str],
    ) -> frozenset[str]:
        """
        Calculate effective permissions for a set of roles.

        Permissions from all valid roles are unioned.

        Unknown roles are intentionally ignored.
        """

        if not roles:
            return frozenset()

        granted: set[str] = set()

        for role in roles:
            definition = self.get(
                role,
            )

            if definition is None:
                continue

            granted.update(
                definition.permissions,
            )

        return frozenset(
            granted,
        )

    # ========================================================================
    # All Definitions
    # ========================================================================

    def all(
        self,
    ) -> tuple[RoleDefinition, ...]:
        """
        Return all registered role definitions.
        """

        return tuple(
            self._definitions.values(),
        )

    # ========================================================================
    # Role Names
    # ========================================================================

    def names(
        self,
    ) -> frozenset[str]:
        """
        Return all registered role names.
        """

        return frozenset(
            role.value
            for role in self._definitions
        )

    # ========================================================================
    # Permission Membership
    # ========================================================================

    def has_permission(
        self,
        role: str | Role,
        permission: str | Permission,
    ) -> bool:
        """
        Check whether a role grants a permission.

        This method does not perform user authorization.
        """

        definition = self.get(
            role,
        )

        if definition is None:
            return False

        if isinstance(
            permission,
            Permission,
        ):
            permission_value = permission.value

        elif isinstance(
            permission,
            str,
        ):
            permission_value = permission.strip().lower()

        else:
            return False

        return permission_value in definition.permissions

    # ========================================================================
    # Permission Count
    # ========================================================================

    def permission_count(
        self,
        role: str | Role,
    ) -> int:
        """
        Return the number of permissions granted to a role.

        Unknown roles return zero.
        """

        definition = self.get(
            role,
        )

        if definition is None:
            return 0

        return len(
            definition.permissions,
        )

    # ========================================================================
    # Internal Validation
    # ========================================================================

    def _validate_definitions(
        self,
    ) -> None:
        """
        Validate the complete SentinelSIEM RBAC contract.

        Validation covers:

            - exact role set
            - RoleDefinition types
            - role/name consistency
            - unknown permissions
            - exact permission counts
            - ADMIN full permission access
            - ADMIN-only users:read
            - absence of dedicated audit permissions
        """

        # --------------------------------------------------------------------
        # Validate exact role set.
        # --------------------------------------------------------------------

        expected_roles = frozenset(
            Role,
        )

        configured_roles = frozenset(
            self._definitions.keys(),
        )

        if configured_roles != expected_roles:
            missing = (
                expected_roles
                - configured_roles
            )

            unknown = (
                configured_roles
                - expected_roles
            )

            raise ValueError(
                "Invalid role registry configuration: "
                f"missing={sorted(role.value for role in missing)}, "
                f"unknown={sorted(str(role) for role in unknown)}"
            )

        # --------------------------------------------------------------------
        # Canonical permission registry.
        # --------------------------------------------------------------------

        all_permission_values = frozenset(
            permission.value
            for permission in Permission
        )

        # --------------------------------------------------------------------
        # Dedicated audit permissions are prohibited.
        #
        # Audit access is intentionally controlled through users:read.
        # --------------------------------------------------------------------

        prohibited_audit_permissions = frozenset(
            {
                "audit:read",
                "audit:export",
            }
        )

        configured_audit_permissions = (
            all_permission_values
            & prohibited_audit_permissions
        )

        if configured_audit_permissions:
            raise ValueError(
                "Invalid permission registry configuration: "
                "dedicated audit permissions are prohibited: "
                f"{sorted(configured_audit_permissions)}"
            )

        # --------------------------------------------------------------------
        # Validate every role definition.
        # --------------------------------------------------------------------

        for role, definition in self._definitions.items():
            if not isinstance(
                definition,
                RoleDefinition,
            ):
                raise TypeError(
                    f"Invalid definition for role {role!r}."
                )

            if definition.name is not role:
                raise ValueError(
                    f"Role definition name mismatch for {role!r}."
                )

            unknown_permissions = (
                definition.permissions
                - all_permission_values
            )

            if unknown_permissions:
                raise ValueError(
                    f"Role {role.value} contains unknown permissions: "
                    f"{sorted(unknown_permissions)}"
                )

            role_audit_permissions = (
                definition.permissions
                & prohibited_audit_permissions
            )

            if role_audit_permissions:
                raise ValueError(
                    f"Role {role.value} contains prohibited audit "
                    "permissions: "
                    f"{sorted(role_audit_permissions)}"
                )

        # --------------------------------------------------------------------
        # Validate exact permission counts.
        # --------------------------------------------------------------------

        for (
            role,
            expected_count,
        ) in EXPECTED_ROLE_PERMISSION_COUNTS.items():
            actual_count = len(
                self._definitions[
                    role
                ].permissions
            )

            if actual_count != expected_count:
                raise ValueError(
                    "RBAC permission count mismatch for "
                    f"{role.value}: expected {expected_count}, "
                    f"found {actual_count}."
                )

        # --------------------------------------------------------------------
        # ADMIN must receive every registered permission.
        # --------------------------------------------------------------------

        admin_permissions = self._definitions[
            Role.ADMIN
        ].permissions

        if admin_permissions != all_permission_values:
            missing = (
                all_permission_values
                - admin_permissions
            )

            extra = (
                admin_permissions
                - all_permission_values
            )

            raise ValueError(
                "ADMIN must receive all registered permissions: "
                f"missing={sorted(missing)}, "
                f"extra={sorted(extra)}"
            )

        # --------------------------------------------------------------------
        # Audit access boundary.
        #
        # Audit access is controlled through users:read.
        # Only ADMIN receives users:read.
        # --------------------------------------------------------------------

        users_read = Permission.USERS_READ.value

        if users_read not in admin_permissions:
            raise ValueError(
                "ADMIN must have users:read for audit access."
            )

        for role in (
            Role.SECURITY_ANALYST,
            Role.SOC_ANALYST,
            Role.INVESTIGATOR,
            Role.VIEWER,
        ):
            if (
                users_read
                in self._definitions[
                    role
                ].permissions
            ):
                raise ValueError(
                    f"{role.value} must not have users:read. "
                    "Audit access is ADMIN-only."
                )


# ============================================================================
# Default Registry
# ============================================================================


DEFAULT_ROLE_REGISTRY = RoleRegistry()


# ============================================================================
# Public Exports
# ============================================================================


__all__ = [
    "DEFAULT_ROLE_REGISTRY",
    "EXPECTED_ROLE_PERMISSION_COUNTS",
    "ROLE_DEFINITIONS",
    "Role",
    "RoleDefinition",
    "RoleRegistry",
]