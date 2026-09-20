/* ==========================================================================
 * SentinelSIEM Frontend RBAC
 * ========================================================================== */

/* ==========================================================================
 * Permissions
 * ========================================================================== */

/**
 * Canonical SentinelSIEM frontend permission registry.
 *
 * IMPORTANT:
 * These permission identifiers MUST remain synchronized with
 * the backend authorization layer.
 *
 * Backend remains the authoritative security boundary.
 */
export const PERMISSIONS = {
  /* ------------------------------------------------------------------------
   * Dashboard
   * ---------------------------------------------------------------------- */

  DASHBOARD_READ: "dashboard:read",

  /* ------------------------------------------------------------------------
   * Events
   * ---------------------------------------------------------------------- */

  EVENTS_READ: "events:read",

  /* ------------------------------------------------------------------------
   * Alerts
   * ---------------------------------------------------------------------- */

  ALERTS_READ: "alerts:read",
  ALERTS_MANAGE: "alerts:manage",

  /* ------------------------------------------------------------------------
   * Incidents
   * ---------------------------------------------------------------------- */

  INCIDENTS_READ: "incidents:read",
  INCIDENTS_MANAGE: "incidents:manage",

  /* ------------------------------------------------------------------------
   * Indicators of Compromise
   * ---------------------------------------------------------------------- */

  IOCS_READ: "iocs:read",
  IOCS_MANAGE: "iocs:manage",

  /* ------------------------------------------------------------------------
   * MITRE ATT&CK
   * ---------------------------------------------------------------------- */

  MITRE_READ: "mitre:read",

  /* ------------------------------------------------------------------------
   * Detection
   * ---------------------------------------------------------------------- */

  DETECTIONS_READ: "detections:read",
  DETECTIONS_MANAGE: "detections:manage",

  /* ------------------------------------------------------------------------
   * Assets
   * ---------------------------------------------------------------------- */

  ASSETS_READ: "assets:read",
  ASSETS_MANAGE: "assets:manage",

  /* ------------------------------------------------------------------------
   * System
   * ---------------------------------------------------------------------- */

  SYSTEM_READ: "system:read",

  /* ------------------------------------------------------------------------
   * User Management
   * ---------------------------------------------------------------------- */

  USERS_READ: "users:read",
  USERS_MANAGE: "users:manage",

  /* ------------------------------------------------------------------------
   * Role Management
   * ---------------------------------------------------------------------- */

  ROLES_READ: "roles:read",
  ROLES_MANAGE: "roles:manage",

  /* ------------------------------------------------------------------------
   * Global Audit
   * ---------------------------------------------------------------------- */

  AUDIT_READ: "audit:read",
  AUDIT_EXPORT: "audit:export",
} as const;

/**
 * Union of all canonical SentinelSIEM permissions.
 */
export type Permission =
  (typeof PERMISSIONS)[keyof typeof PERMISSIONS];

/* ==========================================================================
 * Roles
 * ========================================================================== */

/**
 * Canonical SentinelSIEM application roles.
 *
 * IMPORTANT:
 * These values MUST remain synchronized with:
 *
 * backend/app/auth/roles.py
 *
 * Backend canonical values:
 *
 * ADMIN
 * SECURITY_ANALYST
 * SOC_ANALYST
 * INVESTIGATOR
 * VIEWER
 */
export const ROLES = {
  ADMIN: "ADMIN",
  SECURITY_ANALYST: "SECURITY_ANALYST",
  SOC_ANALYST: "SOC_ANALYST",
  INVESTIGATOR: "INVESTIGATOR",
  VIEWER: "VIEWER",
} as const;

/**
 * Union of all canonical SentinelSIEM roles.
 */
export type Role =
  (typeof ROLES)[keyof typeof ROLES];

/* ==========================================================================
 * Role List
 * ========================================================================== */

/**
 * Ordered list of selectable SentinelSIEM roles.
 *
 * This is the single frontend source of truth for
 * role-selection controls.
 */
export const ROLE_LIST: readonly Role[] = [
  ROLES.ADMIN,
  ROLES.SECURITY_ANALYST,
  ROLES.SOC_ANALYST,
  ROLES.INVESTIGATOR,
  ROLES.VIEWER,
];

/* ==========================================================================
 * Role Validation
 * ========================================================================== */

/**
 * Check whether an unknown string is a valid
 * SentinelSIEM role.
 */
export function isRole(
  value: string,
): value is Role {
  return ROLE_LIST.includes(
    value as Role,
  );
}

/* ==========================================================================
 * Role Formatting
 * ========================================================================== */

/**
 * Convert a canonical role into a human-readable label.
 *
 * Examples:
 *
 * ADMIN
 *   -> Admin
 *
 * SECURITY_ANALYST
 *   -> Security Analyst
 *
 * SOC_ANALYST
 *   -> Soc Analyst
 *
 * INVESTIGATOR
 *   -> Investigator
 *
 * VIEWER
 *   -> Viewer
 */
export function formatRole(
  role: Role | string,
): string {
  return role
    .replace(/[-_]+/g, " ")
    .toLowerCase()
    .replace(
      /\b\w/g,
      (character) =>
        character.toUpperCase(),
    );
}

/* ==========================================================================
 * Permission Validation
 * ========================================================================== */

/**
 * Check whether an unknown string is a valid
 * SentinelSIEM permission.
 */
export function isPermission(
  value: string,
): value is Permission {
  return (
    Object.values(PERMISSIONS) as readonly string[]
  ).includes(value);
}

/* ==========================================================================
 * Exports
 * ========================================================================== */

export default {
  PERMISSIONS,
  ROLES,
  ROLE_LIST,
  isRole,
  isPermission,
  formatRole,
};