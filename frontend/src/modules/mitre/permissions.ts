/* ============================================================================
 * MITRE ATT&CK Module Permissions
 * SentinelSIEM SOC Dashboard
 * ========================================================================== */

import { PERMISSIONS } from "../../auth/rbac";

/* ============================================================================
 * Permission Constants
 * ========================================================================== */

/**
 * Read access to the MITRE ATT&CK module.
 *
 * Source of truth:
 *   frontend/src/auth/rbac.ts
 *
 * Backend permission:
 *   mitre:read
 */
export const MITRE_READ =
  PERMISSIONS.MITRE_READ;

/* ============================================================================
 * Module Permission Contract
 * ========================================================================== */

/**
 * MITRE module permissions.
 *
 * Keep this module-level contract small and explicit.
 *
 * The MITRE module currently exposes read-only
 * functionality, so there is intentionally no
 * MITRE_MANAGE permission here.
 */
export const MITRE_PERMISSIONS = {
  READ: MITRE_READ,
} as const;

/**
 * Union type of permissions owned by the MITRE module.
 */
export type MitrePermission =
  (typeof MITRE_PERMISSIONS)[keyof typeof MITRE_PERMISSIONS];

/* ============================================================================
 * Default Export
 * ========================================================================== */

export default MITRE_PERMISSIONS;