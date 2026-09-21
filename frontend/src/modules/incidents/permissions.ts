/**
 * ============================================================================
 * SentinelSIEM — Incident Module Permissions
 * ============================================================================
 *
 * Authoritative RBAC permission boundaries for the Incidents module.
 *
 * Backend permissions:
 *
 *   incidents:read
 *   incidents:manage
 *
 * Role access:
 *
 *   ADMIN
 *     - incidents:read
 *     - incidents:manage
 *
 *   SECURITY_ANALYST
 *     - incidents:read
 *     - incidents:manage
 *
 *   SOC_ANALYST
 *     - incidents:read
 *     - incidents:manage
 *
 *   INVESTIGATOR
 *     - incidents:read
 *     - incidents:manage
 *
 *   VIEWER
 *     - incidents:read
 *
 * IMPORTANT
 * ----------------------------------------------------------------------------
 * - This module does not invent additional permissions.
 * - The global RBAC configuration remains authoritative.
 * - Backend authorization remains the final security boundary.
 * - Frontend permissions are used only for UI visibility/interaction.
 * - Backend must independently validate every protected operation.
 *
 * Final Incident management operations:
 *
 *   - Create Incident
 *   - Edit Incident
 *   - Assign / Reassign Incident
 *   - Change Severity
 *   - Change Status
 *
 * No Delete / Archive operation exists in the final Incident workflow.
 *
 * ============================================================================
 */

import { PERMISSIONS } from "../../auth/rbac";

/* ============================================================================
 * Incident Read Permission
 * ========================================================================== */

/**
 * Permission required to access the Incidents module.
 *
 * Used for:
 *
 *   - Incident navigation
 *   - Incident list
 *   - Incident details
 *   - Related Alerts
 *   - Incident timeline
 *   - Incident audit/history
 *
 * Backend permission:
 *
 *   incidents:read
 */
export const INCIDENTS_READ =
  PERMISSIONS.INCIDENTS_READ;


/* ============================================================================
 * Incident Management Permission
 * ========================================================================== */

/**
 * Permission required to perform Incident management operations.
 *
 * Covers:
 *
 *   - Create Incident
 *   - Edit Incident
 *   - Assign / Reassign
 *   - Change Severity
 *   - Change Status
 *
 * Backend permission:
 *
 *   incidents:manage
 *
 * The backend remains responsible for:
 *
 *   - Authentication
 *   - RBAC authorization
 *   - Field validation
 *   - Status transition validation
 *   - Assignee validation
 *   - Audit generation
 */
export const INCIDENTS_MANAGE =
  PERMISSIONS.INCIDENTS_MANAGE;


/* ============================================================================
 * Incident Permission Map
 * ========================================================================== */

/**
 * Module-level Incident permission map.
 *
 * Components should consume this map instead of importing the global
 * permission definitions directly where possible.
 */
export const INCIDENT_PERMISSIONS = {
  read: INCIDENTS_READ,
  manage: INCIDENTS_MANAGE,
} as const;


/* ============================================================================
 * Permission Helpers
 * ========================================================================== */

/**
 * Check whether a permission collection contains Incident read access.
 *
 * This helper is intentionally UI-oriented.
 *
 * Backend authorization must still be enforced server-side.
 */
export const canReadIncidents = (
  permissions: readonly string[],
): boolean => {
  return permissions.includes(INCIDENTS_READ);
};


/**
 * Check whether a permission collection contains Incident management access.
 *
 * This helper is intentionally UI-oriented.
 *
 * Backend authorization must still be enforced server-side.
 */
export const canManageIncidents = (
  permissions: readonly string[],
): boolean => {
  return permissions.includes(INCIDENTS_MANAGE);
};


/* ============================================================================
 * Default Export
 * ========================================================================== */

export default INCIDENT_PERMISSIONS;