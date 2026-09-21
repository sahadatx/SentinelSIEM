import { PERMISSIONS } from "../../auth/rbac";

/* ==========================================================================
 * Threat Intelligence Permissions
 * ========================================================================== */

/**
 * Permissions required by the Threat Intelligence module.
 *
 * READ:
 *   - View IOC inventory
 *   - View IOC details
 *   - View IOC relationships
 *   - View IOC analytics / summary
 *
 * MANAGE:
 *   - Create IOC records
 *   - Update IOC records
 *   - Enable IOC
 *   - Disable IOC
 *
 * Backend permissions:
 *   - iocs:read
 *   - iocs:manage
 *
 * RBAC:
 *
 * ADMIN
 *   - READ   ✓
 *   - MANAGE ✓
 *
 * SECURITY_ANALYST
 *   - READ   ✓
 *   - MANAGE ✓
 *
 * SOC_ANALYST
 *   - READ   ✓
 *   - MANAGE ✗
 *
 * INVESTIGATOR
 *   - READ   ✓
 *   - MANAGE ✓
 *
 * VIEWER
 *   - READ   ✓
 *   - MANAGE ✗
 *
 * Important:
 *   - Delete IOC is intentionally not supported.
 *   - IOC lifecycle uses dedicated Enable / Disable actions.
 *   - Backend remains the source of truth for authorization.
 */

export const THREAT_INTELLIGENCE_PERMISSIONS = {
  READ: PERMISSIONS.IOCS_READ,
  MANAGE: PERMISSIONS.IOCS_MANAGE,
} as const;

/* ==========================================================================
 * Named Permission Exports
 * ========================================================================== */

/**
 * Threat Intelligence read permission.
 *
 * Kept as a named module-level export for compatibility
 * with existing imports.
 */
export const THREAT_INTELLIGENCE_READ =
  THREAT_INTELLIGENCE_PERMISSIONS.READ;

/**
 * Threat Intelligence manage permission.
 *
 * Grants create, edit, and enable/disable capabilities
 * according to backend RBAC authorization.
 */
export const THREAT_INTELLIGENCE_MANAGE =
  THREAT_INTELLIGENCE_PERMISSIONS.MANAGE;

/* ==========================================================================
 * Permission Helpers
 * ========================================================================== */

/**
 * Returns whether the caller has Threat Intelligence read access.
 */
export function canReadThreatIntelligence(
  permissions: readonly string[],
): boolean {
  return permissions.includes(THREAT_INTELLIGENCE_READ);
}

/**
 * Returns whether the caller has Threat Intelligence management access.
 */
export function canManageThreatIntelligence(
  permissions: readonly string[],
): boolean {
  return permissions.includes(THREAT_INTELLIGENCE_MANAGE);
}