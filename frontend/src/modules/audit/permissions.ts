/**
 * ============================================================================
 * SentinelSIEM — Global Audit Permissions
 * ============================================================================
 *
 * Centralized frontend permission contract for the Global Audit module.
 *
 * IMPORTANT
 * ---------
 *
 * Global Audit does NOT define dedicated:
 *
 *     audit:read
 *     audit:export
 *
 * permissions.
 *
 * The locked SentinelSIEM RBAC contract uses:
 *
 *     users:read
 *
 * for privileged Global Audit access.
 *
 * Backend authorization remains the final security boundary.
 *
 * These constants:
 *
 *     - DO NOT grant permissions
 *     - DO NOT authenticate users
 *     - DO NOT replace backend authorization
 *     - DO NOT define new RBAC permissions
 *
 * They only provide stable frontend identifiers for UI permission checks.
 *
 * ============================================================================
 */

/* ============================================================================
 * Canonical Global Audit Permission
 * ============================================================================ */

/**
 * Permission required by the frontend to expose Global Audit functionality.
 *
 * Canonical SentinelSIEM permission:
 *
 *     users:read
 *
 * This is intentionally shared with User Management because the locked
 * SentinelSIEM RBAC contract does not define an audit-specific permission.
 */
export const AUDIT_READ = "users:read" as const;

/* ============================================================================
 * Canonical User Management Permission
 * ============================================================================ */

/**
 * Canonical User Management read permission.
 *
 * This explicit semantic alias exists because Global Audit access relies on
 * the same permission identifier.
 */
export const USERS_READ = "users:read" as const;

/* ============================================================================
 * Global Audit Permission Collection
 * ============================================================================ */

/**
 * Permissions directly required by the Global Audit frontend module.
 *
 * There is intentionally no:
 *
 *     audit:read
 *     audit:export
 *
 * permission entry.
 *
 * Audit export authorization remains the responsibility of the backend.
 */
export const AUDIT_PERMISSIONS = {
  READ: AUDIT_READ,
} as const;

/* ============================================================================
 * Permission Type
 * ============================================================================ */

/**
 * Type representing the canonical permission used by the Global Audit module.
 */
export type AuditPermission =
  (typeof AUDIT_PERMISSIONS)[keyof typeof AUDIT_PERMISSIONS];

/* ============================================================================
 * Permission Helper
 * ============================================================================ */

/**
 * Check whether a permission identifier belongs to the Global Audit
 * permission contract.
 *
 * This function only validates the permission identifier.
 *
 * It does NOT determine whether the current authenticated user actually
 * possesses the permission.
 */
export function isAuditPermission(
  permission: string,
): permission is AuditPermission {
  return permission === AUDIT_READ;
}

/* ============================================================================
 * Public API
 * ============================================================================ */

export default AUDIT_PERMISSIONS;