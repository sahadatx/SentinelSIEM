/**
 * ============================================================================
 * SentinelSIEM — User Management Permissions
 * ============================================================================
 *
 * Centralized permission definitions for the Users module.
 *
 * Backend RBAC contract:
 *
 *   users:read
 *   users:manage
 *
 * IMPORTANT:
 * - These identifiers MUST remain synchronized with the backend.
 * - The frontend MUST NOT invent additional Users permissions.
 * - Backend authorization remains the final security boundary.
 *
 * ============================================================================
 */

/* ============================================================================
 * Read Permission
 * ========================================================================== */

/**
 * Users read permission.
 *
 * Required for read-only User Management operations.
 *
 * Covers:
 *
 *   GET /api/v1/users
 *   GET /api/v1/users/statistics
 *   GET /api/v1/users/{user_id}
 *   GET /api/v1/users/{user_id}/audit
 *
 * This permission does NOT grant mutation privileges.
 */
export const USERS_READ =
  "users:read" as const;

/* ============================================================================
 * Management Permission
 * ========================================================================== */

/**
 * Users management permission.
 *
 * Required for User Management mutations.
 *
 * Covers:
 *
 *   POST   /api/v1/users
 *   PATCH  /api/v1/users/{user_id}
 *   PATCH  /api/v1/users/{user_id}/role
 *   PATCH  /api/v1/users/{user_id}/active
 *   PATCH  /api/v1/users/{user_id}/lock
 *   PATCH  /api/v1/users/{user_id}/password/force-change
 *   POST   /api/v1/users/{user_id}/password/reset
 *   POST   /api/v1/users/{user_id}/sessions/revoke
 *   DELETE /api/v1/users/{user_id}
 *
 * IMPORTANT:
 *
 * The Users module intentionally does NOT define separate
 * frontend permissions for:
 *
 *   users:delete
 *   users:password:reset
 *   users:sessions:manage
 *   users:role:manage
 *   users:security:manage
 *
 * All User Management mutations use:
 *
 *   users:manage
 *
 * Backend authorization remains authoritative.
 */
export const USERS_MANAGE =
  "users:manage" as const;

/* ============================================================================
 * Complete Users Permission Set
 * ========================================================================== */

/**
 * Complete and locked permission collection owned by
 * the SentinelSIEM Users module.
 *
 * DO NOT add additional permissions here unless the backend
 * RBAC contract is explicitly changed.
 */
export const USER_PERMISSIONS = [
  USERS_READ,
  USERS_MANAGE,
] as const;

/**
 * Union of all permissions owned by the Users module.
 *
 * Resolves to:
 *
 *   "users:read" | "users:manage"
 */
export type UserPermission =
  (typeof USER_PERMISSIONS)[number];

/* ============================================================================
 * Permission Groups
 * ========================================================================== */

/**
 * Read-only Users permission group.
 */
export const USER_READ_PERMISSIONS = [
  USERS_READ,
] as const;

/**
 * Users management permission group.
 *
 * All administrative User Management mutations require
 * users:manage.
 */
export const USER_MANAGE_PERMISSIONS = [
  USERS_MANAGE,
] as const;

/* ============================================================================
 * Permission Helpers
 * ========================================================================== */

/**
 * Check whether a permission belongs to the Users module.
 *
 * This is a local frontend membership check only.
 *
 * It does NOT replace backend authorization.
 */
export function isUserPermission(
  permission: string,
): permission is UserPermission {
  return (
    permission === USERS_READ ||
    permission === USERS_MANAGE
  );
}

/**
 * Check whether a permission grants
 * Users read access.
 */
export function isUsersReadPermission(
  permission: string,
): permission is typeof USERS_READ {
  return permission === USERS_READ;
}

/**
 * Check whether a permission grants
 * Users management access.
 */
export function isUsersManagePermission(
  permission: string,
): permission is typeof USERS_MANAGE {
  return permission === USERS_MANAGE;
}

/* ============================================================================
 * Permission Assertions
 * ========================================================================== */

/**
 * Runtime-safe Users permission list.
 *
 * Useful for tests, diagnostics, and module metadata.
 */
export function getUserPermissions(): readonly UserPermission[] {
  return USER_PERMISSIONS;
}

/**
 * Check whether a permission is sufficient for
 * Users read operations.
 *
 * users:manage is intentionally NOT treated as
 * users:read here because permission semantics should
 * remain explicit and synchronized with the backend
 * contract.
 */
export function canReadUsers(
  permission: string,
): boolean {
  return isUsersReadPermission(
    permission,
  );
}

/**
 * Check whether a permission is sufficient for
 * Users management operations.
 */
export function canManageUsers(
  permission: string,
): boolean {
  return isUsersManagePermission(
    permission,
  );
}

/* ============================================================================
 * Default Export
 * ========================================================================== */

/**
 * Complete Users module permission collection.
 */
export default USER_PERMISSIONS;