/* ==========================================================================
 * Asset Management Permissions
 * SentinelSIEM SOC Dashboard
 * ========================================================================== */

/**
 * Permission required to read/list assets.
 *
 * Backend:
 * GET /api/v1/assets
 * GET /api/v1/assets/{asset_id}
 * GET /api/v1/assets/statistics
 */
export const ASSETS_READ = "assets:read" as const;

/**
 * Permission required for asset-management mutations.
 *
 * Backend:
 * POST  /api/v1/assets
 * PATCH /api/v1/assets/{asset_id}
 * PATCH /api/v1/assets/{asset_id}/status
 *
 * Covers:
 * - Create Asset
 * - Edit Asset
 * - Enable Asset
 * - Disable Asset
 */
export const ASSETS_MANAGE = "assets:manage" as const;

/* ==========================================================================
 * Complete Asset Permission Set
 * ========================================================================== */

/**
 * Complete permission set owned by the Assets module.
 *
 * Useful for:
 * - tests
 * - navigation metadata
 * - permission introspection
 * - RBAC integration
 */
export const ASSET_PERMISSIONS = [
  ASSETS_READ,
  ASSETS_MANAGE,
] as const;

/**
 * Type-safe Asset permission union.
 */
export type AssetPermission = (typeof ASSET_PERMISSIONS)[number];

/* ==========================================================================
 * Permission Helpers
 * ========================================================================== */

/**
 * Check whether a value is a valid Asset permission.
 */
export function isAssetPermission(
  permission: string,
): permission is AssetPermission {
  return (
    permission === ASSETS_READ ||
    permission === ASSETS_MANAGE
  );
}

/**
 * Check whether the user has the required Asset permission.
 */
export function hasAssetPermission(
  permissions: readonly string[] | undefined,
  requiredPermission: AssetPermission,
): boolean {
  if (!permissions) {
    return false;
  }

  return permissions.includes(requiredPermission);
}

/**
 * Check whether the user can read Assets.
 *
 * Includes:
 * - Asset inventory access
 * - Asset details access
 * - Asset statistics access
 * - Asset list/filter/search access
 */
export function canReadAssets(
  permissions: readonly string[] | undefined,
): boolean {
  return hasAssetPermission(permissions, ASSETS_READ);
}

/**
 * Check whether the user can manage Assets.
 *
 * Includes:
 * - Create Asset
 * - Edit Asset
 * - Enable Asset
 * - Disable Asset
 */
export function canManageAssets(
  permissions: readonly string[] | undefined,
): boolean {
  return hasAssetPermission(permissions, ASSETS_MANAGE);
}

/* ==========================================================================
 * Public Exports
 * ========================================================================== */

export default ASSET_PERMISSIONS;