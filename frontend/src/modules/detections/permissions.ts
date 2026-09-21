/* ==========================================================================
 * Detection Module Permissions
 * SentinelSIEM SOC Dashboard
 * ========================================================================== */

/**
 * Detection permissions exposed by the application RBAC layer.
 *
 * These values must remain aligned with:
 *
 *   frontend/src/auth/rbac.ts
 *
 * Current permissions:
 *
 *   detections:read
 *   detections:manage
 *
 * Permission ownership:
 *
 *   READ
 *     - View Detection capability
 *     - View Detection summary
 *     - View Detection rules
 *
 *   MANAGE
 *     - Create Detection rules
 *     - Update Detection rules
 *     - Enable / disable Detection rules
 *     - Delete Detection rules
 */

export const DETECTION_PERMISSIONS = {
  /**
   * Allows viewing Detection resources and operations.
   */
  READ: "detections:read",

  /**
   * Allows managing Detection rules.
   *
   * This includes:
   *
   * - Create rule
   * - Update rule
   * - Enable / disable rule
   * - Delete rule
   */
  MANAGE: "detections:manage",
} as const;

/* ==========================================================================
 * Permission Type
 * ========================================================================== */

/**
 * Union type containing every Detection-specific permission.
 */
export type DetectionPermission =
  (typeof DETECTION_PERMISSIONS)[keyof typeof DETECTION_PERMISSIONS];

/* ==========================================================================
 * Permission Helpers
 * ========================================================================== */

/**
 * Check whether a permission belongs to the Detection module.
 *
 * Useful when building module-level RBAC checks without duplicating
 * permission strings throughout the application.
 */
export function isDetectionPermission(
  permission: string,
): permission is DetectionPermission {
  return (
    permission === DETECTION_PERMISSIONS.READ ||
    permission === DETECTION_PERMISSIONS.MANAGE
  );
}

/**
 * Check whether the supplied permission allows Detection management.
 */
export function canManageDetection(
  permissions: readonly string[],
): boolean {
  return permissions.includes(
    DETECTION_PERMISSIONS.MANAGE,
  );
}

/**
 * Check whether the supplied permission allows Detection read access.
 */
export function canReadDetection(
  permissions: readonly string[],
): boolean {
  return permissions.includes(
    DETECTION_PERMISSIONS.READ,
  );
}

/* ==========================================================================
 * Default Export
 * ========================================================================== */

export default DETECTION_PERMISSIONS;