/*
 * ============================================================================
 * Dashboard Permissions
 * SentinelSIEM SOC Dashboard
 * ============================================================================
 *
 * Dashboard-specific permission boundary.
 *
 * Permission definitions themselves remain owned by the central RBAC layer:
 *
 *   auth/rbac.ts
 *
 * This module exposes only the permissions required by the Dashboard.
 * ============================================================================
 */

import { PERMISSIONS } from "../../auth/rbac";

/* ==========================================================================
 * Dashboard Permission Contract
 * ========================================================================== */

export const DASHBOARD_PERMISSIONS = {
  read: PERMISSIONS.DASHBOARD_READ,
} as const;

/* ==========================================================================
 * Default Export
 * ========================================================================== */

export default DASHBOARD_PERMISSIONS;
