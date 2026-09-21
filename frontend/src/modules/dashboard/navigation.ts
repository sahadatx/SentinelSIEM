/*
 * ============================================================================
 * Dashboard Navigation
 * SentinelSIEM SOC Dashboard
 * ============================================================================
 *
 * Dashboard-owned navigation metadata.
 *
 * The application navigation registry should compose this definition rather
 * than duplicating the Dashboard route, label, permission, and icon.
 * ============================================================================
 */

import { LayoutDashboard } from "lucide-react";

import { DASHBOARD_PERMISSIONS } from "./permissions";

/* ==========================================================================
 * Dashboard Navigation Contract
 * ========================================================================== */

export const dashboardNavigation = {
  to: "/",
  label: "Overview",
  permission: DASHBOARD_PERMISSIONS.read,
  icon: LayoutDashboard,
  end: true,
} as const;

/* ==========================================================================
 * Default Export
 * ========================================================================== */

export default dashboardNavigation;
