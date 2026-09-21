import { AlertTriangle } from "lucide-react";

import { ALERTS_READ } from "./permissions";

/* ==========================================================================
 * Alerts Module Navigation
 * SentinelSIEM SOC Dashboard
 * ========================================================================== */

/**
 * Feature-level navigation definition for the Alerts module.
 *
 * The application navigation layer consumes this definition instead of
 * duplicating Alerts-specific route and permission information.
 */
export const alertsNavigation = {
  to: "/alerts",
  label: "Alerts",
  permission: ALERTS_READ,
  icon: AlertTriangle,
} as const;

export default alertsNavigation;
