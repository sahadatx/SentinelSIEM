import { Siren } from "lucide-react";

import { PERMISSIONS } from "../../auth/rbac";

/* ==========================================================================
 * Incidents Navigation
 * SentinelSIEM SOC Dashboard
 * ========================================================================== */

/**
 * Navigation metadata owned by the Incidents module.
 *
 * The application-level navigation registry only composes this definition.
 */
export const incidentsNavigation = {
  to: "/incidents",
  label: "Incidents",
  permission: PERMISSIONS.INCIDENTS_READ,
  icon: Siren,
} as const;

export default incidentsNavigation;