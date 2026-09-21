/*
 * ==========================================================================
 * System Navigation
 * SentinelSIEM SOC Dashboard
 * ==========================================================================
 *
 * System module-owned navigation metadata.
 *
 * The System module owns:
 *
 * - route
 * - label
 * - permission
 * - icon
 *
 * The application-level navigation registry only composes this definition.
 *
 * ==========================================================================
 */

import { Server } from "lucide-react";

import { PERMISSIONS } from "../../auth/rbac";

/*
 * ==========================================================================
 * System Navigation Definition
 * ==========================================================================
 */

export const systemNavigation = {
  to: "/system",
  label: "System Health",
  permission: PERMISSIONS.SYSTEM_READ,
  icon: Server,
};

/*
 * ==========================================================================
 * Default Export
 * ==========================================================================
 */

export default systemNavigation;
