/* ============================================================================
 * MITRE ATT&CK Module Navigation
 * SentinelSIEM SOC Dashboard
 * ========================================================================== */

import type { LucideIcon } from "lucide-react";

import { Crosshair } from "lucide-react";

import { MITRE_READ } from "./permissions";

/* ============================================================================
 * Navigation Contract
 * ========================================================================== */

/**
 * Feature-level navigation definition for the MITRE ATT&CK module.
 *
 * The MITRE module owns:
 *
 * - route
 * - label
 * - permission
 * - icon
 * - route matching behavior
 *
 * The application-level navigation registry consumes this
 * definition without duplicating MITRE-specific metadata.
 */
export interface MitreNavigationItem {
  to: string;
  label: string;
  permission: string;
  icon: LucideIcon;
  end: boolean;
}

/* ============================================================================
 * Navigation Definition
 * ========================================================================== */

/**
 * MITRE ATT&CK navigation entry.
 *
 * Route:
 *   /mitre
 *
 * Permission:
 *   mitre:read
 *
 * `end: true` ensures the navigation item is considered
 * active only for the MITRE root route rather than every
 * nested MITRE route.
 */
export const mitreNavigation: MitreNavigationItem = {
  to: "/mitre",
  label: "MITRE ATT&CK",
  permission: MITRE_READ,
  icon: Crosshair,
  end: true,
};

/* ============================================================================
 * Navigation Type
 * ========================================================================== */

/**
 * Exact type of the module-owned MITRE navigation definition.
 */
export type MitreNavigation = typeof mitreNavigation;

/* ============================================================================
 * Default Export
 * ========================================================================== */

export default mitreNavigation;