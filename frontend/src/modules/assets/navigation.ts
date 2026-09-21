/* ==========================================================================
 * Assets Navigation
 * SentinelSIEM SOC Dashboard
 * ========================================================================== */

import type { LucideIcon } from "lucide-react";
import { Database } from "lucide-react";

import { ASSETS_READ } from "./permissions";

/* ==========================================================================
 * Navigation Contract
 * ========================================================================== */

export interface AssetsNavigationItem {
  to: string;
  label: string;
  permission: string;
  icon: LucideIcon;
  end?: boolean;
}

/* ==========================================================================
 * Assets Navigation
 * ========================================================================== */

/**
 * Primary navigation entry for the Assets module.
 *
 * Route:
 *   /assets
 *
 * Required permission:
 *   assets:read
 *
 * All users with ASSETS_READ can access the Assets module.
 */
export const assetsNavigation: AssetsNavigationItem = {
  to: "/assets",
  label: "Assets",
  permission: ASSETS_READ,
  icon: Database,
  end: true,
};

/* ==========================================================================
 * Navigation Helpers
 * ========================================================================== */

/**
 * Complete Assets navigation entries.
 *
 * Kept as an array so the module can be extended with additional
 * Assets-related navigation entries without changing the public contract.
 */
export const assetsNavigationItems: AssetsNavigationItem[] = [
  assetsNavigation,
];

/* ==========================================================================
 * Default Export
 * ========================================================================== */

export default assetsNavigation;