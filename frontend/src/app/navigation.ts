/**
 * ============================================================================
 * SentinelSIEM — Application Navigation
 * ============================================================================
 *
 * Application-level navigation registry.
 *
 * Feature modules own their navigation metadata:
 *
 * - Dashboard
 * - Events
 * - Alerts
 * - Incidents
 * - Threat Intelligence
 * - Detection
 * - MITRE ATT&CK
 * - Assets
 * - Users
 * - Audit
 * - System
 *
 * The application registry only composes feature-owned navigation
 * definitions.
 *
 * It must not duplicate:
 *
 * - feature-specific routes
 * - labels
 * - permissions
 * - icons
 *
 * The application-level layer may provide structural metadata such as:
 *
 * - navigation section
 *
 * This allows AppShell to render a professional grouped navigation
 * without taking ownership of feature-specific metadata.
 * ============================================================================
 */

import type { LucideIcon } from "lucide-react";


/**
 * ============================================================================
 * Feature Navigation
 * ============================================================================
 */

import { alertsNavigation } from "../modules/alerts/navigation";
import { assetsNavigation } from "../modules/assets/navigation";
import { auditNavigation } from "../modules/audit/navigation";
import { dashboardNavigation } from "../modules/dashboard/navigation";
import { detectionNavigation } from "../modules/detections/navigation";
import { eventsNavigation } from "../modules/events/navigation";
import { incidentsNavigation } from "../modules/incidents/navigation";
import { mitreNavigation } from "../modules/mitre/navigation";
import {
  threatIntelligenceNavigation,
} from "../modules/threat-intelligence/navigation";
import { usersNavigation } from "../modules/users/navigation";
import { systemNavigation } from "../modules/system/navigation";


/**
 * ============================================================================
 * Navigation Section
 * ============================================================================
 */

/**
 * Top-level visual grouping used by AppShell.
 *
 * This is presentation/organization metadata only.
 *
 * It does not represent authorization.
 *
 * Authorization remains controlled exclusively by:
 *
 *   item.permission
 *
 * and:
 *
 *   getNavigation()
 */
export type NavigationSection =
  | "operations"
  | "administration";


/**
 * ============================================================================
 * Navigation Contract
 * ============================================================================
 */

/**
 * Application-level navigation contract.
 *
 * Every rendered navigation item satisfies this shape.
 *
 * Feature modules remain responsible for:
 *
 * - route
 * - label
 * - permission
 * - icon
 *
 * The application registry adds only structural section metadata.
 */
export interface NavigationItem {
  /**
   * Route destination.
   */
  to: string;

  /**
   * Human-readable navigation label.
   */
  label: string;

  /**
   * Required RBAC permission.
   */
  permission: string;

  /**
   * Navigation icon.
   */
  icon: LucideIcon;

  /**
   * Whether the route should use exact matching.
   */
  end?: boolean;

  /**
   * Visual navigation section.
   *
   * This does NOT perform authorization.
   */
  section: NavigationSection;
}


/**
 * ============================================================================
 * Feature Navigation Contract
 * ============================================================================
 */

/**
 * Structural contract accepted from feature-owned navigation definitions.
 *
 * Feature modules do not need to know about application-level sections.
 *
 * Their existing route/label/permission/icon ownership remains unchanged.
 */
interface FeatureNavigationItem {
  to: string;
  label: string;
  permission: string;
  icon: LucideIcon;
  end?: boolean;
}


/**
 * ============================================================================
 * Navigation Adapter
 * ============================================================================
 */

/**
 * Convert a feature-owned navigation definition into the application-level
 * navigation contract.
 *
 * The feature remains the owner of:
 *
 * - route
 * - label
 * - permission
 * - icon
 *
 * The application registry supplies only the structural section.
 */
function composeNavigationItem(
  item: FeatureNavigationItem,
  section: NavigationSection,
): NavigationItem {
  const navigationItem: NavigationItem = {
    to: item.to,
    label: item.label,
    permission: item.permission,
    icon: item.icon,
    section,
  };

  if (item.end !== undefined) {
    navigationItem.end = item.end;
  }

  return navigationItem;
}


/**
 * ============================================================================
 * Users Navigation Adapter
 * ============================================================================
 *
 * The existing Users module exposes `path` instead of `to`.
 *
 * Keep the compatibility adapter here so the application registry does
 * not duplicate the Users module's permission, label, or icon values.
 */

function composeUsersNavigationItem(
  section: NavigationSection,
): NavigationItem {
  return composeNavigationItem(
    {
      to: usersNavigation.path,
      label: usersNavigation.label,
      permission: usersNavigation.permission,
      icon: usersNavigation.icon,
    },
    section,
  );
}


/**
 * ============================================================================
 * Central Navigation Registry
 * ============================================================================
 */

/**
 * Application-level navigation registry.
 *
 * All feature-specific navigation metadata remains owned by its module.
 *
 * Ordering here controls the visual ordering inside AppShell.
 */
export const navigation: NavigationItem[] = [

  /**
   * --------------------------------------------------------------------------
   * Operations
   * --------------------------------------------------------------------------
   */

  composeNavigationItem(
    dashboardNavigation,
    "operations",
  ),

  composeNavigationItem(
    eventsNavigation,
    "operations",
  ),

  composeNavigationItem(
    alertsNavigation,
    "operations",
  ),

  composeNavigationItem(
    incidentsNavigation,
    "operations",
  ),

  composeNavigationItem(
    threatIntelligenceNavigation,
    "operations",
  ),

  composeNavigationItem(
    detectionNavigation,
    "operations",
  ),

  composeNavigationItem(
    mitreNavigation,
    "operations",
  ),

  composeNavigationItem(
    assetsNavigation,
    "operations",
  ),

  composeUsersNavigationItem(
    "operations",
  ),

  /**
   * --------------------------------------------------------------------------
   * Administration
   * --------------------------------------------------------------------------
   */

  composeNavigationItem(
    auditNavigation,
    "administration",
  ),

  composeNavigationItem(
    systemNavigation,
    "administration",
  ),
];


/**
 * ============================================================================
 * Navigation Helpers
 * ============================================================================
 */

/**
 * Return only navigation entries allowed for the current user.
 *
 * Permission evaluation remains owned by the authentication/RBAC layer.
 *
 * The `section` property is intentionally ignored during authorization.
 *
 * Backend authorization remains the authoritative security boundary.
 */
export function getNavigation(
  hasPermission: (
    permission: string,
  ) => boolean,
): NavigationItem[] {
  return navigation.filter(
    (item) =>
      hasPermission(
        item.permission,
      ),
  );
}


/**
 * ============================================================================
 * Navigation Group Helpers
 * ============================================================================
 */

/**
 * Return only navigation items belonging to a section.
 *
 * This helper is intentionally presentation-oriented.
 *
 * It does not perform permission checks.
 *
 * Call `getNavigation()` first when authorization filtering is required.
 */
export function getNavigationBySection(
  items: NavigationItem[],
  section: NavigationSection,
): NavigationItem[] {
  return items.filter(
    (item) =>
      item.section === section,
  );
}


/**
 * ============================================================================
 * Default Export
 * ============================================================================
 */

export default navigation;