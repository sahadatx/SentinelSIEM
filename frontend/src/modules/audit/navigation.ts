/**
 * ============================================================================
 * SentinelSIEM — Global Audit Navigation
 * ============================================================================
 *
 * Feature-owned navigation metadata for the Global Audit module.
 *
 * The application-level navigation registry is responsible only for
 * composing this definition into the global navigation.
 *
 * Global Audit access uses the locked RBAC permission:
 *
 *     users:read
 *
 * Backend authorization remains the authoritative security boundary.
 *
 * ============================================================================
 */

import {
  FileSearch,
} from "lucide-react";

import {
  AUDIT_READ,
} from "./permissions";

/* ============================================================================
 * Navigation Contract
 * ========================================================================== */

/**
 * Canonical navigation definition for the Global Audit module.
 *
 * This metadata is intentionally owned by the Audit feature module.
 */
export const auditNavigation = {
  /**
   * Global Audit route.
   */
  to: "/audit",

  /**
   * Navigation label displayed in the application sidebar.
   */
  label: "Audit Logs",

  /**
   * Locked SentinelSIEM permission required to expose Audit navigation.
   *
   * This resolves to:
   *
   *     users:read
   */
  permission: AUDIT_READ,

  /**
   * Audit navigation icon.
   */
  icon: FileSearch,

  /**
   * Exact route matching.
   *
   * Prevents the Audit navigation item from remaining active on
   * unrelated routes.
   */
  end: true,
} as const;

/* ============================================================================
 * Type
 * ========================================================================== */

/**
 * Structural type of the Audit navigation definition.
 */
export type AuditNavigation = typeof auditNavigation;

/* ============================================================================
 * Default Export
 * ========================================================================== */

export default auditNavigation;
