/* ==========================================================================
 * Detection Module Navigation
 * SentinelSIEM SOC Dashboard
 * ========================================================================== */

import { FileSearch } from "lucide-react";

import { DETECTION_PERMISSIONS } from "./permissions";

/* ==========================================================================
 * Navigation Item
 * ========================================================================== */

/**
 * Feature-level navigation definition for the Detection module.
 *
 * The application navigation layer consumes this definition without
 * duplicating Detection-specific route or permission information.
 *
 * Route:
 *   /detections
 *
 * Permission:
 *   detections:read
 */

export const detectionNavigation = {
  to: "/detections",
  label: "Detection",
  permission: DETECTION_PERMISSIONS.READ,
  icon: FileSearch,
  end: true,
} as const;

/* ==========================================================================
 * Types
 * ========================================================================== */

/**
 * Type of the Detection navigation definition.
 */
export type DetectionNavigation =
  typeof detectionNavigation;

/* ==========================================================================
 * Default Export
 * ========================================================================== */

export default detectionNavigation;