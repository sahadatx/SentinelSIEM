import type { LucideIcon } from "lucide-react";
import { Shield } from "lucide-react";

import { THREAT_INTELLIGENCE_PERMISSIONS } from "./permissions";

/* ==========================================================================
 * Threat Intelligence Navigation
 * SentinelSIEM SOC Dashboard
 * ========================================================================== */

/**
 * Navigation metadata owned by the Threat Intelligence module.
 *
 * The application-level navigation registry should consume this definition
 * instead of duplicating the module's route, label, icon, or permission.
 */
export interface ThreatIntelligenceNavigation {
  to: string;
  label: string;
  permission: string;
  icon: LucideIcon;
}

/**
 * Primary Threat Intelligence navigation entry.
 *
 * Route:
 *   /threat-intelligence
 *
 * Permission:
 *   iocs:read
 */
export const threatIntelligenceNavigation = {
  to: "/threat-intelligence",
  label: "Threat Intelligence",
  permission: THREAT_INTELLIGENCE_PERMISSIONS.READ,
  icon: Shield,
} satisfies ThreatIntelligenceNavigation;

export default threatIntelligenceNavigation;
