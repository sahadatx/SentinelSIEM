/**
 * ============================================================================
 * Dashboard Types
 * SentinelSIEM SOC Dashboard
 * ============================================================================
 *
 * Dashboard-specific TypeScript contracts.
 *
 * Domain and API models remain owned by their respective modules.
 * This file composes those models into contracts required by the
 * Dashboard feature.
 *
 * Design principles:
 * - Keep Dashboard contracts explicit.
 * - Preserve nullable endpoint responses for partial rendering.
 * - Avoid duplicating shared API/domain models.
 * - Keep presentation contracts independent from API implementation.
 * ============================================================================
 */

import type {
  HealthResponse,
  IOC,
  MitreCoverage,
  PaginatedResponse,
  SecurityEvent,
  SystemResponse,
} from "../../types/api";

import type {
  Alert,
} from "../alerts/types";

import type {
  IncidentListResponse,
} from "../incidents/types";

/* ==========================================================================
 * Dashboard Snapshot
 * ========================================================================== */

/**
 * Complete data snapshot consumed by the Dashboard.
 *
 * Each endpoint is independently nullable because Dashboard data loading
 * uses Promise.allSettled(). This allows the Dashboard to continue rendering
 * available information when one or more backend services are unavailable.
 */
export interface DashboardSnapshot {
  /**
   * Security event data.
   */
  events: PaginatedResponse<SecurityEvent> | null;

  /**
   * Alert data.
   */
  alerts: PaginatedResponse<Alert> | null;

  /**
   * Incident data.
   */
  incidents: IncidentListResponse | null;

  /**
   * IOC data.
   */
  iocs: PaginatedResponse<IOC> | null;

  /**
   * MITRE ATT&CK coverage information.
   */
  mitre: MitreCoverage | null;

  /**
   * Backend health information.
   */
  health: HealthResponse | null;

  /**
   * Platform/system information.
   */
  system: SystemResponse | null;
}

/* ==========================================================================
 * Dashboard Load Result
 * ========================================================================== */

/**
 * Result produced by the Dashboard data-loading workflow.
 *
 * `failedEndpoints` represents the number of Dashboard API requests that
 * could not be resolved successfully during the loading cycle.
 */
export interface DashboardLoadResult {
  /**
   * Aggregated Dashboard data.
   */
  snapshot: DashboardSnapshot;

  /**
   * Number of unavailable API endpoints.
   */
  failedEndpoints: number;
}

/* ==========================================================================
 * Dashboard Platform Status
 * ========================================================================== */

/**
 * Normalized platform status used by Dashboard status presentation.
 */
export interface DashboardPlatformStatus {
  /**
   * Human-readable service/platform name.
   */
  name: string;

  /**
   * Current service/platform state.
   *
   * The value intentionally remains a string because backend health
   * responses may expose different state values.
   */
  state: string;
}

/* ==========================================================================
 * Dashboard Metrics
 * ========================================================================== */

/**
 * High-level security metrics displayed by Dashboard metric cards.
 *
 * Nullable values indicate that the corresponding backend service did not
 * return usable data during the current Dashboard refresh.
 */
export interface DashboardMetrics {
  /**
   * Total number of security events.
   */
  securityEvents: number | null;

  /**
   * Number of currently available/open alerts.
   */
  openAlerts: number | null;

  /**
   * Number of alerts classified as critical.
   *
   * This remains non-null because the metric is derived locally from the
   * available alert collection.
   */
  criticalAlerts: number;

  /**
   * Number of currently active incidents.
   */
  activeIncidents: number | null;

  /**
   * MITRE ATT&CK coverage percentage.
   */
  mitreCoverage: number | null;
}