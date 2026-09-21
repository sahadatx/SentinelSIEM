/**
 * ============================================================================
 * Dashboard API
 * SentinelSIEM SOC Dashboard
 * ============================================================================
 *
 * Dashboard-owned API boundary.
 *
 * Responsibilities:
 * - Expose only API operations required by the Dashboard.
 * - Keep Dashboard components independent from the shared HTTP client.
 * - Preserve the shared API transport as the single network boundary.
 * - Normalize Dashboard-specific transport data into Dashboard domain types.
 *
 * Architecture:
 *
 *   Dashboard Components
 *          ↓
 *   Dashboard API
 *          ↓
 *   Shared API Service
 *          ↓
 *   SentinelSIEM Backend
 *
 * No business logic, state, caching, or presentation concerns belong here.
 * ============================================================================
 */

import { api } from "../../services/api";

import type {
  IOC,
  PaginatedResponse,
} from "../../types/api";

import type {
  IOCTransportResponse,
} from "../../services/api";

/* ============================================================================
 * IOC Normalization
 * ========================================================================== */

/**
 * Convert the shared IOC transport model into the IOC model consumed by the
 * existing Dashboard domain.
 *
 * Dashboard's IOC contract intentionally remains:
 *
 *   src/types/api.ts -> IOC
 *
 * while the shared API transport remains:
 *
 *   src/services/api.ts -> IOCTransportResponse
 */
function normalizeDashboardIOC(
  ioc: IOCTransportResponse,
): IOC {
  return {
    ioc_id: ioc.ioc_id,
    ioc_type: ioc.ioc_type,
    value: ioc.value,
    confidence: ioc.confidence,
    source: ioc.source ?? "",
    first_seen: ioc.first_seen,
    last_seen: ioc.last_seen,
    expiration: ioc.expiration,
    feed: ioc.feed,
    reputation: ioc.reputation,
    status: ioc.status,
    metadata: ioc.metadata ?? {},
  };
}

/**
 * Convert the shared transport pagination response into the existing
 * Dashboard IOC pagination contract.
 */
function normalizeDashboardIOCs(
  response: PaginatedResponse<IOCTransportResponse>,
): PaginatedResponse<IOC> {
  return {
    ...response,
    items: response.items.map(normalizeDashboardIOC),
  };
}

/* ============================================================================
 * Dashboard API
 * ========================================================================== */

export const dashboardApi = {
  /* --------------------------------------------------------------------------
   * Security Events
   * ------------------------------------------------------------------------ */

  /**
   * Load security events displayed by the Dashboard.
   */
  events() {
    return api.events();
  },

  /* --------------------------------------------------------------------------
   * Alerts
   * ------------------------------------------------------------------------ */

  /**
   * Load alerts displayed by the Dashboard.
   */
  alerts() {
    return api.alerts();
  },

  /* --------------------------------------------------------------------------
   * Incidents
   * ------------------------------------------------------------------------ */

  /**
   * Load incidents displayed by the Dashboard.
   */
  incidents() {
    return api.incidents();
  },

  /* --------------------------------------------------------------------------
   * Indicators of Compromise
   * ------------------------------------------------------------------------ */

  /**
   * Load IOC data used by Dashboard widgets.
   *
   * Shared API transport:
   *   IOCTransportResponse
   *
   * Dashboard domain:
   *   IOC
   *
   * The conversion happens here so Dashboard components never need to know
   * about transport-specific field names or nullable transport values.
   */
  async iocs(): Promise<PaginatedResponse<IOC>> {
    const response = await api.iocs();

    return normalizeDashboardIOCs(response);
  },

  /* --------------------------------------------------------------------------
   * MITRE ATT&CK
   * ------------------------------------------------------------------------ */

  /**
   * Load MITRE ATT&CK coverage information.
   */
  mitre() {
    return api.mitre();
  },

  /* --------------------------------------------------------------------------
   * Health
   * ------------------------------------------------------------------------ */

  /**
   * Load API health information.
   */
  health() {
    return api.health();
  },

  /* --------------------------------------------------------------------------
   * System / Platform
   * ------------------------------------------------------------------------ */

  /**
   * Load SentinelSIEM system and platform information.
   */
  system() {
    return api.system();
  },
} as const;

/* ============================================================================
 * Default Export
 * ========================================================================== */

export default dashboardApi;