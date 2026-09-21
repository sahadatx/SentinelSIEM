/*
 * ============================================================================
 * Events API
 * SentinelSIEM — Security Events Module
 * ============================================================================
 *
 * Feature-specific API boundary for the Events module.
 *
 * Responsibilities:
 * - Expose Events-related backend operations.
 * - Keep the shared HTTP client isolated in services/api.ts.
 * - Provide strongly typed feature-level parameters.
 * - Expose dynamic Events filter options.
 * - Expose backend aggregate Events statistics.
 *
 * Transport:
 *   ../../services/api
 *
 * Backend endpoints:
 *   GET /api/v1/events
 *   GET /api/v1/events/filter-options
 *   GET /api/v1/events/statistics
 *   GET /api/v1/events/{event_id}
 * ============================================================================
 */

import { api as sharedApi } from "../../services/api";

import type {
  EventFilterOptions,
  EventListParams,
  EventStatisticsResponse,
} from "./types";

/*
 * ============================================================================
 * Events API
 * ============================================================================
 */

export const eventsApi = {
  /*
   * --------------------------------------------------------------------------
   * Fetch Events
   * --------------------------------------------------------------------------
   */

  /**
   * Fetch paginated security events.
   *
   * GET /api/v1/events
   *
   * Supported filters:
   * - query
   * - source
   * - source_ip
   * - destination_ip
   * - username
   * - action
   * - outcome
   * - severity
   * - category
   * - start_time
   * - end_time
   * - page
   * - page_size
   */
  list(params: EventListParams = {}) {
    return sharedApi.events(params);
  },

  /*
   * --------------------------------------------------------------------------
   * Fetch Event Statistics
   * --------------------------------------------------------------------------
   */

  /**
   * Fetch aggregate Events statistics.
   *
   * GET /api/v1/events/statistics
   *
   * The backend returns statistics for the complete filtered dataset.
   * Pagination is intentionally not part of the statistics calculation.
   *
   * Returned values:
   * - total
   * - critical
   * - high
   * - medium
   * - low
   * - info
   */
  getStatistics(
    params: Omit<EventListParams, "page" | "page_size"> = {},
  ): Promise<EventStatisticsResponse> {
    return sharedApi.getEventStatistics(params);
  },

  /*
   * --------------------------------------------------------------------------
   * Fetch Dynamic Filter Options
   * --------------------------------------------------------------------------
   */

  /**
   * Fetch dynamic filter options for the Events page.
   *
   * GET /api/v1/events/filter-options
   *
   * The backend provides these values from persisted event data.
   *
   * The frontend must not hardcode event filter values.
   */
  getFilterOptions(): Promise<EventFilterOptions> {
    return sharedApi.getEventFilterOptions();
  },

  /*
   * --------------------------------------------------------------------------
   * Fetch Single Event
   * --------------------------------------------------------------------------
   */

  /**
   * Fetch a single security event by ID.
   *
   * GET /api/v1/events/{event_id}
   */
  getEvent(eventId: string) {
    return sharedApi.getEvent(eventId);
  },
};

/*
 * ============================================================================
 * Backward-Compatible Feature API
 * ============================================================================
 *
 * Keep `api` available for existing Events components/pages that currently
 * import:
 *
 *   import { api } from "../api";
 *
 * This is the same API object and does not create a second implementation.
 * ============================================================================
 */

export const api = eventsApi;

/*
 * ============================================================================
 * Default Export
 * ============================================================================
 */

export default eventsApi;