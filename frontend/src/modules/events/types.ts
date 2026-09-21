/*
 * ============================================================================
 * Events Types
 * SentinelSIEM — Security Events Module
 * ============================================================================
 *
 * Feature-owned TypeScript contracts for the Events module.
 *
 * Responsibilities:
 * - Define the public SecurityEvent model.
 * - Define Events filter parameters.
 * - Define dynamic Events filter options.
 * - Define controlled Events filter state.
 * - Define the paginated Events response.
 * - Define backend Events statistics response.
 * - Keep compatibility with existing Events components during migration.
 *
 * Backend contracts:
 *   backend/app/api/schemas/events.py
 *   backend/app/storage/repositories/events.py
 *   backend/app/storage/opensearch/events.py
 *
 * Endpoints:
 *   GET /api/v1/events
 *   GET /api/v1/events/{event_id}
 *   GET /api/v1/events/filter-options
 *   GET /api/v1/events/statistics
 * ============================================================================
 */

import type { PaginatedResponse } from "../../types/api";

/* ============================================================================
 * Security Event
 * ========================================================================== */

/**
 * Public API representation of a persisted SentinelSIEM security event.
 */
export interface SecurityEvent {
  /**
   * Globally unique event identifier.
   */
  event_id: string;

  /**
   * Original event timestamp.
   */
  timestamp: string;

  /**
   * Timestamp when the event was ingested by SentinelSIEM.
   */
  ingestion_timestamp: string;

  /**
   * Event source or collector identifier.
   */
  source: string;

  /**
   * Source transport / collector type.
   */
  source_type: string;

  /**
   * Source hostname, when available.
   */
  hostname: string | null;

  /**
   * Source IP address, when available.
   */
  source_ip: string | null;

  /**
   * Destination IP address, when available.
   */
  destination_ip: string | null;

  /**
   * Source port, when available.
   */
  source_port: number | null;

  /**
   * Destination port, when available.
   */
  destination_port: number | null;

  /**
   * Network protocol, when available.
   */
  protocol: string | null;

  /**
   * Event username, when available.
   *
   * This represents the identity observed inside the security event.
   * It is not necessarily a SentinelSIEM application user.
   */
  username: string | null;

  /**
   * Associated process name, when available.
   */
  process: string | null;

  /**
   * Associated command or command line, when available.
   */
  command: string | null;

  /**
   * Security action represented by the event.
   */
  action: string | null;

  /**
   * Event outcome.
   */
  outcome: string;

  /**
   * Normalized event severity.
   */
  severity: string;

  /**
   * Normalized event category.
   */
  category: string;

  /**
   * Original raw event payload.
   */
  raw_event: string;

  /**
   * Source-specific parsed fields.
   */
  parsed_data: Record<string, unknown>;

  /**
   * Canonical normalized event fields.
   */
  normalized_data: Record<string, unknown>;

  /**
   * Optional enrichment information.
   */
  enrichment: Record<string, unknown> | null;

  /**
   * Additional event metadata.
   */
  metadata: Record<string, unknown>;

  /**
   * Current event processing stage.
   */
  stage: string;
}

/* ============================================================================
 * Events Filter Parameters
 * ========================================================================== */

/**
 * Query parameters supported by:
 *
 *   GET /api/v1/events
 *
 * These fields intentionally match the finalized Events filter UI.
 */
export interface EventListParams {
  /**
   * Free-text event search.
   *
   * Backend search fields:
   * - username
   * - action
   * - command
   * - process
   * - raw_event
   */
  query?: string;

  /**
   * Exact event source filter.
   */
  source?: string;

  /**
   * Exact source IP filter.
   */
  source_ip?: string;

  /**
   * Exact destination IP filter.
   */
  destination_ip?: string;

  /**
   * Exact event username filter.
   *
   * This is the username observed in the event,
   * not necessarily an application user.
   */
  username?: string;

  /**
   * Exact event action filter.
   */
  action?: string;

  /**
   * Exact event outcome filter.
   */
  outcome?: string;

  /**
   * Exact event severity filter.
   */
  severity?: string;

  /**
   * Exact event category filter.
   */
  category?: string;

  /**
   * Inclusive lower event timestamp boundary.
   *
   * Expected API representation:
   * ISO-8601 datetime string.
   */
  start_time?: string;

  /**
   * Inclusive upper event timestamp boundary.
   *
   * Expected API representation:
   * ISO-8601 datetime string.
   */
  end_time?: string;

  /**
   * One-based page number.
   */
  page?: number;

  /**
   * Number of events requested per page.
   */
  page_size?: number;
}

/* ============================================================================
 * Dynamic Events Filter Options
 * ========================================================================== */

/**
 * Dynamic dropdown values returned by:
 *
 *   GET /api/v1/events/filter-options
 *
 * These values must come from persisted event data on the backend.
 *
 * The frontend must NOT maintain hardcoded event-option lists.
 */
export interface EventFilterOptions {
  /**
   * Distinct event sources.
   */
  sources: string[];

  /**
   * Distinct usernames observed in security events.
   *
   * These are event identities, not necessarily application users.
   */
  users: string[];

  /**
   * Distinct event actions.
   */
  actions: string[];

  /**
   * Distinct event outcomes.
   */
  outcomes: string[];

  /**
   * Distinct event severities.
   */
  severities: string[];

  /**
   * Distinct event categories.
   */
  categories: string[];
}

/* ============================================================================
 * Event Filter State
 * ========================================================================== */

/**
 * Controlled frontend state for the Events filter panel.
 *
 * Empty strings represent an unselected / cleared filter.
 *
 * This state intentionally contains only the finalized Events filters:
 * - Search
 * - Source
 * - Source IP
 * - Destination IP
 * - User
 * - Action
 * - Outcome
 * - Severity
 * - Category
 * - From
 * - To
 */
export interface EventFilterState {
  /**
   * Free-text event search.
   */
  query: string;

  /**
   * Selected event source.
   */
  source: string;

  /**
   * Source IP input.
   */
  source_ip: string;

  /**
   * Destination IP input.
   */
  destination_ip: string;

  /**
   * Selected event username.
   */
  username: string;

  /**
   * Selected event action.
   */
  action: string;

  /**
   * Selected event outcome.
   */
  outcome: string;

  /**
   * Selected event severity.
   */
  severity: string;

  /**
   * Selected event category.
   */
  category: string;

  /**
   * From date/time.
   */
  start_time: string;

  /**
   * To date/time.
   */
  end_time: string;
}

/* ============================================================================
 * Event Statistics
 * ========================================================================== */

/**
 * Aggregate event statistics returned by:
 *
 *   GET /api/v1/events/statistics
 *
 * Counts represent the complete filtered dataset and are independent
 * of pagination.
 *
 * Backend contract:
 *
 * {
 *   total: number,
 *   critical: number,
 *   high: number,
 *   medium: number,
 *   low: number,
 *   info: number
 * }
 */
export interface EventStatisticsResponse {
  /**
   * Total number of events matching the active filters.
   */
  total: number;

  /**
   * Number of critical-severity events matching the active filters.
   */
  critical: number;

  /**
   * Number of high-severity events matching the active filters.
   */
  high: number;

  /**
   * Number of medium-severity events matching the active filters.
   */
  medium: number;

  /**
   * Number of low-severity events matching the active filters.
   */
  low: number;

  /**
   * Number of informational events matching the active filters.
   */
  info: number;
}

/**
 * Compatibility alias for components that use EventStatistics.
 */
export type EventStatistics = EventStatisticsResponse;

/* ============================================================================
 * Event List Response
 * ========================================================================== */

/**
 * Paginated response returned by:
 *
 *   GET /api/v1/events
 */
export type EventListResponse = PaginatedResponse<SecurityEvent>;

/* ============================================================================
 * Compatibility
 * ========================================================================== */

/**
 * Temporary compatibility alias.
 *
 * Existing Events components may still import:
 *
 *   import type { Event } from "../types";
 *
 * New code should prefer SecurityEvent.
 */
export type Event = SecurityEvent;