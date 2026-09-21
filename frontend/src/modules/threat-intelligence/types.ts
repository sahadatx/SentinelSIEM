import type { Pagination } from "../../types/api";

/* ============================================================================
 * SentinelSIEM — Threat Intelligence Types
 * ========================================================================== */

/**
 * Backend-owned IOC catalogues.
 *
 * These remain `string` intentionally so newly introduced backend values can
 * be consumed without requiring a frontend type change.
 */
export type IOCType = string;

export type IOCSeverity = string;

export type IOCStatus = string;

export type IOCReputation = string;

/* ============================================================================
 * IOC Relationships
 * ========================================================================== */

export interface IOCRelationships {
  event_ids: string[];

  alert_ids: string[];

  incident_ids: string[];

  asset_ids: string[];

  mitre_technique_ids: string[];

  event_count: number;

  alert_count: number;

  incident_count: number;

  asset_count: number;

  mitre_technique_count: number;
}

/* ============================================================================
 * IOC Entity
 * ========================================================================== */

export interface IOC {
  /**
   * Backend IOC identifier.
   */
  id: string;

  /**
   * Backend indicator/display representation.
   */
  indicator: string;

  /**
   * IOC type.
   */
  type: IOCType;

  /**
   * IOC value.
   */
  value: string;

  /**
   * Backend confidence value.
   */
  confidence: number;

  /**
   * IOC severity.
   */
  severity: IOCSeverity;

  /**
   * Backend lifecycle status.
   */
  status: IOCStatus;

  /**
   * IOC source.
   */
  source: string | null;

  /**
   * IOC feed.
   */
  feed: string | null;

  /**
   * IOC reputation.
   */
  reputation: IOCReputation;

  /**
   * IOC description.
   */
  description: string;

  /**
   * IOC tags.
   */
  tags: string[];

  /**
   * Backend lifecycle convenience flag.
   */
  active: boolean;

  /**
   * First observation timestamp.
   */
  first_seen: string;

  /**
   * Last observation timestamp.
   */
  last_seen: string;

  /**
   * Expiration timestamp.
   */
  expiration: string | null;

  /**
   * Creation timestamp.
   *
   * May be null for legacy records.
   */
  created_at: string | null;

  /**
   * Update timestamp.
   *
   * May be null for legacy records.
   */
  updated_at: string | null;

  /**
   * Additional backend metadata.
   */
  metadata: Record<string, unknown>;
}

/* ============================================================================
 * IOC Detail
 * ========================================================================== */

/**
 * Detailed IOC entity.
 *
 * The backend detail endpoint includes relationships.
 */
export interface IOCDetail extends IOC {
  relationships: IOCRelationships;
}

/* ============================================================================
 * IOC Match
 * ========================================================================== */

/**
 * IOC observable match response.
 *
 * Backend:
 *   GET /api/v1/iocs/match?observable=...
 */
export interface IOCMatch {
  id: string;

  indicator: string;

  type: IOCType;

  value: string;

  matched: boolean;

  confidence: number;

  severity: IOCSeverity;

  status: IOCStatus;

  reputation: IOCReputation;

  source: string | null;

  feed: string | null;

  tags: string[];

  metadata: Record<string, unknown>;
}

/* ============================================================================
 * IOC List Response
 * ========================================================================== */

/**
 * Paginated IOC inventory response.
 *
 * Backend response:
 *
 * {
 *   "items": [],
 *   "pagination": {
 *     "page": 1,
 *     "page_size": 30,
 *     "total": 2
 *   }
 * }
 *
 * IMPORTANT:
 * The frontend does not calculate total_pages.
 */
export interface IOCListResponse {
  items: IOC[];

  pagination: Pagination & {
    total_pages: number;
  };
}

/* ============================================================================
 * IOC Summary / KPI
 * ========================================================================== */

/**
 * Backend:
 *   GET /api/v1/iocs/summary
 *
 * KPI fields:
 *   total
 *   active
 *   high_risk
 *   expired
 */
export interface IOCSummary {
  /**
   * Total IOCs.
   *
   * Backend field:
   *   total
   */
  total: number;

  /**
   * Active IOCs.
   */
  active: number;

  /**
   * High-risk IOCs.
   */
  high_risk: number;

  /**
   * Expired IOCs.
   */
  expired: number;

  /**
   * Additional backend summary metric.
   */
  malicious: number;

  /**
   * Additional backend summary metric.
   */
  recently_updated: number;

  /**
   * Additional backend summary metric.
   */
  revoked: number;

  /**
   * Backend grouped counts.
   */
  by_type: Record<string, number>;

  /**
   * Backend grouped counts.
   */
  by_source: Record<string, number>;

  /**
   * Backend grouped counts.
   */
  by_severity: Record<string, number>;

  /**
   * Backend grouped counts.
   */
  by_status: Record<string, number>;

  /**
   * Backend grouped counts.
   */
  by_reputation: Record<string, number>;
}

/* ============================================================================
 * Backend Filter Options
 * ========================================================================== */

/**
 * Authoritative IOC catalogue.
 *
 * Backend:
 *   GET /api/v1/iocs/filter-options
 *
 * The frontend does not define IOC catalogue values.
 */
export interface IOCFilterOptions {
  types: string[];

  severities: string[];

  statuses: string[];

  sources: string[];

  reputations: string[];
}

/* ============================================================================
 * IOC List Filters
 * ========================================================================== */

/**
 * IOC inventory filters.
 *
 * Filtering is performed by the backend.
 */
export interface IOCListFilters {
  /**
   * Canonical backend search parameter.
   */
  query?: string;

  /**
   * Compatibility alias.
   *
   * The feature API normalizes this to `query`.
   */
  search?: string;

  /**
   * IOC type.
   */
  type?: IOCType;

  /**
   * IOC severity.
   */
  severity?: IOCSeverity;

  /**
   * IOC status.
   */
  status?: IOCStatus;

  /**
   * IOC source.
   */
  source?: string;

  /**
   * IOC reputation.
   */
  reputation?: IOCReputation;

  /**
   * Optional backend active filter.
   */
  active?: boolean;

  /**
   * Optional backend start time.
   */
  start_time?: string;

  /**
   * Optional backend end time.
   */
  end_time?: string;

  /**
   * Backend page.
   */
  page?: number;

  /**
   * Backend page size.
   */
  page_size?: number;
}

/* ============================================================================
 * IOC Relationship Endpoint
 * ========================================================================== */

/**
 * Dedicated relationship endpoint response.
 *
 * Backend:
 *   GET /api/v1/iocs/{ioc_id}/relationships
 *
 * The detail endpoint already includes the same relationship information.
 */
export interface IOCRelationshipResponse
  extends IOCRelationships {
  ioc_id: string;
}

/* ============================================================================
 * Create IOC Request
 * ========================================================================== */

/**
 * Create IOC request.
 *
 * Backend:
 *   POST /api/v1/iocs
 *
 * IMPORTANT:
 * `status` is intentionally absent.
 *
 * Initial lifecycle state is owned by the backend.
 *
 * Backend-managed fields include:
 *   id
 *   status
 *   active
 *   first_seen
 *   last_seen
 *   created_at
 *   updated_at
 */
export interface IOCCreateRequest {
  /**
   * IOC value.
   */
  value: string;

  /**
   * IOC type.
   *
   * Value comes from the backend catalogue.
   */
  type: IOCType;

  /**
   * Optional confidence.
   */
  confidence?: number;

  /**
   * Optional severity.
   *
   * Value comes from the backend catalogue.
   */
  severity?: IOCSeverity;

  /**
   * Optional source.
   */
  source?: string;

  /**
   * Optional feed.
   */
  feed?: string;

  /**
   * Optional reputation.
   *
   * Value comes from the backend catalogue.
   */
  reputation?: IOCReputation;

  /**
   * Optional expiration timestamp.
   */
  expiration?: string | null;

  /**
   * Optional description.
   */
  description?: string;

  /**
   * Optional tags.
   */
  tags?: string[];

  /**
   * Optional backend metadata.
   */
  metadata?: Record<string, unknown>;

  /**
   * Optional relationship identifiers.
   */
  relationships?: Partial<IOCRelationships>;
}

/* ============================================================================
 * Update IOC Request
 * ========================================================================== */

/**
 * Update IOC request.
 *
 * Backend:
 *   PATCH /api/v1/iocs/{ioc_id}
 *
 * IMPORTANT:
 * `status` is intentionally absent.
 *
 * Lifecycle changes use dedicated endpoints:
 *
 *   POST /api/v1/iocs/{ioc_id}/revoke
 *   POST /api/v1/iocs/{ioc_id}/activate
 */
export interface IOCUpdateRequest {
  /**
   * Updated IOC value.
   */
  value?: string;

  /**
   * Updated IOC type.
   */
  type?: IOCType;

  /**
   * Updated confidence.
   */
  confidence?: number;

  /**
   * Updated severity.
   */
  severity?: IOCSeverity;

  /**
   * Updated source.
   */
  source?: string;

  /**
   * Updated feed.
   */
  feed?: string;

  /**
   * Updated reputation.
   */
  reputation?: IOCReputation;

  /**
   * Updated expiration timestamp.
   */
  expiration?: string | null;

  /**
   * Updated description.
   */
  description?: string;

  /**
   * Updated tags.
   */
  tags?: string[];

  /**
   * Updated backend metadata.
   */
  metadata?: Record<string, unknown>;

  /**
   * Updated relationship identifiers.
   */
  relationships?: Partial<IOCRelationships>;
}

/* ============================================================================
 * IOC Lifecycle Responses
 * ========================================================================== */

/**
 * Response returned after a lifecycle operation.
 */
export type IOCStatusActionResponse = IOC;

/**
 * Revoke IOC response.
 *
 * Backend:
 *   POST /api/v1/iocs/{ioc_id}/revoke
 */
export type IOCRevokeResponse = IOCStatusActionResponse;

/**
 * Activate IOC response.
 *
 * Backend:
 *   POST /api/v1/iocs/{ioc_id}/activate
 */
export type IOCActivateResponse = IOCStatusActionResponse;

/* ============================================================================
 * Create Form State
 * ========================================================================== */

/**
 * Add IOC form state.
 *
 * Status is intentionally absent because the backend owns initial lifecycle
 * state.
 */
export interface IOCCreateFormState {
  value: string;

  type: IOCType | "";

  severity: IOCSeverity | "";

  reputation: IOCReputation | "";

  source: string;

  feed: string;

  description: string;

  tags: string[];

  expiration: string;
}

/* ============================================================================
 * Edit Form State
 * ========================================================================== */

/**
 * Edit IOC form state.
 *
 * Status is intentionally absent.
 *
 * Enable/Disable is a separate lifecycle operation.
 */
export interface IOCEditFormState {
  value: string;

  type: IOCType | "";

  severity: IOCSeverity | "";

  reputation: IOCReputation | "";

  source: string;

  feed: string;

  description: string;

  tags: string[];

  expiration: string;
}

/* ============================================================================
 * Drawer State
 * ========================================================================== */

/**
 * Threat Intelligence drawer mode.
 */
export type IOCDrawerMode =
  | "view"
  | "create"
  | "edit";

/**
 * IOC lifecycle action.
 */
export type IOCLifecycleAction =
  | "revoke"
  | "activate";

/* ============================================================================
 * UI Catalogue Option
 * ========================================================================== */

/**
 * Renderable catalogue option.
 *
 * `value` comes from the backend.
 * `label` is display-only formatting.
 */
export interface IOCOption {
  value: string;

  label: string;
}

/* ============================================================================
 * API Error
 * ========================================================================== */

export interface IOCAPIError {
  detail?: string;

  message?: string;

  code?: string;
}

/* ============================================================================
 * Runtime State Helpers
 * ========================================================================== */

/**
 * Determine whether an IOC is active.
 *
 * This does not define the backend status catalogue.
 */
export function isIOCActive(
  ioc: Pick<IOC, "active" | "status">,
): boolean {
  return (
    ioc.active === true ||
    ioc.status === "active"
  );
}

/**
 * Determine whether an IOC is revoked.
 */
export function isIOCRevoked(
  ioc: Pick<IOC, "status">,
): boolean {
  return ioc.status === "revoked";
}

/**
 * Determine whether an IOC is expired.
 */
export function isIOCExpired(
  ioc: Pick<IOC, "status">,
): boolean {
  return ioc.status === "expired";
}

/* ============================================================================
 * End of File
 * ========================================================================== */