/**
 * ============================================================================
 * SentinelSIEM — Global Audit Module Types
 * ============================================================================
 *
 * Canonical frontend type boundary for the Global Audit subsystem.
 *
 * Backend:
 *
 *     /api/v1/audit
 *
 * Locked permission:
 *
 *     users:read
 *
 * ============================================================================
 * BACKEND CANONICAL RESPONSE
 * ============================================================================
 *
 * {
 *   total: 446,
 *   page: 1,
 *   page_size: 50,
 *   pages: 9,
 *   events: [
 *     {
 *       audit_id: "...",
 *       actor_user_id: "...",
 *       target_user_id: null,
 *       session_id: "...",
 *       actor: null,
 *       target: null,
 *       request_id: null,
 *       source_ip: "172.20.0.1",
 *       action: "authentication.login_success",
 *       outcome: "success",
 *       metadata_json: {...},
 *       created_at: "..."
 *     }
 *   ]
 * }
 *
 * ============================================================================
 * IMPORTANT
 * ============================================================================
 *
 * Backend uses:
 *
 *     events
 *
 * NOT:
 *
 *     items
 *
 * The API service is responsible for normalizing:
 *
 *     backend.events
 *
 * into:
 *
 *     frontend.items
 *
 * ============================================================================
 * SECURITY
 * ============================================================================
 *
 * Audit types must never expose credential material.
 *
 * Never add:
 *
 *     password
 *     password_hash
 *     access_token
 *     refresh_token
 *     session_token
 *     api_key
 *     client_secret
 *     secret
 *     private_key
 *     authorization
 *     cookie
 *
 * ============================================================================
 */


/* ============================================================================
 * Primitive Types
 * ========================================================================== */

export type ISODateString = string;

export type UserId = string;

export type AuditEventId = string;

export type SessionId = string;

export type RequestId = string;


/* ============================================================================
 * Metadata
 * ========================================================================== */

/**
 * Sanitized audit metadata.
 *
 * Backend is authoritative for sanitization.
 */
export type AuditMetadata =
  Record<string, unknown>;


/* ============================================================================
 * Audit Domain Types
 * ========================================================================== */

export type AuditAction = string;

export type AuditCategory = string;

export type AuditOutcome = string;


/**
 * Canonical backend outcomes.
 */
export type CanonicalAuditOutcome =
  | "success"
  | "failure"
  | "denied";


/* ============================================================================
 * Actor / Target Identity
 * ========================================================================== */

/**
 * Resolved audit identity.
 *
 * Example:
 *
 * {
 *   user_id: "...",
 *   username: "admin",
 *   role: "Administrator"
 * }
 */
export interface AuditIdentity {

  user_id:
    UserId;

  username:
    string;

  role:
    string;
}


/**
 * Actor identity.
 */
export type AuditActor =
  AuditIdentity;


/**
 * Target identity.
 */
export type AuditTarget =
  AuditIdentity;


/* ============================================================================
 * Backend Audit Event
 * ========================================================================== */

/**
 * Canonical backend audit event.
 *
 * This interface matches the current backend JSON response.
 */
export interface BackendAuditEvent {

  /* --------------------------------------------------------------------------
   * Identity
   * ------------------------------------------------------------------------ */

  audit_id:
    AuditEventId;

  actor_user_id:
    UserId | null;

  target_user_id:
    UserId | null;


  /* --------------------------------------------------------------------------
   * Enriched identity
   * ------------------------------------------------------------------------ */

  actor?:
    AuditActor | null;

  target?:
    AuditTarget | null;


  /* --------------------------------------------------------------------------
   * Correlation
   * ------------------------------------------------------------------------ */

  session_id:
    SessionId | null;

  request_id:
    RequestId | null;


  /* --------------------------------------------------------------------------
   * Network
   * ------------------------------------------------------------------------ */

  source_ip:
    string | null;


  /**
   * Compatibility field.
   */
  source?:
    string | null;


  /**
   * Optional user agent.
   */
  user_agent?:
    string | null;


  /* --------------------------------------------------------------------------
   * Classification
   * ------------------------------------------------------------------------ */

  action:
    AuditAction;

  outcome:
    AuditOutcome;


  /**
   * Optional category.
   */
  category?:
    AuditCategory | null;


  /* --------------------------------------------------------------------------
   * Metadata
   * ------------------------------------------------------------------------ */

  metadata_json:
    AuditMetadata | null;


  /**
   * Compatibility metadata alias.
   */
  metadata?:
    AuditMetadata | null;


  /* --------------------------------------------------------------------------
   * Timestamp
   * ------------------------------------------------------------------------ */

  created_at:
    ISODateString;
}


/* ============================================================================
 * Normalized Frontend Audit Event
 * ========================================================================== */

/**
 * Event consumed by frontend Audit components.
 *
 * services/api.ts normalizes backend data into this structure.
 */
export interface AuditEvent
  extends BackendAuditEvent {

  /**
   * Frontend event identifier.
   *
   * Normally equal to audit_id.
   */
  event_id:
    AuditEventId;


  /**
   * Frontend timestamp.
   *
   * Normally equal to created_at.
   */
  timestamp:
    ISODateString;


  /**
   * Guaranteed frontend metadata object.
   *
   * null backend metadata becomes {}.
   */
  metadata:
    AuditMetadata;
}


/* ============================================================================
 * Pagination
 * ========================================================================== */

/**
 * Basic pagination.
 */
export interface AuditPagination {

  total:
    number;

  page:
    number;

  page_size:
    number;
}


/**
 * Backend pagination.
 */
export interface AuditPageInfo
  extends AuditPagination {

  pages:
    number;
}


/* ============================================================================
 * Backend Global Audit List Response
 * ========================================================================== */

/**
 * Current backend response:
 *
 * {
 *   total: 446,
 *   page: 1,
 *   page_size: 50,
 *   pages: 9,
 *   events: [...]
 * }
 */
export interface BackendAuditListResponse
  extends AuditPageInfo {

  events:
    BackendAuditEvent[];
}


/* ============================================================================
 * Frontend Global Audit List Response
 * ========================================================================== */

/**
 * Normalized frontend response.
 *
 * Backend:
 *
 *     events
 *
 * Frontend:
 *
 *     items
 */
export interface AuditListResponse
  extends AuditPagination {

  items:
    AuditEvent[];
}


/* ============================================================================
 * Audit Filters
 * ========================================================================== */

export interface AuditFilterParams {

  /* --------------------------------------------------------------------------
   * Classification
   * ------------------------------------------------------------------------ */

  action?:
    AuditAction;

  category?:
    AuditCategory;

  /**
   * Canonical backend query parameter.
   */
  result?:
    AuditOutcome;

  /**
   * Compatibility alias.
   */
  outcome?:
    AuditOutcome;


  /* --------------------------------------------------------------------------
   * Actor
   * ------------------------------------------------------------------------ */

  /**
   * Canonical backend parameter.
   */
  actor?:
    UserId;

  /**
   * Compatibility alias.
   */
  actor_user_id?:
    UserId;


  /* --------------------------------------------------------------------------
   * Target
   * ------------------------------------------------------------------------ */

  /**
   * Canonical backend parameter.
   */
  target?:
    UserId;

  /**
   * Compatibility alias.
   */
  target_user_id?:
    UserId;


  /* --------------------------------------------------------------------------
   * Correlation
   * ------------------------------------------------------------------------ */

  session_id?:
    SessionId;

  request_id?:
    RequestId;


  /* --------------------------------------------------------------------------
   * Source
   * ------------------------------------------------------------------------ */

  /**
   * Canonical backend parameter.
   */
  source?:
    string;

  /**
   * Compatibility alias.
   */
  source_ip?:
    string;


  /* --------------------------------------------------------------------------
   * Date range
   * ------------------------------------------------------------------------ */

  date_from?:
    ISODateString;

  date_to?:
    ISODateString;


  /* --------------------------------------------------------------------------
   * Search
   * ------------------------------------------------------------------------ */

  search?:
    string;
}


/* ============================================================================
 * Audit List Parameters
 * ========================================================================== */

export interface AuditListParams
  extends AuditFilterParams {

  /**
   * One-based page number.
   */
  page?:
    number;


  /**
   * Page size.
   */
  page_size?:
    number;


  /**
   * Legacy compatibility.
   */
  limit?:
    number;


  /**
   * Legacy compatibility.
   */
  offset?:
    number;
}


/* ============================================================================
 * Statistics
 * ========================================================================== */

export interface AuditStatistics {

  total:
    number;

  success:
    number;

  failure:
    number;

  denied:
    number;

  unique_actors:
    number;

  unique_targets:
    number;
}


export type AuditStatisticsResponse =
  AuditStatistics;


export type AuditStatisticsParams =
  AuditFilterParams;


/* ============================================================================
 * Related Events
 * ========================================================================== */

/**
 * Backend related event response.
 */
export interface BackendAuditRelatedEventListResponse {

  audit_id:
    AuditEventId;

  items:
    BackendAuditEvent[];

  total:
    number;
}


/**
 * Normalized frontend related-event response.
 */
export interface AuditRelatedEventListResponse {

  audit_id:
    AuditEventId;

  items:
    AuditEvent[];

  total:
    number;

  page?:
    number;

  page_size?:
    number;
}


export type RelatedAuditEventListResponse =
  AuditRelatedEventListResponse;


/* ============================================================================
 * Related Event Parameters
 * ========================================================================== */

export interface AuditRelatedEventParams {

  limit?:
    number;
}


/* ============================================================================
 * Audit Export
 * ========================================================================== */

export interface AuditExportResponse {

  items:
    AuditEvent[];

  count:
    number;

  limit:
    number;
}


export interface AuditExportParams
  extends AuditFilterParams {

  limit?:
    number;

  offset?:
    number;

  format?:
    "json" | "csv";
}


/* ============================================================================
 * User Audit History
 * ========================================================================== */

export interface UserAuditHistoryResponse
  extends AuditPagination {

  user_id:
    UserId;

  items:
    AuditEvent[];
}


export type UserActivityResponse =
  UserAuditHistoryResponse;


/* ============================================================================
 * Timeline
 * ========================================================================== */

export interface AuditTimelineGroup {

  date:
    string;

  events:
    AuditEvent[];
}


/* ============================================================================
 * Event Details
 * ========================================================================== */

export type AuditEventDetails =
  AuditEvent;


/* ============================================================================
 * Legacy Compatibility
 * ========================================================================== */

export type AuditActivity =
  AuditEvent;


export type AuditActivityListResponse =
  AuditListResponse;


/* ============================================================================
 * Permission Contract
 * ========================================================================== */

export const AUDIT_REQUIRED_PERMISSION =
  "users:read" as const;


export type AuditRequiredPermission =
  typeof AUDIT_REQUIRED_PERMISSION;


/* ============================================================================
 * API Routes
 * ========================================================================== */

export const AUDIT_API_ROUTES = {

  LIST:
    "/audit",

  STATISTICS:
    "/audit/statistics",

  EXPORT:
    "/audit/export",

  DETAIL:
    (
      auditId: AuditEventId,
    ): string =>
      `/audit/${encodeURIComponent(
        auditId,
      )}`,

  RELATED:
    (
      auditId: AuditEventId,
    ): string =>
      `/audit/${encodeURIComponent(
        auditId,
      )}/related`,

} as const;


/* ============================================================================
 * Defaults
 * ========================================================================== */

export const DEFAULT_AUDIT_PAGE =
  1;


export const DEFAULT_AUDIT_PAGE_SIZE =
  50;


export const MAX_AUDIT_PAGE_SIZE =
  200;


export const DEFAULT_RELATED_AUDIT_LIMIT =
  100;


export const MAX_RELATED_AUDIT_LIMIT =
  200;


export const DEFAULT_AUDIT_EXPORT_LIMIT =
  10_000;


export const MAX_AUDIT_EXPORT_LIMIT =
  50_000;


/* ============================================================================
 * Runtime Helpers
 * ========================================================================== */

/**
 * Safely checks whether a value is a plain metadata object.
 */
export function isAuditMetadata(
  value: unknown,
): value is AuditMetadata {

  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}


/**
 * Safely checks enriched identity.
 */
export function isAuditIdentity(
  value: unknown,
): value is AuditIdentity {

  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value)
  ) {
    return false;
  }


  const identity =
    value as {
      user_id?: unknown;
      username?: unknown;
      role?: unknown;
    };


  return (
    typeof identity.user_id ===
      "string" &&

    typeof identity.username ===
      "string" &&

    typeof identity.role ===
      "string"
  );
}


/* ============================================================================
 * Backend Audit Event Guard
 * ========================================================================== */

/**
 * Runtime validation for backend audit events.
 *
 * IMPORTANT:
 *
 * This function operates on unknown input first.
 *
 * It does NOT cast a BackendAuditEvent directly
 * into Record<string, unknown>.
 *
 * This avoids TS2352.
 */
export function isBackendAuditEvent(
  value: unknown,
): value is BackendAuditEvent {

  /* --------------------------------------------------------------------------
   * Object check
   * ------------------------------------------------------------------------ */

  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value)
  ) {
    return false;
  }


  /*
   * At this point value is safely treated as
   * an arbitrary object for runtime inspection.
   *
   * We use an explicit structural type instead
   * of casting BackendAuditEvent to Record.
   */
  const event =
    value as {
      audit_id?: unknown;

      actor_user_id?: unknown;

      target_user_id?: unknown;

      session_id?: unknown;

      request_id?: unknown;

      source_ip?: unknown;

      source?: unknown;

      user_agent?: unknown;

      action?: unknown;

      outcome?: unknown;

      category?: unknown;

      metadata_json?: unknown;

      metadata?: unknown;

      created_at?: unknown;

      actor?: unknown;

      target?: unknown;
    };


  /* --------------------------------------------------------------------------
   * Required canonical fields
   * ------------------------------------------------------------------------ */

  if (
    typeof event.audit_id !==
      "string"
  ) {
    return false;
  }


  /* --------------------------------------------------------------------------
   * Actor UUID
   * ------------------------------------------------------------------------ */

  if (
    event.actor_user_id !== null &&
    event.actor_user_id !== undefined &&
    typeof event.actor_user_id !==
      "string"
  ) {
    return false;
  }


  /* --------------------------------------------------------------------------
   * Target UUID
   * ------------------------------------------------------------------------ */

  if (
    event.target_user_id !== null &&
    event.target_user_id !== undefined &&
    typeof event.target_user_id !==
      "string"
  ) {
    return false;
  }


  /* --------------------------------------------------------------------------
   * Session ID
   * ------------------------------------------------------------------------ */

  if (
    event.session_id !== null &&
    event.session_id !== undefined &&
    typeof event.session_id !==
      "string"
  ) {
    return false;
  }


  /* --------------------------------------------------------------------------
   * Request ID
   * ------------------------------------------------------------------------ */

  if (
    event.request_id !== null &&
    event.request_id !== undefined &&
    typeof event.request_id !==
      "string"
  ) {
    return false;
  }


  /* --------------------------------------------------------------------------
   * Source IP
   * ------------------------------------------------------------------------ */

  if (
    event.source_ip !== null &&
    event.source_ip !== undefined &&
    typeof event.source_ip !==
      "string"
  ) {
    return false;
  }


  /* --------------------------------------------------------------------------
   * Action
   * ------------------------------------------------------------------------ */

  if (
    typeof event.action !==
      "string"
  ) {
    return false;
  }


  /* --------------------------------------------------------------------------
   * Outcome
   * ------------------------------------------------------------------------ */

  if (
    typeof event.outcome !==
      "string"
  ) {
    return false;
  }


  /* --------------------------------------------------------------------------
   * Metadata JSON
   * ------------------------------------------------------------------------ */

  if (
    event.metadata_json !== null &&
    event.metadata_json !== undefined &&
    !isAuditMetadata(
      event.metadata_json,
    )
  ) {
    return false;
  }


  /* --------------------------------------------------------------------------
   * Created At
   * ------------------------------------------------------------------------ */

  if (
    typeof event.created_at !==
      "string"
  ) {
    return false;
  }


  /* --------------------------------------------------------------------------
   * Actor enrichment
   * ------------------------------------------------------------------------ */

  if (
    event.actor !== undefined &&
    event.actor !== null &&
    !isAuditIdentity(
      event.actor,
    )
  ) {
    return false;
  }


  /* --------------------------------------------------------------------------
   * Target enrichment
   * ------------------------------------------------------------------------ */

  if (
    event.target !== undefined &&
    event.target !== null &&
    !isAuditIdentity(
      event.target,
    )
  ) {
    return false;
  }


  /* --------------------------------------------------------------------------
   * Optional source
   * ------------------------------------------------------------------------ */

  if (
    event.source !== undefined &&
    event.source !== null &&
    typeof event.source !==
      "string"
  ) {
    return false;
  }


  /* --------------------------------------------------------------------------
   * Optional user agent
   * ------------------------------------------------------------------------ */

  if (
    event.user_agent !== undefined &&
    event.user_agent !== null &&
    typeof event.user_agent !==
      "string"
  ) {
    return false;
  }


  /* --------------------------------------------------------------------------
   * Optional category
   * ------------------------------------------------------------------------ */

  if (
    event.category !== undefined &&
    event.category !== null &&
    typeof event.category !==
      "string"
  ) {
    return false;
  }


  /* --------------------------------------------------------------------------
   * Optional compatibility metadata
   * ------------------------------------------------------------------------ */

  if (
    event.metadata !== undefined &&
    event.metadata !== null &&
    !isAuditMetadata(
      event.metadata,
    )
  ) {
    return false;
  }


  return true;
}


/* ============================================================================
 * Normalized Frontend Event Guard
 * ========================================================================== */

/**
 * Runtime validation for normalized frontend events.
 */
export function isAuditEvent(
  value: unknown,
): value is AuditEvent {

  if (
    !isBackendAuditEvent(
      value,
    )
  ) {
    return false;
  }


  /*
   * DO NOT do:
   *
   *     value as Record<string, unknown>
   *
   * here.
   *
   * value has already been narrowed to BackendAuditEvent.
   *
   * Access the extended properties through a small
   * structural view instead.
   */
  const event =
    value as BackendAuditEvent & {
      event_id?: unknown;
      timestamp?: unknown;
      metadata?: unknown;
    };


  if (
    typeof event.event_id !==
      "string"
  ) {
    return false;
  }


  if (
    typeof event.timestamp !==
      "string"
  ) {
    return false;
  }


  if (
    !isAuditMetadata(
      event.metadata,
    )
  ) {
    return false;
  }


  return true;
}


/* ============================================================================
 * Backend List Response Guard
 * ========================================================================== */

/**
 * Runtime validation for the actual backend Global Audit response.
 *
 * This matches:
 *
 *     {
 *       total,
 *       page,
 *       page_size,
 *       pages,
 *       events
 *     }
 */
export function isBackendAuditListResponse(
  value: unknown,
): value is BackendAuditListResponse {

  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value)
  ) {
    return false;
  }


  const response =
    value as {
      total?: unknown;
      page?: unknown;
      page_size?: unknown;
      pages?: unknown;
      events?: unknown;
    };


  if (
    typeof response.total !==
      "number"
  ) {
    return false;
  }


  if (
    typeof response.page !==
      "number"
  ) {
    return false;
  }


  if (
    typeof response.page_size !==
      "number"
  ) {
    return false;
  }


  if (
    typeof response.pages !==
      "number"
  ) {
    return false;
  }


  if (
    !Array.isArray(
      response.events,
    )
  ) {
    return false;
  }


  return response.events.every(
    (
      event,
    ) =>
      isBackendAuditEvent(
        event,
      ),
  );
}


/* ============================================================================
 * End of File
 * ============================================================================
 */