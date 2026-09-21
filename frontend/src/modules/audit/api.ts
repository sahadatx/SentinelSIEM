/**
 * ============================================================================
 * SentinelSIEM — Global Audit API
 * ============================================================================
 *
 * Feature-level API boundary for the Global Audit module.
 *
 * Architecture
 * ------------
 *
 *     Audit Pages / Components
 *                |
 *                v
 *     modules/audit/api.ts
 *                |
 *                v
 *     services/api.ts
 *                |
 *                v
 *     /api/v1/audit
 *
 * ============================================================================
 *
 * Responsibilities
 * ============================================================================
 *
 * This module:
 *
 *     - exposes the Global Audit feature API
 *     - provides strongly typed API functions
 *     - normalizes feature-level query parameters
 *     - delegates HTTP transport to the shared API client
 *     - keeps Audit UI independent from the shared transport implementation
 *
 * This module does NOT:
 *
 *     - authenticate users
 *     - authorize users
 *     - perform RBAC decisions
 *     - calculate statistics
 *     - generate audit events
 *     - mutate audit records
 *     - store credentials
 *     - store access tokens
 *     - store refresh tokens
 *
 * Backend authorization remains authoritative.
 *
 * ============================================================================
 *
 * IMPORTANT NORMALIZATION BOUNDARY
 * ============================================================================
 *
 * The shared API client:
 *
 *     frontend/src/services/api.ts
 *
 * is the SINGLE HTTP response normalization boundary.
 *
 * It converts backend AuditEvent responses into the frontend AuditEvent
 * contract.
 *
 * Therefore this feature API MUST NOT:
 *
 *     - validate backend AuditEvent shapes again
 *     - filter AuditEvent[] using backend-only fields
 *     - map backend AuditEvent fields again
 *     - convert AuditEvent[] into another AuditEvent[]
 *
 * The flow is:
 *
 *     Backend
 *        |
 *        v
 *     services/api.ts
 *        |
 *        | normalizeAuditEvent()
 *        v
 *     AuditEvent
 *        |
 *        v
 *     modules/audit/api.ts
 *        |
 *        v
 *     Audit UI
 *
 * ============================================================================
 *
 * Locked Global Audit permission:
 *
 *     users:read
 *
 * Permission enforcement belongs to the page/auth boundary and backend.
 *
 * ============================================================================
 */

import { api as sharedApi } from "../../services/api";

import type {
  AuditEvent,
  AuditExportParams,
  AuditExportResponse,
  AuditListParams,
  AuditListResponse,
  AuditRelatedEventListResponse,
  AuditStatistics,
  AuditStatisticsParams,
} from "./types";


/* ============================================================================
 * Local API Types
 * ========================================================================== */

/**
 * Parameters accepted by:
 *
 *     GET /api/v1/audit
 */
export type AuditApiListParams =
  AuditListParams;


/**
 * Parameters accepted by:
 *
 *     GET /api/v1/audit/statistics
 */
export type AuditApiStatisticsParams =
  AuditStatisticsParams;


/**
 * Parameters accepted by:
 *
 *     GET /api/v1/audit/export
 */
export type AuditApiExportParams =
  AuditExportParams;


/* ============================================================================
 * Utility Helpers
 * ========================================================================== */

/**
 * Normalize optional string values.
 *
 * Empty strings are converted to undefined.
 *
 * Examples:
 *
 *     undefined -> undefined
 *     null      -> undefined
 *     ""        -> undefined
 *     "   "     -> undefined
 *     " abc "   -> "abc"
 */
function normalizeOptionalString(
  value:
    | string
    | null
    | undefined,
): string | undefined {

  if (
    value === undefined ||
    value === null
  ) {
    return undefined;
  }

  const normalized =
    value.trim();

  if (
    normalized.length === 0
  ) {
    return undefined;
  }

  return normalized;
}


/**
 * Normalize an optional positive integer.
 *
 * This helper is intentionally conservative.
 *
 * It does not impose backend limits.
 *
 * Backend transport remains responsible for final pagination bounds.
 */
function normalizeOptionalPositiveInteger(
  value:
    | number
    | null
    | undefined,
): number | undefined {

  if (
    value === undefined ||
    value === null
  ) {
    return undefined;
  }

  if (
    !Number.isFinite(value)
  ) {
    return undefined;
  }

  return Math.max(
    1,
    Math.floor(value),
  );
}


/**
 * Normalize an optional non-negative integer.
 */
function normalizeOptionalNonNegativeInteger(
  value:
    | number
    | null
    | undefined,
): number | undefined {

  if (
    value === undefined ||
    value === null
  ) {
    return undefined;
  }

  if (
    !Number.isFinite(value)
  ) {
    return undefined;
  }

  return Math.max(
    0,
    Math.floor(value),
  );
}


/* ============================================================================
 * Filter Normalization
 * ========================================================================== */

/**
 * Normalize Audit query parameters.
 *
 * This function ONLY handles query parameters.
 *
 * It does NOT normalize API responses.
 *
 * ============================================================================
 *
 * Supported logical fields
 * ============================================================================
 *
 *     action
 *     category
 *     outcome
 *     actor_user_id
 *     target_user_id
 *     session_id
 *     request_id
 *     source_ip
 *     date_from
 *     date_to
 *     search
 *
 * Existing UI aliases:
 *
 *     actor
 *     target
 *     result
 *     source
 *
 * ============================================================================
 *
 * The shared transport remains responsible for translating the logical
 * frontend fields into the exact backend route parameter names.
 * ============================================================================
 */
function normalizeAuditParams(
  params?:
    | AuditListParams
    | AuditStatisticsParams
    | AuditExportParams,
):
  | AuditListParams
  | AuditStatisticsParams
  | AuditExportParams
  | undefined {

  if (!params) {
    return undefined;
  }


  const normalized:
    Record<string, unknown> = {};


  /* --------------------------------------------------------------------------
   * Pagination
   * ------------------------------------------------------------------------ */

  if (
    "page" in params
  ) {

    const page =
      normalizeOptionalPositiveInteger(
        params.page,
      );

    if (
      page !== undefined
    ) {
      normalized.page =
        page;
    }
  }


  if (
    "page_size" in params
  ) {

    const pageSize =
      normalizeOptionalPositiveInteger(
        params.page_size,
      );

    if (
      pageSize !== undefined
    ) {
      normalized.page_size =
        pageSize;
    }
  }


  if (
    "limit" in params
  ) {

    const limit =
      normalizeOptionalPositiveInteger(
        params.limit,
      );

    if (
      limit !== undefined
    ) {
      normalized.limit =
        limit;
    }
  }


  if (
    "offset" in params
  ) {

    const offset =
      normalizeOptionalNonNegativeInteger(
        params.offset,
      );

    if (
      offset !== undefined
    ) {
      normalized.offset =
        offset;
    }
  }


  /* --------------------------------------------------------------------------
   * Action
   * ------------------------------------------------------------------------ */

  const action =
    normalizeOptionalString(
      params.action,
    );

  if (
    action !== undefined
  ) {
    normalized.action =
      action;
  }


  /* --------------------------------------------------------------------------
   * Category
   * ------------------------------------------------------------------------ */

  const category =
    normalizeOptionalString(
      params.category,
    );

  if (
    category !== undefined
  ) {
    normalized.category =
      category;
  }


  /* --------------------------------------------------------------------------
   * Outcome
   *
   * Preserve both canonical and compatibility fields.
   *
   * services/api.ts owns final backend query translation.
   * ------------------------------------------------------------------------ */

  const outcome =
    normalizeOptionalString(
      params.outcome,
    );

  if (
    outcome !== undefined
  ) {
    normalized.outcome =
      outcome;
  }


  /* --------------------------------------------------------------------------
   * Result Alias
   * ------------------------------------------------------------------------ */

  const result =
    normalizeOptionalString(
      params.result,
    );

  if (
    result !== undefined
  ) {
    normalized.result =
      result;
  }


  /* --------------------------------------------------------------------------
   * Actor User ID
   * ------------------------------------------------------------------------ */

  const actorUserId =
    normalizeOptionalString(
      params.actor_user_id,
    );

  if (
    actorUserId !== undefined
  ) {
    normalized.actor_user_id =
      actorUserId;
  }


  /* --------------------------------------------------------------------------
   * Actor Alias
   * ------------------------------------------------------------------------ */

  const actor =
    normalizeOptionalString(
      params.actor,
    );

  if (
    actor !== undefined
  ) {
    normalized.actor =
      actor;
  }


  /* --------------------------------------------------------------------------
   * Target User ID
   * ------------------------------------------------------------------------ */

  const targetUserId =
    normalizeOptionalString(
      params.target_user_id,
    );

  if (
    targetUserId !== undefined
  ) {
    normalized.target_user_id =
      targetUserId;
  }


  /* --------------------------------------------------------------------------
   * Target Alias
   * ------------------------------------------------------------------------ */

  const target =
    normalizeOptionalString(
      params.target,
    );

  if (
    target !== undefined
  ) {
    normalized.target =
      target;
  }


  /* --------------------------------------------------------------------------
   * Session ID
   * ------------------------------------------------------------------------ */

  const sessionId =
    normalizeOptionalString(
      params.session_id,
    );

  if (
    sessionId !== undefined
  ) {
    normalized.session_id =
      sessionId;
  }


  /* --------------------------------------------------------------------------
   * Request ID
   * ------------------------------------------------------------------------ */

  const requestId =
    normalizeOptionalString(
      params.request_id,
    );

  if (
    requestId !== undefined
  ) {
    normalized.request_id =
      requestId;
  }


  /* --------------------------------------------------------------------------
   * Source IP
   * ------------------------------------------------------------------------ */

  const sourceIp =
    normalizeOptionalString(
      params.source_ip,
    );

  if (
    sourceIp !== undefined
  ) {
    normalized.source_ip =
      sourceIp;
  }


  /* --------------------------------------------------------------------------
   * Source Alias
   * ------------------------------------------------------------------------ */

  const source =
    normalizeOptionalString(
      params.source,
    );

  if (
    source !== undefined
  ) {
    normalized.source =
      source;
  }


  /* --------------------------------------------------------------------------
   * Date From
   * ------------------------------------------------------------------------ */

  const dateFrom =
    normalizeOptionalString(
      params.date_from,
    );

  if (
    dateFrom !== undefined
  ) {
    normalized.date_from =
      dateFrom;
  }


  /* --------------------------------------------------------------------------
   * Date To
   * ------------------------------------------------------------------------ */

  const dateTo =
    normalizeOptionalString(
      params.date_to,
    );

  if (
    dateTo !== undefined
  ) {
    normalized.date_to =
      dateTo;
  }


  /* --------------------------------------------------------------------------
   * Search
   * ------------------------------------------------------------------------ */

  const search =
    normalizeOptionalString(
      params.search,
    );

  if (
    search !== undefined
  ) {
    normalized.search =
      search;
  }


  return normalized as
    | AuditListParams
    | AuditStatisticsParams
    | AuditExportParams;
}


/* ============================================================================
 * Global Audit API
 * ========================================================================== */

export const auditApi = {

  /* ==========================================================================
   * LIST AUDIT EVENTS
   * ======================================================================== */

  /**
   * Retrieve paginated Global Audit events.
   *
   * Endpoint:
   *
   *     GET /api/v1/audit
   *
   * IMPORTANT:
   *
   * sharedApi.listAuditLogs() already returns:
   *
   *     Promise<AuditListResponse>
   *
   * No response normalization is performed here.
   */
  async list(
    params?: AuditApiListParams,
  ): Promise<AuditListResponse> {

    const normalizedParams =
      normalizeAuditParams(
        params,
      ) as AuditListParams | undefined;


    return sharedApi.listAuditLogs(
      normalizedParams,
    );
  },


  /* ==========================================================================
   * AUDIT STATISTICS
   * ======================================================================== */

  /**
   * Retrieve backend-calculated Audit statistics.
   *
   * Endpoint:
   *
   *     GET /api/v1/audit/statistics
   *
   * Statistics are authoritative backend values.
   *
   * The frontend must not calculate them from the currently loaded page.
   */
  async statistics(
    params?: AuditApiStatisticsParams,
  ): Promise<AuditStatistics> {

    const normalizedParams =
      normalizeAuditParams(
        params,
      ) as AuditStatisticsParams | undefined;


    return sharedApi.getAuditStatistics(
      normalizedParams,
    );
  },


  /* ==========================================================================
   * AUDIT EVENT DETAIL
   * ======================================================================== */

  /**
   * Retrieve one immutable Audit event.
   *
   * Endpoint:
   *
   *     GET /api/v1/audit/{audit_id}
   */
  async get(
    auditId: string,
  ): Promise<AuditEvent> {

    return sharedApi.getAuditEvent(
      auditId,
    );
  },


  /* ==========================================================================
   * RELATED AUDIT EVENTS
   * ======================================================================== */

  /**
   * Retrieve events related to one Audit event.
   *
   * Endpoint:
   *
   *     GET /api/v1/audit/{audit_id}/related
   */
  async related(
    auditId: string,
  ): Promise<AuditRelatedEventListResponse> {

    return sharedApi.getRelatedAuditEvents(
      auditId,
    );
  },


  /* ==========================================================================
   * EXPORT AUDIT EVENTS
   * ======================================================================== */

  /**
   * Retrieve Audit events for export.
   *
   * Endpoint:
   *
   *     GET /api/v1/audit/export
   *
   * Export is read-only.
   *
   * Backend authorization remains authoritative.
   */
  async export(
    params?: AuditApiExportParams,
  ): Promise<AuditExportResponse> {

    const normalizedParams =
      normalizeAuditParams(
        params,
      ) as AuditExportParams | undefined;


    return sharedApi.exportAuditLogs(
      normalizedParams,
    );
  },

} as const;


/* ============================================================================
 * Named API Functions
 * ========================================================================== */

/**
 * Retrieve paginated Global Audit events.
 */
export function listAuditLogs(
  params?: AuditApiListParams,
): Promise<AuditListResponse> {

  return auditApi.list(
    params,
  );
}


/**
 * Retrieve backend-calculated Global Audit statistics.
 */
export function getAuditStatistics(
  params?: AuditApiStatisticsParams,
): Promise<AuditStatistics> {

  return auditApi.statistics(
    params,
  );
}


/**
 * Retrieve one Global Audit event.
 */
export function getAuditEvent(
  auditId: string,
): Promise<AuditEvent> {

  return auditApi.get(
    auditId,
  );
}


/**
 * Retrieve events related to one Global Audit event.
 */
export function getRelatedAuditEvents(
  auditId: string,
): Promise<AuditRelatedEventListResponse> {

  return auditApi.related(
    auditId,
  );
}


/**
 * Export Global Audit events.
 */
export function exportAuditLogs(
  params?: AuditApiExportParams,
): Promise<AuditExportResponse> {

  return auditApi.export(
    params,
  );
}


/* ============================================================================
 * Public API Type
 * ========================================================================== */

/**
 * Structural type of the Global Audit API.
 */
export type AuditApi =
  typeof auditApi;


/* ============================================================================
 * Default Export
 * ========================================================================== */

export default auditApi;


/* ============================================================================
 * End of File
 * ============================================================================
 */