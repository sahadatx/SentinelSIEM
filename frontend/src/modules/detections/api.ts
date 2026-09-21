/* ==========================================================================
 * Detection Module API
 * SentinelSIEM SOC Dashboard
 *
 * Feature-level API boundary.
 *
 * Shared API client owns:
 *   - authentication
 *   - authorization
 *   - HTTP transport
 *   - API error handling
 *   - 401 handling
 *
 * Detection module owns:
 *   - Detection-specific API methods
 *   - Detection-specific request/response types
 *   - Detection-specific API normalization
 *
 * Backend is the source of truth.
 *
 * Canonical backend contract:
 *
 *   GET    /api/v1/detections
 *   GET    /api/v1/detections/{rule_id}
 *   GET    /api/v1/detections/filter-options
 *   GET    /api/v1/detections/statistics
 *   GET    /api/v1/detections/summary
 *
 *   POST   /api/v1/detections
 *   PATCH  /api/v1/detections/{rule_id}
 *   POST   /api/v1/detections/{rule_id}/enable
 *   POST   /api/v1/detections/{rule_id}/disable
 *   DELETE /api/v1/detections/{rule_id}
 *
 * Compatibility rule endpoints:
 *
 *   GET    /api/v1/detections/rules
 *   POST   /api/v1/detections/rules
 *   GET    /api/v1/detections/rules/{rule_id}
 *   PATCH  /api/v1/detections/rules/{rule_id}
 *
 * Detection results:
 *
 *   GET    /api/v1/detections/results
 *   GET    /api/v1/detections/results/{detection_id}
 *
 * IMPORTANT:
 * - This module never bypasses the shared API client.
 * - This module never stores authentication state.
 * - This module never implements RBAC enforcement.
 * - Backend authorization remains authoritative.
 * - Frontend does not calculate authoritative Detection statistics.
 * - Frontend does not perform local rule/result filtering.
 * - Pagination is owned by the backend.
 * ========================================================================== */

import { api as sharedApi } from "../../services/api";

import type {
  DetectionCapability,
  DetectionFilterOptions,
  DetectionResult,
  DetectionResultListResponse,
  DetectionRule,
  DetectionRuleCreateRequest,
  DetectionRuleListResponse,
  DetectionRuleUpdateRequest,
  DetectionStatistics,
  DetectionSummary,
} from "./types";


/* ==========================================================================
 * Local API Types
 * ========================================================================== */

/**
 * Query parameters supported by:
 *
 *   GET /api/v1/detections/results
 */
export interface DetectionResultListParams {
  query?: string;
  rule_id?: string;
  event_id?: string;
  severity?: string;
  category?: string;
  suppressed?: boolean;
  start_time?: string;
  end_time?: string;

  /**
   * Backend-owned pagination.
   */
  page?: number;
  page_size?: number;
}


/**
 * Query parameters supported by:
 *
 *   GET /api/v1/detections
 *
 * All filtering is executed by the backend.
 */
export interface DetectionRuleListParams {
  query?: string;
  enabled?: boolean;
  severity?: string;
  category?: string;
  tag?: string;

  /**
   * Backend-owned pagination.
   */
  page?: number;
  page_size?: number;
}


/**
 * Backend-derived filter options.
 */
export type DetectionFilterOptionsResponse =
  DetectionFilterOptions;


/* ==========================================================================
 * Internal Helpers
 * ========================================================================== */

/**
 * Validate and normalize a required ID.
 *
 * Prevents accidental requests such as:
 *
 *   /detections/
 *   /detections/undefined
 *   /detections/null
 */
function requireId(
  value: string,
  label: string,
): string {
  if (
    typeof value !== "string"
  ) {
    throw new Error(
      `${label} is required.`,
    );
  }

  const normalized =
    value.trim();

  if (!normalized) {
    throw new Error(
      `${label} is required.`,
    );
  }

  return normalized;
}


/**
 * Normalize a positive integer query parameter.
 *
 * Undefined remains undefined.
 *
 * The backend remains authoritative for the final validation.
 */
function normalizePositiveInteger(
  value: number | undefined,
): number | undefined {
  if (
    value === undefined
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
 * Normalize an optional string query parameter.
 *
 * Empty/whitespace-only values are omitted.
 */
function normalizeOptionalString(
  value: string | undefined,
): string | undefined {
  if (
    typeof value !== "string"
  ) {
    return undefined;
  }

  const normalized =
    value.trim();

  return normalized
    ? normalized
    : undefined;
}


/* ==========================================================================
 * Result Query Normalization
 * ========================================================================== */

/**
 * Normalize Detection result-list parameters.
 *
 * This function performs transport normalization only.
 *
 * It does NOT:
 *   - filter results
 *   - calculate totals
 *   - calculate pagination
 *   - calculate statistics
 *   - mutate backend data
 */
function normalizeResultParams(
  params: DetectionResultListParams = {},
): DetectionResultListParams {
  const normalized:
    DetectionResultListParams = {};

  const query =
    normalizeOptionalString(
      params.query,
    );

  if (
    query !== undefined
  ) {
    normalized.query =
      query;
  }

  const ruleId =
    normalizeOptionalString(
      params.rule_id,
    );

  if (
    ruleId !== undefined
  ) {
    normalized.rule_id =
      ruleId;
  }

  const eventId =
    normalizeOptionalString(
      params.event_id,
    );

  if (
    eventId !== undefined
  ) {
    normalized.event_id =
      eventId;
  }

  const severity =
    normalizeOptionalString(
      params.severity,
    );

  if (
    severity !== undefined
  ) {
    normalized.severity =
      severity;
  }

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

  if (
    params.suppressed !== undefined
  ) {
    normalized.suppressed =
      Boolean(
        params.suppressed,
      );
  }

  const startTime =
    normalizeOptionalString(
      params.start_time,
    );

  if (
    startTime !== undefined
  ) {
    normalized.start_time =
      startTime;
  }

  const endTime =
    normalizeOptionalString(
      params.end_time,
    );

  if (
    endTime !== undefined
  ) {
    normalized.end_time =
      endTime;
  }

  const page =
    normalizePositiveInteger(
      params.page,
    );

  if (
    page !== undefined
  ) {
    normalized.page =
      page;
  }

  const pageSize =
    normalizePositiveInteger(
      params.page_size,
    );

  if (
    pageSize !== undefined
  ) {
    normalized.page_size =
      pageSize;
  }

  return normalized;
}


/* ==========================================================================
 * Rule Query Normalization
 * ========================================================================== */

/**
 * Normalize Detection rule-list parameters.
 *
 * Backend-supported filters:
 *   - query
 *   - enabled
 *   - severity
 *   - category
 *   - tag
 *   - page
 *   - page_size
 *
 * No local filtering is performed.
 */
function normalizeRuleListParams(
  params: DetectionRuleListParams = {},
): DetectionRuleListParams {
  const normalized:
    DetectionRuleListParams = {};

  const query =
    normalizeOptionalString(
      params.query,
    );

  if (
    query !== undefined
  ) {
    normalized.query =
      query;
  }

  if (
    params.enabled !== undefined
  ) {
    normalized.enabled =
      Boolean(
        params.enabled,
      );
  }

  const severity =
    normalizeOptionalString(
      params.severity,
    );

  if (
    severity !== undefined
  ) {
    normalized.severity =
      severity;
  }

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

  const tag =
    normalizeOptionalString(
      params.tag,
    );

  if (
    tag !== undefined
  ) {
    normalized.tag =
      tag;
  }

  const page =
    normalizePositiveInteger(
      params.page,
    );

  if (
    page !== undefined
  ) {
    normalized.page =
      page;
  }

  const pageSize =
    normalizePositiveInteger(
      params.page_size,
    );

  if (
    pageSize !== undefined
  ) {
    normalized.page_size =
      pageSize;
  }

  return normalized;
}


/* ==========================================================================
 * Detection API
 * ========================================================================== */

export const detectionApi = {

  /* ------------------------------------------------------------------------
   * Capability
   * ---------------------------------------------------------------------- */

  /**
   * GET /api/v1/detections/capability
   *
   * Returns Detection subsystem capability/status.
   */
  getCapability(): Promise<DetectionCapability> {
    return sharedApi.getDetectionCapability();
  },


  /* ------------------------------------------------------------------------
   * Statistics
   * ---------------------------------------------------------------------- */

  /**
   * GET /api/v1/detections/statistics
   *
   * Canonical Detection runtime statistics.
   *
   * No statistics are calculated in the frontend.
   */
  getStatistics(): Promise<DetectionStatistics> {
    return sharedApi.getDetectionStatistics();
  },


  /* ------------------------------------------------------------------------
   * Summary
   * ---------------------------------------------------------------------- */

  /**
   * GET /api/v1/detections/summary
   *
   * Detection summary endpoint.
   */
  getSummary(): Promise<DetectionSummary> {
    return sharedApi.getDetectionSummary();
  },


  /* ------------------------------------------------------------------------
   * Filter Options
   * ---------------------------------------------------------------------- */

  /**
   * GET /api/v1/detections/filter-options
   *
   * Backend-derived Detection filter values.
   */
  getFilterOptions(): Promise<DetectionFilterOptions> {
    return sharedApi.getDetectionFilterOptions();
  },


  /* ------------------------------------------------------------------------
   * Rules - Canonical List
   * ---------------------------------------------------------------------- */

  /**
   * GET /api/v1/detections
   *
   * Canonical Detection rule list.
   *
   * Backend owns:
   *   - filtering
   *   - pagination
   *   - total
   *   - total_pages
   *
   * The frontend only transports query parameters and renders
   * the returned page.
   */
  listRules(
    params: DetectionRuleListParams = {},
  ): Promise<DetectionRuleListResponse> {
    const normalized =
      normalizeRuleListParams(
        params,
      );

    return sharedApi.listDetectionRules(
      normalized,
    );
  },


  /**
   * Convenience alias for:
   *
   *   GET /api/v1/detections
   */
  list(
    params: DetectionRuleListParams = {},
  ): Promise<DetectionRuleListResponse> {
    return this.listRules(
      params,
    );
  },


  /* ------------------------------------------------------------------------
   * Rules - Get
   * ---------------------------------------------------------------------- */

  /**
   * GET /api/v1/detections/{rule_id}
   */
  getRule(
    ruleId: string,
  ): Promise<DetectionRule> {
    return sharedApi.getDetectionRule(
      requireId(
        ruleId,
        "Detection rule ID",
      ),
    );
  },


  /* ------------------------------------------------------------------------
   * Rules - Create
   * ---------------------------------------------------------------------- */

  /**
   * POST /api/v1/detections
   */
  create(
    payload: DetectionRuleCreateRequest,
  ): Promise<DetectionRule> {
    return sharedApi.createDetectionRule(
      payload,
    );
  },


  /**
   * Compatibility alias for rule creation.
   */
  createRule(
    payload: DetectionRuleCreateRequest,
  ): Promise<DetectionRule> {
    return this.create(
      payload,
    );
  },


  /* ------------------------------------------------------------------------
   * Rules - Update
   * ---------------------------------------------------------------------- */

  /**
   * PATCH /api/v1/detections/{rule_id}
   */
  update(
    ruleId: string,
    payload: DetectionRuleUpdateRequest,
  ): Promise<DetectionRule> {
    return sharedApi.updateDetectionRule(
      requireId(
        ruleId,
        "Detection rule ID",
      ),
      payload,
    );
  },


  /**
   * Compatibility alias for rule update.
   */
  updateRule(
    ruleId: string,
    payload: DetectionRuleUpdateRequest,
  ): Promise<DetectionRule> {
    return this.update(
      ruleId,
      payload,
    );
  },


  /* ------------------------------------------------------------------------
   * Rules - Enable
   * ---------------------------------------------------------------------- */

  /**
   * POST /api/v1/detections/{rule_id}/enable
   */
  enableRule(
    ruleId: string,
  ): Promise<DetectionRule> {
    const id =
      requireId(
        ruleId,
        "Detection rule ID",
      );

    return sharedApi.enableDetectionRule(
      id,
    );
  },


  /* ------------------------------------------------------------------------
   * Rules - Disable
   * ---------------------------------------------------------------------- */

  /**
   * POST /api/v1/detections/{rule_id}/disable
   */
  disableRule(
    ruleId: string,
  ): Promise<DetectionRule> {
    const id =
      requireId(
        ruleId,
        "Detection rule ID",
      );

    return sharedApi.disableDetectionRule(
      id,
    );
  },


  /* ------------------------------------------------------------------------
   * Rules - Enable / Disable
   * ---------------------------------------------------------------------- */

  /**
   * Enable or disable a Detection rule.
   *
   * enabled=true
   *   → POST /detections/{rule_id}/enable
   *
   * enabled=false
   *   → POST /detections/{rule_id}/disable
   */
  setRuleEnabled(
    ruleId: string,
    enabled: boolean,
  ): Promise<DetectionRule> {
    return enabled
      ? this.enableRule(
          ruleId,
        )
      : this.disableRule(
          ruleId,
        );
  },


  /* ------------------------------------------------------------------------
   * Rules - Delete
   * ---------------------------------------------------------------------- */

  /**
   * DELETE /api/v1/detections/{rule_id}
   *
   * Backend returns HTTP 204.
   */
  delete(
    ruleId: string,
  ): Promise<void> {
    return sharedApi.deleteDetectionRule(
      requireId(
        ruleId,
        "Detection rule ID",
      ),
    );
  },


  /**
   * Compatibility alias for deletion.
   */
  deleteRule(
    ruleId: string,
  ): Promise<void> {
    return this.delete(
      ruleId,
    );
  },


  /* ------------------------------------------------------------------------
   * Detection Results - List
   * ---------------------------------------------------------------------- */

  /**
   * GET /api/v1/detections/results
   *
   * Retrieves persisted DetectionResult records.
   *
   * Backend owns:
   *   - filtering
   *   - pagination
   *   - total
   *   - total_pages
   */
  listResults(
    params: DetectionResultListParams = {},
  ): Promise<DetectionResultListResponse> {
    const normalized =
      normalizeResultParams(
        params,
      );

    return sharedApi.listDetectionResults(
      normalized,
    );
  },


  /* ------------------------------------------------------------------------
   * Detection Results - Get
   * ---------------------------------------------------------------------- */

  /**
   * GET /api/v1/detections/results/{detection_id}
   */
  getResult(
    detectionId: string,
  ): Promise<DetectionResult> {
    return sharedApi.getDetectionResult(
      requireId(
        detectionId,
        "Detection ID",
      ),
    );
  },


  /* ------------------------------------------------------------------------
   * Detection Results - Find Local
   * ---------------------------------------------------------------------- */

  /**
   * Find one DetectionResult from an already-loaded collection.
   *
   * No HTTP request is made.
   *
   * This helper is intentionally non-authoritative:
   * it only searches the collection supplied by the caller.
   */
  findResult(
    results: DetectionResult[],
    detectionId: string,
  ): DetectionResult | null {
    const id =
      requireId(
        detectionId,
        "Detection ID",
      );

    return (
      results.find(
        (result) =>
          result.detection_id === id,
      ) ??
      null
    );
  },
};


/* ==========================================================================
 * Named API Functions
 * ========================================================================== */

/**
 * GET /api/v1/detections/capability
 */
export function getDetectionCapability():
  Promise<DetectionCapability> {
  return detectionApi.getCapability();
}


/**
 * GET /api/v1/detections/statistics
 */
export function getDetectionStatistics():
  Promise<DetectionStatistics> {
  return detectionApi.getStatistics();
}


/**
 * GET /api/v1/detections/summary
 */
export function getDetectionSummary():
  Promise<DetectionSummary> {
  return detectionApi.getSummary();
}


/**
 * GET /api/v1/detections/filter-options
 */
export function getDetectionFilterOptions():
  Promise<DetectionFilterOptions> {
  return detectionApi.getFilterOptions();
}


/**
 * GET /api/v1/detections
 *
 * Backward-compatible convenience function.
 *
 * For advanced filtering/pagination use detectionApi.listRules()
 * or getDetectionRulesWithParams().
 */
export function getDetectionRules(
  enabled?: boolean,
): Promise<DetectionRuleListResponse> {
  return detectionApi.listRules({
    enabled,
  });
}


/**
 * GET /api/v1/detections
 *
 * Full backend filter + pagination support.
 */
export function getDetectionRulesWithParams(
  params: DetectionRuleListParams = {},
): Promise<DetectionRuleListResponse> {
  return detectionApi.listRules(
    params,
  );
}


/**
 * GET /api/v1/detections/{rule_id}
 */
export function getDetectionRule(
  ruleId: string,
): Promise<DetectionRule> {
  return detectionApi.getRule(
    ruleId,
  );
}


/**
 * POST /api/v1/detections
 */
export function createDetectionRule(
  payload: DetectionRuleCreateRequest,
): Promise<DetectionRule> {
  return detectionApi.create(
    payload,
  );
}


/**
 * PATCH /api/v1/detections/{rule_id}
 */
export function updateDetectionRule(
  ruleId: string,
  payload: DetectionRuleUpdateRequest,
): Promise<DetectionRule> {
  return detectionApi.update(
    ruleId,
    payload,
  );
}


/**
 * POST /api/v1/detections/{rule_id}/enable
 */
export function enableDetectionRule(
  ruleId: string,
): Promise<DetectionRule> {
  return detectionApi.enableRule(
    ruleId,
  );
}


/**
 * POST /api/v1/detections/{rule_id}/disable
 */
export function disableDetectionRule(
  ruleId: string,
): Promise<DetectionRule> {
  return detectionApi.disableRule(
    ruleId,
  );
}


/**
 * Enable or disable a Detection rule.
 */
export function setDetectionRuleEnabled(
  ruleId: string,
  enabled: boolean,
): Promise<DetectionRule> {
  return detectionApi.setRuleEnabled(
    ruleId,
    enabled,
  );
}


/**
 * DELETE /api/v1/detections/{rule_id}
 *
 * Backend returns HTTP 204.
 */
export function deleteDetectionRule(
  ruleId: string,
): Promise<void> {
  return detectionApi.delete(
    ruleId,
  );
}


/**
 * GET /api/v1/detections/results
 */
export function getDetectionResults(
  params: DetectionResultListParams = {},
): Promise<DetectionResultListResponse> {
  return detectionApi.listResults(
    params,
  );
}


/**
 * GET /api/v1/detections/results/{detection_id}
 */
export function getDetectionResult(
  detectionId: string,
): Promise<DetectionResult> {
  return detectionApi.getResult(
    detectionId,
  );
}


/* ==========================================================================
 * Default Export
 * ========================================================================== */

export default detectionApi;