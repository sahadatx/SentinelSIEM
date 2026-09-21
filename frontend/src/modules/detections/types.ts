/* ==========================================================================
 * SentinelSIEM
 * Detection Module Types
 *
 * FINAL LOCKED DETECTION UI CONTRACT
 *
 * Detection workflow:
 *
 *   Events
 *      ↓
 *   Detection Engine
 *      ↓
 *   Detection Results
 *      ↓
 *   Alerts
 *
 * Current implementation:
 *
 *   Rules → Detection Matches → Detection Results
 *
 * Detection → Alert integration is not yet authoritative.
 *
 * Backend is the source of truth.
 * ========================================================================== */


/* ==========================================================================
 * Detection RBAC
 * ========================================================================== */

export type DetectionAllowedRole =
  | "ADMIN"
  | "SECURITY_ANALYST"
  | "SOC_ANALYST";

export type DetectionDeniedRole =
  | "INVESTIGATOR"
  | "VIEWER";

export type DetectionRole =
  | DetectionAllowedRole
  | DetectionDeniedRole;

export type DetectionPermission =
  | "detections:read"
  | "detections:manage";


export interface DetectionAccess {
  canView: boolean;
  canCreate: boolean;
  canEdit: boolean;
  canEnableDisable: boolean;
  canDelete: boolean;
}


export function getDetectionAccess(
  role: DetectionRole | null | undefined,
): DetectionAccess {
  const canManage =
    role === "ADMIN" ||
    role === "SECURITY_ANALYST" ||
    role === "SOC_ANALYST";

  return {
    canView: canManage,
    canCreate: canManage,
    canEdit: canManage,
    canEnableDisable: canManage,
    canDelete: canManage,
  };
}


export function canViewDetection(
  role: DetectionRole | null | undefined,
): boolean {
  return getDetectionAccess(role).canView;
}


export function canCreateDetectionRule(
  role: DetectionRole | null | undefined,
): boolean {
  return getDetectionAccess(role).canCreate;
}


export function canEditDetectionRule(
  role: DetectionRole | null | undefined,
): boolean {
  return getDetectionAccess(role).canEdit;
}


export function canToggleDetectionRule(
  role: DetectionRole | null | undefined,
): boolean {
  return getDetectionAccess(role).canEnableDisable;
}


export function canDeleteDetectionRule(
  role: DetectionRole | null | undefined,
): boolean {
  return getDetectionAccess(role).canDelete;
}


/* ==========================================================================
 * Detection Status
 * ========================================================================== */

export type DetectionStatus =
  | "available"
  | "planned"
  | "unavailable"
  | "unknown";


/* ==========================================================================
 * Detection Condition Operators
 * ========================================================================== */

export type ConditionOperator =
  | "equals"
  | "not_equals"
  | "in"
  | "not_in"
  | "contains"
  | "exists";


/* ==========================================================================
 * Detection Rule Match Mode
 * ========================================================================== */

export type DetectionMatch =
  | "all"
  | "any";


/* ==========================================================================
 * Detection Severity / Category
 * ========================================================================== */

/**
 * Backend accepts arbitrary non-empty values.
 *
 * Do not hardcode severity/category unions here.
 */
export type DetectionSeverity = string;

export type DetectionCategory = string;


/* ==========================================================================
 * Rule Condition
 * ========================================================================== */

export interface DetectionRuleCondition {
  field: string;
  operator: ConditionOperator;
  value: unknown | null;
}


/* ==========================================================================
 * Detection Rule Statistics
 * ========================================================================== */

export interface DetectionRuleStatistics {
  matches: number;
  alerts: number;
  suppressed: number;
  last_match_at: string | null;
}


export interface DetectionRuleStatisticsView {
  matches: number;
  alerts: number;
  suppressed: number;
  lastMatchAt: string | null;
}


/* ==========================================================================
 * Detection Rule
 * ========================================================================== */

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  severity: string;
  category: string;
  conditions: DetectionRuleCondition[];
  match: DetectionMatch;
  tags: string[];

  /**
   * Optional nested statistics compatibility.
   */
  statistics?: DetectionRuleStatistics;

  /**
   * Canonical backend read-side statistics.
   */
  matches?: number;
  alerts?: number;
  suppressed?: number;
  last_match?: string | null;

  /**
   * Legacy compatibility.
   */
  last_match_at?: string | null;
}


/* ==========================================================================
 * Detection Rule Create Request
 * ========================================================================== */

export interface DetectionRuleCreateRequest {
  id: string;
  name: string;
  description: string;
  enabled?: boolean;
  severity: string;
  category: string;
  conditions: DetectionRuleCondition[];
  match?: DetectionMatch;
  tags?: string[];
}


/* ==========================================================================
 * Detection Rule Update Request
 * ========================================================================== */

export interface DetectionRuleUpdateRequest {
  name?: string;
  description?: string;
  enabled?: boolean;
  severity?: string;
  category?: string;
  conditions?: DetectionRuleCondition[];
  match?: DetectionMatch;
  tags?: string[];
}


/* ==========================================================================
 * Pagination
 * ========================================================================== */

/**
 * Canonical backend pagination metadata.
 *
 * Backend list schemas expose these values at the TOP LEVEL:
 *
 *   page
 *   page_size
 *   total
 *   total_pages
 */
export interface DetectionPagination {
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
}


/* ==========================================================================
 * Detection Rule List Response
 * ========================================================================== */

/**
 * Canonical:
 *
 * GET /api/v1/detections
 *
 * Example:
 *
 * {
 *   "items": [...],
 *   "total": 42,
 *   "page": 1,
 *   "page_size": 30,
 *   "total_pages": 2
 * }
 */
export interface DetectionRuleListResponse {
  items: DetectionRule[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}


/* ==========================================================================
 * Detection Result
 * ========================================================================== */

export interface DetectionResult {
  detection_id: string;
  rule_id: string;
  rule_name: string;
  event_id: string;
  severity: string;
  category: string;
  description: string;
  matched_at: string;
  tags: string[];
  suppressed: boolean;
}


/* ==========================================================================
 * Detection Result List Response
 * ========================================================================== */

/**
 * Canonical:
 *
 * GET /api/v1/detections/results
 *
 * Pagination is also TOP-LEVEL here.
 */
export interface DetectionResultListResponse {
  items: DetectionResult[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}


/* ==========================================================================
 * Detection Statistics
 * ========================================================================== */

export interface DetectionStatistics {
  total_rules: number;
  enabled_rules: number;
  disabled_rules: number;

  total_plugins: number;
  enabled_plugins: number;

  total_evaluations: number;
  detection_matches: number;
  suppressed_matches: number;
  evaluation_failures: number;

  plugin_evaluations: number;
  plugin_failures: number;
}


/* ==========================================================================
 * Detection Summary
 * ========================================================================== */

/**
 * Compatibility endpoint:
 *
 * GET /api/v1/detections/summary
 *
 * Prefer /statistics for new UI code.
 */
export interface DetectionSummary {
  total_rules: number;
  enabled_rules: number;
  disabled_rules: number;

  total_plugins: number;
  enabled_plugins: number;

  total_evaluations?: number;
  detection_matches?: number;
  suppressed_matches?: number;
  evaluation_failures?: number;

  plugin_evaluations?: number;
  plugin_failures?: number;

  /**
   * Legacy compatibility only.
   */
  active_rules?: number;
}


/* ==========================================================================
 * Detection Engine Health
 * ========================================================================== */

/**
 * FINAL LOCKED HEALTH:
 *
 *   Engine Status
 *   Rule Registry
 *   Rules Loaded
 *   Plugin Registry
 *   Plugins Enabled
 *   Evaluation Errors
 *
 * No:
 *
 *   Last Evaluation
 *   Alert Pipeline
 */
export interface DetectionEngineHealth {
  engineStatus: DetectionStatus;
  ruleRegistry: string;
  rulesLoaded: number;
  pluginRegistry: string;
  pluginsEnabled: number;
  evaluationErrors: number;
}


/* ==========================================================================
 * Detection Capability
 * ========================================================================== */

export interface DetectionCapability {
  resource: string;
  status: DetectionStatus;
  message: string;

  rules_api: boolean;
  results_api: boolean;
  plugins_api: boolean;
}


/* ==========================================================================
 * Detection Overview
 * ========================================================================== */

export interface DetectionOverview {
  resource: string;
  status: DetectionStatus;
  message: string;

  available: boolean;

  rulesApiAvailable: boolean;
  resultsApiAvailable: boolean;
  pluginsApiAvailable: boolean;

  rulesLoaded: number;
  pluginsEnabled: number;

  evaluationErrors: number;
}


/* ==========================================================================
 * Detection API Error
 * ========================================================================== */

export interface DetectionApiError {
  message: string;
  status?: number;
  code?: string;
  details?: unknown;
}


/* ==========================================================================
 * Detection Loading State
 * ========================================================================== */

export interface DetectionLoadingState {
  loading: boolean;
  error: string | null;
}


/* ==========================================================================
 * Detection Rule Filters
 * ========================================================================== */

export interface DetectionRuleFilters {
  query: string;

  /**
   * UI-only value.
   *
   * "all" means no enabled query parameter.
   */
  status:
    | "all"
    | "enabled"
    | "disabled";

  /**
   * "all" means no severity filter.
   */
  severity: string;

  /**
   * "all" means no category filter.
   */
  category: string;

  /**
   * Empty array means no tag filter.
   *
   * Actual values come from backend filter-options.
   */
  tags: string[];
}


/**
 * UI-only defaults.
 *
 * No backend severity/category/tag values are hardcoded.
 */
export const DEFAULT_DETECTION_RULE_FILTERS: DetectionRuleFilters = {
  query: "",
  status: "all",
  severity: "all",
  category: "all",
  tags: [],
};


/* ==========================================================================
 * Detection Filter Options
 * ========================================================================== */

/**
 * Exact backend:
 *
 * GET /api/v1/detections/filter-options
 *
 * {
 *   "status": [...],
 *   "severity": [...],
 *   "category": [...],
 *   "tags": [...]
 * }
 */
export interface DetectionFilterOptions {
  status: string[];
  severity: string[];
  category: string[];
  tags: string[];
}


export const EMPTY_DETECTION_FILTER_OPTIONS: DetectionFilterOptions = {
  status: [],
  severity: [],
  category: [],
  tags: [],
};


/* ==========================================================================
 * Detection Rule Form State
 * ========================================================================== */

export interface DetectionRuleFormState {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  severity: string;
  category: string;
  conditions: DetectionRuleCondition[];
  match: DetectionMatch;
  tags: string[];
}


/* ==========================================================================
 * Detection Rule Details State
 * ========================================================================== */

export interface DetectionRuleDetailsState {
  open: boolean;
  ruleId: string | null;
}


/* ==========================================================================
 * Detection Rule Table Row
 * ========================================================================== */

export interface DetectionRuleTableRow {
  rule: DetectionRule;

  matches: number;

  suppressed: number;

  lastMatchAt: string | null;

  /**
   * Compatibility only.
   *
   * Not displayed as a Detection table column.
   */
  alerts: number;
}


/* ==========================================================================
 * Detection KPI Statistics
 * ========================================================================== */

export interface DetectionKpiStatistics {
  activeRules: number;
  detectionMatches: number;
  enabledPlugins: number;
  totalEvaluations: number;
}


/* ==========================================================================
 * Detection Rule Actions
 * ========================================================================== */

export type DetectionRuleAction =
  | "view"
  | "edit"
  | "enable"
  | "disable"
  | "delete";


/* ==========================================================================
 * Detection Result Filters
 * ========================================================================== */

export interface DetectionResultFilters {
  severity: string;
  category: string;

  suppressed:
    | "all"
    | "true"
    | "false";

  startTime: string;
  endTime: string;

  /**
   * Optional API-level context.
   */
  ruleId?: string;
  eventId?: string;
}


export const DEFAULT_DETECTION_RESULT_FILTERS: DetectionResultFilters = {
  severity: "all",
  category: "all",
  suppressed: "all",
  startTime: "",
  endTime: "",
};


/* ==========================================================================
 * Detection Result Query Parameters
 * ========================================================================== */

export interface DetectionResultQueryParams {
  query?: string;
  rule_id?: string;
  event_id?: string;
  severity?: string;
  category?: string;
  suppressed?: boolean;
  start_time?: string;
  end_time?: string;
  page?: number;
  page_size?: number;
}


/* ==========================================================================
 * Detection Rule Query Parameters
 * ========================================================================== */

export interface DetectionRuleQueryParams {
  query?: string;
  enabled?: boolean;
  severity?: string;
  category?: string;
  tag?: string;
  page?: number;
  page_size?: number;
}


/* ==========================================================================
 * Detection Table State
 * ========================================================================== */

export interface DetectionRuleTableState {
  loading: boolean;
  error: string | null;

  items: DetectionRule[];

  /**
   * Backend authoritative total.
   *
   * Do not replace this with items.length.
   */
  total: number;

  page: number;
  pageSize: number;
  totalPages: number;
}


/* ==========================================================================
 * Detection Results State
 * ========================================================================== */

export interface DetectionResultsState {
  loading: boolean;
  error: string | null;

  items: DetectionResult[];

  pagination: DetectionPagination | null;
}


/* ==========================================================================
 * Detection UI State
 * ========================================================================== */

export interface DetectionPageState {
  loading: boolean;
  refreshing: boolean;
  error: string | null;

  rules: DetectionRule[];

  /**
   * Backend authoritative pagination values.
   */
  totalRules: number;
  currentPage: number;
  pageSize: number;
  totalPages: number;

  selectedRuleId: string | null;
  detailsOpen: boolean;

  formOpen: boolean;
  editingRuleId: string | null;
}


/* ==========================================================================
 * Detection Sort
 * ========================================================================== */

export type DetectionRuleSortField =
  | "name"
  | "severity"
  | "category"
  | "matches"
  | "suppressed"
  | "last_match";


export type DetectionSortDirection =
  | "asc"
  | "desc";


export interface DetectionRuleSort {
  field: DetectionRuleSortField;
  direction: DetectionSortDirection;
}


/* ==========================================================================
 * Internal Utility
 * ========================================================================== */

function isFiniteNumber(
  value: unknown,
): value is number {
  return (
    typeof value === "number" &&
    Number.isFinite(value)
  );
}


function isStringArray(
  value: unknown,
): value is string[] {
  return (
    Array.isArray(value) &&
    value.every(
      (item) =>
        typeof item === "string",
    )
  );
}


function uniqueStrings(
  values: string[],
): string[] {
  return [
    ...new Set(values),
  ];
}


/* ==========================================================================
 * Type Guards
 * ========================================================================== */

export function isDetectionStatus(
  value: unknown,
): value is DetectionStatus {
  return (
    value === "available" ||
    value === "planned" ||
    value === "unavailable" ||
    value === "unknown"
  );
}


export function isConditionOperator(
  value: unknown,
): value is ConditionOperator {
  return (
    value === "equals" ||
    value === "not_equals" ||
    value === "in" ||
    value === "not_in" ||
    value === "contains" ||
    value === "exists"
  );
}


export function isDetectionMatch(
  value: unknown,
): value is DetectionMatch {
  return (
    value === "all" ||
    value === "any"
  );
}


/* ==========================================================================
 * Rule Condition Guard
 * ========================================================================== */

export function isDetectionRuleCondition(
  value: unknown,
): value is DetectionRuleCondition {
  if (
    typeof value !== "object" ||
    value === null
  ) {
    return false;
  }

  const candidate =
    value as Record<string, unknown>;

  return (
    typeof candidate.field === "string" &&
    candidate.field.trim().length > 0 &&
    isConditionOperator(
      candidate.operator,
    )
  );
}


/* ==========================================================================
 * Rule Statistics Guard
 * ========================================================================== */

export function isDetectionRuleStatistics(
  value: unknown,
): value is DetectionRuleStatistics {
  if (
    typeof value !== "object" ||
    value === null
  ) {
    return false;
  }

  const candidate =
    value as Record<string, unknown>;

  return (
    isFiniteNumber(
      candidate.matches,
    ) &&

    isFiniteNumber(
      candidate.alerts,
    ) &&

    isFiniteNumber(
      candidate.suppressed,
    ) &&

    (
      candidate.last_match_at ===
        null ||
      typeof candidate.last_match_at ===
        "string"
    )
  );
}


/* ==========================================================================
 * Detection Rule Guard
 * ========================================================================== */

export function isDetectionRule(
  value: unknown,
): value is DetectionRule {
  if (
    typeof value !== "object" ||
    value === null
  ) {
    return false;
  }

  const candidate =
    value as Record<string, unknown>;

  const validDirectLastMatch =
    candidate.last_match ===
      undefined ||
    candidate.last_match ===
      null ||
    typeof candidate.last_match ===
      "string";

  const validLegacyLastMatch =
    candidate.last_match_at ===
      undefined ||
    candidate.last_match_at ===
      null ||
    typeof candidate.last_match_at ===
      "string";

  const validStatistics =
    candidate.statistics ===
      undefined ||
    isDetectionRuleStatistics(
      candidate.statistics,
    );

  return (
    typeof candidate.id ===
      "string" &&

    candidate.id.trim().length >
      0 &&

    typeof candidate.name ===
      "string" &&

    typeof candidate.description ===
      "string" &&

    typeof candidate.enabled ===
      "boolean" &&

    typeof candidate.severity ===
      "string" &&

    typeof candidate.category ===
      "string" &&

    Array.isArray(
      candidate.conditions,
    ) &&

    candidate.conditions.every(
      isDetectionRuleCondition,
    ) &&

    isDetectionMatch(
      candidate.match,
    ) &&

    Array.isArray(
      candidate.tags,
    ) &&

    candidate.tags.every(
      (tag) =>
        typeof tag === "string",
    ) &&

    validDirectLastMatch &&

    validLegacyLastMatch &&

    validStatistics
  );
}


/* ==========================================================================
 * Detection Capability Guard
 * ========================================================================== */

export function isDetectionCapability(
  value: unknown,
): value is DetectionCapability {
  if (
    typeof value !== "object" ||
    value === null
  ) {
    return false;
  }

  const candidate =
    value as Record<string, unknown>;

  return (
    typeof candidate.resource ===
      "string" &&

    isDetectionStatus(
      candidate.status,
    ) &&

    typeof candidate.message ===
      "string" &&

    typeof candidate.rules_api ===
      "boolean" &&

    typeof candidate.results_api ===
      "boolean" &&

    typeof candidate.plugins_api ===
      "boolean"
  );
}


/* ==========================================================================
 * Detection Statistics Guard
 * ========================================================================== */

export function isDetectionStatistics(
  value: unknown,
): value is DetectionStatistics {
  if (
    typeof value !== "object" ||
    value === null
  ) {
    return false;
  }

  const candidate =
    value as Record<string, unknown>;

  return (
    isFiniteNumber(
      candidate.total_rules,
    ) &&

    isFiniteNumber(
      candidate.enabled_rules,
    ) &&

    isFiniteNumber(
      candidate.disabled_rules,
    ) &&

    isFiniteNumber(
      candidate.total_plugins,
    ) &&

    isFiniteNumber(
      candidate.enabled_plugins,
    ) &&

    isFiniteNumber(
      candidate.total_evaluations,
    ) &&

    isFiniteNumber(
      candidate.detection_matches,
    ) &&

    isFiniteNumber(
      candidate.suppressed_matches,
    ) &&

    isFiniteNumber(
      candidate.evaluation_failures,
    ) &&

    isFiniteNumber(
      candidate.plugin_evaluations,
    ) &&

    isFiniteNumber(
      candidate.plugin_failures,
    )
  );
}


/* ==========================================================================
 * Detection Summary Guard
 * ========================================================================== */

export function isDetectionSummary(
  value: unknown,
): value is DetectionSummary {
  if (
    typeof value !== "object" ||
    value === null
  ) {
    return false;
  }

  const candidate =
    value as Record<string, unknown>;

  return (
    isFiniteNumber(
      candidate.total_rules,
    ) &&

    isFiniteNumber(
      candidate.enabled_rules,
    ) &&

    isFiniteNumber(
      candidate.disabled_rules,
    ) &&

    isFiniteNumber(
      candidate.total_plugins,
    ) &&

    isFiniteNumber(
      candidate.enabled_plugins,
    )
  );
}


/* ==========================================================================
 * Detection Result Guard
 * ========================================================================== */

export function isDetectionResult(
  value: unknown,
): value is DetectionResult {
  if (
    typeof value !== "object" ||
    value === null
  ) {
    return false;
  }

  const candidate =
    value as Record<string, unknown>;

  return (
    typeof candidate.detection_id ===
      "string" &&

    typeof candidate.rule_id ===
      "string" &&

    typeof candidate.rule_name ===
      "string" &&

    typeof candidate.event_id ===
      "string" &&

    typeof candidate.severity ===
      "string" &&

    typeof candidate.category ===
      "string" &&

    typeof candidate.description ===
      "string" &&

    typeof candidate.matched_at ===
      "string" &&

    isStringArray(
      candidate.tags,
    ) &&

    typeof candidate.suppressed ===
      "boolean"
  );
}


/* ==========================================================================
 * Detection Filter Options Guard
 * ========================================================================== */

export function isDetectionFilterOptions(
  value: unknown,
): value is DetectionFilterOptions {
  if (
    typeof value !== "object" ||
    value === null
  ) {
    return false;
  }

  const candidate =
    value as Record<string, unknown>;

  return (
    isStringArray(
      candidate.status,
    ) &&

    isStringArray(
      candidate.severity,
    ) &&

    isStringArray(
      candidate.category,
    ) &&

    isStringArray(
      candidate.tags,
    )
  );
}


/* ==========================================================================
 * Pagination Guard
 * ========================================================================== */

export function isDetectionPagination(
  value: unknown,
): value is DetectionPagination {
  if (
    typeof value !== "object" ||
    value === null
  ) {
    return false;
  }

  const candidate =
    value as Record<string, unknown>;

  return (
    isFiniteNumber(
      candidate.page,
    ) &&

    isFiniteNumber(
      candidate.page_size,
    ) &&

    isFiniteNumber(
      candidate.total,
    ) &&

    isFiniteNumber(
      candidate.total_pages,
    )
  );
}


/* ==========================================================================
 * Rule List Response Guard
 * ========================================================================== */

export function isDetectionRuleListResponse(
  value: unknown,
): value is DetectionRuleListResponse {
  if (
    typeof value !== "object" ||
    value === null
  ) {
    return false;
  }

  const candidate =
    value as Record<string, unknown>;

  return (
    Array.isArray(
      candidate.items,
    ) &&

    candidate.items.every(
      isDetectionRule,
    ) &&

    isFiniteNumber(
      candidate.total,
    ) &&

    isFiniteNumber(
      candidate.page,
    ) &&

    isFiniteNumber(
      candidate.page_size,
    ) &&

    isFiniteNumber(
      candidate.total_pages,
    )
  );
}


/* ==========================================================================
 * Result List Response Guard
 * ========================================================================== */

export function isDetectionResultListResponse(
  value: unknown,
): value is DetectionResultListResponse {
  if (
    typeof value !== "object" ||
    value === null
  ) {
    return false;
  }

  const candidate =
    value as Record<string, unknown>;

  return (
    Array.isArray(
      candidate.items,
    ) &&

    candidate.items.every(
      isDetectionResult,
    ) &&

    isFiniteNumber(
      candidate.total,
    ) &&

    isFiniteNumber(
      candidate.page,
    ) &&

    isFiniteNumber(
      candidate.page_size,
    ) &&

    isFiniteNumber(
      candidate.total_pages,
    )
  );
}


/* ==========================================================================
 * Number Normalization
 * ========================================================================== */

/**
 * Presentation safety only.
 *
 * This does not calculate a security metric.
 */
export function normalizeDetectionNumber(
  value: unknown,
  fallback = 0,
): number {
  if (
    !isFiniteNumber(value)
  ) {
    return fallback;
  }

  return Math.max(
    0,
    value,
  );
}


/* ==========================================================================
 * Rule Statistics Mapping
 * ========================================================================== */

export function getDetectionRuleStatistics(
  rule: DetectionRule,
): DetectionRuleStatisticsView {
  const statistics =
    rule.statistics;

  return {
    matches:
      normalizeDetectionNumber(
        rule.matches ??
        statistics?.matches,
      ),

    alerts:
      normalizeDetectionNumber(
        rule.alerts ??
        statistics?.alerts,
      ),

    suppressed:
      normalizeDetectionNumber(
        rule.suppressed ??
        statistics?.suppressed,
      ),

    lastMatchAt:
      rule.last_match ??
      rule.last_match_at ??
      statistics?.last_match_at ??
      null,
  };
}


/* ==========================================================================
 * Rule → Table Row
 * ========================================================================== */

export function detectionRuleToTableRow(
  rule: DetectionRule,
): DetectionRuleTableRow {
  const statistics =
    getDetectionRuleStatistics(
      rule,
    );

  return {
    rule,

    matches:
      statistics.matches,

    alerts:
      statistics.alerts,

    suppressed:
      statistics.suppressed,

    lastMatchAt:
      statistics.lastMatchAt ??
      null,
  };
}


/* ==========================================================================
 * Detection KPI Builder
 * ========================================================================== */

export function buildDetectionKpiStatistics(
  statistics:
    | DetectionStatistics
    | DetectionSummary
    | null,
): DetectionKpiStatistics {
  return {
    activeRules:
      normalizeDetectionNumber(
        statistics?.enabled_rules,
      ),

    detectionMatches:
      normalizeDetectionNumber(
        statistics?.detection_matches,
      ),

    enabledPlugins:
      normalizeDetectionNumber(
        statistics?.enabled_plugins,
      ),

    totalEvaluations:
      normalizeDetectionNumber(
        statistics?.total_evaluations,
      ),
  };
}


/* ==========================================================================
 * Detection Engine Health Builder
 * ========================================================================== */

export function buildDetectionEngineHealth(
  capability: DetectionCapability | null,
  statistics:
    | DetectionStatistics
    | DetectionSummary
    | null,
): DetectionEngineHealth {
  const status =
    capability?.status ??
    "unknown";

  const registryStatus =
    status === "available"
      ? "loaded"
      : status === "unavailable"
        ? "unavailable"
        : status === "planned"
          ? "planned"
          : "unknown";

  return {
    engineStatus:
      status,

    ruleRegistry:
      registryStatus,

    rulesLoaded:
      normalizeDetectionNumber(
        statistics?.total_rules,
      ),

    pluginRegistry:
      registryStatus,

    pluginsEnabled:
      normalizeDetectionNumber(
        statistics?.enabled_plugins,
      ),

    evaluationErrors:
      normalizeDetectionNumber(
        statistics?.evaluation_failures,
      ),
  };
}


/* ==========================================================================
 * Detection Overview Builder
 * ========================================================================== */

export function buildDetectionOverview(
  capability: DetectionCapability | null,
  statistics:
    | DetectionStatistics
    | DetectionSummary
    | null,
): DetectionOverview {
  return {
    resource:
      capability?.resource ??
      "detections",

    status:
      capability?.status ??
      "unknown",

    message:
      capability?.message ??
      "Detection subsystem status is unavailable.",

    available:
      capability?.status ===
      "available",

    rulesApiAvailable:
      capability?.rules_api ??
      false,

    resultsApiAvailable:
      capability?.results_api ??
      false,

    pluginsApiAvailable:
      capability?.plugins_api ??
      false,

    rulesLoaded:
      normalizeDetectionNumber(
        statistics?.total_rules,
      ),

    pluginsEnabled:
      normalizeDetectionNumber(
        statistics?.enabled_plugins,
      ),

    evaluationErrors:
      normalizeDetectionNumber(
        statistics?.evaluation_failures,
      ),
  };
}


/* ==========================================================================
 * Filter Options Normalization
 * ========================================================================== */

export function normalizeDetectionFilterOptions(
  value: unknown,
): DetectionFilterOptions {
  if (
    typeof value !== "object" ||
    value === null
  ) {
    return {
      ...EMPTY_DETECTION_FILTER_OPTIONS,
    };
  }

  const candidate =
    value as Record<string, unknown>;

  return {
    status: uniqueStrings(
      isStringArray(
        candidate.status,
      )
        ? candidate.status
        : [],
    ),

    severity: uniqueStrings(
      isStringArray(
        candidate.severity,
      )
        ? candidate.severity
        : [],
    ),

    category: uniqueStrings(
      isStringArray(
        candidate.category,
      )
        ? candidate.category
        : [],
    ),

    tags: uniqueStrings(
      isStringArray(
        candidate.tags,
      )
        ? candidate.tags
        : [],
    ),
  };
}


/* ==========================================================================
 * Rule Filter → API Query
 * ========================================================================== */

export function detectionFiltersToQueryParams(
  filters: DetectionRuleFilters,
): DetectionRuleQueryParams {
  const params: DetectionRuleQueryParams = {};

  const query =
    filters.query.trim();

  if (query) {
    params.query = query;
  }

  if (
    filters.status ===
    "enabled"
  ) {
    params.enabled = true;
  }

  if (
    filters.status ===
    "disabled"
  ) {
    params.enabled = false;
  }

  const severity =
    filters.severity.trim();

  if (
    severity &&
    severity !== "all"
  ) {
    params.severity =
      severity;
  }

  const category =
    filters.category.trim();

  if (
    category &&
    category !== "all"
  ) {
    params.category =
      category;
  }

  /**
   * Backend currently accepts a singular `tag` query parameter.
   *
   * The UI stores selected tags as an array for compatibility,
   * but the current Detection filter UI uses one selected tag.
   *
   * Optional chaining is intentional because TypeScript cannot
   * guarantee that index 0 exists even after length checks.
   */
  const tag =
    filters.tags[0]?.trim();

  if (tag) {
    params.tag = tag;
  }

  return params;
}


/* ==========================================================================
 * Result Filter → API Query
 * ========================================================================== */

export function detectionResultFiltersToQueryParams(
  filters: DetectionResultFilters,
): DetectionResultQueryParams {
  const params: DetectionResultQueryParams = {};

  const severity =
    filters.severity.trim();

  if (
    severity &&
    severity !== "all"
  ) {
    params.severity =
      severity;
  }

  const category =
    filters.category.trim();

  if (
    category &&
    category !== "all"
  ) {
    params.category =
      category;
  }

  if (
    filters.suppressed ===
    "true"
  ) {
    params.suppressed =
      true;
  } else if (
    filters.suppressed ===
    "false"
  ) {
    params.suppressed =
      false;
  }

  const startTime =
    filters.startTime.trim();

  if (startTime) {
    params.start_time =
      startTime;
  }

  const endTime =
    filters.endTime.trim();

  if (endTime) {
    params.end_time =
      endTime;
  }

  const ruleId =
    filters.ruleId?.trim();

  if (ruleId) {
    params.rule_id =
      ruleId;
  }

  const eventId =
    filters.eventId?.trim();

  if (eventId) {
    params.event_id =
      eventId;
  }

  return params;
}


/* ==========================================================================
 * Form Helpers
 * ========================================================================== */

export function createEmptyDetectionCondition(): DetectionRuleCondition {
  return {
    field: "",
    operator: "equals",
    value: "",
  };
}


export function createEmptyDetectionRuleForm(): DetectionRuleFormState {
  return {
    id: "",
    name: "",
    description: "",
    enabled: true,
    severity: "",
    category: "",
    conditions: [
      createEmptyDetectionCondition(),
    ],
    match: "all",
    tags: [],
  };
}


export function detectionRuleToFormState(
  rule: DetectionRule,
): DetectionRuleFormState {
  return {
    id:
      rule.id,

    name:
      rule.name,

    description:
      rule.description,

    enabled:
      rule.enabled,

    severity:
      rule.severity,

    category:
      rule.category,

    conditions:
      rule.conditions.map(
        (condition) => ({
          field:
            condition.field,

          operator:
            condition.operator,

          value:
            condition.value,
        }),
      ),

    match:
      rule.match,

    tags: [
      ...rule.tags,
    ],
  };
}


/* ==========================================================================
 * Create Request Builder
 * ========================================================================== */

export function detectionFormToCreateRequest(
  form: DetectionRuleFormState,
): DetectionRuleCreateRequest {
  return {
    id:
      form.id.trim(),

    name:
      form.name.trim(),

    description:
      form.description.trim(),

    enabled:
      form.enabled,

    severity:
      form.severity.trim(),

    category:
      form.category.trim(),

    conditions:
      form.conditions.map(
        (condition) => ({
          field:
            condition.field.trim(),

          operator:
            condition.operator,

          value:
            condition.value,
        }),
      ),

    match:
      form.match,

    tags:
      form.tags
        .map(
          (tag) =>
            tag.trim(),
        )
        .filter(Boolean),
  };
}


/* ==========================================================================
 * Update Request Builder
 * ========================================================================== */

export function detectionFormToUpdateRequest(
  form: DetectionRuleFormState,
): DetectionRuleUpdateRequest {
  return {
    name:
      form.name.trim(),

    description:
      form.description.trim(),

    enabled:
      form.enabled,

    severity:
      form.severity.trim(),

    category:
      form.category.trim(),

    conditions:
      form.conditions.map(
        (condition) => ({
          field:
            condition.field.trim(),

          operator:
            condition.operator,

          value:
            condition.value,
        }),
      ),

    match:
      form.match,

    tags:
      form.tags
        .map(
          (tag) =>
            tag.trim(),
        )
        .filter(Boolean),
  };
}


/* ==========================================================================
 * Detection UI Helpers
 * ========================================================================== */

export function getDetectionStatusLabel(
  status: DetectionStatus,
): string {
  switch (status) {
    case "available":
      return "Operational";

    case "planned":
      return "Planned";

    case "unavailable":
      return "Unavailable";

    case "unknown":
    default:
      return "Unknown";
  }
}


export function isDetectionOperational(
  status: DetectionStatus,
): boolean {
  return status ===
    "available";
}


export function getDetectionRuleStatusLabel(
  enabled: boolean,
): string {
  return enabled
    ? "Enabled"
    : "Disabled";
}


export function getDetectionRuleToggleAction(
  rule: DetectionRule,
): "enable" | "disable" {
  return rule.enabled
    ? "disable"
    : "enable";
}


export function getDetectionConditionSummary(
  rule: DetectionRule,
): string {
  const count =
    rule.conditions.length;

  return `${count} ${
    count === 1
      ? "condition"
      : "conditions"
  }`;
}


/* ==========================================================================
 * Detection Action Authorization
 * ========================================================================== */

export function canUseDetectionRuleAction(
  role: DetectionRole | null | undefined,
  action: DetectionRuleAction,
  rule?: DetectionRule | null,
): boolean {
  const access =
    getDetectionAccess(role);

  switch (action) {
    case "view":
      return access.canView;

    case "edit":
      return access.canEdit;

    case "enable":
      return (
        access.canEnableDisable &&
        rule?.enabled === false
      );

    case "disable":
      return (
        access.canEnableDisable &&
        rule?.enabled === true
      );

    case "delete":
      return access.canDelete;

    default:
      return false;
  }
}


/* ==========================================================================
 * Event Navigation
 * ========================================================================== */

export interface DetectionEventReference {
  eventId: string;
}


export function detectionResultToEventReference(
  result: DetectionResult,
): DetectionEventReference {
  return {
    eventId:
      result.event_id,
  };
}


/* ==========================================================================
 * Default Export
 * ========================================================================== */

export type {
  DetectionRule as default,
};