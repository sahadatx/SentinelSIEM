/**
 * ============================================================================
 * SentinelSIEM — MITRE ATT&CK Module Types
 * ============================================================================
 *
 * Read-only MITRE ATT&CK knowledge + SentinelSIEM intelligence contracts.
 *
 * Authoritative MITRE knowledge source:
 *
 *   PostgreSQL-backed MITRE ATT&CK repository
 *
 * Authoritative SentinelSIEM intelligence sources:
 *
 *   Detections
 *   Events
 *   Alerts
 *   Incidents
 *   IOCs
 *   Assets
 *   Detection → MITRE mappings
 *
 * MITRE knowledge is READ-ONLY.
 *
 * There are intentionally NO:
 *
 *   createTechnique()
 *   updateTechnique()
 *   deleteTechnique()
 *   createTactic()
 *   updateTactic()
 *   deleteTactic()
 *
 * Detection → MITRE mapping management is a separate capability and is
 * deliberately not represented as MITRE knowledge CRUD.
 *
 * ============================================================================
 */


/* ============================================================================
 * Primitive Types
 * ========================================================================== */

export type ISODateString = string;


/**
 * PostgreSQL-backed MITRE record identifier.
 */
export type MitreRecordId = string;


/**
 * MITRE ATT&CK external technique identifier.
 *
 * Examples:
 *
 *   T1059
 *   T1078
 *   T1548
 */
export type MitreTechniqueId = string;


/**
 * MITRE ATT&CK sub-technique identifier.
 *
 * Examples:
 *
 *   T1059.001
 *   T1059.003
 */
export type MitreSubTechniqueId = string;


/**
 * MITRE ATT&CK tactic identifier.
 *
 * Examples:
 *
 *   TA0001
 *   TA0002
 */
export type MitreTacticId = string;


/**
 * MITRE ATT&CK platform identifier.
 *
 * Examples:
 *
 *   windows
 *   linux
 *   macos
 */
export type MitrePlatformId = string;


/* ============================================================================
 * Coverage
 * ========================================================================== */

/**
 * Backend-authoritative SentinelSIEM coverage state.
 *
 * Values:
 *
 *   full
 *   partial
 *   unmapped
 */
export type MitreCoverageState =
  | "full"
  | "partial"
  | "unmapped";


/**
 * UI aliases.
 */
export type MitreCoverageTone =
  MitreCoverageState;


export type MitreTechniqueStatus =
  MitreCoverageState;


/**
 * Coverage information for a MITRE technique.
 *
 * All values are backend-authoritative.
 *
 * The frontend must not derive coverage state from mapping IDs or detection
 * counts.
 */
export interface MitreTechniqueCoverage {
  /**
   * Internal/backend technique identifier.
   */
  technique_id: string;

  /**
   * Backend-derived coverage state.
   */
  state: MitreCoverageState;

  /**
   * Number of SentinelSIEM mappings associated with the technique.
   */
  mapping_count: number;

  /**
   * Number of detections associated with the technique.
   */
  detection_count: number;

  /**
   * Number of child sub-techniques.
   */
  subtechnique_count: number;

  /**
   * Number of mapped child sub-techniques.
   */
  mapped_subtechnique_count: number;

  /**
   * Backend-provided confidence value.
   */
  confidence: number;
}


/* ============================================================================
 * Pagination
 * ========================================================================== */

/**
 * Pagination metadata returned by MITRE list endpoints.
 */
export interface MitrePagination {
  page: number;

  page_size: number;

  total: number;

  total_pages: number;
}


/* ============================================================================
 * Tactics
 * ========================================================================== */

export interface MitreTactic {
  /**
   * PostgreSQL UUID.
   */
  id: string;

  /**
   * MITRE external tactic identifier.
   *
   * Example:
   *
   *   TA0001
   */
  external_id: string | null;

  /**
   * Human-readable tactic name.
   */
  name: string;

  /**
   * MITRE tactic description.
   */
  description: string;
}


/**
 * GET /api/v1/mitre/tactics
 */
export interface MitreTacticListResponse {
  items: MitreTactic[];

  pagination: MitrePagination;
}


/* ============================================================================
 * Platforms
 * ========================================================================== */

/**
 * MITRE ATT&CK platform.
 *
 * IMPORTANT:
 *
 * Both the internal PostgreSQL ID and MITRE external platform identifier are
 * retained because different parts of the frontend may need either one.
 */
export interface MitrePlatform {
  /**
   * PostgreSQL-backed platform identifier.
   */
  id: string;

  /**
   * MITRE ATT&CK platform external identifier.
   *
   * Examples:
   *
   *   windows
   *   linux
   *   macos
   *
   * Backend may return null when an external identifier is unavailable.
   */
  external_id: string | null;

  /**
   * Human-readable platform name.
   */
  name: string;

  /**
   * Optional MITRE platform description.
   */
  description?: string | null;
}


/**
 * GET /api/v1/mitre/platforms
 */
export interface MitrePlatformListResponse {
  items: MitrePlatform[];

  pagination: MitrePagination;
}


/* ============================================================================
 * Technique Type
 * ========================================================================== */

export type MitreTechniqueType =
  | "TECHNIQUE"
  | "SUB_TECHNIQUE";


/* ============================================================================
 * Techniques
 * ========================================================================== */

/**
 * Base MITRE ATT&CK technique representation.
 *
 * Backend list/detail responses expose:
 *
 *   id
 *   external_id
 *   name
 *   type
 *   tactic_ids
 *   platform_ids
 *   platforms
 *   description
 *
 * IMPORTANT:
 *
 * `platforms` contains full platform objects rather than strings so the
 * frontend can consistently resolve:
 *
 *   platform.id
 *   platform.external_id
 *   platform.name
 *
 * without unsafe type assertions.
 */
export interface MitreTechnique {
  /**
   * PostgreSQL UUID.
   */
  id: string;

  /**
   * MITRE ATT&CK external technique identifier.
   *
   * Examples:
   *
   *   T1059
   *   T1059.001
   */
  external_id: string | null;

  /**
   * Human-readable technique name.
   */
  name: string;

  /**
   * Backend technique type.
   */
  type: MitreTechniqueType;

  /**
   * Associated tactic identifiers.
   *
   * These may represent PostgreSQL IDs or backend-resolved identifiers
   * depending on the endpoint contract.
   */
  tactic_ids: string[];

  /**
   * Associated platform identifiers.
   */
  platform_ids: string[];

  /**
   * Resolved MITRE platform objects.
   */
  platforms: MitrePlatform[];

  /**
   * MITRE technique description.
   */
  description: string;
}


/**
 * GET /api/v1/mitre/techniques
 */
export interface MitreTechniqueListResponse {
  items: MitreTechnique[];

  pagination: MitrePagination;
}


/* ============================================================================
 * Sub-Techniques
 * ========================================================================== */

export interface MitreSubTechnique {
  /**
   * PostgreSQL UUID.
   */
  id: string;

  /**
   * MITRE ATT&CK external sub-technique identifier.
   *
   * Example:
   *
   *   T1059.001
   */
  external_id: string | null;

  /**
   * Human-readable sub-technique name.
   */
  name: string;

  /**
   * Sub-techniques are always represented with this type.
   */
  type: "SUB_TECHNIQUE";

  /**
   * Parent technique identifier.
   */
  parent_id: string;

  /**
   * Associated tactic identifiers.
   */
  tactic_ids: string[];

  /**
   * Associated platform identifiers.
   */
  platform_ids: string[];

  /**
   * Resolved MITRE platform objects.
   */
  platforms: MitrePlatform[];

  /**
   * MITRE sub-technique description.
   */
  description: string;
}


/**
 * GET /api/v1/mitre/techniques/{technique_id}/sub-techniques
 */
export interface MitreSubTechniqueListResponse {
  items: MitreSubTechnique[];

  pagination: MitrePagination;
}


/* ============================================================================
 * Matrix
 * ========================================================================== */

/**
 * Technique representation used by the ATT&CK matrix.
 *
 * This combines:
 *
 *   MITRE knowledge
 *   +
 *   SentinelSIEM coverage
 *   +
 *   detection mapping context
 */
export interface MitreMatrixTechnique
  extends MitreTechnique {
  /**
   * Backend-authoritative technique coverage.
   */
  coverage: MitreTechniqueCoverage;

  /**
   * Child sub-techniques.
   */
  subtechniques: MitreSubTechnique[];

  /**
   * SentinelSIEM mapping identifiers.
   */
  mapping_ids: string[];

  /**
   * SentinelSIEM detection identifiers.
   */
  detection_ids: string[];
}


/**
 * One tactic column in the ATT&CK matrix.
 */
export interface MitreMatrixTactic
  extends MitreTactic {
  /**
   * Techniques belonging to this tactic.
   */
  techniques: MitreMatrixTechnique[];

  /**
   * Backend-authoritative tactic coverage percentage.
   */
  coverage_percent: number;
}


/**
 * GET /api/v1/mitre/matrix
 */
export interface MitreMatrix {
  tactics: MitreMatrixTactic[];

  /**
   * Backend-authoritative total technique count.
   */
  total_techniques: number;

  /**
   * Backend-authoritative full coverage count.
   */
  full_techniques: number;

  /**
   * Backend-authoritative partial coverage count.
   */
  partial_techniques: number;

  /**
   * Backend-authoritative unmapped count.
   */
  unmapped_techniques: number;

  /**
   * Backend-authoritative overall matrix coverage.
   */
  coverage_percent: number;
}


/* ============================================================================
 * Global Coverage
 * ========================================================================== */

/**
 * GET /api/v1/mitre/coverage
 *
 * IMPORTANT:
 *
 * This response is kept separate from MitreAnalytics because the backend
 * currently exposes different coverage-oriented response contracts.
 *
 * Consumers must not mix its total_techniques with analytics counters unless
 * the backend explicitly guarantees that they represent the same universe.
 */
export interface MitreCoverage {
  /**
   * Backend-authoritative technique count for this coverage response.
   */
  total_techniques: number;

  /**
   * Backend-authoritative mapped technique count.
   */
  mapped_techniques: number;

  /**
   * Backend-authoritative coverage percentage.
   */
  coverage_percent: number;

  /**
   * Backend-provided mapped technique identifiers.
   */
  mapped_technique_ids: string[];

  /**
   * Backend-provided unmapped technique identifiers.
   */
  unmapped_technique_ids: string[];
}


/**
 * GET /api/v1/mitre/coverage/tactics
 *
 * Individual tactic coverage entry.
 */
export interface MitreTacticCoverage {
  /**
   * Tactic identifier.
   */
  tactic_id: string;

  /**
   * Backend-authoritative tactic coverage percentage.
   */
  coverage_percent: number;
}


/**
 * Backend may expose tactic coverage either directly as an array or through
 * an object wrapper.
 *
 * The API adapter normalizes the response into this structure.
 */
export interface MitreTacticCoverageListResponse {
  items: MitreTacticCoverage[];

  pagination?: MitrePagination;
}


/* ============================================================================
 * Statistics
 * ========================================================================== */

/**
 * GET /api/v1/mitre/statistics
 *
 * Backend-authoritative MITRE dataset statistics.
 */
export interface MitreStatistics {
  /**
   * Number of ATT&CK tactics.
   */
  tactics: number;

  /**
   * Number of top-level ATT&CK techniques.
   */
  techniques: number;

  /**
   * Number of ATT&CK sub-techniques.
   */
  subtechniques: number;

  /**
   * Backend-authoritative coverage percentage.
   */
  coverage_percent: number;
}


/* ============================================================================
 * Analytics
 * ========================================================================== */

/**
 * GET /api/v1/mitre/analytics
 *
 * Backend-authoritative SentinelSIEM MITRE coverage analytics.
 *
 * IMPORTANT:
 *
 * When a UI displays Full / Partial / Unmapped / Total together, it should
 * use these fields from this same response.
 */
export interface MitreAnalytics {
  /**
   * Technique universe used by analytics.
   */
  total_techniques: number;

  /**
   * Techniques with full coverage.
   */
  full_techniques: number;

  /**
   * Techniques with partial coverage.
   */
  partial_techniques: number;

  /**
   * Techniques without coverage.
   */
  unmapped_techniques: number;

  /**
   * Backend-authoritative analytics coverage percentage.
   */
  coverage_percent: number;

  /**
   * Coverage information grouped by tactic identifier.
   */
  by_tactic: Record<string, number>;

  /**
   * Detection counts grouped by technique identifier.
   */
  technique_detection_counts: Record<
    string,
    number
  >;

  /**
   * Backend-selected top detected technique identifiers.
   */
  top_detected_technique_ids: string[];
}


/* ============================================================================
 * Detection → MITRE Mapping
 * ========================================================================== */

/**
 * Existing SentinelSIEM Detection → MITRE mapping.
 *
 * IMPORTANT:
 *
 * This is NOT MITRE knowledge.
 *
 * It is SentinelSIEM intelligence/context associated with MITRE techniques.
 *
 * Mapping management belongs to the detection/mapping workflow, not the
 * read-only MITRE knowledge UI.
 */
export interface MitreMapping {
  /**
   * Mapping record identifier.
   */
  mapping_id: string;

  /**
   * SentinelSIEM detection identifier.
   */
  detection_id: string;

  /**
   * MITRE technique identifier.
   */
  technique_id: string;

  /**
   * Optional MITRE sub-technique identifier.
   */
  subtechnique_id: string | null;

  /**
   * Associated tactic identifiers.
   */
  tactic_ids: string[];

  /**
   * Backend-provided mapping confidence.
   */
  confidence: number;

  /**
   * Mapping source.
   */
  source: string;

  /**
   * Mapping description.
   */
  description: string;

  /**
   * Mapping creation timestamp.
   */
  created_at: ISODateString;
}


/* ============================================================================
 * Technique Detail
 * ========================================================================== */

/**
 * GET /api/v1/mitre/techniques/{technique_id}/detail
 */
export interface MitreTechniqueDetail {
  /**
   * Requested MITRE technique.
   */
  technique: MitreTechnique;

  /**
   * Backend-authoritative coverage information.
   */
  coverage: MitreTechniqueCoverage;

  /**
   * Associated child sub-techniques.
   */
  subtechniques: MitreSubTechnique[];

  /**
   * SentinelSIEM Detection → MITRE mappings.
   */
  mappings: MitreMapping[];

  /**
   * Associated detection identifiers.
   */
  detection_ids: string[];

  /**
   * Associated event identifiers.
   */
  event_ids: string[];

  /**
   * Associated alert identifiers.
   */
  alert_ids: string[];

  /**
   * Associated incident identifiers.
   */
  incident_ids: string[];

  /**
   * Associated IOC identifiers.
   */
  ioc_ids: string[];

  /**
   * Associated asset identifiers.
   */
  asset_ids: string[];
}


/* ============================================================================
 * Technique Relationships
 * ========================================================================== */

/**
 * GET /api/v1/mitre/techniques/{technique_id}/relationships
 */
export interface MitreTechniqueRelationships {
  /**
   * Requested technique identifier.
   */
  technique_id: string;

  /**
   * Associated detection identifiers.
   */
  detection_ids: string[];

  /**
   * Associated event identifiers.
   */
  event_ids: string[];

  /**
   * Associated alert identifiers.
   */
  alert_ids: string[];

  /**
   * Associated incident identifiers.
   */
  incident_ids: string[];

  /**
   * Associated IOC identifiers.
   */
  ioc_ids: string[];

  /**
   * Associated asset identifiers.
   */
  asset_ids: string[];

  /**
   * SentinelSIEM Detection → MITRE mappings.
   */
  mappings: MitreMapping[];

  /**
   * Associated child sub-techniques.
   */
  subtechniques: MitreSubTechnique[];
}


/* ============================================================================
 * SentinelSIEM Intelligence Records
 * ========================================================================== */

/**
 * These records intentionally remain flexible.
 *
 * The MITRE endpoints return associated SentinelSIEM records whose exact
 * schemas belong to their respective modules.
 *
 * MITRE should not duplicate the full Event / Alert / Incident / IOC domain
 * models.
 */
export type MitreDetectionRecord =
  Record<string, unknown>;


export type MitreEventRecord =
  Record<string, unknown>;


export type MitreAlertRecord =
  Record<string, unknown>;


export type MitreIncidentRecord =
  Record<string, unknown>;


export type MitreIocRecord =
  Record<string, unknown>;


/* ============================================================================
 * Technique Filters
 * ========================================================================== */

/**
 * Filters supported by:
 *
 * GET /api/v1/mitre/techniques
 *
 * Backend query parameters:
 *
 *   search
 *   tactic
 *   platform
 *   type
 *   coverage
 *   page
 *   page_size
 *
 * IMPORTANT:
 *
 * There is intentionally NO tactic_id property.
 *
 * The backend contract uses:
 *
 *   tactic=TA0002
 *
 * or another accepted tactic identifier/name.
 */
export interface MitreTechniqueFilters {
  /**
   * Free-text technique search.
   */
  search?: string;

  /**
   * Backend tactic filter.
   */
  tactic?: string;

  /**
   * Backend platform filter.
   */
  platform?: string;

  /**
   * Technique type filter.
   */
  type?: MitreTechniqueType;

  /**
   * Backend coverage filter.
   */
  coverage?: MitreCoverageState;
}


/**
 * Matrix presentation filters.
 *
 * Matrix is loaded from /matrix. These filters describe UI state and do not
 * imply a second matrix API.
 */
export interface MitreMatrixFilters {
  search?: string;

  tactic?: string;

  platform?: string;

  type?: MitreTechniqueType;

  coverage?: MitreCoverageState;
}


/**
 * GET /api/v1/mitre/techniques query parameters.
 */
export interface MitreTechniqueQuery {
  search?: string;

  tactic?: string;

  platform?: string;

  type?: MitreTechniqueType;

  coverage?: MitreCoverageState;

  page?: number;

  page_size?: number;
}


/* ============================================================================
 * Technique Detail Tabs
 * ========================================================================== */

export type MitreTechniqueDetailTab =
  | "overview"
  | "sub-techniques"
  | "detections"
  | "events"
  | "alerts"
  | "incidents"
  | "iocs"
  | "activity";


/* ============================================================================
 * Generic Async State
 * ========================================================================== */

export interface MitreAsyncState {
  loading: boolean;

  error: string | null;
}


/* ============================================================================
 * Technique List State
 * ========================================================================== */

export interface MitreTechniqueListState
  extends MitreAsyncState {
  items: MitreTechnique[];

  pagination: MitrePagination | null;
}


/* ============================================================================
 * Tactic List State
 * ========================================================================== */

export interface MitreTacticListState
  extends MitreAsyncState {
  items: MitreTactic[];

  pagination: MitrePagination | null;
}


/* ============================================================================
 * Platform List State
 * ========================================================================== */

export interface MitrePlatformListState
  extends MitreAsyncState {
  items: MitrePlatform[];

  pagination: MitrePagination | null;
}


/* ============================================================================
 * Matrix State
 * ========================================================================== */

export interface MitreMatrixState
  extends MitreAsyncState {
  data: MitreMatrix | null;
}


/* ============================================================================
 * Statistics State
 * ========================================================================== */

export interface MitreStatisticsState
  extends MitreAsyncState {
  data: MitreStatistics | null;
}


/* ============================================================================
 * Coverage State
 * ========================================================================== */

export interface MitreCoverageStateData
  extends MitreAsyncState {
  data: MitreCoverage | null;
}


/* ============================================================================
 * Analytics State
 * ========================================================================== */

export interface MitreAnalyticsState
  extends MitreAsyncState {
  data: MitreAnalytics | null;
}


/* ============================================================================
 * Technique Detail State
 * ========================================================================== */

export interface MitreTechniqueDetailState
  extends MitreAsyncState {
  data: MitreTechniqueDetail | null;
}


/* ============================================================================
 * Technique Relationships State
 * ========================================================================== */

export interface MitreTechniqueRelationshipsState
  extends MitreAsyncState {
  data: MitreTechniqueRelationships | null;
}


/* ============================================================================
 * Module State
 * ========================================================================== */

export interface MitreModuleState {
  /**
   * Backend MITRE dataset statistics.
   */
  statistics: MitreStatistics | null;

  /**
   * Backend global coverage response.
   */
  coverage: MitreCoverage | null;

  /**
   * Backend coverage analytics.
   */
  analytics: MitreAnalytics | null;

  /**
   * Backend matrix.
   */
  matrix: MitreMatrix | null;

  /**
   * Current technique page.
   */
  techniques: MitreTechnique[];

  /**
   * Technique pagination.
   */
  techniquesPagination: MitrePagination | null;

  /**
   * Tactic catalog.
   */
  tactics: MitreTactic[];

  /**
   * Tactic pagination.
   */
  tacticsPagination: MitrePagination | null;

  /**
   * Platform catalog.
   */
  platforms: MitrePlatform[];

  /**
   * Platform pagination.
   */
  platformsPagination: MitrePagination | null;

  /**
   * Current technique filters.
   */
  filters: MitreTechniqueFilters;

  /**
   * Module-level loading state.
   */
  loading: boolean;

  /**
   * Module-level error.
   */
  error: string | null;
}


/* ============================================================================
 * Runtime Validation Helpers
 * ========================================================================== */

/**
 * Validate MITRE coverage state.
 */
export function isMitreCoverageState(
  value: string,
): value is MitreCoverageState {
  return (
    value === "full" ||
    value === "partial" ||
    value === "unmapped"
  );
}


/**
 * Validate MITRE technique type.
 */
export function isMitreTechniqueType(
  value: string,
): value is MitreTechniqueType {
  return (
    value === "TECHNIQUE" ||
    value === "SUB_TECHNIQUE"
  );
}


/**
 * Validate top-level MITRE technique ID.
 *
 * T1059      → true
 * T1059.001  → false
 */
export function isMitreTechniqueId(
  value: string,
): value is MitreTechniqueId {
  return /^T\d{4}$/.test(
    value.trim(),
  );
}


/**
 * Validate MITRE sub-technique ID.
 *
 * T1059.001 → true
 * T1059      → false
 */
export function isMitreSubTechniqueId(
  value: string,
): value is MitreSubTechniqueId {
  return /^T\d{4}\.\d{3}$/.test(
    value.trim(),
  );
}


/**
 * Validate MITRE tactic ID.
 */
export function isMitreTacticId(
  value: string,
): value is MitreTacticId {
  return /^TA\d{4}$/.test(
    value.trim(),
  );
}


/**
 * Validate MITRE platform ID.
 */
export function isMitrePlatformId(
  value: string,
): value is MitrePlatformId {
  return value.trim().length > 0;
}


/**
 * Validate a platform object.
 *
 * Useful when consuming backend responses containing optional/mixed platform
 * values.
 */
export function isMitrePlatform(
  value: unknown,
): value is MitrePlatform {
  if (
    typeof value !== "object" ||
    value === null
  ) {
    return false;
  }

  const candidate =
    value as Record<
      string,
      unknown
    >;

  return (
    typeof candidate.id === "string" &&
    typeof candidate.name === "string" &&
    (
      candidate.external_id ===
        null ||
      typeof candidate.external_id ===
        "string"
    )
  );
}


/* ============================================================================
 * Normalization Helpers
 * ========================================================================== */

/**
 * Normalize technique type for API requests.
 */
export function normalizeMitreTechniqueType(
  value:
    | string
    | undefined,
): MitreTechniqueType | undefined {
  if (
    value === undefined ||
    value === null
  ) {
    return undefined;
  }

  const normalized =
    value
      .trim()
      .toUpperCase();

  if (
    normalized ===
      "TECHNIQUE" ||
    normalized ===
      "SUB_TECHNIQUE"
  ) {
    return normalized;
  }

  return undefined;
}


/**
 * Normalize coverage filter.
 */
export function normalizeMitreCoverage(
  value:
    | string
    | undefined,
): MitreCoverageState | undefined {
  if (
    value === undefined ||
    value === null
  ) {
    return undefined;
  }

  const normalized =
    value
      .trim()
      .toLowerCase();

  if (
    isMitreCoverageState(
      normalized,
    )
  ) {
    return normalized;
  }

  return undefined;
}


/**
 * Normalize a generic optional filter string.
 */
export function normalizeMitreFilter(
  value:
    | string
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

  return normalized.length > 0
    ? normalized
    : undefined;
}


/**
 * Normalize an optional numeric page value.
 *
 * This helper only validates the value for UI/API transport.
 *
 * It does not derive pagination metadata.
 */
export function normalizeMitrePage(
  value:
    | number
    | undefined,
): number | undefined {
  if (
    value === undefined ||
    !Number.isFinite(
      value,
    )
  ) {
    return undefined;
  }

  return Math.max(
    1,
    Math.floor(value),
  );
}


/**
 * Normalize an optional page-size value.
 *
 * This helper does not calculate total pages.
 */
export function normalizeMitrePageSize(
  value:
    | number
    | undefined,
): number | undefined {
  if (
    value === undefined ||
    !Number.isFinite(
      value,
    )
  ) {
    return undefined;
  }

  return Math.max(
    1,
    Math.floor(value),
  );
}


/* ============================================================================
 * UI Labels
 * ========================================================================== */

export const MITRE_COVERAGE_LABELS: Record<
  MitreCoverageState,
  string
> = {
  full: "Covered",

  partial: "Partially Covered",

  unmapped: "Not Covered",
};


export const MITRE_TECHNIQUE_TYPE_LABELS: Record<
  MitreTechniqueType,
  string
> = {
  TECHNIQUE: "Technique",

  SUB_TECHNIQUE: "Sub-Technique",
};


/* ============================================================================
 * Default Values
 * ========================================================================== */

export const DEFAULT_MITRE_PAGE =
  1;


export const DEFAULT_MITRE_PAGE_SIZE =
  30;


/**
 * Empty technique filters.
 *
 * Useful for Reset Filters.
 */
export const DEFAULT_MITRE_TECHNIQUE_FILTERS: MitreTechniqueFilters =
  {};


/* ============================================================================
 * End of File
 * ============================================================================
 */