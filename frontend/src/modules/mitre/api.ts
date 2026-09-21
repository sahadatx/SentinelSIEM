/**
 * ============================================================================
 * SentinelSIEM — MITRE ATT&CK Module API
 * ============================================================================
 *
 * Feature-level API facade for the read-only MITRE ATT&CK module.
 *
 * Architecture:
 *
 *   MITRE Pages / Components
 *             ↓
 *   modules/mitre/api.ts
 *             ↓
 *   services/api.ts
 *             ↓
 *   Authenticated HTTP Transport
 *             ↓
 *   /api/v1/mitre/*
 *
 * Responsibilities:
 *
 * - expose MITRE-specific read operations
 * - delegate HTTP transport to services/api.ts
 * - normalize identifiers
 * - normalize query parameters
 * - normalize backend collection responses
 * - keep MITRE UI independent from HTTP implementation details
 *
 * MITRE KNOWLEDGE IS READ-ONLY.
 *
 * There are intentionally NO MITRE knowledge CRUD operations here.
 *
 * Detection → MITRE mapping management is a separate SentinelSIEM
 * capability and is not part of the MITRE knowledge UI.
 *
 * ============================================================================
 */

import { api as sharedApi } from "../../services/api";

import type {
  MitreAnalytics,
  MitreCoverage,
  MitreMatrix,
  MitrePagination,
  MitrePlatform,
  MitrePlatformListResponse,
  MitreStatistics,
  MitreSubTechnique,
  MitreSubTechniqueListResponse,
  MitreTactic,
  MitreTacticCoverage,
  MitreTacticListResponse,
  MitreTechnique,
  MitreTechniqueDetail,
  MitreTechniqueFilters,
  MitreTechniqueListResponse,
  MitreTechniqueQuery,
  MitreTechniqueRelationships,
} from "./types";

import {
  DEFAULT_MITRE_PAGE,
  DEFAULT_MITRE_PAGE_SIZE,
  normalizeMitreCoverage,
  normalizeMitreFilter,
  normalizeMitreTechniqueType,
} from "./types";


/* ============================================================================
 * Constants
 * ========================================================================== */

export const MITRE_DEFAULT_PAGE =
  DEFAULT_MITRE_PAGE;

export const MITRE_DEFAULT_PAGE_SIZE =
  DEFAULT_MITRE_PAGE_SIZE;


/* ============================================================================
 * Internal Types
 * ========================================================================== */

type UnknownRecord =
  Record<string, unknown>;


/* ============================================================================
 * Validation / Normalization
 * ========================================================================== */

/**
 * Normalize and validate a required MITRE identifier.
 */
function requireIdentifier(
  value: string,
  label: string,
): string {
  if (
    typeof value !== "string"
  ) {
    throw new Error(
      `MITRE ${label} must be a string.`,
    );
  }

  const normalized =
    value.trim();

  if (!normalized) {
    throw new Error(
      `MITRE ${label} cannot be empty.`,
    );
  }

  return normalized;
}


/**
 * Normalize a positive integer.
 */
function normalizePositiveInteger(
  value: number | undefined,
  fallback: number,
): number {
  if (
    value === undefined ||
    !Number.isFinite(value)
  ) {
    return fallback;
  }

  const normalized =
    Math.floor(value);

  return normalized > 0
    ? normalized
    : fallback;
}


/**
 * Convert an unknown value to an object record.
 */
function asRecord(
  value: unknown,
): UnknownRecord | null {
  if (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  ) {
    return value as UnknownRecord;
  }

  return null;
}


/* ============================================================================
 * Pagination Normalization
 * ========================================================================== */

/**
 * Normalize backend pagination metadata.
 *
 * The authoritative backend list contract is:
 *
 * {
 *   items: [...],
 *   pagination: {
 *     page,
 *     page_size,
 *     total,
 *     total_pages
 *   }
 * }
 *
 * The normalization also tolerates an array response so the module facade
 * remains resilient to older collection responses from the shared transport.
 */
function normalizePagination(
  value: unknown,
  fallbackPage: number,
  fallbackPageSize: number,
  fallbackTotal: number,
): MitrePagination {
  const record =
    asRecord(value);

  const page =
    typeof record?.page === "number"
      ? record.page
      : fallbackPage;

  const pageSize =
    typeof record?.page_size === "number"
      ? record.page_size
      : fallbackPageSize;

  const total =
    typeof record?.total === "number"
      ? record.total
      : fallbackTotal;

  const totalPages =
    typeof record?.total_pages === "number"
      ? record.total_pages
      : total > 0
        ? Math.ceil(
            total / pageSize,
          )
        : 0;

  return {
    page,
    page_size: pageSize,
    total,
    total_pages: totalPages,
  };
}


/**
 * Normalize a paginated collection.
 */
function normalizePaginatedResponse<T>(
  response: unknown,
  page: number,
  pageSize: number,
): {
  items: T[];
  pagination: MitrePagination;
} {
  if (
    Array.isArray(response)
  ) {
    const items =
      response as T[];

    return {
      items,
      pagination:
        normalizePagination(
          undefined,
          page,
          pageSize,
          items.length,
        ),
    };
  }

  const record =
    asRecord(response);

  if (
    record &&
    Array.isArray(record.items)
  ) {
    const items =
      record.items as T[];

    return {
      items,
      pagination:
        normalizePagination(
          record.pagination,
          page,
          pageSize,
          items.length,
        ),
    };
  }

  return {
    items: [],
    pagination:
      normalizePagination(
        undefined,
        page,
        pageSize,
        0,
      ),
  };
}


/* ============================================================================
 * Technique Query
 * ========================================================================== */

/**
 * Normalize the module-level technique query.
 *
 * IMPORTANT:
 *
 * The locked frontend contract uses:
 *
 *   tactic
 *
 * NOT:
 *
 *   tactic_id
 *
 * The backend endpoint is:
 *
 * GET /api/v1/mitre/techniques
 *
 * with:
 *
 *   search
 *   tactic
 *   platform
 *   type
 *   coverage
 *   page
 *   page_size
 */
function normalizeTechniqueQuery(
  query: MitreTechniqueQuery = {},
): MitreTechniqueQuery {
  const page =
    normalizePositiveInteger(
      query.page,
      MITRE_DEFAULT_PAGE,
    );

  const pageSize =
    normalizePositiveInteger(
      query.page_size,
      MITRE_DEFAULT_PAGE_SIZE,
    );

  const search =
    normalizeMitreFilter(
      query.search,
    );

  const tactic =
    normalizeMitreFilter(
      query.tactic,
    );

  const platform =
    normalizeMitreFilter(
      query.platform,
    );

  const type =
    normalizeMitreTechniqueType(
      query.type,
    );

  const coverage =
    normalizeMitreCoverage(
      query.coverage,
    );

  return {
    ...(search !== undefined
      ? { search }
      : {}),

    ...(tactic !== undefined
      ? { tactic }
      : {}),

    ...(platform !== undefined
      ? { platform }
      : {}),

    ...(type !== undefined
      ? { type }
      : {}),

    ...(coverage !== undefined
      ? { coverage }
      : {}),

    page,

    page_size:
      pageSize,
  };
}


/**
 * Convert module query into the shared transport query.
 *
 * The shared API is expected to expose the same backend query semantics:
 *
 *   search
 *   tactic
 *   platform
 *   type
 *   coverage
 *   page
 *   page_size
 *
 * Coverage remains lowercase because that is the canonical module/backend
 * representation:
 *
 *   full
 *   partial
 *   unmapped
 */
function toSharedTechniqueQuery(
  query: MitreTechniqueQuery,
): Parameters<
  typeof sharedApi.mitreTechniques
>[0] {
  return {
    search:
      query.search,

    tactic:
      query.tactic,

    platform:
      query.platform,

    type:
      query.type,

    coverage:
      query.coverage,

    page:
      query.page,

    page_size:
      query.page_size,
  };
}


/* ============================================================================
 * Statistics
 * ========================================================================== */

/**
 * GET /api/v1/mitre/statistics
 */
async function getStatistics(): Promise<MitreStatistics> {
  return sharedApi.mitreStatistics();
}


/* ============================================================================
 * Global MITRE Overview
 * ========================================================================== */

/**
 * GET /api/v1/mitre
 *
 * The overview endpoint is retained as a backend compatibility/read
 * operation. The main workspace uses the dedicated statistics, coverage,
 * matrix, tactic, platform and technique endpoints.
 *
 * The exact overview payload is intentionally not re-modeled here because
 * the dedicated endpoint contracts are the authoritative UI contracts.
 */
async function getOverview(): Promise<unknown> {
  return sharedApi.mitreOverview();
}


/* ============================================================================
 * Global Coverage
 * ========================================================================== */

/**
 * GET /api/v1/mitre/coverage
 */
async function getCoverage(): Promise<MitreCoverage> {
  return sharedApi.mitre();
}


/**
 * GET /api/v1/mitre/coverage/tactics
 *
 * Normalizes the backend collection into:
 *
 *   MitreTacticCoverage[]
 */
async function getTacticCoverage(): Promise<
  MitreTacticCoverage[]
> {
  const response =
    await sharedApi.mitreTacticCoverage();

  if (
    Array.isArray(response)
  ) {
    return response as MitreTacticCoverage[];
  }

  const record =
    asRecord(response);

  if (
    record &&
    Array.isArray(record.items)
  ) {
    return record.items as MitreTacticCoverage[];
  }

  return [];
}


/**
 * Paginated/normalized tactic coverage response.
 */
async function getTacticCoveragePage(): Promise<
  MitreTacticCoverage[]
> {
  return getTacticCoverage();
}


/* ============================================================================
 * Analytics
 * ========================================================================== */

/**
 * GET /api/v1/mitre/analytics
 */
async function getAnalytics(): Promise<MitreAnalytics> {
  return sharedApi.mitreAnalytics();
}


/* ============================================================================
 * Matrix
 * ========================================================================== */

/**
 * GET /api/v1/mitre/matrix
 *
 * Matrix construction belongs to the backend.
 */
async function getMatrix(): Promise<MitreMatrix> {
  return sharedApi.mitreMatrix();
}


/* ============================================================================
 * Tactics
 * ========================================================================== */

/**
 * GET /api/v1/mitre/tactics
 */
async function listTactics(): Promise<MitreTactic[]> {
  const response =
    await sharedApi.mitreTactics();

  if (
    Array.isArray(response)
  ) {
    return response as MitreTactic[];
  }

  const record =
    asRecord(response);

  if (
    record &&
    Array.isArray(record.items)
  ) {
    return record.items as MitreTactic[];
  }

  return [];
}


/**
 * GET /api/v1/mitre/tactics
 *
 * Collection response normalized into the module pagination contract.
 *
 * Note:
 *
 * The current shared transport exposes the complete tactic collection without
 * pagination arguments, so pagination here represents the returned
 * collection rather than client-side slicing.
 */
async function listTacticsPage(
  page = MITRE_DEFAULT_PAGE,
  pageSize = MITRE_DEFAULT_PAGE_SIZE,
): Promise<MitreTacticListResponse> {
  const normalizedPage =
    normalizePositiveInteger(
      page,
      MITRE_DEFAULT_PAGE,
    );

  const normalizedPageSize =
    normalizePositiveInteger(
      pageSize,
      MITRE_DEFAULT_PAGE_SIZE,
    );

  const response =
    await sharedApi.mitreTactics();

  return normalizePaginatedResponse<MitreTactic>(
    response,
    normalizedPage,
    normalizedPageSize,
  );
}


/* ============================================================================
 * Platforms
 * ========================================================================== */

/**
 * GET /api/v1/mitre/platforms
 */
async function listPlatforms(): Promise<MitrePlatform[]> {
  const response =
    await sharedApi.mitrePlatforms();

  if (
    Array.isArray(response)
  ) {
    return response as MitrePlatform[];
  }

  const record =
    asRecord(response);

  if (
    record &&
    Array.isArray(record.items)
  ) {
    return record.items as MitrePlatform[];
  }

  return [];
}


/**
 * GET /api/v1/mitre/platforms
 */
async function listPlatformsPage(
  page = MITRE_DEFAULT_PAGE,
  pageSize = MITRE_DEFAULT_PAGE_SIZE,
): Promise<MitrePlatformListResponse> {
  const normalizedPage =
    normalizePositiveInteger(
      page,
      MITRE_DEFAULT_PAGE,
    );

  const normalizedPageSize =
    normalizePositiveInteger(
      pageSize,
      MITRE_DEFAULT_PAGE_SIZE,
    );

  const response =
    await sharedApi.mitrePlatforms();

  return normalizePaginatedResponse<MitrePlatform>(
    response,
    normalizedPage,
    normalizedPageSize,
  );
}


/* ============================================================================
 * Techniques
 * ========================================================================== */

/**
 * GET /api/v1/mitre/techniques
 *
 * Backend-driven:
 *
 *   search
 *   tactic
 *   platform
 *   type
 *   coverage
 *   page
 *   page_size
 */
async function listTechniques(
  query: MitreTechniqueQuery = {},
): Promise<MitreTechniqueListResponse> {
  const normalizedQuery =
    normalizeTechniqueQuery(
      query,
    );

  const transportQuery =
    toSharedTechniqueQuery(
      normalizedQuery,
    );

  const response =
    await sharedApi.mitreTechniques(
      transportQuery,
    );

  return normalizePaginatedResponse<MitreTechnique>(
    response,
    normalizedQuery.page ??
      MITRE_DEFAULT_PAGE,
    normalizedQuery.page_size ??
      MITRE_DEFAULT_PAGE_SIZE,
  );
}


/**
 * Convenience wrapper for UI filter state.
 *
 * IMPORTANT:
 *
 * Filtering is backend-driven.
 *
 * No technique filtering is performed locally here.
 */
async function listFilteredTechniques(
  filters: MitreTechniqueFilters = {},
  page = MITRE_DEFAULT_PAGE,
  pageSize = MITRE_DEFAULT_PAGE_SIZE,
): Promise<MitreTechniqueListResponse> {
  return listTechniques({
    search:
      filters.search,

    tactic:
      filters.tactic,

    platform:
      filters.platform,

    type:
      filters.type,

    coverage:
      filters.coverage,

    page,

    page_size:
      pageSize,
  });
}


/**
 * GET /api/v1/mitre/techniques/{technique_id}
 */
async function getTechnique(
  techniqueId: string,
): Promise<MitreTechnique> {
  const normalizedId =
    requireIdentifier(
      techniqueId,
      "technique ID",
    );

  return sharedApi.mitreTechnique(
    normalizedId,
  ) as Promise<MitreTechnique>;
}


/* ============================================================================
 * Sub-Techniques
 * ========================================================================== */

/**
 * GET /api/v1/mitre/techniques/{technique_id}/sub-techniques
 */
async function listSubTechniques(
  techniqueId: string,
): Promise<MitreSubTechnique[]> {
  const normalizedId =
    requireIdentifier(
      techniqueId,
      "technique ID",
    );

  const response =
    await sharedApi.mitreSubTechniques(
      normalizedId,
    );

  if (
    Array.isArray(response)
  ) {
    return response as MitreSubTechnique[];
  }

  const record =
    asRecord(response);

  if (
    record &&
    Array.isArray(record.items)
  ) {
    return record.items as MitreSubTechnique[];
  }

  return [];
}


/**
 * GET /api/v1/mitre/techniques/{technique_id}/sub-techniques
 */
async function listSubTechniquesPage(
  techniqueId: string,
  page = MITRE_DEFAULT_PAGE,
  pageSize = MITRE_DEFAULT_PAGE_SIZE,
): Promise<MitreSubTechniqueListResponse> {
  const normalizedId =
    requireIdentifier(
      techniqueId,
      "technique ID",
    );

  const normalizedPage =
    normalizePositiveInteger(
      page,
      MITRE_DEFAULT_PAGE,
    );

  const normalizedPageSize =
    normalizePositiveInteger(
      pageSize,
      MITRE_DEFAULT_PAGE_SIZE,
    );

  const response =
    await sharedApi.mitreSubTechniques(
      normalizedId,
    );

  return normalizePaginatedResponse<MitreSubTechnique>(
    response,
    normalizedPage,
    normalizedPageSize,
  );
}


/* ============================================================================
 * Technique Detail
 * ========================================================================== */

/**
 * GET /api/v1/mitre/techniques/{technique_id}/detail
 */
async function getTechniqueDetail(
  techniqueId: string,
): Promise<MitreTechniqueDetail> {
  const normalizedId =
    requireIdentifier(
      techniqueId,
      "technique ID",
    );

  return sharedApi.mitreTechniqueDetail(
    normalizedId,
  );
}


/* ============================================================================
 * Technique Relationships
 * ========================================================================== */

/**
 * GET /api/v1/mitre/techniques/{technique_id}/relationships
 */
async function getTechniqueRelationships(
  techniqueId: string,
): Promise<MitreTechniqueRelationships> {
  const normalizedId =
    requireIdentifier(
      techniqueId,
      "technique ID",
    );

  return sharedApi.mitreTechniqueRelationships(
    normalizedId,
  );
}


/* ============================================================================
 * Technique Intelligence
 * ========================================================================== */

/**
 * GET /api/v1/mitre/techniques/{technique_id}/detections
 */
async function listTechniqueDetections(
  techniqueId: string,
): Promise<unknown> {
  const normalizedId =
    requireIdentifier(
      techniqueId,
      "technique ID",
    );

  return sharedApi.mitreTechniqueDetections(
    normalizedId,
  );
}


/**
 * GET /api/v1/mitre/techniques/{technique_id}/events
 */
async function listTechniqueEvents(
  techniqueId: string,
): Promise<unknown> {
  const normalizedId =
    requireIdentifier(
      techniqueId,
      "technique ID",
    );

  return sharedApi.mitreTechniqueEvents(
    normalizedId,
  );
}


/**
 * GET /api/v1/mitre/techniques/{technique_id}/alerts
 */
async function listTechniqueAlerts(
  techniqueId: string,
): Promise<unknown> {
  const normalizedId =
    requireIdentifier(
      techniqueId,
      "technique ID",
    );

  return sharedApi.mitreTechniqueAlerts(
    normalizedId,
  );
}


/**
 * GET /api/v1/mitre/techniques/{technique_id}/incidents
 */
async function listTechniqueIncidents(
  techniqueId: string,
): Promise<unknown> {
  const normalizedId =
    requireIdentifier(
      techniqueId,
      "technique ID",
    );

  return sharedApi.mitreTechniqueIncidents(
    normalizedId,
  );
}


/**
 * GET /api/v1/mitre/techniques/{technique_id}/iocs
 */
async function listTechniqueIocs(
  techniqueId: string,
): Promise<unknown> {
  const normalizedId =
    requireIdentifier(
      techniqueId,
      "technique ID",
    );

  return sharedApi.mitreTechniqueIocs(
    normalizedId,
  );
}


/* ============================================================================
 * Composite Workspace Operations
 * ========================================================================== */

/**
 * Load all primary data required by the MITRE main workspace.
 *
 * This does NOT load technique rows because technique rows are independently
 * paginated and filterable.
 */
async function getWorkspaceData(): Promise<{
  statistics: MitreStatistics;
  coverage: MitreCoverage;
  matrix: MitreMatrix;
  tactics: MitreTactic[];
  platforms: MitrePlatform[];
}> {
  const [
    statistics,
    coverage,
    matrix,
    tactics,
    platforms,
  ] = await Promise.all([
    getStatistics(),
    getCoverage(),
    getMatrix(),
    listTactics(),
    listPlatforms(),
  ]);

  return {
    statistics,
    coverage,
    matrix,
    tactics,
    platforms,
  };
}


/**
 * Load the core data required by a technique details page.
 *
 * Knowledge detail and relationship context remain separate backend
 * operations.
 */
async function getTechniqueWorkspace(
  techniqueId: string,
): Promise<{
  detail: MitreTechniqueDetail;
  relationships: MitreTechniqueRelationships;
}> {
  const normalizedId =
    requireIdentifier(
      techniqueId,
      "technique ID",
    );

  const [
    detail,
    relationships,
  ] = await Promise.all([
    getTechniqueDetail(
      normalizedId,
    ),

    getTechniqueRelationships(
      normalizedId,
    ),
  ]);

  return {
    detail,
    relationships,
  };
}


/**
 * Load SentinelSIEM intelligence associated with a technique.
 *
 * These are intentionally separate from MITRE knowledge.
 */
async function getTechniqueIntelligence(
  techniqueId: string,
): Promise<{
  detections: unknown;
  events: unknown;
  alerts: unknown;
  incidents: unknown;
  iocs: unknown;
}> {
  const normalizedId =
    requireIdentifier(
      techniqueId,
      "technique ID",
    );

  const [
    detections,
    events,
    alerts,
    incidents,
    iocs,
  ] = await Promise.all([
    listTechniqueDetections(
      normalizedId,
    ),

    listTechniqueEvents(
      normalizedId,
    ),

    listTechniqueAlerts(
      normalizedId,
    ),

    listTechniqueIncidents(
      normalizedId,
    ),

    listTechniqueIocs(
      normalizedId,
    ),
  ]);

  return {
    detections,
    events,
    alerts,
    incidents,
    iocs,
  };
}


/* ============================================================================
 * Public API
 * ========================================================================== */

export const mitreApi = {
  /* ------------------------------------------------------------------------
   * Overview
   * ---------------------------------------------------------------------- */

  getOverview,

  /* ------------------------------------------------------------------------
   * Statistics
   * ---------------------------------------------------------------------- */

  getStatistics,

  /* ------------------------------------------------------------------------
   * Coverage
   * ---------------------------------------------------------------------- */

  getCoverage,

  getTacticCoverage,

  getTacticCoveragePage,

  /* ------------------------------------------------------------------------
   * Analytics
   * ---------------------------------------------------------------------- */

  getAnalytics,

  /* ------------------------------------------------------------------------
   * Matrix
   * ---------------------------------------------------------------------- */

  getMatrix,

  /* ------------------------------------------------------------------------
   * Tactics
   * ---------------------------------------------------------------------- */

  listTactics,

  listTacticsPage,

  /* ------------------------------------------------------------------------
   * Platforms
   * ---------------------------------------------------------------------- */

  listPlatforms,

  listPlatformsPage,

  /* ------------------------------------------------------------------------
   * Techniques
   * ---------------------------------------------------------------------- */

  listTechniques,

  listFilteredTechniques,

  getTechnique,

  /* ------------------------------------------------------------------------
   * Sub-Techniques
   * ---------------------------------------------------------------------- */

  listSubTechniques,

  listSubTechniquesPage,

  /* ------------------------------------------------------------------------
   * Technique Detail
   * ---------------------------------------------------------------------- */

  getTechniqueDetail,

  /* ------------------------------------------------------------------------
   * Relationships
   * ---------------------------------------------------------------------- */

  getTechniqueRelationships,

  /* ------------------------------------------------------------------------
   * SentinelSIEM Intelligence
   * ---------------------------------------------------------------------- */

  listTechniqueDetections,

  listTechniqueEvents,

  listTechniqueAlerts,

  listTechniqueIncidents,

  listTechniqueIocs,

  /* ------------------------------------------------------------------------
   * Composite Operations
   * ---------------------------------------------------------------------- */

  getWorkspaceData,

  getTechniqueWorkspace,

  getTechniqueIntelligence,
} as const;


/* ============================================================================
 * Public API Type
 * ========================================================================== */

export type MitreApi =
  typeof mitreApi;


/* ============================================================================
 * Default Export
 * ========================================================================== */

export default mitreApi;


/* ============================================================================
 * End of File
 * ============================================================================
 */