/**
 * ============================================================================
 * SentinelSIEM — Threat Intelligence Module API
 * ============================================================================
 *
 * Feature-specific API boundary for Threat Intelligence.
 *
 * Architecture:
 *
 *   UI
 *     ↓
 *   threatIntelligenceApi
 *     ↓
 *   shared API transport
 *     ↓
 *   FastAPI
 *
 * Responsibilities:
 *
 *   - IOC inventory
 *   - IOC filtering
 *   - IOC details
 *   - IOC summary / KPI
 *   - IOC creation
 *   - IOC updates
 *   - IOC lifecycle actions
 *   - IOC matching
 *   - IOC relationships
 *
 * Backend contract:
 *
 *   GET    /api/v1/iocs
 *   GET    /api/v1/iocs/summary
 *   GET    /api/v1/iocs/filter-options
 *   GET    /api/v1/iocs/{ioc_id}
 *   GET    /api/v1/iocs/{ioc_id}/relationships
 *   POST   /api/v1/iocs
 *   PATCH  /api/v1/iocs/{ioc_id}
 *   POST   /api/v1/iocs/{ioc_id}/revoke
 *   POST   /api/v1/iocs/{ioc_id}/activate
 *   GET    /api/v1/iocs/match
 *
 * Lifecycle:
 *
 *   ACTIVE
 *      ↓
 *    REVOKE
 *      ↓
 *   REVOKED
 *
 *   REVOKED
 *      ↓
 *   ACTIVATE
 *      ↓
 *   ACTIVE
 *
 *   ACTIVE + expiration passed
 *      ↓
 *   EXPIRED
 *
 * IMPORTANT:
 *
 *   - Delete is intentionally NOT supported.
 *   - Generic update does NOT modify status.
 *   - Status changes use dedicated backend endpoints.
 *   - KPI values come from backend summary.
 *   - Filter catalogues come from backend filter-options.
 *   - Pagination remains backend-owned.
 *   - Detail response already contains relationships.
 *
 * ============================================================================
 */

import {
  api as sharedApi,
} from "../../services/api";

import type {
  IOC,
  IOCDetail,
  IOCFilterOptions,
  IOCListFilters,
  IOCListResponse,
  IOCMatch,
  IOCRelationshipResponse,
  IOCSummary,
  IOCCreateRequest,
  IOCUpdateRequest,
  IOCReputation,
  IOCSeverity,
  IOCStatus,
  IOCType,
} from "./types";

import type {
  IOCTransportResponse,
  IOCMatchTransportResponse,
  IOCRelationshipTransportResponse,
  IOCCreateTransportRequest,
  IOCUpdateTransportRequest,
  IOCListTransportParams,
  IOCSummaryTransportResponse,
} from "../../services/api";


/* ============================================================================
 * Constants
 * ========================================================================== */

const DEFAULT_PAGE = 1;

const DEFAULT_PAGE_SIZE = 30;


/* ============================================================================
 * Validation Helpers
 * ========================================================================== */

function requireNonEmpty(
  value: string,
  field: string,
): string {
  const normalized = value.trim();

  if (!normalized) {
    throw new Error(
      `${field} is required.`,
    );
  }

  return normalized;
}


function normalizeNumber(
  value: unknown,
  fallback = 0,
): number {
  if (
    typeof value !== "number" ||
    !Number.isFinite(value)
  ) {
    return fallback;
  }

  return value;
}


function normalizeString(
  value: unknown,
  fallback = "",
): string {
  if (typeof value === "string") {
    return value;
  }

  if (
    value === null ||
    value === undefined
  ) {
    return fallback;
  }

  return String(value);
}


function normalizeNullableString(
  value: unknown,
): string | null {
  if (
    value === null ||
    value === undefined
  ) {
    return null;
  }

  if (typeof value === "string") {
    return value;
  }

  return String(value);
}


function normalizeBoolean(
  value: unknown,
  fallback = false,
): boolean {
  if (typeof value === "boolean") {
    return value;
  }

  return fallback;
}


function normalizeStringArray(
  value: unknown,
): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .filter(
      (
        item,
      ): item is string =>
        typeof item === "string",
    )
    .map(
      (item) =>
        item.trim(),
    )
    .filter(Boolean);
}


function normalizeObject(
  value: unknown,
): Record<string, unknown> {
  if (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  ) {
    return {
      ...(
        value as Record<
          string,
          unknown
        >
      ),
    };
  }

  return {};
}


/* ============================================================================
 * IOC Field Normalization
 * ========================================================================== */

function normalizeIOCType(
  value: unknown,
): IOCType {
  return normalizeString(
    value,
    "",
  ) as IOCType;
}


function normalizeIOCSeverity(
  value: unknown,
): IOCSeverity {
  return normalizeString(
    value,
    "",
  ) as IOCSeverity;
}


function normalizeIOCStatus(
  value: unknown,
): IOCStatus {
  return normalizeString(
    value,
    "",
  ) as IOCStatus;
}


function normalizeIOCReputation(
  value: unknown,
): IOCReputation {
  return normalizeString(
    value,
    "",
  ) as IOCReputation;
}


/* ============================================================================
 * Transport Types
 * ========================================================================== */

type CompatibleIOCTransport =
  IOCTransportResponse & {
    id?: unknown;
    type?: unknown;
    indicator?: unknown;
  };


type CompatibleIOCMatchTransport =
  IOCMatchTransportResponse & {
    id?: unknown;
    type?: unknown;
    indicator?: unknown;
  };


type CompatibleIOCRelationshipTransport =
  IOCRelationshipTransportResponse & {
    id?: unknown;
  };


/* ============================================================================
 * IOC Field Resolution
 * ========================================================================== */

function resolveIOCId(
  raw: CompatibleIOCTransport,
): string {
  const id =
    normalizeString(
      raw.id ??
        raw.ioc_id,
    );

  if (!id) {
    throw new Error(
      "IOC response is missing IOC ID.",
    );
  }

  return id;
}


function resolveIOCType(
  raw: CompatibleIOCTransport,
): IOCType {
  return normalizeIOCType(
    raw.type ??
      raw.ioc_type,
  );
}


function resolveIOCIndicator(
  raw: CompatibleIOCTransport,
): string {
  return normalizeString(
    raw.indicator ??
      raw.value,
  );
}


/* ============================================================================
 * IOC Normalization
 * ========================================================================== */

function normalizeIOC(
  raw: IOCTransportResponse,
): IOC {
  const compatible =
    raw as CompatibleIOCTransport;

  const status =
    normalizeIOCStatus(
      compatible.status,
    );

  const active =
    compatible.active !== undefined
      ? normalizeBoolean(
          compatible.active,
        )
      : status === "active";

  return {
    id:
      resolveIOCId(
        compatible,
      ),

    indicator:
      resolveIOCIndicator(
        compatible,
      ),

    type:
      resolveIOCType(
        compatible,
      ),

    value:
      normalizeString(
        compatible.value,
      ),

    confidence:
      normalizeNumber(
        compatible.confidence,
      ),

    severity:
      normalizeIOCSeverity(
        compatible.severity,
      ),

    status,

    source:
      normalizeNullableString(
        compatible.source,
      ),

    feed:
      normalizeNullableString(
        compatible.feed,
      ),

    reputation:
      normalizeIOCReputation(
        compatible.reputation,
      ),

    description:
      normalizeString(
        compatible.description,
      ),

    tags:
      normalizeStringArray(
        compatible.tags,
      ),

    active,

    first_seen:
      normalizeString(
        compatible.first_seen,
      ),

    last_seen:
      normalizeString(
        compatible.last_seen,
      ),

    expiration:
      normalizeNullableString(
        compatible.expiration,
      ),

    created_at:
      normalizeNullableString(
        compatible.created_at,
      ),

    updated_at:
      normalizeNullableString(
        compatible.updated_at,
      ),

    metadata:
      normalizeObject(
        compatible.metadata,
      ),
  };
}


/* ============================================================================
 * IOC Match Normalization
 * ========================================================================== */

function normalizeIOCMatch(
  raw: IOCMatchTransportResponse,
): IOCMatch {
  const compatible =
    raw as CompatibleIOCMatchTransport;

  const id =
    normalizeString(
      compatible.id ??
        compatible.ioc_id,
    );

  if (!id) {
    throw new Error(
      "IOC match response is missing IOC ID.",
    );
  }

  return {
    id,

    indicator:
      normalizeString(
        compatible.indicator ??
          compatible.value,
      ),

    type:
      normalizeIOCType(
        compatible.type ??
          compatible.ioc_type,
      ),

    value:
      normalizeString(
        compatible.value,
      ),

    matched:
      compatible.matched === undefined
        ? true
        : Boolean(
            compatible.matched,
          ),

    confidence:
      normalizeNumber(
        compatible.confidence,
      ),

    severity:
      normalizeIOCSeverity(
        compatible.severity,
      ),

    status:
      normalizeIOCStatus(
        compatible.status,
      ),

    reputation:
      normalizeIOCReputation(
        compatible.reputation,
      ),

    source:
      normalizeNullableString(
        compatible.source,
      ),

    feed:
      normalizeNullableString(
        compatible.feed,
      ),

    tags:
      normalizeStringArray(
        compatible.tags,
      ),

    metadata:
      normalizeObject(
        compatible.metadata,
      ),
  };
}


/* ============================================================================
 * IOC Relationship Normalization
 * ========================================================================== */

function normalizeIOCRelationships(
  raw: IOCRelationshipTransportResponse,
): IOCRelationshipResponse {
  const compatible =
    raw as CompatibleIOCRelationshipTransport;

  const iocId =
    normalizeString(
      compatible.ioc_id ??
        compatible.id,
    );

  if (!iocId) {
    throw new Error(
      "IOC relationship response is missing IOC ID.",
    );
  }

  return {
    ioc_id: iocId,

    event_ids:
      normalizeStringArray(
        compatible.event_ids,
      ),

    alert_ids:
      normalizeStringArray(
        compatible.alert_ids,
      ),

    incident_ids:
      normalizeStringArray(
        compatible.incident_ids,
      ),

    asset_ids:
      normalizeStringArray(
        compatible.asset_ids,
      ),

    mitre_technique_ids:
      normalizeStringArray(
        compatible.mitre_technique_ids,
      ),

    event_count:
      normalizeNumber(
        compatible.event_count,
      ),

    alert_count:
      normalizeNumber(
        compatible.alert_count,
      ),

    incident_count:
      normalizeNumber(
        compatible.incident_count,
      ),

    asset_count:
      normalizeNumber(
        compatible.asset_count,
      ),

    mitre_technique_count:
      normalizeNumber(
        compatible.mitre_technique_count,
      ),
  };
}


/* ============================================================================
 * Pagination Normalization
 * ========================================================================== */

interface RawIOCListResponse {
  items?: unknown;

  pagination?: {
    page?: unknown;
    page_size?: unknown;
    total?: unknown;
    total_pages?: unknown;
  };

  total?: unknown;

  page?: unknown;

  page_size?: unknown;

  total_pages?: unknown;
}


function normalizeIOCListResponse(
  raw: RawIOCListResponse,
): IOCListResponse {
  const rawItems =
    Array.isArray(
      raw.items,
    )
      ? raw.items
      : [];

  const items =
    rawItems
      .filter(
        (
          item,
        ): item is IOCTransportResponse =>
          typeof item === "object" &&
          item !== null &&
          !Array.isArray(item),
      )
      .map(
        normalizeIOC,
      );

  const rawPagination =
    raw.pagination ?? raw;

  const total =
    normalizeNumber(
      rawPagination?.total ??
        raw.total,
      items.length,
    );

  const page =
    Math.max(
      1,
      Math.floor(
        normalizeNumber(
          rawPagination?.page ??
            raw.page,
          DEFAULT_PAGE,
        ),
      ),
    );

  const pageSize =
    Math.max(
      1,
      Math.floor(
        normalizeNumber(
          rawPagination?.page_size ??
            raw.page_size,
          DEFAULT_PAGE_SIZE,
        ),
      ),
    );

  const totalPages =
    Math.max(
      0,
      Math.floor(
        normalizeNumber(
          rawPagination?.total_pages,
          0,
        ),
      ),
    );

  return {
    items,

    pagination: {
      page,

      page_size:
        pageSize,

      total,
      total_pages:
        totalPages,
    },
  };
}


/* ============================================================================
 * Summary / KPI Normalization
 * ========================================================================== */

function normalizeIOCCountMap(
  value: unknown,
): Record<string, number> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value)
  ) {
    return {};
  }

  const result:
    Record<string, number> = {};

  for (
    const [
      key,
      count,
    ] of Object.entries(
      value as Record<
        string,
        unknown
      >,
    )
  ) {
    result[key] =
      normalizeNumber(
        count,
      );
  }

  return result;
}


function normalizeIOCSummary(
  raw: IOCSummaryTransportResponse,
): IOCSummary {
  const compatible =
    raw as IOCSummaryTransportResponse & {
      total?: unknown;
      total_iocs?: unknown;
    };

  /*
   * Current backend field:
   *
   *   total
   *
   * `total_iocs` is accepted only as a transport compatibility fallback
   * for older responses. The domain model remains `total`.
   */
  const total =
    normalizeNumber(
      compatible.total ??
        compatible.total_iocs,
    );

  return {
    total,

    malicious:
      normalizeNumber(
        raw.malicious,
      ),

    high_risk:
      normalizeNumber(
        raw.high_risk,
      ),

    recently_updated:
      normalizeNumber(
        raw.recently_updated,
      ),

    active:
      normalizeNumber(
        raw.active,
      ),

    expired:
      normalizeNumber(
        raw.expired,
      ),

    revoked:
      normalizeNumber(
        raw.revoked,
      ),

    by_type:
      normalizeIOCCountMap(
        raw.by_type,
      ),

    by_source:
      normalizeIOCCountMap(
        raw.by_source,
      ),

    by_severity:
      normalizeIOCCountMap(
        raw.by_severity,
      ),

    by_status:
      normalizeIOCCountMap(
        raw.by_status,
      ),

    by_reputation:
      normalizeIOCCountMap(
        raw.by_reputation,
      ),
  };
}


/* ============================================================================
 * Request Mapping
 * ========================================================================== */

/**
 * UI:
 *
 *   value
 *
 * Backend transport:
 *
 *   indicator
 *
 * Status is deliberately omitted.
 */
function normalizeExpiration(
  value: string | null | undefined,
): string | null | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (value === null || !value.trim()) {
    return null;
  }

  const trimmed = value.trim();
  const date = new Date(trimmed);

  if (Number.isNaN(date.getTime())) {
    throw new Error(
      "Invalid IOC expiration date/time.",
    );
  }

  return date.toISOString();
}


function toTransportCreateRequest(
  payload: IOCCreateRequest,
): IOCCreateTransportRequest {
  const value = requireNonEmpty(
    payload.value,
    "IOC value",
  );

  const type = requireNonEmpty(
    payload.type,
    "IOC type",
  );

  const sourceValue =
    payload.source?.trim() ?? "";

  const source = requireNonEmpty(
    sourceValue,
    "IOC source",
  );

  return {
    value,
    type,
    source,

    confidence:
      payload.confidence,

    severity:
      payload.severity,

    feed:
      payload.feed?.trim()
        ? payload.feed.trim()
        : undefined,

    reputation:
      payload.reputation,

    expiration:
      normalizeExpiration(
        payload.expiration,
      ),

    description:
      payload.description?.trim()
        ? payload.description.trim()
        : undefined,

    tags:
      payload.tags ?? [],

    metadata:
      payload.metadata ?? undefined,

    relationships:
      payload.relationships,
  };
}


/**
 * Generic update.
 *
 * Status is deliberately omitted.
 */
function toTransportUpdateRequest(
  payload: IOCUpdateRequest,
): IOCUpdateTransportRequest {
  return {
    value:
      payload.value?.trim()
        ? payload.value.trim()
        : undefined,
    confidence:
      payload.confidence,

    severity:
      payload.severity,

    source:
      payload.source?.trim()
        ? payload.source.trim()
        : undefined,

    feed:
      payload.feed?.trim()
        ? payload.feed.trim()
        : undefined,

    reputation:
      payload.reputation,

    expiration:
      normalizeExpiration(
        payload.expiration,
      ),

    description:
      payload.description?.trim()
        ? payload.description.trim()
        : undefined,

    tags:
      payload.tags
        ?.map(
          (tag) =>
            tag.trim(),
        )
        .filter(Boolean),

    metadata:
      payload.metadata,

    relationships:
      payload.relationships,
  };
}


/**
 * Convert UI filters to backend transport parameters.
 */
function toTransportListParams(
  params: IOCListFilters = {},
): IOCListTransportParams {
  const search =
    params.search?.trim()
      ? params.search.trim()
      : undefined;

  const query =
    params.query?.trim()
      ? params.query.trim()
      : search;

  return {
    query,

    search,

    type:
      params.type,

    severity:
      params.severity,

    status:
      params.status,

    source:
      params.source?.trim()
        ? params.source.trim()
        : undefined,

    reputation:
      params.reputation,

    active:
      params.active,

    start_time:
      params.start_time?.trim()
        ? params.start_time.trim()
        : undefined,

    end_time:
      params.end_time?.trim()
        ? params.end_time.trim()
        : undefined,

    page:
      params.page,

    page_size:
      params.page_size,
  };
}


/* ============================================================================
 * Filter Options Normalization
 * ========================================================================== */

/**
 * The backend's authoritative filter-options response is:
 *
 * {
 *   types: string[],
 *   severities: string[],
 *   statuses: string[],
 *   sources: string[],
 *   reputations: string[]
 * }
 *
 * No frontend catalogue is created here.
 */
function normalizeIOCFilterOptions(
  raw: unknown,
): IOCFilterOptions {
  if (
    typeof raw !== "object" ||
    raw === null ||
    Array.isArray(raw)
  ) {
    return {
      types: [],
      severities: [],
      statuses: [],
      sources: [],
      reputations: [],
    };
  }

  const record =
    raw as Record<
      string,
      unknown
    >;

  return {
    types:
      normalizeStringArray(
        record.types,
      ),

    severities:
      normalizeStringArray(
        record.severities,
      ),

    statuses:
      normalizeStringArray(
        record.statuses,
      ),

    sources:
      normalizeStringArray(
        record.sources,
      ),

    reputations:
      normalizeStringArray(
        record.reputations,
      ),
  };
}


/* ============================================================================
 * API Object
 * ========================================================================== */

export const threatIntelligenceApi = {

  /* --------------------------------------------------------------------------
   * IOC Inventory
   * ------------------------------------------------------------------------ */

  async list(
    page = DEFAULT_PAGE,
    pageSize = DEFAULT_PAGE_SIZE,
  ): Promise<IOCListResponse> {
    const raw =
      await sharedApi.iocs(
        page,
        pageSize,
      );

    return normalizeIOCListResponse(
      raw as RawIOCListResponse,
    );
  },


  /* --------------------------------------------------------------------------
   * Filtered IOC Inventory
   * ------------------------------------------------------------------------ */

  async listWithFilters(
    params: IOCListFilters = {},
  ): Promise<IOCListResponse> {
    const raw =
      await sharedApi.iocsWithFilters(
        toTransportListParams(
          params,
        ),
      );

    return normalizeIOCListResponse(
      raw as RawIOCListResponse,
    );
  },


  /* --------------------------------------------------------------------------
   * IOC Details
   * ------------------------------------------------------------------------ */

  async get(
    iocId: string,
  ): Promise<IOC> {
    const id =
      requireNonEmpty(
        iocId,
        "IOC ID",
      );

    const raw =
      await sharedApi.getIOC(
        id,
      );

    return normalizeIOC(
      raw,
    );
  },


  /* --------------------------------------------------------------------------
   * IOC Detail
   * ------------------------------------------------------------------------ */

  async getDetail(
    iocId: string,
  ): Promise<IOCDetail> {
    const id =
      requireNonEmpty(
        iocId,
        "IOC ID",
      );

    /*
     * The backend detail endpoint already returns:
     *
     *   IOC fields
     *   +
     *   relationships
     *
     * Therefore this method intentionally performs ONE request.
     */

    const raw =
      await sharedApi.getIOC(
        id,
      );

    const normalized =
      normalizeIOC(
        raw,
      );

    const compatible =
      raw as IOCTransportResponse & {
        relationships?: unknown;
      };

    const rawRelationships =
      compatible.relationships;

    /*
     * Safe fallback for older records/responses that may not contain
     * relationships directly.
     */
    if (
      !rawRelationships ||
      typeof rawRelationships !== "object" ||
      Array.isArray(rawRelationships)
    ) {
      return {
        ...normalized,

        relationships: {


          event_ids: [],

          alert_ids: [],

          incident_ids: [],

          asset_ids: [],

          mitre_technique_ids: [],

          event_count: 0,

          alert_count: 0,

          incident_count: 0,

          asset_count: 0,

          mitre_technique_count: 0,
        },
      };
    }

    const relationships =
      normalizeIOCRelationships(
        {
          ...(
            rawRelationships as Record<
              string,
              unknown
            >
          ),

          ioc_id: id,
        } as IOCRelationshipTransportResponse,
      );

    return {
      ...normalized,

      relationships,
    };
  },


  /* --------------------------------------------------------------------------
   * IOC Summary / KPI
   * ------------------------------------------------------------------------ */

  async summary(): Promise<IOCSummary> {
    const raw =
      await sharedApi.getIOCSummary();

    return normalizeIOCSummary(
      raw,
    );
  },


  /* --------------------------------------------------------------------------
   * Backend Filter Options
   * ------------------------------------------------------------------------ */

  async filterOptions(): Promise<IOCFilterOptions> {
    /*
     * This method requires the shared API transport to expose:
     *
     *   getIOCFilterOptions()
     *
     * The backend endpoint is:
     *
     *   GET /api/v1/iocs/filter-options
     *
     * Do not derive these values from IOC inventory or summary because those
     * are data-driven and can omit valid catalogue values.
     */

    const raw =
      await sharedApi.getIOCFilterOptions();

    return normalizeIOCFilterOptions(
      raw,
    );
  },


  /* --------------------------------------------------------------------------
   * Create IOC
   * ------------------------------------------------------------------------ */

  async create(
    payload: IOCCreateRequest,
  ): Promise<IOC> {
    const raw =
      await sharedApi.createIOC(
        toTransportCreateRequest(
          payload,
        ),
      );

    return normalizeIOC(
      raw,
    );
  },


  /* --------------------------------------------------------------------------
   * Update IOC
   * ------------------------------------------------------------------------ */

  async update(
    iocId: string,
    payload: IOCUpdateRequest,
  ): Promise<IOC> {
    const id =
      requireNonEmpty(
        iocId,
        "IOC ID",
      );

    const raw =
      await sharedApi.updateIOC(
        id,
        toTransportUpdateRequest(
          payload,
        ),
      );

    return normalizeIOC(
      raw,
    );
  },


  /* --------------------------------------------------------------------------
   * Revoke IOC
   * ------------------------------------------------------------------------ */

  async revoke(
    iocId: string,
  ): Promise<IOC> {
    const id =
      requireNonEmpty(
        iocId,
        "IOC ID",
      );

    const raw =
      await sharedApi.revokeIOC(
        id,
      );

    return normalizeIOC(
      raw,
    );
  },


  /* --------------------------------------------------------------------------
   * Activate IOC
   * ------------------------------------------------------------------------ */

  async activate(
    iocId: string,
  ): Promise<IOC> {
    const id =
      requireNonEmpty(
        iocId,
        "IOC ID",
      );

    const raw =
      await sharedApi.activateIOC(
        id,
      );

    return normalizeIOC(
      raw,
    );
  },


  /* --------------------------------------------------------------------------
   * IOC Matching
   * ------------------------------------------------------------------------ */

  async match(
    observable: string,
  ): Promise<IOCMatch[]> {
    const value =
      requireNonEmpty(
        observable,
        "Observable",
      );

    const raw =
      await sharedApi.matchIOC(
        value,
      );

    return raw.map(
      normalizeIOCMatch,
    );
  },


  /* --------------------------------------------------------------------------
   * Dedicated Relationships
   * ------------------------------------------------------------------------ */

  async relationships(
    iocId: string,
  ): Promise<IOCRelationshipResponse> {
    const id =
      requireNonEmpty(
        iocId,
        "IOC ID",
      );

    const raw =
      await sharedApi.getIOCRelationships(
        id,
      );

    return normalizeIOCRelationships(
      raw,
    );
  },
};


/* ============================================================================
 * Named API Functions
 * ========================================================================== */

export function listIOCs(
  page = DEFAULT_PAGE,
  pageSize = DEFAULT_PAGE_SIZE,
): Promise<IOCListResponse> {
  return threatIntelligenceApi.list(
    page,
    pageSize,
  );
}


export function listIOCsWithFilters(
  params: IOCListFilters = {},
): Promise<IOCListResponse> {
  return threatIntelligenceApi.listWithFilters(
    params,
  );
}


export function getIOC(
  iocId: string,
): Promise<IOC> {
  return threatIntelligenceApi.get(
    iocId,
  );
}


export function getIOCDetail(
  iocId: string,
): Promise<IOCDetail> {
  return threatIntelligenceApi.getDetail(
    iocId,
  );
}


export function getIOCSummary(): Promise<IOCSummary> {
  return threatIntelligenceApi.summary();
}


export function getIOCFilterOptions(): Promise<IOCFilterOptions> {
  return threatIntelligenceApi.filterOptions();
}


export function createIOC(
  payload: IOCCreateRequest,
): Promise<IOC> {
  return threatIntelligenceApi.create(
    payload,
  );
}


export function updateIOC(
  iocId: string,
  payload: IOCUpdateRequest,
): Promise<IOC> {
  return threatIntelligenceApi.update(
    iocId,
    payload,
  );
}


export function revokeIOC(
  iocId: string,
): Promise<IOC> {
  return threatIntelligenceApi.revoke(
    iocId,
  );
}


export function activateIOC(
  iocId: string,
): Promise<IOC> {
  return threatIntelligenceApi.activate(
    iocId,
  );
}


export function matchIOC(
  observable: string,
): Promise<IOCMatch[]> {
  return threatIntelligenceApi.match(
    observable,
  );
}


export function getIOCRelationships(
  iocId: string,
): Promise<IOCRelationshipResponse> {
  return threatIntelligenceApi.relationships(
    iocId,
  );
}


/* ============================================================================
 * Default Export
 * ========================================================================== */

export default threatIntelligenceApi;


/* ============================================================================
 * End of File
 * ========================================================================== */
