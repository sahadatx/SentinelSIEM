/**
 * ============================================================================
 * SentinelSIEM — Central API Client
 * ============================================================================
 *
 * Single frontend transport layer.
 *
 * Responsibilities:
 *   - Authenticated HTTP transport
 *   - Centralized API error handling
 *   - Authentication lifecycle
 *   - Events
 *   - Alerts
 *   - Incidents
 *   - Global Audit
 *   - User Management
 *   - Threat Intelligence
 *   - Detection
 *   - MITRE ATT&CK
 *   - Assets
 *   - Health / System
 *
 * Security:
 *   - Backend remains authoritative for authorization.
 *   - 401 clears authentication.
 *   - 403 NEVER clears authentication.
 *   - Credentials are never logged.
 *
 * ============================================================================
 */

import type {
  HealthResponse,
  LoginResponse,
  PaginatedResponse,
  SecurityEvent,
  SystemResponse,
} from "../types/api";

import type {
  Asset,
  AssetCreateRequest,
  AssetListParams,
  AssetListResponse,
  AssetStatisticsResponse,
  AssetStatusUpdateRequest,
  AssetUpdateRequest,
} from "../modules/assets/types";

import type {
  Alert,
  AlertAssignmentRequest,
  AlertAuditEntry,
  AlertFilterOptions,
  AlertListParams,
  AlertStatistics,
  AlertTransitionRequest,
} from "../modules/alerts/types";

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
} from "../modules/detections/types";

import type {
  Incident,
  IncidentAuditEntry,
  IncidentAssignmentRequest,
  IncidentCreateRequest,
  IncidentDetail,
  IncidentEvidence,
  IncidentEvidenceCreateRequest,
  IncidentFilterOptions,
  IncidentListFilters,
  IncidentRelatedAlert,
  IncidentStatistics,
  IncidentListResponse,
  IncidentNote,
  IncidentNoteCreateRequest,
  IncidentTimelineEntry,
  IncidentUpdateRequest,
  IncidentTransitionRequest,
} from "../modules/incidents/types";

import type {
  AuditEvent,
  AuditExportParams,
  AuditExportResponse,
  AuditListParams,
  AuditListResponse,
  AuditRelatedEventListResponse,
  AuditStatistics,
  AuditStatisticsParams,
} from "../modules/audit/types";

import type {
  ChangeRoleRequest,
  CreateUserRequest,
  DeleteUserResponse,
  RevokeSessionsResponse,
  ResetPasswordRequest,
  ResetPasswordResponse,
  SetActiveRequest,
  SetForcePasswordChangeRequest,
  SetLockedRequest,
  UpdateUserRequest,
  User,
  UserAuditListResponse,
  UserListParams,
  UserListResponse,
  UserStatistics,
} from "../modules/users/types";

import type {
  EventFilterOptions,
  EventStatisticsResponse,
} from "../modules/events/types";

import type {
  MitreAnalytics,
  MitreCoverage,
  MitreMatrix,
  MitrePlatformListResponse,
  MitreStatistics,
  MitreSubTechniqueListResponse,
  MitreTacticCoverageListResponse,
  MitreTacticListResponse,
  MitreTechnique,
  MitreTechniqueDetail,
  MitreTechniqueListResponse,
  MitreTechniqueQuery,
  MitreTechniqueRelationships,
  MitreMapping,
} from "../modules/mitre/types";

import {
  useAuthStore,
} from "../store/auth";


/* ============================================================================
 * Configuration
 * ========================================================================== */

const API_BASE_URL =
  (
    import.meta.env
      .VITE_API_BASE_URL as
      | string
      | undefined
  )?.trim() || "";


/* ============================================================================
 * Limits
 * ========================================================================== */

const DEFAULT_PAGE = 1;

const DEFAULT_PAGE_SIZE = 100;

const MAX_PAGE_SIZE = 1000;

const INCIDENT_MAX_PAGE_SIZE = 200;

const INCIDENT_DEFAULT_PAGE_SIZE = 50;

const USER_MAX_LIMIT = 200;

const AUDIT_MAX_PAGE_SIZE = 200;

const AUDIT_DEFAULT_PAGE_SIZE = 50;

const AUDIT_MAX_EXPORT_SIZE = 50_000;

const AUDIT_DEFAULT_EXPORT_SIZE = 10_000;


/* ============================================================================
 * Authentication Types
 * ========================================================================== */

export interface AuthUser {
  user_id: string;
  username: string;
  roles: string[];
  permissions: string[];
  session_id: string;
}


export interface ApiLoginResponse {
  access_token: string;
  token_type: string;
  user: AuthUser;
}


/* ============================================================================
 * Threat Intelligence Transport Types
 * ========================================================================== */

export interface IOCTransportResponse {
  ioc_id: string;
  ioc_type: string;
  value: string;
  confidence: number;
  severity?: string;
  status: string;
  reputation: string;
  source: string | null;
  feed: string | null;
  description?: string;
  tags?: string[];
  active?: boolean;
  first_seen: string;
  last_seen: string;
  expiration: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  metadata: Record<string, unknown>;
}


export interface IOCMatchTransportResponse {
  ioc_id: string;
  ioc_type: string;
  value: string;
  matched?: boolean;
  confidence: number;
  severity?: string;
  status?: string;
  reputation: string;
  source?: string | null;
  feed?: string | null;
  tags?: string[];
  metadata?: Record<string, unknown>;
}


export interface IOCRelationshipTransportResponse {
  ioc_id: string;

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


export interface IOCCreateTransportRequest {
  value: string;
  type: string;
  source: string;

  confidence?: number;
  severity?: string;
  feed?: string;
  reputation?: string;

  expiration?: string | null;

  description?: string;

  tags?: string[];

  metadata?: Record<string, unknown>;

  relationships?: Partial<
    IOCRelationshipTransportResponse
  >;
}


export interface IOCUpdateTransportRequest {
  value?: string;

  confidence?: number;
  severity?: string;
  source?: string;
  feed?: string;
  reputation?: string;

  expiration?: string | null;

  description?: string;

  tags?: string[];

  metadata?: Record<string, unknown>;

  relationships?: Partial<
    IOCRelationshipTransportResponse
  >;
}


export interface IOCListTransportParams {
  query?: string;
  search?: string;

  type?: string;
  severity?: string;
  status?: string;
  source?: string;
  reputation?: string;

  active?: boolean;

  start_time?: string;
  end_time?: string;

  page?: number;
  page_size?: number;
}


export interface IOCSummaryTransportResponse {
  total_iocs: number;
  malicious: number;
  high_risk: number;
  recently_updated: number;

  active: number;
  expired: number;
  revoked: number;

  by_type: Record<string, number>;
  by_source: Record<string, number>;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  by_reputation: Record<string, number>;
}


/* ============================================================================
 * API Error
 * ========================================================================== */

export class ApiError extends Error {
  readonly status: number;

  readonly detail: string;

  constructor(
    status: number,
    detail: string,
  ) {
    super(detail);

    this.name = "ApiError";

    this.status = status;

    this.detail = detail;

    Object.setPrototypeOf(
      this,
      ApiError.prototype,
    );
  }
}


/* ============================================================================
 * Generic Helpers
 * ========================================================================== */

function normalizePositiveInteger(
  value: unknown,
  fallback: number,
): number {
  if (
    typeof value !== "number" ||
    !Number.isFinite(value)
  ) {
    return fallback;
  }

  return Math.max(
    1,
    Math.floor(value),
  );
}


function normalizeNonNegativeInteger(
  value: unknown,
): number {
  if (
    typeof value !== "number" ||
    !Number.isFinite(value)
  ) {
    return 0;
  }

  return Math.max(
    0,
    Math.floor(value),
  );
}


function normalizeBoundedInteger(
  value: unknown,
  minimum: number,
  maximum: number,
  fallback: number,
): number {
  if (
    typeof value !== "number" ||
    !Number.isFinite(value)
  ) {
    return fallback;
  }

  return Math.min(
    maximum,
    Math.max(
      minimum,
      Math.floor(value),
    ),
  );
}


function requireId(
  value: string,
  fieldName: string,
): string {
  const normalized =
    value.trim();

  if (!normalized) {
    throw new Error(
      `${fieldName} cannot be empty.`,
    );
  }

  return normalized;
}


function stringOrNull(
  value: unknown,
): string | null {
  if (
    typeof value === "string"
  ) {
    return value;
  }

  if (
    value === null ||
    value === undefined
  ) {
    return null;
  }

  return String(value);
}


function buildUrl(
  path: string,
): string {
  if (!API_BASE_URL) {
    return path;
  }

  return `${API_BASE_URL.replace(
    /\/+$/,
    "",
  )}/${path.replace(
    /^\/+/,
    "",
  )}`;
}


/* ============================================================================
 * API Error Parser
 * ========================================================================== */

async function createApiError(
  response: Response,
): Promise<ApiError> {
  let detail =
    `Request failed with status ${response.status}.`;

  try {
    const text =
      await response.text();

    if (!text.trim()) {
      return new ApiError(
        response.status,
        detail,
      );
    }

    let body: unknown;

    try {
      body =
        JSON.parse(text);
    } catch {
      return new ApiError(
        response.status,
        text.trim(),
      );
    }

    if (
      typeof body !== "object" ||
      body === null
    ) {
      return new ApiError(
        response.status,
        detail,
      );
    }

    const record =
      body as Record<
        string,
        unknown
      >;

    if (
      typeof record.detail === "string" &&
      record.detail.trim()
    ) {
      detail =
        record.detail.trim();
    } else if (
      typeof record.message === "string" &&
      record.message.trim()
    ) {
      detail =
        record.message.trim();
    } else if (
      Array.isArray(
        record.detail,
      )
    ) {
      detail =
        record.detail
          .map(
            (item) => {
              if (
                typeof item ===
                  "object" &&
                item !== null &&
                "msg" in item
              ) {
                return String(
                  (
                    item as Record<
                      string,
                      unknown
                    >
                  ).msg,
                );
              }

              return String(item);
            },
          )
          .join("; ");
    }
  } catch {
    /*
     * Keep default HTTP error.
     */
  }

  return new ApiError(
    response.status,
    detail,
  );
}


/* ============================================================================
 * JSON Response Parser
 * ========================================================================== */

async function parseJsonResponse<T>(
  response: Response,
): Promise<T> {
  if (
    response.status === 204
  ) {
    return undefined as T;
  }

  const text =
    await response.text();

  if (!text.trim()) {
    return undefined as T;
  }

  try {
    return JSON.parse(
      text,
    ) as T;
  } catch {
    throw new ApiError(
      response.status,
      "The server returned an invalid JSON response.",
    );
  }
}


/* ============================================================================
 * Request
 * ========================================================================== */

async function request<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const token =
    useAuthStore
      .getState()
      .accessToken;

  const headers =
    new Headers(
      init?.headers,
    );

  headers.set(
    "Accept",
    "application/json",
  );

  if (
    token
  ) {
    headers.set(
      "Authorization",
      `Bearer ${token}`,
    );
  }

  let response: Response;

  try {
    response =
      await fetch(
        buildUrl(path),
        {
          ...init,
          headers,
        },
      );
  } catch (error) {
    throw new ApiError(
      0,
      error instanceof Error
        ? error.message
        : "Network request failed.",
    );
  }

  if (
    !response.ok
  ) {
    const error =
      await createApiError(
        response,
      );

    if (
      response.status === 401
    ) {
      useAuthStore
        .getState()
        .clearAuthentication();
    }

    throw error;
  }

  return parseJsonResponse<T>(
    response,
  );
}


/* ============================================================================
 * Request With Explicit Token
 * ========================================================================== */

async function requestWithToken<T>(
  path: string,
  accessToken: string,
  init?: RequestInit,
): Promise<T> {
  const token =
    accessToken.trim();

  if (!token) {
    throw new Error(
      "Access token cannot be empty.",
    );
  }

  const headers =
    new Headers(
      init?.headers,
    );

  headers.set(
    "Accept",
    "application/json",
  );

  headers.set(
    "Authorization",
    `Bearer ${token}`,
  );

  let response: Response;

  try {
    response =
      await fetch(
        buildUrl(path),
        {
          ...init,
          headers,
        },
      );
  } catch (error) {
    throw new ApiError(
      0,
      error instanceof Error
        ? error.message
        : "Network request failed.",
    );
  }

  if (
    !response.ok
  ) {
    throw await createApiError(
      response,
    );
  }

  return parseJsonResponse<T>(
    response,
  );
}


/* ============================================================================
 * Events
 * ========================================================================== */

export interface EventListParams {
  query?: string;
  source?: string;
  source_ip?: string;
  destination_ip?: string;
  username?: string;
  action?: string;
  outcome?: string;
  severity?: string;
  category?: string;
  start_time?: string;
  end_time?: string;
  page?: number;
  page_size?: number;
}


function eventsPath(
  params: EventListParams = {},
): string {
  const query =
    new URLSearchParams();

  const stringFields: Array<
    [
      string,
      string | undefined,
    ]
  > = [
    ["query", params.query],
    ["source", params.source],
    ["source_ip", params.source_ip],
    ["destination_ip", params.destination_ip],
    ["username", params.username],
    ["action", params.action],
    ["outcome", params.outcome],
    ["severity", params.severity],
    ["category", params.category],
    ["start_time", params.start_time],
    ["end_time", params.end_time],
  ];

  for (
    const [key, value] of
    stringFields
  ) {
    if (
      value?.trim()
    ) {
      query.set(
        key,
        value.trim(),
      );
    }
  }

  if (
    params.page !== undefined
  ) {
    query.set(
      "page",
      String(
        normalizePositiveInteger(
          params.page,
          DEFAULT_PAGE,
        ),
      ),
    );
  }

  if (
    params.page_size !== undefined
  ) {
    query.set(
      "page_size",
      String(
        normalizeBoundedInteger(
          params.page_size,
          1,
          MAX_PAGE_SIZE,
          DEFAULT_PAGE_SIZE,
        ),
      ),
    );
  }

  const queryString =
    query.toString();

  return queryString
    ? `/api/v1/events?${queryString}`
    : "/api/v1/events";
}


/**
 * Build the aggregate Events statistics endpoint.
 *
 * The statistics endpoint intentionally receives every Events filter except
 * pagination. KPI values must represent the complete filtered dataset rather
 * than the currently visible page.
 */
function eventStatisticsPath(
  params: Omit<EventListParams, "page" | "page_size"> = {},
): string {
  const query =
    new URLSearchParams();

  const stringFields: Array<
    [
      string,
      string | undefined,
    ]
  > = [
    ["query", params.query],
    ["source", params.source],
    ["source_ip", params.source_ip],
    ["destination_ip", params.destination_ip],
    ["username", params.username],
    ["action", params.action],
    ["outcome", params.outcome],
    ["severity", params.severity],
    ["category", params.category],
    ["start_time", params.start_time],
    ["end_time", params.end_time],
  ];

  for (
    const [key, value] of stringFields
  ) {
    if (
      value?.trim()
    ) {
      query.set(
        key,
        value.trim(),
      );
    }
  }

  const queryString =
    query.toString();

  return queryString
    ? `/api/v1/events/statistics?${queryString}`
    : "/api/v1/events/statistics";
}


function eventPath(
  eventId: string,
): string {
  return `/api/v1/events/${encodeURIComponent(
    requireId(
      eventId,
      "Event ID",
    ),
  )}`;
}


/* ============================================================================
 * Alerts
 * ========================================================================== */

function alertsPath(
  params: AlertListParams = {},
): string {
  const query =
    new URLSearchParams();

  const fields: Array<
    [
      string,
      string | undefined,
    ]
  > = [
    ["query", params.query],
    ["status", params.status],
    ["severity", params.severity],
    ["source_type", params.source_type],
    ["source_id", params.source_id],
    ["rule_id", params.rule_id],
    ["assigned_to", params.assigned_to],
  ];

  for (
    const [key, value] of fields
  ) {
    if (
      value?.trim()
    ) {
      query.set(
        key,
        value.trim(),
      );
    }
  }

  query.set(
    "page",
    String(
      normalizePositiveInteger(
        params.page,
        DEFAULT_PAGE,
      ),
    ),
  );

  query.set(
    "page_size",
    String(
      normalizeBoundedInteger(
        params.page_size,
        1,
        MAX_PAGE_SIZE,
        DEFAULT_PAGE_SIZE,
      ),
    ),
  );

  return `/api/v1/alerts?${query.toString()}`;
}


function alertPath(
  alertId: string,
): string {
  return `/api/v1/alerts/${encodeURIComponent(
    requireId(
      alertId,
      "Alert ID",
    ),
  )}`;
}


/* ============================================================================
 * Incidents
 * ========================================================================== */

const INCIDENTS_BASE_PATH =
  "/api/v1/incidents";

const INCIDENT_STATISTICS_PATH =
  `${INCIDENTS_BASE_PATH}/statistics`;

const INCIDENT_FILTER_OPTIONS_PATH =
  `${INCIDENTS_BASE_PATH}/filter-options`;


function incidentPath(
  incidentId: string,
): string {
  return `${INCIDENTS_BASE_PATH}/${encodeURIComponent(
    requireId(
      incidentId,
      "Incident ID",
    ),
  )}`;
}


function incidentSubPath(
  incidentId: string,
  suffix: string,
): string {
  return `${incidentPath(
    incidentId,
  )}/${suffix}`;
}


function incidentsPath(
  params: IncidentListFilters = {},
): string {
  const query =
    new URLSearchParams();

  const fields: Array<
    [
      string,
      string | undefined,
    ]
  > = [
    ["query", params.query],
    ["status", params.status],
    ["severity", params.severity],
    ["assigned_to", params.assigned_to],
  ];

  for (
    const [key, value] of fields
  ) {
    if (
      value?.trim()
    ) {
      query.set(
        key,
        value.trim(),
      );
    }
  }

  query.set(
    "page",
    String(
      normalizePositiveInteger(
        params.page,
        DEFAULT_PAGE,
      ),
    ),
  );

  query.set(
    "page_size",
    String(
      normalizeBoundedInteger(
        params.page_size,
        1,
        INCIDENT_MAX_PAGE_SIZE,
        INCIDENT_DEFAULT_PAGE_SIZE,
      ),
    ),
  );

  return `${INCIDENTS_BASE_PATH}?${query.toString()}`;
}


/* ============================================================================
 * Threat Intelligence Paths
 * ========================================================================== */

const IOCs_BASE_PATH =
  "/api/v1/iocs";

const IOC_SUMMARY_PATH =
  `${IOCs_BASE_PATH}/summary`;


function iocPath(
  iocId: string,
): string {
  return `${IOCs_BASE_PATH}/${encodeURIComponent(
    requireId(
      iocId,
      "IOC ID",
    ),
  )}`;
}


function iocRelationshipsPath(
  iocId: string,
): string {
  return `${iocPath(
    iocId,
  )}/relationships`;
}


function iocMatchPath(
  observable: string,
): string {
  const query =
    new URLSearchParams();

  query.set(
    "observable",
    requireId(
      observable,
      "IOC observable",
    ),
  );

  return `${IOCs_BASE_PATH}/match?${query.toString()}`;
}


function iocsPath(
  params: IOCListTransportParams = {},
): string {
  const query =
    new URLSearchParams();

  const fields: Array<
    [
      string,
      string | undefined,
    ]
  > = [
    ["query", params.query],
    ["search", params.search],
    ["type", params.type],
    ["severity", params.severity],
    ["status", params.status],
    ["source", params.source],
    ["reputation", params.reputation],
    ["start_time", params.start_time],
    ["end_time", params.end_time],
  ];

  for (
    const [key, value] of fields
  ) {
    if (
      value?.trim()
    ) {
      query.set(
        key,
        value.trim(),
      );
    }
  }

  if (
    params.active !== undefined
  ) {
    query.set(
      "active",
      String(
        params.active,
      ),
    );
  }

  query.set(
    "page",
    String(
      normalizePositiveInteger(
        params.page,
        DEFAULT_PAGE,
      ),
    ),
  );

  query.set(
    "page_size",
    String(
      normalizeBoundedInteger(
        params.page_size,
        1,
        MAX_PAGE_SIZE,
        DEFAULT_PAGE_SIZE,
      ),
    ),
  );

  return `${IOCs_BASE_PATH}?${query.toString()}`;
}


/* ============================================================================
 * Detection
 * ========================================================================== */

/**
 * Detection rule-list query parameters.
 *
 * Transport names intentionally match the backend contract.
 * Filtering and pagination are performed by the backend.
 */
export interface DetectionRuleListParams {
  query?: string;
  enabled?: boolean;
  severity?: string;
  category?: string;
  tag?: string;
  page?: number;
  page_size?: number;
}


/**
 * Detection result-list query parameters.
 *
 * Transport names intentionally match backend query parameters.
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
  page?: number;
  page_size?: number;
}


const DETECTIONS_BASE_PATH =
  "/api/v1/detections";

const DETECTION_CAPABILITY_PATH =
  `${DETECTIONS_BASE_PATH}/capability`;

const DETECTION_STATISTICS_PATH =
  `${DETECTIONS_BASE_PATH}/statistics`;

const DETECTION_SUMMARY_PATH =
  `${DETECTIONS_BASE_PATH}/summary`;

const DETECTION_FILTER_OPTIONS_PATH =
  `${DETECTIONS_BASE_PATH}/filter-options`;

const DETECTION_RESULTS_PATH =
  `${DETECTIONS_BASE_PATH}/results`;

/*
 * Compatibility rule endpoints remain available separately.
 * Do not use these for canonical Detection CRUD/list operations.
 */
const DETECTION_RULES_PATH =
  `${DETECTIONS_BASE_PATH}/rules`;


function detectionRulePath(
  ruleId: string,
): string {
  return `${DETECTIONS_BASE_PATH}/${encodeURIComponent(
    requireId(
      ruleId,
      "Detection rule ID",
    ),
  )}`;
}


function detectionRulesPath(
  params: DetectionRuleListParams = {},
): string {
  const query =
    new URLSearchParams();

  const stringFields: Array<
    [string, string | undefined]
  > = [
    ["query", params.query],
    ["severity", params.severity],
    ["category", params.category],
    ["tag", params.tag],
  ];

  for (
    const [key, value] of stringFields
  ) {
    if (
      typeof value === "string" &&
      value.trim()
    ) {
      query.set(
        key,
        value.trim(),
      );
    }
  }

  if (
    params.enabled !== undefined
  ) {
    query.set(
      "enabled",
      String(params.enabled),
    );
  }

  if (
    params.page !== undefined
  ) {
    query.set(
      "page",
      String(
        normalizePositiveInteger(
          params.page,
          DEFAULT_PAGE,
        ),
      ),
    );
  }

  if (
    params.page_size !== undefined
  ) {
    query.set(
      "page_size",
      String(
        normalizeBoundedInteger(
          params.page_size,
          1,
          MAX_PAGE_SIZE,
          30,
        ),
      ),
    );
  }

  const queryString =
    query.toString();

  return queryString
    ? `${DETECTIONS_BASE_PATH}?${queryString}`
    : DETECTIONS_BASE_PATH;
}


function detectionCompatibilityRulesPath(
  enabled?: boolean,
): string {
  if (
    enabled === undefined
  ) {
    return DETECTION_RULES_PATH;
  }

  const query =
    new URLSearchParams();

  query.set(
    "enabled",
    String(enabled),
  );

  return `${DETECTION_RULES_PATH}?${query.toString()}`;
}


function detectionResultPath(
  detectionId: string,
): string {
  return `${DETECTION_RESULTS_PATH}/${encodeURIComponent(
    requireId(
      detectionId,
      "Detection ID",
    ),
  )}`;
}


function detectionResultsPath(
  params: DetectionResultListParams = {},
): string {
  const query =
    new URLSearchParams();

  const fields: Array<
    [string, string | undefined]
  > = [
    ["query", params.query],
    ["rule_id", params.rule_id],
    ["event_id", params.event_id],
    ["severity", params.severity],
    ["category", params.category],
    ["start_time", params.start_time],
    ["end_time", params.end_time],
  ];

  for (
    const [key, value] of fields
  ) {
    if (
      typeof value === "string" &&
      value.trim()
    ) {
      query.set(
        key,
        value.trim(),
      );
    }
  }

  if (
    params.suppressed !== undefined
  ) {
    query.set(
      "suppressed",
      String(params.suppressed),
    );
  }

  if (
    params.page !== undefined
  ) {
    query.set(
      "page",
      String(
        normalizePositiveInteger(
          params.page,
          DEFAULT_PAGE,
        ),
      ),
    );
  }

  if (
    params.page_size !== undefined
  ) {
    query.set(
      "page_size",
      String(
        normalizeBoundedInteger(
          params.page_size,
          1,
          MAX_PAGE_SIZE,
          30,
        ),
      ),
    );
  }

  const queryString =
    query.toString();

  return queryString
    ? `${DETECTION_RESULTS_PATH}?${queryString}`
    : DETECTION_RESULTS_PATH;
}


/* ============================================================================
 * MITRE ATT&CK
 * ========================================================================== */

/**
 * MITRE ATT&CK is a READ-ONLY threat-intelligence/security-knowledge
 * transport surface.
 *
 * Detection → MITRE mapping operations are kept separate because they
 * represent SentinelSIEM operational capability rather than ATT&CK knowledge
 * CRUD.
 */

const MITRE_BASE_PATH =
  "/api/v1/mitre";

const MITRE_STATISTICS_PATH =
  `${MITRE_BASE_PATH}/statistics`;

const MITRE_TACTICS_PATH =
  `${MITRE_BASE_PATH}/tactics`;

const MITRE_PLATFORMS_PATH =
  `${MITRE_BASE_PATH}/platforms`;

const MITRE_TECHNIQUES_PATH =
  `${MITRE_BASE_PATH}/techniques`;

const MITRE_COVERAGE_PATH =
  `${MITRE_BASE_PATH}/coverage`;

const MITRE_COVERAGE_TACTICS_PATH =
  `${MITRE_BASE_PATH}/coverage/tactics`;

const MITRE_ANALYTICS_PATH =
  `${MITRE_BASE_PATH}/analytics`;

const MITRE_MATRIX_PATH =
  `${MITRE_BASE_PATH}/matrix`;

const MITRE_MAPPINGS_PATH =
  `${MITRE_BASE_PATH}/mappings`;

const MITRE_DEFAULT_PAGE_SIZE = 30;

type MitreMappingCreateTransportRequest = {
  detection_id: string;
  technique_id: string;
  subtechnique_id?: string | null;
  tactic_ids?: string[];
  confidence?: number;
  source?: string;
  description?: string;
};

interface MitreOverviewResponse {
  [key: string]: unknown;
}

function mitreTechniquePath(
  techniqueId: string,
): string {
  return `${MITRE_TECHNIQUES_PATH}/${encodeURIComponent(
    requireId(
      techniqueId,
      "MITRE technique ID",
    ),
  )}`;
}

function mitreTechniqueSubTechniquesPath(
  techniqueId: string,
): string {
  return `${mitreTechniquePath(
    techniqueId,
  )}/sub-techniques`;
}

function mitreTechniqueDetailPath(
  techniqueId: string,
): string {
  return `${mitreTechniquePath(
    techniqueId,
  )}/detail`;
}

function mitreTechniqueRelationshipsPath(
  techniqueId: string,
): string {
  return `${mitreTechniquePath(
    techniqueId,
  )}/relationships`;
}

function mitreTechniqueDetectionsPath(
  techniqueId: string,
): string {
  return `${mitreTechniquePath(
    techniqueId,
  )}/detections`;
}

function mitreTechniqueEventsPath(
  techniqueId: string,
): string {
  return `${mitreTechniquePath(
    techniqueId,
  )}/events`;
}

function mitreTechniqueAlertsPath(
  techniqueId: string,
): string {
  return `${mitreTechniquePath(
    techniqueId,
  )}/alerts`;
}

function mitreTechniqueIncidentsPath(
  techniqueId: string,
): string {
  return `${mitreTechniquePath(
    techniqueId,
  )}/incidents`;
}

function mitreTechniqueIocsPath(
  techniqueId: string,
): string {
  return `${mitreTechniquePath(
    techniqueId,
  )}/iocs`;
}

function mitreTechniquesPath(
  params: MitreTechniqueQuery = {},
): string {
  const query =
    new URLSearchParams();

  const stringFields: Array<
    [string, string | undefined]
  > = [
    ["search", params.search],
    ["tactic", params.tactic],
    ["platform", params.platform],
    ["type", params.type],
    ["coverage", params.coverage],
  ];

  for (
    const [key, value] of stringFields
  ) {
    if (
      typeof value === "string" &&
      value.trim()
    ) {
      query.set(
        key,
        value.trim(),
      );
    }
  }

  const page =
    normalizePositiveInteger(
      params.page,
      DEFAULT_PAGE,
    );

  const pageSize =
    normalizeBoundedInteger(
      params.page_size,
      1,
      MITRE_DEFAULT_PAGE_SIZE,
      MITRE_DEFAULT_PAGE_SIZE,
    );

  query.set(
    "page",
    String(page),
  );

  query.set(
    "page_size",
    String(pageSize),
  );

  return `${MITRE_TECHNIQUES_PATH}?${query.toString()}`;
}

function mitreMappingPath(
  mappingId: string,
): string {
  return `${MITRE_MAPPINGS_PATH}/${encodeURIComponent(
    requireId(
      mappingId,
      "MITRE mapping ID",
    ),
  )}`;
}


/* ============================================================================
 * MITRE TRANSPORT TYPES
 * ========================================================================== */

/**
 * The backend returns the authoritative MITRE contracts represented by
 * modules/mitre/types.ts.
 *
 * These aliases exist only to make the central transport explicit.
 */
type MitreStatisticsResponse =
  MitreStatistics;

type MitreTacticsTransportResponse =
  MitreTacticListResponse;

type MitrePlatformsTransportResponse =
  MitrePlatformListResponse;

type MitreTechniquesTransportResponse =
  MitreTechniqueListResponse;

type MitreSubTechniquesTransportResponse =
  MitreSubTechniqueListResponse;

/* ============================================================================
 * Users
 * ========================================================================== */

const USERS_BASE_PATH =
  "/api/v1/users";

const USER_STATISTICS_PATH =
  `${USERS_BASE_PATH}/statistics`;


function usersPath(
  params?: UserListParams,
): string {
  const query =
    new URLSearchParams();

  if (
    params?.search?.trim()
  ) {
    query.set(
      "search",
      params.search.trim(),
    );
  }

  if (
    params?.role?.trim()
  ) {
    query.set(
      "role",
      params.role.trim(),
    );
  }

  if (
    params?.is_active !== undefined
  ) {
    query.set(
      "is_active",
      String(
        params.is_active,
      ),
    );
  }

  if (
    params?.is_locked !== undefined
  ) {
    query.set(
      "is_locked",
      String(
        params.is_locked,
      ),
    );
  }

  if (
    params?.limit !== undefined
  ) {
    query.set(
      "limit",
      String(
        normalizeBoundedInteger(
          params.limit,
          1,
          USER_MAX_LIMIT,
          50,
        ),
      ),
    );
  }

  if (
    params?.offset !== undefined
  ) {
    query.set(
      "offset",
      String(
        normalizeNonNegativeInteger(
          params.offset,
        ),
      ),
    );
  }

  const queryString =
    query.toString();

  return queryString
    ? `${USERS_BASE_PATH}?${queryString}`
    : USERS_BASE_PATH;
}


function userPath(
  userId: string,
): string {
  return `${USERS_BASE_PATH}/${encodeURIComponent(
    requireId(
      userId,
      "User ID",
    ),
  )}`;
}


function userRolePath(
  userId: string,
): string {
  return `${userPath(userId)}/role`;
}


function userActivePath(
  userId: string,
): string {
  return `${userPath(userId)}/active`;
}


function userLockPath(
  userId: string,
): string {
  return `${userPath(userId)}/lock`;
}


function userForcePasswordChangePath(
  userId: string,
): string {
  return `${userPath(
    userId,
  )}/password/force-change`;
}


function userPasswordResetPath(
  userId: string,
): string {
  return `${userPath(
    userId,
  )}/password/reset`;
}


function userSessionsRevokePath(
  userId: string,
): string {
  return `${userPath(
    userId,
  )}/sessions/revoke`;
}


function userAuditPath(
  userId: string,
): string {
  return `${userPath(userId)}/audit`;
}


/* ============================================================================
 * Global Audit
 * ========================================================================== */

const AUDIT_BASE_PATH =
  "/api/v1/audit";

const AUDIT_STATISTICS_PATH =
  `${AUDIT_BASE_PATH}/statistics`;

const AUDIT_EXPORT_PATH =
  `${AUDIT_BASE_PATH}/export`;


function auditPath(
  auditId: string,
): string {
  return `${AUDIT_BASE_PATH}/${encodeURIComponent(
    requireId(
      auditId,
      "Audit event ID",
    ),
  )}`;
}


function auditRelatedPath(
  auditId: string,
): string {
  return `${auditPath(
    auditId,
  )}/related`;
}


function setAuditString(
  query: URLSearchParams,
  key: string,
  value: unknown,
): void {
  if (
    typeof value === "string" &&
    value.trim()
  ) {
    query.set(
      key,
      value.trim(),
    );
  }
}


function buildAuditQuery(
  params:
    | AuditListParams
    | AuditStatisticsParams
    | AuditExportParams
    = {},
  options: {
    includePagination?: boolean;
    exportRequest?: boolean;
  } = {},
): string {
  const query =
    new URLSearchParams();

  const actor =
    params.actor ??
    params.actor_user_id;

  const target =
    params.target ??
    params.target_user_id;

  const result =
    params.result ??
    params.outcome;

  const source =
    params.source ??
    params.source_ip;

  setAuditString(
    query,
    "action",
    params.action,
  );

  setAuditString(
    query,
    "category",
    params.category,
  );

  setAuditString(
    query,
    "actor",
    actor,
  );

  setAuditString(
    query,
    "target",
    target,
  );

  setAuditString(
    query,
    "result",
    result,
  );

  setAuditString(
    query,
    "source",
    source,
  );

  setAuditString(
    query,
    "date_from",
    params.date_from,
  );

  setAuditString(
    query,
    "date_to",
    params.date_to,
  );

  setAuditString(
    query,
    "search",
    params.search,
  );

  if (
    options.includePagination
  ) {
    let page:
      | number
      | undefined =
      "page" in params
        ? params.page
        : undefined;

    let pageSize:
      | number
      | undefined =
      "page_size" in params
        ? params.page_size
        : undefined;

    if (
      page === undefined &&
      pageSize === undefined &&
      (
        "limit" in params ||
        "offset" in params
      )
    ) {
      const rawLimit =
        "limit" in params
          ? params.limit
          : undefined;

      const rawOffset =
        "offset" in params
          ? params.offset
          : undefined;

      const maximum =
        options.exportRequest
          ? AUDIT_MAX_EXPORT_SIZE
          : AUDIT_MAX_PAGE_SIZE;

      const fallback =
        options.exportRequest
          ? AUDIT_DEFAULT_EXPORT_SIZE
          : AUDIT_DEFAULT_PAGE_SIZE;

      const limit =
        rawLimit !== undefined
          ? normalizeBoundedInteger(
              rawLimit,
              1,
              maximum,
              fallback,
            )
          : fallback;

      const offset =
        rawOffset !== undefined
          ? normalizeNonNegativeInteger(
              rawOffset,
            )
          : 0;

      pageSize =
        Math.min(
          maximum,
          limit,
        );

      page =
        Math.floor(
          offset / pageSize,
        ) + 1;
    }

    if (
      page !== undefined
    ) {
      query.set(
        "page",
        String(
          normalizePositiveInteger(
            page,
            DEFAULT_PAGE,
          ),
        ),
      );
    }

    if (
      pageSize !== undefined
    ) {
      const maximum =
        options.exportRequest
          ? AUDIT_MAX_EXPORT_SIZE
          : AUDIT_MAX_PAGE_SIZE;

      const fallback =
        options.exportRequest
          ? AUDIT_DEFAULT_EXPORT_SIZE
          : AUDIT_DEFAULT_PAGE_SIZE;

      query.set(
        "page_size",
        String(
          Math.min(
            maximum,
            normalizePositiveInteger(
              pageSize,
              fallback,
            ),
          ),
        ),
      );
    }
  }

  return query.toString();
}


function auditLogsPath(
  params: AuditListParams = {},
): string {
  const queryString =
    buildAuditQuery(
      params,
      {
        includePagination: true,
      },
    );

  return queryString
    ? `${AUDIT_BASE_PATH}?${queryString}`
    : AUDIT_BASE_PATH;
}


function auditStatisticsPath(
  params: AuditStatisticsParams = {},
): string {
  const queryString =
    buildAuditQuery(
      params,
      {
        includePagination: false,
      },
    );

  return queryString
    ? `${AUDIT_STATISTICS_PATH}?${queryString}`
    : AUDIT_STATISTICS_PATH;
}


function auditExportPath(
  params: AuditExportParams = {},
): string {
  const queryString =
    buildAuditQuery(
      params,
      {
        includePagination: true,
        exportRequest: true,
      },
    );

  return queryString
    ? `${AUDIT_EXPORT_PATH}?${queryString}`
    : AUDIT_EXPORT_PATH;
}


/* ============================================================================
 * Raw Audit Types
 * ========================================================================== */

interface RawAuditIdentity {
  user_id?: unknown;
  username?: unknown;
  role?: unknown;
}


interface RawAuditEvent {
  audit_id?: unknown;
  actor_user_id?: unknown;
  target_user_id?: unknown;
  session_id?: unknown;
  request_id?: unknown;
  source_ip?: unknown;
  action?: unknown;
  outcome?: unknown;
  metadata_json?: unknown;
  created_at?: unknown;
  actor?: unknown;
  target?: unknown;
  event_id?: unknown;
  timestamp?: unknown;
  metadata?: unknown;
}


interface RawAuditListResponse {
  total?: unknown;
  page?: unknown;
  page_size?: unknown;
  pages?: unknown;
  events?: unknown;
  items?: unknown;
}


interface RawAuditRelatedResponse {
  audit_id?: unknown;
  total?: unknown;
  page?: unknown;
  page_size?: unknown;
  pages?: unknown;
  events?: unknown;
  items?: unknown;
}


interface RawAuditExportResponse {
  total?: unknown;
  count?: unknown;
  limit?: unknown;
  events?: unknown;
  items?: unknown;
}


/* ============================================================================
 * Audit Normalization
 * ========================================================================== */

function normalizeAuditActor(
  value: unknown,
): AuditEvent["actor"] {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value)
  ) {
    return null;
  }

  const raw =
    value as RawAuditIdentity;

  const userId =
    stringOrNull(raw.user_id);

  const username =
    stringOrNull(raw.username);

  const role =
    stringOrNull(raw.role);

  if (
    !userId ||
    !username ||
    !role
  ) {
    return null;
  }

  return {
    user_id: userId,
    username,
    role,
  };
}


function normalizeAuditTarget(
  value: unknown,
): AuditEvent["target"] {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value)
  ) {
    return null;
  }

  const raw =
    value as RawAuditIdentity;

  const userId =
    stringOrNull(raw.user_id);

  const username =
    stringOrNull(raw.username);

  const role =
    stringOrNull(raw.role);

  if (
    !userId ||
    !username ||
    !role
  ) {
    return null;
  }

  return {
    user_id: userId,
    username,
    role,
  };
}


function normalizeAuditMetadata(
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


function isRawAuditEvent(
  value: unknown,
): value is RawAuditEvent {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}


function normalizeAuditEvent(
  raw: RawAuditEvent,
): AuditEvent {
  const auditId =
    stringOrNull(
      raw.audit_id ??
        raw.event_id,
    );

  const createdAt =
    stringOrNull(
      raw.created_at ??
        raw.timestamp,
    );

  if (!auditId) {
    throw new ApiError(
      200,
      "Audit response is missing audit_id.",
    );
  }

  if (!createdAt) {
    throw new ApiError(
      200,
      "Audit response is missing created_at.",
    );
  }

  const metadata =
    normalizeAuditMetadata(
      raw.metadata_json ??
        raw.metadata,
    );

  return {
    audit_id: auditId,

    actor_user_id:
      stringOrNull(
        raw.actor_user_id,
      ),

    target_user_id:
      stringOrNull(
        raw.target_user_id,
      ),

    session_id:
      stringOrNull(
        raw.session_id,
      ),

    actor:
      normalizeAuditActor(
        raw.actor,
      ),

    target:
      normalizeAuditTarget(
        raw.target,
      ),

    request_id:
      stringOrNull(
        raw.request_id,
      ),

    source_ip:
      stringOrNull(
        raw.source_ip,
      ),

    action:
      stringOrNull(
        raw.action,
      ) ?? "",

    outcome:
      stringOrNull(
        raw.outcome,
      ) ?? "",

    metadata_json:
      metadata,

    created_at:
      createdAt,

    event_id:
      auditId,

    timestamp:
      createdAt,

    metadata,
  } satisfies AuditEvent;
}


function extractAuditEvents(
  raw: {
    events?: unknown;
    items?: unknown;
  },
): RawAuditEvent[] {
  const source =
    Array.isArray(raw.events)
      ? raw.events
      : Array.isArray(raw.items)
        ? raw.items
        : [];

  return source.filter(
    isRawAuditEvent,
  );
}


function normalizeAuditListResponse(
  raw: RawAuditListResponse,
): AuditListResponse {
  const items =
    extractAuditEvents(raw)
      .map(normalizeAuditEvent);

  return {
    items,

    total:
      normalizeNonNegativeInteger(
        raw.total,
      ),

    page:
      normalizePositiveInteger(
        raw.page,
        DEFAULT_PAGE,
      ),

    page_size:
      normalizePositiveInteger(
        raw.page_size,
        AUDIT_DEFAULT_PAGE_SIZE,
      ),
  };
}


function normalizeAuditStatistics(
  raw: Partial<AuditStatistics>,
): AuditStatistics {
  return {
    total:
      normalizeNonNegativeInteger(
        raw.total,
      ),

    success:
      normalizeNonNegativeInteger(
        raw.success,
      ),

    failure:
      normalizeNonNegativeInteger(
        raw.failure,
      ),

    denied:
      normalizeNonNegativeInteger(
        raw.denied,
      ),

    unique_actors:
      normalizeNonNegativeInteger(
        raw.unique_actors,
      ),

    unique_targets:
      normalizeNonNegativeInteger(
        raw.unique_targets,
      ),
  };
}


function normalizeAuditRelatedResponse(
  raw: RawAuditRelatedResponse,
): AuditRelatedEventListResponse {
  const items =
    extractAuditEvents(raw)
      .map(normalizeAuditEvent);

  const auditId =
    stringOrNull(raw.audit_id);

  if (!auditId) {
    throw new ApiError(
      200,
      "Related audit response is missing audit_id.",
    );
  }

  return {
    audit_id: auditId,

    items,

    total:
      normalizeNonNegativeInteger(
        raw.total,
      ) || items.length,

    page:
      normalizePositiveInteger(
        raw.page,
        DEFAULT_PAGE,
      ),

    page_size:
      normalizePositiveInteger(
        raw.page_size,
        items.length ||
          AUDIT_DEFAULT_PAGE_SIZE,
      ),
  };
}


function normalizeAuditExportResponse(
  raw: RawAuditExportResponse,
): AuditExportResponse {
  const items =
    extractAuditEvents(raw)
      .map(normalizeAuditEvent);

  return {
    items,

    count:
      normalizeNonNegativeInteger(
        raw.count,
      ) || items.length,

    limit:
      normalizePositiveInteger(
        raw.limit,
        AUDIT_DEFAULT_EXPORT_SIZE,
      ),
  };
}


/* ============================================================================
 * Assets
 * ========================================================================== */

const ASSETS_BASE_PATH =
  "/api/v1/assets";

const ASSET_STATISTICS_PATH =
  `${ASSETS_BASE_PATH}/statistics`;


function assetsPath(
  params: AssetListParams = {},
): string {
  const query =
    new URLSearchParams();

  if (params.search?.trim()) {
    query.set("search", params.search.trim());
  }

  if (params.asset_type?.trim()) {
    query.set("asset_type", params.asset_type.trim());
  }

  if (params.status) {
    query.set("status", params.status);
  }

  if (params.risk) {
    query.set("risk", params.risk);
  }

  if (params.os?.trim()) {
    query.set("os", params.os.trim());
  }

  if (params.environment?.trim()) {
    query.set("environment", params.environment.trim());
  }

  const page = normalizePositiveInteger(
    params.page,
    1,
  );

  const pageSize = normalizeBoundedInteger(
    params.page_size,
    1,
    30,
    30,
  );

  query.set("page", String(page));
  query.set("page_size", String(pageSize));

  return `${ASSETS_BASE_PATH}?${query.toString()}`;
}

function assetPath(
  assetId: string,
): string {
  return `${ASSETS_BASE_PATH}/${encodeURIComponent(
    requireId(
      assetId,
      "Asset ID",
    ),
  )}`;
}


/* ============================================================================
 * CENTRAL API
 * ========================================================================== */

export const api = {

  /* ========================================================================
   * Authentication
   * ====================================================================== */

  async login(
    login: string,
    password: string,
  ): Promise<LoginResponse> {
    const response =
      await request<LoginResponse>(
        "/api/v1/auth/login",
        {
          method: "POST",

          headers: {
            "Content-Type":
              "application/json",
          },

          body: JSON.stringify({
            login,
            password,
          }),
        },
      );

    useAuthStore
      .getState()
      .setAuthentication(
        response.access_token,
        response.user,
      );

    return response;
  },


  me(): Promise<AuthUser> {
    return request<AuthUser>(
      "/api/v1/auth/me",
    );
  },


  meWithToken(
    accessToken: string,
  ): Promise<AuthUser> {
    return requestWithToken<AuthUser>(
      "/api/v1/auth/me",
      accessToken,
    );
  },


  async logout(): Promise<void> {
    try {
      await request<void>(
        "/api/v1/auth/logout",
        {
          method: "POST",
        },
      );
    } finally {
      useAuthStore
        .getState()
        .clearAuthentication();
    }
  },


  /* ========================================================================
   * Health / System
   * ====================================================================== */

  health(): Promise<HealthResponse> {
    return request<HealthResponse>(
      "/api/v1/health",
    );
  },


  system(): Promise<SystemResponse> {
    return request<SystemResponse>(
      "/api/v1/system",
    );
  },


  /* ========================================================================
   * Events
   * ====================================================================== */

  events(
    params: EventListParams = {},
  ): Promise<
    PaginatedResponse<SecurityEvent>
  > {
    return request<
      PaginatedResponse<SecurityEvent>
    >(
      eventsPath(params),
    );
  },


  /**
   * Fetch aggregate Events statistics.
   *
   * GET /api/v1/events/statistics
   *
   * Pagination is deliberately excluded. The backend calculates these
   * counters over the full dataset matching the supplied filters.
   */
  getEventStatistics(
    params: Omit<EventListParams, "page" | "page_size"> = {},
  ): Promise<EventStatisticsResponse> {
    return request<EventStatisticsResponse>(
      eventStatisticsPath(params),
    );
  },


  getEventFilterOptions():
    Promise<EventFilterOptions> {
    return request<EventFilterOptions>(
      "/api/v1/events/filter-options",
    );
  },


  getEvent(
    eventId: string,
  ): Promise<SecurityEvent> {
    return request<SecurityEvent>(
      eventPath(eventId),
    );
  },


  /* ========================================================================
   * Alerts
   * ====================================================================== */

  alerts(
    page = DEFAULT_PAGE,
    pageSize = DEFAULT_PAGE_SIZE,
  ): Promise<
    PaginatedResponse<Alert>
  > {
    return request<
      PaginatedResponse<Alert>
    >(
      alertsPath({
        page,
        page_size: pageSize,
      }),
    );
  },


  alertsWithFilters(
    params: AlertListParams = {},
  ): Promise<
    PaginatedResponse<Alert>
  > {
    return request<
      PaginatedResponse<Alert>
    >(
      alertsPath(params),
    );
  },


  getAlertStatistics(
    params: Omit<AlertListParams, "page" | "page_size"> = {},
  ): Promise<AlertStatistics> {
    const query = new URLSearchParams();

    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null && String(value).trim() !== "") {
        query.set(key, String(value));
      }
    }

    const suffix = query.toString() ? `?${query.toString()}` : "";

    return request<AlertStatistics>(
      `/api/v1/alerts/statistics${suffix}`,
    );
  },


  getAlertFilterOptions(): Promise<AlertFilterOptions> {
    return request<AlertFilterOptions>(
      "/api/v1/alerts/filter-options",
    );
  },


  getAlert(
    alertId: string,
  ): Promise<Alert> {
    return request<Alert>(
      alertPath(alertId),
    );
  },


  getAlertAudit(
    alertId: string,
  ): Promise<AlertAuditEntry[]> {
    return request<AlertAuditEntry[]>(
      `${alertPath(alertId)}/audit`,
    );
  },


  transitionAlert(
    alertId: string,
    payload: AlertTransitionRequest,
  ): Promise<Alert> {
    return request<Alert>(
      `${alertPath(alertId)}/transition`,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify(payload),
      },
    );
  },


  assignAlert(
    alertId: string,
    payload: AlertAssignmentRequest,
  ): Promise<Alert> {
    return request<Alert>(
      `${alertPath(alertId)}/assignment`,
      {
        method: "PATCH",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify(payload),
      },
    );
  },


  /* ========================================================================
   * Incidents
   * ====================================================================== */

  incidents(
    page = DEFAULT_PAGE,
    pageSize = INCIDENT_DEFAULT_PAGE_SIZE,
  ): Promise<IncidentListResponse> {
    return request<IncidentListResponse>(
      incidentsPath({
        page,
        page_size: pageSize,
      }),
    );
  },


  incidentsWithFilters(
    params: IncidentListFilters = {},
  ): Promise<IncidentListResponse> {
    return request<IncidentListResponse>(
      incidentsPath(params),
    );
  },


  getIncident(
    incidentId: string,
  ): Promise<Incident> {
    return request<Incident>(
      incidentPath(incidentId),
    );
  },


  getIncidentDetail(
    incidentId: string,
  ): Promise<IncidentDetail> {
    return request<IncidentDetail>(
      incidentPath(incidentId),
    );
  },


  getIncidentStatistics(): Promise<IncidentStatistics> {
    return request<IncidentStatistics>(
      INCIDENT_STATISTICS_PATH,
    );
  },


  /**
   * Fetch backend-driven Incident filter options.
   *
   * GET /api/v1/incidents/filter-options
   *
   * The backend/OpenSearch is authoritative for statuses, severities,
   * priorities, assignees, ownership groups, and tags. The frontend
   * must not hardcode dropdown values.
   */
  getIncidentFilterOptions():
    Promise<IncidentFilterOptions> {
    return request<IncidentFilterOptions>(
      INCIDENT_FILTER_OPTIONS_PATH,
    );
  },


  createIncident(
    payload: IncidentCreateRequest,
  ): Promise<Incident> {
    return request<Incident>(
      INCIDENTS_BASE_PATH,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify(payload),
      },
    );
  },


  updateIncident(
    incidentId: string,
    payload: IncidentUpdateRequest,
  ): Promise<Incident> {
    return request<Incident>(
      incidentPath(incidentId),
      {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      },
    );
  },


  getIncidentRelatedAlerts(
    incidentId: string,
  ): Promise<IncidentRelatedAlert[]> {
    return request<IncidentRelatedAlert[]>(
      incidentSubPath(incidentId, "alerts"),
    );
  },


  assignIncident(
    incidentId: string,
    payload: IncidentAssignmentRequest,
  ): Promise<Incident> {
    return request<Incident>(
      incidentSubPath(
        incidentId,
        "assignment",
      ),
      {
        method: "PATCH",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify(payload),
      },
    );
  },


  transitionIncident(
    incidentId: string,
    payload: IncidentTransitionRequest,
  ): Promise<Incident> {
    return request<Incident>(
      incidentSubPath(
        incidentId,
        "transition",
      ),
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify(payload),
      },
    );
  },


  addIncidentNote(
    incidentId: string,
    payload: IncidentNoteCreateRequest,
  ): Promise<IncidentNote> {
    return request<IncidentNote>(
      incidentSubPath(
        incidentId,
        "notes",
      ),
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify(payload),
      },
    );
  },


  getIncidentNotes(
    incidentId: string,
  ): Promise<IncidentNote[]> {
    return request<IncidentNote[]>(
      incidentSubPath(
        incidentId,
        "notes",
      ),
    );
  },


  addIncidentEvidence(
    incidentId: string,
    payload: IncidentEvidenceCreateRequest,
  ): Promise<IncidentEvidence> {
    return request<IncidentEvidence>(
      incidentSubPath(
        incidentId,
        "evidence",
      ),
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify(payload),
      },
    );
  },


  getIncidentEvidence(
    incidentId: string,
  ): Promise<IncidentEvidence[]> {
    return request<IncidentEvidence[]>(
      incidentSubPath(
        incidentId,
        "evidence",
      ),
    );
  },


  getIncidentTimeline(
    incidentId: string,
  ): Promise<IncidentTimelineEntry[]> {
    return request<IncidentTimelineEntry[]>(
      incidentSubPath(
        incidentId,
        "timeline",
      ),
    );
  },


  getIncidentAudit(
    incidentId: string,
  ): Promise<IncidentAuditEntry[]> {
    return request<IncidentAuditEntry[]>(
      incidentSubPath(
        incidentId,
        "audit",
      ),
    );
  },


  /* ========================================================================
   * Threat Intelligence
   * ====================================================================== */

  iocs(
    page = DEFAULT_PAGE,
    pageSize = DEFAULT_PAGE_SIZE,
  ): Promise<
    PaginatedResponse<
      IOCTransportResponse
    >
  > {
    return request<
      PaginatedResponse<
        IOCTransportResponse
      >
    >(
      iocsPath({
        page,
        page_size: pageSize,
      }),
    );
  },


  iocsWithFilters(
    params: IOCListTransportParams = {},
  ): Promise<
    PaginatedResponse<
      IOCTransportResponse
    >
  > {
    return request<
      PaginatedResponse<
        IOCTransportResponse
      >
    >(
      iocsPath(params),
    );
  },


  getIOC(
    iocId: string,
  ): Promise<IOCTransportResponse> {
    return request<
      IOCTransportResponse
    >(
      iocPath(iocId),
    );
  },


  getIOCFilterOptions(): Promise<{
    types: string[];
    severities: string[];
    statuses: string[];
    sources: string[];
    reputations: string[];
  }> {
    return request<{
      types: string[];
      severities: string[];
      statuses: string[];
      sources: string[];
      reputations: string[];
    }>(
      `${IOCs_BASE_PATH}/filter-options`,
    );
  },


  getIOCSummary():
    Promise<IOCSummaryTransportResponse> {
    return request<
      IOCSummaryTransportResponse
    >(
      IOC_SUMMARY_PATH,
    );
  },


  createIOC(
    payload: IOCCreateTransportRequest,
  ): Promise<IOCTransportResponse> {
    return request<
      IOCTransportResponse
    >(
      IOCs_BASE_PATH,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify(payload),
      },
    );
  },


  updateIOC(
    iocId: string,
    payload: IOCUpdateTransportRequest,
  ): Promise<IOCTransportResponse> {
    return request<
      IOCTransportResponse
    >(
      iocPath(iocId),
      {
        method: "PATCH",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify(payload),
      },
    );
  },


  /**
   * POST /api/v1/iocs/{ioc_id}/revoke
   *
   * Dedicated lifecycle transition:
   *
   *   ACTIVE → REVOKED
   *
   * Generic PATCH intentionally cannot change IOC status.
   */
  revokeIOC(
    iocId: string,
  ): Promise<IOCTransportResponse> {
    return request<
      IOCTransportResponse
    >(
      `${iocPath(iocId)}/revoke`,
      {
        method: "POST",
      },
    );
  },


  /**
   * POST /api/v1/iocs/{ioc_id}/activate
   *
   * Dedicated lifecycle transition:
   *
   *   REVOKED → ACTIVE
   *
   * Backend remains the source of truth for validation.
   */
  activateIOC(
    iocId: string,
  ): Promise<IOCTransportResponse> {
    return request<
      IOCTransportResponse
    >(
      `${iocPath(iocId)}/activate`,
      {
        method: "POST",
      },
    );
  },






  matchIOC(
    observable: string,
  ): Promise<
    IOCMatchTransportResponse[]
  > {
    return request<
      IOCMatchTransportResponse[]
    >(
      iocMatchPath(observable),
    );
  },


  getIOCRelationships(
    iocId: string,
  ): Promise<
    IOCRelationshipTransportResponse
  > {
    return request<
      IOCRelationshipTransportResponse
    >(
      iocRelationshipsPath(iocId),
    );
  },


  /* ========================================================================
   * Detection
   * ====================================================================== */

  /**
   * GET /api/v1/detections/capability
   *
   * Detection subsystem capability/status.
   */
  getDetectionCapability():
    Promise<DetectionCapability> {
    return request<DetectionCapability>(
      DETECTION_CAPABILITY_PATH,
    );
  },


  /**
   * GET /api/v1/detections/statistics
   *
   * Canonical runtime Detection statistics.
   */
  getDetectionStatistics():
    Promise<DetectionStatistics> {
    return request<DetectionStatistics>(
      DETECTION_STATISTICS_PATH,
    );
  },


  /**
   * GET /api/v1/detections/summary
   *
   * Detection summary endpoint.
   */
  getDetectionSummary():
    Promise<DetectionSummary> {
    return request<DetectionSummary>(
      DETECTION_SUMMARY_PATH,
    );
  },


  /**
   * GET /api/v1/detections/filter-options
   *
   * Backend-derived Detection filter values.
   */
  getDetectionFilterOptions():
    Promise<DetectionFilterOptions> {
    return request<DetectionFilterOptions>(
      DETECTION_FILTER_OPTIONS_PATH,
    );
  },


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
   */
  listDetectionRules(
    params: DetectionRuleListParams = {},
  ): Promise<DetectionRuleListResponse> {
    return request<DetectionRuleListResponse>(
      detectionRulesPath(params),
    );
  },


  /**
   * GET /api/v1/detections/rules
   *
   * Compatibility rule-list endpoint.
   */
  listDetectionRulesCompatibility(
    enabled?: boolean,
  ): Promise<DetectionRuleListResponse> {
    return request<DetectionRuleListResponse>(
      detectionCompatibilityRulesPath(
        enabled,
      ),
    );
  },


  /**
   * GET /api/v1/detections/{rule_id}
   */
  getDetectionRule(
    ruleId: string,
  ): Promise<DetectionRule> {
    return request<DetectionRule>(
      detectionRulePath(ruleId),
    );
  },


  /**
   * POST /api/v1/detections
   */
  createDetectionRule(
    payload: DetectionRuleCreateRequest,
  ): Promise<DetectionRule> {
    return request<DetectionRule>(
      DETECTIONS_BASE_PATH,
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/json",
        },
        body: JSON.stringify(payload),
      },
    );
  },


  /**
   * POST /api/v1/detections/rules
   *
   * Compatibility creation endpoint.
   */
  createDetectionRuleCompatibility(
    payload: DetectionRuleCreateRequest,
  ): Promise<DetectionRule> {
    return request<DetectionRule>(
      DETECTION_RULES_PATH,
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/json",
        },
        body: JSON.stringify(payload),
      },
    );
  },


  /**
   * PATCH /api/v1/detections/{rule_id}
   */
  updateDetectionRule(
    ruleId: string,
    payload: DetectionRuleUpdateRequest,
  ): Promise<DetectionRule> {
    return request<DetectionRule>(
      detectionRulePath(ruleId),
      {
        method: "PATCH",
        headers: {
          "Content-Type":
            "application/json",
        },
        body: JSON.stringify(payload),
      },
    );
  },


  /**
   * PATCH /api/v1/detections/rules/{rule_id}
   *
   * Compatibility update endpoint.
   */
  updateDetectionRuleCompatibility(
    ruleId: string,
    payload: DetectionRuleUpdateRequest,
  ): Promise<DetectionRule> {
    return request<DetectionRule>(
      `${DETECTION_RULES_PATH}/${encodeURIComponent(
        requireId(
          ruleId,
          "Detection rule ID",
        ),
      )}`,
      {
        method: "PATCH",
        headers: {
          "Content-Type":
            "application/json",
        },
        body: JSON.stringify(payload),
      },
    );
  },


  /**
   * POST /api/v1/detections/{rule_id}/enable
   */
  enableDetectionRule(
    ruleId: string,
  ): Promise<DetectionRule> {
    return request<DetectionRule>(
      `${detectionRulePath(ruleId)}/enable`,
      {
        method: "POST",
      },
    );
  },


  /**
   * POST /api/v1/detections/{rule_id}/disable
   */
  disableDetectionRule(
    ruleId: string,
  ): Promise<DetectionRule> {
    return request<DetectionRule>(
      `${detectionRulePath(ruleId)}/disable`,
      {
        method: "POST",
      },
    );
  },


  /**
   * Enable or disable a Detection rule.
   */
  setDetectionRuleEnabled(
    ruleId: string,
    enabled: boolean,
  ): Promise<DetectionRule> {
    return enabled
      ? this.enableDetectionRule(ruleId)
      : this.disableDetectionRule(ruleId);
  },


  /**
   * DELETE /api/v1/detections/{rule_id}
   *
   * Backend returns 204 No Content.
   */
  async deleteDetectionRule(
    ruleId: string,
  ): Promise<void> {
    await request<void>(
      detectionRulePath(ruleId),
      {
        method: "DELETE",
      },
    );
  },


  /**
   * GET /api/v1/detections/results
   *
   * Backend owns filtering and pagination.
   */
  listDetectionResults(
    params: DetectionResultListParams = {},
  ): Promise<DetectionResultListResponse> {
    return request<DetectionResultListResponse>(
      detectionResultsPath(params),
    );
  },


  /**
   * GET /api/v1/detections/results/{detection_id}
   */
  getDetectionResult(
    detectionId: string,
  ): Promise<DetectionResult> {
    return request<DetectionResult>(
      detectionResultPath(detectionId),
    );
  },


  /* ========================================================================
   * MITRE ATT&CK
   * ====================================================================== */

  /**
   * GET /api/v1/mitre
   *
   * Read-only ATT&CK overview.
   */
  mitreOverview(): Promise<MitreOverviewResponse> {
    return request<MitreOverviewResponse>(
      MITRE_BASE_PATH,
    );
  },

  /**
   * GET /api/v1/mitre/statistics
   */
  mitreStatistics(): Promise<MitreStatisticsResponse> {
    return request<MitreStatisticsResponse>(
      MITRE_STATISTICS_PATH,
    );
  },

  /**
   * GET /api/v1/mitre/coverage
   *
   * SentinelSIEM Detection → MITRE coverage.
   */
  mitre(): Promise<MitreCoverage> {
    return request<MitreCoverage>(
      MITRE_COVERAGE_PATH,
    );
  },

  /**
   * Compatibility alias for the coverage operation.
   */
  mitreCoverage(): Promise<MitreCoverage> {
    return request<MitreCoverage>(
      MITRE_COVERAGE_PATH,
    );
  },

  /**
   * GET /api/v1/mitre/coverage/tactics
   */
  mitreTacticCoverage():
    Promise<MitreTacticCoverageListResponse> {
    return request<MitreTacticCoverageListResponse>(
      MITRE_COVERAGE_TACTICS_PATH,
    );
  },

  /**
   * GET /api/v1/mitre/analytics
   */
  mitreAnalytics(): Promise<MitreAnalytics> {
    return request<MitreAnalytics>(
      MITRE_ANALYTICS_PATH,
    );
  },

  /**
   * GET /api/v1/mitre/matrix
   */
  mitreMatrix(): Promise<MitreMatrix> {
    return request<MitreMatrix>(
      MITRE_MATRIX_PATH,
    );
  },

  /**
   * GET /api/v1/mitre/tactics
   */
  mitreTactics(): Promise<MitreTacticsTransportResponse> {
    return request<MitreTacticsTransportResponse>(
      MITRE_TACTICS_PATH,
    );
  },

  /**
   * GET /api/v1/mitre/platforms
   */
  mitrePlatforms(): Promise<MitrePlatformsTransportResponse> {
    return request<MitrePlatformsTransportResponse>(
      MITRE_PLATFORMS_PATH,
    );
  },

  /**
   * GET /api/v1/mitre/techniques
   *
   * Backend owns filtering and pagination.
   */
  mitreTechniques(
    params: MitreTechniqueQuery = {},
  ): Promise<MitreTechniquesTransportResponse> {
    return request<MitreTechniquesTransportResponse>(
      mitreTechniquesPath(params),
    );
  },

  /**
   * GET /api/v1/mitre/techniques/{technique_id}
   */
  mitreTechnique(
    techniqueId: string,
  ): Promise<MitreTechnique> {
    return request<MitreTechnique>(
      mitreTechniquePath(techniqueId),
    );
  },

  /**
   * GET /api/v1/mitre/techniques/{technique_id}/sub-techniques
   */
  mitreSubTechniques(
    techniqueId: string,
  ): Promise<MitreSubTechniquesTransportResponse> {
    return request<MitreSubTechniquesTransportResponse>(
      mitreTechniqueSubTechniquesPath(
        techniqueId,
      ),
    );
  },

  /**
   * GET /api/v1/mitre/techniques/{technique_id}/detail
   */
  mitreTechniqueDetail(
    techniqueId: string,
  ): Promise<MitreTechniqueDetail> {
    return request<MitreTechniqueDetail>(
      mitreTechniqueDetailPath(
        techniqueId,
      ),
    );
  },

  /**
   * GET /api/v1/mitre/techniques/{technique_id}/relationships
   */
  mitreTechniqueRelationships(
    techniqueId: string,
  ): Promise<MitreTechniqueRelationships> {
    return request<MitreTechniqueRelationships>(
      mitreTechniqueRelationshipsPath(
        techniqueId,
      ),
    );
  },

  /**
   * GET /api/v1/mitre/techniques/{technique_id}/detections
   *
   * SentinelSIEM intelligence, separate from ATT&CK knowledge.
   */
  mitreTechniqueDetections(
    techniqueId: string,
  ): Promise<Record<string, unknown>[]> {
    return request<Record<string, unknown>[]>(
      mitreTechniqueDetectionsPath(
        techniqueId,
      ),
    );
  },

  /**
   * GET /api/v1/mitre/techniques/{technique_id}/events
   */
  mitreTechniqueEvents(
    techniqueId: string,
  ): Promise<Record<string, unknown>[]> {
    return request<Record<string, unknown>[]>(
      mitreTechniqueEventsPath(
        techniqueId,
      ),
    );
  },

  /**
   * GET /api/v1/mitre/techniques/{technique_id}/alerts
   */
  mitreTechniqueAlerts(
    techniqueId: string,
  ): Promise<Record<string, unknown>[]> {
    return request<Record<string, unknown>[]>(
      mitreTechniqueAlertsPath(
        techniqueId,
      ),
    );
  },

  /**
   * GET /api/v1/mitre/techniques/{technique_id}/incidents
   */
  mitreTechniqueIncidents(
    techniqueId: string,
  ): Promise<Record<string, unknown>[]> {
    return request<Record<string, unknown>[]>(
      mitreTechniqueIncidentsPath(
        techniqueId,
      ),
    );
  },

  /**
   * GET /api/v1/mitre/techniques/{technique_id}/iocs
   */
  mitreTechniqueIocs(
    techniqueId: string,
  ): Promise<Record<string, unknown>[]> {
    return request<Record<string, unknown>[]>(
      mitreTechniqueIocsPath(
        techniqueId,
      ),
    );
  },

  /**
   * ------------------------------------------------------------------------
   * SentinelSIEM Detection → MITRE mapping capability
   * ------------------------------------------------------------------------
   *
   * These endpoints are operational mapping APIs, NOT ATT&CK knowledge CRUD.
   */

  /**
   * GET /api/v1/mitre/mappings
   */
  mitreMappings(): Promise<MitreMapping[]> {
    return request<MitreMapping[]>(
      MITRE_MAPPINGS_PATH,
    );
  },

  /**
   * POST /api/v1/mitre/mappings
   *
   * Creates a SentinelSIEM detection-to-technique mapping.
   */
  createMitreMapping(
    payload: MitreMappingCreateTransportRequest,
  ): Promise<MitreMapping> {
    return request<MitreMapping>(
      MITRE_MAPPINGS_PATH,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify(
          payload,
        ),
      },
    );
  },

  /**
   * DELETE /api/v1/mitre/mappings/{mapping_id}
   *
   * Deletes a SentinelSIEM detection-to-technique mapping.
   */
  async deleteMitreMapping(
    mappingId: string,
  ): Promise<void> {
    await request<void>(
      mitreMappingPath(
        mappingId,
      ),
      {
        method: "DELETE",
      },
    );
  },

  /* ========================================================================
   * User Management
   * ====================================================================== */

  listUsers(
    params?: UserListParams,
  ): Promise<UserListResponse> {
    return request<UserListResponse>(
      usersPath(params),
    );
  },


  getUserStatistics():
    Promise<UserStatistics> {
    return request<UserStatistics>(
      USER_STATISTICS_PATH,
    );
  },


  getUser(
    userId: string,
  ): Promise<User> {
    return request<User>(
      userPath(userId),
    );
  },


  createUser(
    payload: CreateUserRequest,
  ): Promise<User> {
    return request<User>(
      USERS_BASE_PATH,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify(payload),
      },
    );
  },


  updateUser(
    userId: string,
    payload: UpdateUserRequest,
  ): Promise<User> {
    return request<User>(
      userPath(userId),
      {
        method: "PATCH",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify(payload),
      },
    );
  },


  changeUserRole(
    userId: string,
    payload: ChangeRoleRequest,
  ): Promise<User> {
    return request<User>(
      userRolePath(userId),
      {
        method: "PATCH",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify(payload),
      },
    );
  },


  setUserActive(
    userId: string,
    payload: SetActiveRequest,
  ): Promise<User> {
    return request<User>(
      userActivePath(userId),
      {
        method: "PATCH",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify(payload),
      },
    );
  },


  setUserLocked(
    userId: string,
    payload: SetLockedRequest,
  ): Promise<User> {
    return request<User>(
      userLockPath(userId),
      {
        method: "PATCH",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify(payload),
      },
    );
  },


  setForcePasswordChange(
    userId: string,
    payload: SetForcePasswordChangeRequest,
  ): Promise<User> {
    return request<User>(
      userForcePasswordChangePath(userId),
      {
        method: "PATCH",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify(payload),
      },
    );
  },


  resetUserPassword(
    userId: string,
    payload: ResetPasswordRequest,
  ): Promise<ResetPasswordResponse> {
    return request<
      ResetPasswordResponse
    >(
      userPasswordResetPath(userId),
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify(payload),
      },
    );
  },


  revokeUserSessions(
    userId: string,
  ): Promise<
    RevokeSessionsResponse
  > {
    return request<
      RevokeSessionsResponse
    >(
      userSessionsRevokePath(userId),
      {
        method: "POST",
      },
    );
  },


  deleteUser(
    userId: string,
  ): Promise<DeleteUserResponse> {
    return request<
      DeleteUserResponse
    >(
      userPath(userId),
      {
        method: "DELETE",
      },
    );
  },


  getUserAudit(
    userId: string,
    params?: {
      page?: number;
      page_size?: number;
      action?: string;
      outcome?: string;
      target_user_id?: string;
      source_ip?: string;
      date_from?: string;
      date_to?: string;
    },
  ): Promise<UserAuditListResponse> {
    const query =
      new URLSearchParams();

    if (
      params?.page !== undefined
    ) {
      query.set(
        "page",
        String(
          normalizeBoundedInteger(
            params.page,
            1,
            1000000,
            1,
          ),
        ),
      );
    }

    if (
      params?.page_size !== undefined
    ) {
      query.set(
        "page_size",
        String(
          normalizeBoundedInteger(
            params.page_size,
            1,
            USER_MAX_LIMIT,
            30,
          ),
        ),
      );
    }

    if (
      params?.action?.trim()
    ) {
      query.set(
        "action",
        params.action.trim(),
      );
    }

    if (
      params?.outcome?.trim()
    ) {
      query.set(
        "outcome",
        params.outcome.trim(),
      );
    }

    if (
      params?.target_user_id?.trim()
    ) {
      query.set(
        "target_user_id",
        params.target_user_id.trim(),
      );
    }

    if (
      params?.source_ip?.trim()
    ) {
      query.set(
        "source_ip",
        params.source_ip.trim(),
      );
    }

    if (
      params?.date_from?.trim()
    ) {
      query.set(
        "date_from",
        params.date_from.trim(),
      );
    }

    if (
      params?.date_to?.trim()
    ) {
      query.set(
        "date_to",
        params.date_to.trim(),
      );
    }

    const queryString =
      query.toString();

    const basePath =
      userAuditPath(userId);

    return request<UserAuditListResponse>(
      queryString
        ? `${basePath}?${queryString}`
        : basePath,
    );
  },


  /* ========================================================================
   * Global Audit
   * ====================================================================== */

  async listAuditLogs(
    params?: AuditListParams,
  ): Promise<AuditListResponse> {
    const raw =
      await request<
        RawAuditListResponse
      >(
        auditLogsPath(params),
      );

    return normalizeAuditListResponse(
      raw,
    );
  },


  async getAuditStatistics(
    params?: AuditStatisticsParams,
  ): Promise<AuditStatistics> {
    const raw =
      await request<
        Partial<AuditStatistics>
      >(
        auditStatisticsPath(params),
      );

    return normalizeAuditStatistics(raw);
  },


  async getAuditEvent(
    eventId: string,
  ): Promise<AuditEvent> {
    const raw =
      await request<RawAuditEvent>(
        auditPath(eventId),
      );

    return normalizeAuditEvent(raw);
  },


  async getRelatedAuditEvents(
    eventId: string,
  ): Promise<
    AuditRelatedEventListResponse
  > {
    const raw =
      await request<
        RawAuditRelatedResponse
      >(
        auditRelatedPath(eventId),
      );

    return normalizeAuditRelatedResponse(
      raw,
    );
  },


  async exportAuditLogs(
    params?: AuditExportParams,
  ): Promise<AuditExportResponse> {
    const raw =
      await request<
        RawAuditExportResponse
      >(
        auditExportPath(params),
      );

    return normalizeAuditExportResponse(
      raw,
    );
  },


  /* ========================================================================
   * Assets
   * ====================================================================== */

  listAssets(
    params?: AssetListParams,
  ): Promise<AssetListResponse> {
    return request<AssetListResponse>(
      assetsPath(params),
    );
  },


  getAsset(
    assetId: string,
  ): Promise<Asset> {
    return request<Asset>(
      assetPath(assetId),
    );
  },


  createAsset(
    payload: AssetCreateRequest,
  ): Promise<Asset> {
    return request<Asset>(
      ASSETS_BASE_PATH,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify(payload),
      },
    );
  },


  updateAsset(
    assetId: string,
    payload: AssetUpdateRequest,
  ): Promise<Asset> {
    return request<Asset>(
      assetPath(assetId),
      {
        method: "PATCH",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify(payload),
      },
    );
  },


  /**
   * PATCH /api/v1/assets/{asset_id}/status
   *
   * Dedicated lifecycle operation for enabling/disabling an asset.
   *
   * Permission:
   *   assets:manage
   *
   * IMPORTANT:
   * Lifecycle status is intentionally separate from generic asset editing.
   */
  updateAssetStatus(
    assetId: string,
    payload: AssetStatusUpdateRequest,
  ): Promise<Asset> {
    return request<Asset>(
      `${assetPath(assetId)}/status`,
      {
        method: "PATCH",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify(payload),
      },
    );
  },


  getAssetStatistics():
    Promise<AssetStatisticsResponse> {
    return request<
      AssetStatisticsResponse
    >(
      ASSET_STATISTICS_PATH,
    );
  },

} as const;


/* ============================================================================
 * Default Export
 * ========================================================================== */

export default api;


/* ============================================================================
 * End of File
 * ============================================================================
 */