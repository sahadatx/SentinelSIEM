import { api as sharedApi } from "../../services/api";

import type {
  Alert,
  AlertAuditEntry,
  AlertAssignmentRequest,
  AlertFilterOptions,
  AlertListParams,
  AlertListResponse,
  AlertStatistics,
  AlertTransitionRequest,
} from "./types";

/* ==========================================================================
 * CONSTANTS
 * ========================================================================== */

const DEFAULT_PAGE = 1;
const DEFAULT_PAGE_SIZE = 25;

/* ==========================================================================
 * BACKEND RESPONSE SHAPES
 * ========================================================================== */

/**
 * Backend alert representation.
 *
 * The backend may return the assignee field as either:
 *
 *   assignee
 *
 * or:
 *
 *   assigned_to
 *
 * Frontend normalizes both into:
 *
 *   assigned_to
 */
interface BackendAlert {
  alert_id: string;

  source_type: Alert["source_type"];

  source_id: string;

  rule_id: string;

  title: string;

  description: string;

  severity: Alert["severity"];

  risk_score: number;

  priority: string;

  status: Alert["status"];

  evidence_ids: string[];

  asset_id: string | null;

  user_id: string | null;

  occurrence_count: number;

  first_seen_at: string;

  last_seen_at: string;

  acknowledged_at?: string | null;

  investigating_at?: string | null;

  escalated_at?: string | null;

  resolved_at?: string | null;

  closed_at?: string | null;

  suppressed_at?: string | null;

  sla_due_at?: string | null;

  updated_at: string;

  assignee?: string | null;

  assigned_to?: string | null;

  ownership_group?: string | null;
}

interface BackendAlertListResponse {
  items: BackendAlert[];

  pagination?: {
    page?: number;

    page_size?: number;

    total?: number;
  };
}

interface BackendAlertAuditEntry {
  audit_id: string;

  alert_id: string;

  action: string;

  actor: string;

  from_status: AlertAuditEntry["from_status"];

  to_status: AlertAuditEntry["to_status"];

  reason?: string | null;

  created_at: string;
}

interface BackendAlertAuditResponse {
  items?: BackendAlertAuditEntry[];
}

/* ==========================================================================
 * NORMALIZATION HELPERS
 * ========================================================================== */

/**
 * Normalize a single backend alert into the frontend Alert contract.
 */
function normalizeAlert(
  value: BackendAlert,
): Alert {
  return {
    alert_id: value.alert_id,

    source_type: value.source_type,

    source_id: value.source_id,

    rule_id: value.rule_id,

    title: value.title,

    description: value.description,

    severity: value.severity,

    risk_score: value.risk_score,

    priority: value.priority,

    status: value.status,

    evidence_ids: Array.isArray(
      value.evidence_ids,
    )
      ? value.evidence_ids
      : [],

    asset_id:
      value.asset_id ?? null,

    user_id:
      value.user_id ?? null,

    occurrence_count:
      value.occurrence_count,

    first_seen_at:
      value.first_seen_at,

    last_seen_at:
      value.last_seen_at,

    acknowledged_at:
      value.acknowledged_at ?? null,

    investigating_at:
      value.investigating_at ?? null,

    escalated_at:
      value.escalated_at ?? null,

    resolved_at:
      value.resolved_at ?? null,

    closed_at:
      value.closed_at ?? null,

    suppressed_at:
      value.suppressed_at ?? null,

    sla_due_at:
      value.sla_due_at ?? null,

    updated_at:
      value.updated_at,

    /**
     * Backend canonical field is currently
     * `assignee`.
     *
     * `assigned_to` remains supported for
     * compatibility with older responses.
     */
    assigned_to:
      value.assignee ??
      value.assigned_to ??
      null,

    ownership_group:
      value.ownership_group ??
      null,
  };
}

/**
 * Normalize paginated alert responses.
 */
function normalizeAlertListResponse(
  response: BackendAlertListResponse,
): AlertListResponse {
  const pagination =
    response?.pagination ?? {};

  const page =
    typeof pagination.page === "number" &&
    Number.isFinite(pagination.page)
      ? pagination.page
      : DEFAULT_PAGE;

  const pageSize =
    typeof pagination.page_size === "number" &&
    Number.isFinite(pagination.page_size)
      ? pagination.page_size
      : DEFAULT_PAGE_SIZE;

  const total =
    typeof pagination.total === "number" &&
    Number.isFinite(pagination.total)
      ? pagination.total
      : 0;

  return {
    items: Array.isArray(
      response?.items,
    )
      ? response.items.map(
          normalizeAlert,
        )
      : [],

    pagination: {
      page,

      page_size: pageSize,

      total,
    },
  };
}

/**
 * Normalize one audit entry.
 */
function normalizeAlertAuditEntry(
  value: BackendAlertAuditEntry,
): AlertAuditEntry {
  return {
    audit_id:
      value.audit_id,

    alert_id:
      value.alert_id,

    action:
      value.action,

    actor:
      value.actor,

    from_status:
      value.from_status ?? null,

    to_status:
      value.to_status ?? null,

    reason:
      value.reason ?? "",

    created_at:
      value.created_at,
  };
}

/**
 * Backend audit endpoint may return either:
 *
 *   AlertAuditEntry[]
 *
 * or:
 *
 *   { items: AlertAuditEntry[] }
 */
function normalizeAlertAuditResponse(
  response:
    | BackendAlertAuditEntry[]
    | BackendAlertAuditResponse,
): AlertAuditEntry[] {
  if (Array.isArray(response)) {
    return response.map(
      normalizeAlertAuditEntry,
    );
  }

  if (
    response &&
    Array.isArray(response.items)
  ) {
    return response.items.map(
      normalizeAlertAuditEntry,
    );
  }

  return [];
}

/* ==========================================================================
 * SHARED API CLIENT
 * ========================================================================== */

const apiClient = sharedApi;

/* ==========================================================================
 * ALERTS API
 * ========================================================================== */

export const alertsApi = {
  /* ------------------------------------------------------------------------
   * LIST ALERTS
   *
   * GET /api/v1/alerts
   *
   * This method is intentionally kept as the simple unfiltered list
   * operation.
   * ------------------------------------------------------------------------ */

  async list(
    page = DEFAULT_PAGE,
    pageSize = DEFAULT_PAGE_SIZE,
  ): Promise<AlertListResponse> {
    const response =
      await apiClient.alerts(
        page,
        pageSize,
      );

    return normalizeAlertListResponse(
      response as BackendAlertListResponse,
    );
  },

  /* ------------------------------------------------------------------------
   * FILTERED ALERT LIST
   *
   * GET /api/v1/alerts
   *
   * All supplied filters are forwarded to the backend through
   * alertsWithFilters().
   *
   * IMPORTANT:
   *
   * There is intentionally NO fallback to list().
   *
   * The backend remains the source of truth for:
   *
   * - filtering
   * - pagination
   * - total count
   * - returned alert records
   * ------------------------------------------------------------------------ */

  async listFiltered(
    params: AlertListParams = {},
  ): Promise<AlertListResponse> {
    const response =
      await apiClient.alertsWithFilters(
        params,
      );

    return normalizeAlertListResponse(
      response as BackendAlertListResponse,
    );
  },

  /* ------------------------------------------------------------------------
   * ALERT STATISTICS / KPI
   *
   * GET /api/v1/alerts/statistics
   *
   * The backend is authoritative for all Alert KPI values.
   *
   * No frontend counting/calculation is performed here.
   * ------------------------------------------------------------------------ */

  async statistics(
    params: Omit<
      AlertListParams,
      "page" | "page_size"
    > = {},
  ): Promise<AlertStatistics> {
    return apiClient.getAlertStatistics(
      params,
    );
  },

  /* ------------------------------------------------------------------------
   * ALERT FILTER OPTIONS
   *
   * GET /api/v1/alerts/filter-options
   *
   * The backend is authoritative for all dropdown/filter option values.
   *
   * No frontend-generated option catalogue is used here.
   * ------------------------------------------------------------------------ */

  async filterOptions(): Promise<AlertFilterOptions> {
    return apiClient.getAlertFilterOptions();
  },

  /* ------------------------------------------------------------------------
   * GET SINGLE ALERT
   *
   * GET /api/v1/alerts/{alert_id}
   * ------------------------------------------------------------------------ */

  async get(
    alertId: string,
  ): Promise<Alert> {
    const response =
      await apiClient.getAlert(
        alertId,
      );

    return normalizeAlert(
      response as BackendAlert,
    );
  },

  /* ------------------------------------------------------------------------
   * GET ALERT AUDIT HISTORY
   *
   * GET /api/v1/alerts/{alert_id}/audit
   * ------------------------------------------------------------------------ */

  async audit(
    alertId: string,
  ): Promise<AlertAuditEntry[]> {
    const response =
      await apiClient.getAlertAudit(
        alertId,
      );

    return normalizeAlertAuditResponse(
      response as
        | BackendAlertAuditEntry[]
        | BackendAlertAuditResponse,
    );
  },

  /* ------------------------------------------------------------------------
   * CHANGE ALERT STATUS
   *
   * POST /api/v1/alerts/{alert_id}/transition
   *
   * The backend is authoritative for lifecycle transition validation.
   *
   * The frontend must NOT maintain its own transition matrix.
   * ------------------------------------------------------------------------ */

  async transition(
    alertId: string,
    request: AlertTransitionRequest,
  ): Promise<Alert> {
    const response =
      await apiClient.transitionAlert(
        alertId,
        request,
      );

    return normalizeAlert(
      response as BackendAlert,
    );
  },

  /* ------------------------------------------------------------------------
   * ASSIGN / REASSIGN ALERT
   *
   * PATCH /api/v1/alerts/{alert_id}/assignment
   *
   * The request contains the selected user's UUID.
   *
   * Role validation is performed by the backend.
   * ------------------------------------------------------------------------ */

  async assign(
    alertId: string,
    request: AlertAssignmentRequest,
  ): Promise<Alert> {
    const response =
      await apiClient.assignAlert(
        alertId,
        request,
      );

    return normalizeAlert(
      response as BackendAlert,
    );
  },

  /* ------------------------------------------------------------------------
   * LIFECYCLE HELPERS
   *
   * These helpers all delegate to transition().
   *
   * They do NOT implement lifecycle validation locally.
   * ------------------------------------------------------------------------ */

  async acknowledge(
    alertId: string,
    reason = "",
  ): Promise<Alert> {
    return this.transition(
      alertId,
      {
        status: "acknowledged",
        reason,
      },
    );
  },

  async investigate(
    alertId: string,
    reason = "",
  ): Promise<Alert> {
    return this.transition(
      alertId,
      {
        status: "investigating",
        reason,
      },
    );
  },

  async escalate(
    alertId: string,
    reason = "",
  ): Promise<Alert> {
    return this.transition(
      alertId,
      {
        status: "escalated",
        reason,
      },
    );
  },

  async resolve(
    alertId: string,
    reason = "",
  ): Promise<Alert> {
    return this.transition(
      alertId,
      {
        status: "resolved",
        reason,
      },
    );
  },

  async close(
    alertId: string,
    reason = "",
  ): Promise<Alert> {
    return this.transition(
      alertId,
      {
        status: "closed",
        reason,
      },
    );
  },

  async suppress(
    alertId: string,
    reason = "",
  ): Promise<Alert> {
    return this.transition(
      alertId,
      {
        status: "suppressed",
        reason,
      },
    );
  },
};

/* ==========================================================================
 * NAMED EXPORTS
 * ========================================================================== */

/**
 * List alerts without filters.
 */
export function listAlerts(
  page = DEFAULT_PAGE,
  pageSize = DEFAULT_PAGE_SIZE,
): Promise<AlertListResponse> {
  return alertsApi.list(
    page,
    pageSize,
  );
}

/**
 * List alerts using backend filters.
 */
export function listFilteredAlerts(
  params: AlertListParams = {},
): Promise<AlertListResponse> {
  return alertsApi.listFiltered(
    params,
  );
}

/**
 * Retrieve backend-authoritative Alert KPI/statistics.
 */
export function getAlertStatistics(
  params: Omit<
    AlertListParams,
    "page" | "page_size"
  > = {},
): Promise<AlertStatistics> {
  return alertsApi.statistics(
    params,
  );
}

/**
 * Retrieve backend-authoritative Alert filter options.
 */
export function getAlertFilterOptions(): Promise<AlertFilterOptions> {
  return alertsApi.filterOptions();
}

/**
 * Retrieve a single alert.
 */
export function getAlert(
  alertId: string,
): Promise<Alert> {
  return alertsApi.get(
    alertId,
  );
}

/**
 * Retrieve alert audit history.
 */
export function getAlertAudit(
  alertId: string,
): Promise<AlertAuditEntry[]> {
  return alertsApi.audit(
    alertId,
  );
}

/**
 * Transition an alert through the backend lifecycle.
 */
export function transitionAlert(
  alertId: string,
  request: AlertTransitionRequest,
): Promise<Alert> {
  return alertsApi.transition(
    alertId,
    request,
  );
}

/**
 * Assign or reassign an alert.
 */
export function assignAlert(
  alertId: string,
  request: AlertAssignmentRequest,
): Promise<Alert> {
  return alertsApi.assign(
    alertId,
    request,
  );
}

/* ==========================================================================
 * DEFAULT EXPORT
 * ========================================================================== */

export default alertsApi;
