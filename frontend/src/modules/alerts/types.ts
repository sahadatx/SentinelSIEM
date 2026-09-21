import type { Pagination } from "../../types/api";


/* ==========================================================================
 * SentinelSIEM — Alerts Module
 * Type Definitions
 *
 * FINAL ALERT MANAGEMENT CONTRACT
 *
 * Covers:
 * - Alert list
 * - Alert details
 * - Alert lifecycle
 * - Alert assignment
 * - Alert audit history
 * - Alert filtering
 * - Pagination
 * - KPI statistics
 * ========================================================================== */


/* ==========================================================================
 * ALERT STATUS
 * ========================================================================== */

export type AlertStatus =
  | "new"
  | "acknowledged"
  | "investigating"
  | "escalated"
  | "resolved"
  | "closed"
  | "suppressed";


/* ==========================================================================
 * ALERT SOURCE TYPE
 * ========================================================================== */

export type AlertSourceType =
  | "detection"
  | "correlation";


/* ==========================================================================
 * ALERT SEVERITY
 * ========================================================================== */

export type AlertSeverity =
  | "info"
  | "low"
  | "medium"
  | "high"
  | "critical";


/* ==========================================================================
 * ALERT
 * ========================================================================== */

export interface Alert {
  alert_id: string;

  source_type: AlertSourceType;

  source_id: string;

  rule_id: string;

  title: string;

  description: string;

  severity: AlertSeverity;

  risk_score: number;

  priority: string;

  status: AlertStatus;

  evidence_ids: string[];

  asset_id: string | null;

  user_id: string | null;

  occurrence_count: number;

  first_seen_at: string;

  last_seen_at: string;

  /*
   * Lifecycle timestamps are optional because test fixtures,
   * partial API payloads, and older persisted records may omit them.
   *
   * When supplied by the backend they remain nullable.
   */
  acknowledged_at?: string | null;

  investigating_at?: string | null;

  escalated_at?: string | null;

  resolved_at?: string | null;

  closed_at?: string | null;

  suppressed_at?: string | null;

  sla_due_at?: string | null;

  updated_at: string;

  assigned_to: string | null;

  ownership_group: string | null;
}


/* ==========================================================================
 * ALERT LIST RESPONSE
 * ========================================================================== */

export interface AlertListResponse {
  items: Alert[];

  pagination: Pagination;
}


/* ==========================================================================
 * ALERT AUDIT ENTRY
 * ========================================================================== */

export interface AlertAuditEntry {
  audit_id: string;

  alert_id: string;

  action: string;

  actor: string;

  from_status: AlertStatus | null;

  to_status: AlertStatus | null;

  reason: string;

  created_at: string;
}


/* ==========================================================================
 * ALERT TRANSITION REQUEST
 * ========================================================================== */

export interface AlertTransitionRequest {
  status: AlertStatus;

  reason?: string;
}


/* ==========================================================================
 * ALERT ASSIGNMENT REQUEST
 * ========================================================================== */

export interface AlertAssignmentRequest {
  assignee?: string | null;

  ownership_group?: string | null;
}


/* ==========================================================================
 * ALERT FILTERS
 *
 * Backend-supported operational filters.
 * ========================================================================== */

export interface AlertFilters {
  query?: string;

  status?: AlertStatus;

  severity?: AlertSeverity;

  priority?: string;

  source_type?: AlertSourceType;

  source_id?: string;

  rule_id?: string;

  assigned_to?: string;

  ownership_group?: string;

  start_time?: string;

  end_time?: string;
}


/* ==========================================================================
 * ALERT LIST PARAMETERS
 * ========================================================================== */

export interface AlertListParams
  extends AlertFilters {
  page?: number;

  page_size?: number;
}


/* ==========================================================================
 * ALERT KPI STATISTICS
 *
 * Used by the Alerts page KPI cards.
 *
 * The values are intentionally frontend-neutral.
 * The backend can provide these directly in the future.
 * ========================================================================== */

export interface AlertStatistics {
  total: number;

  new: number;

  critical: number;

  escalated: number;

  acknowledged: number;

  investigating: number;

  resolved: number;

  suppressed?: number;
}


/* ==========================================================================
 * ALERT LIFECYCLE ACTION
 *
 * UI representation of a valid transition.
 * ========================================================================== */

export interface AlertLifecycleAction {
  status: AlertStatus;

  label: string;

  disabled?: boolean;
}


/* ==========================================================================
 * ALERT DETAILS VIEW MODEL
 *
 * Drawer-specific state.
 * ========================================================================== */

export interface AlertDetailsState {
  alert: Alert | null;

  audit: AlertAuditEntry[];

  loading: boolean;

  auditLoading: boolean;

  error: string | null;

  auditError: string | null;
}


/* ==========================================================================
 * ALERT TABLE SORT
 * ========================================================================== */

export type AlertSortField =
  | "severity"
  | "title"
  | "rule_id"
  | "source_id"
  | "status"
  | "occurrence_count"
  | "assigned_to"
  | "last_seen_at";


export type AlertSortDirection =
  | "asc"
  | "desc";


export interface AlertSort {
  field: AlertSortField;

  direction: AlertSortDirection;
}


/* ==========================================================================
 * ALERT FILTER OPTIONS
 *
 * Dynamic values used by operational filter controls.
 * ========================================================================== */

export interface AlertFilterOptions {
  statuses: AlertStatus[];

  severities: AlertSeverity[];

  priorities: string[];

  source_types: AlertSourceType[];

  sources: string[];

  rules: string[];

  assignees: string[];

  ownership_groups: string[];
}


/* ==========================================================================
 * DEFAULT ALERT STATUS VALUES
 * ========================================================================== */

export const DEFAULT_ALERT_STATUSES: AlertStatus[] = [
  "new",
  "acknowledged",
  "investigating",
  "escalated",
  "resolved",
  "closed",
  "suppressed",
];


/* ==========================================================================
 * DEFAULT ALERT SEVERITY VALUES
 * ========================================================================== */

export const DEFAULT_ALERT_SEVERITIES: AlertSeverity[] = [
  "info",
  "low",
  "medium",
  "high",
  "critical",
];


/* ==========================================================================
 * DEFAULT ALERT SOURCE TYPES
 * ========================================================================== */

export const DEFAULT_ALERT_SOURCE_TYPES: AlertSourceType[] = [
  "detection",
  "correlation",
];


/* ==========================================================================
 * DEFAULT ALERT FILTER OPTIONS
 *
 * Provides a complete valid object for UI initialization.
 * ========================================================================== */

export const DEFAULT_ALERT_FILTER_OPTIONS: AlertFilterOptions = {
  statuses: [
    ...DEFAULT_ALERT_STATUSES,
  ],

  severities: [
    ...DEFAULT_ALERT_SEVERITIES,
  ],

  priorities: [],

  source_types: [
    ...DEFAULT_ALERT_SOURCE_TYPES,
  ],

  sources: [],

  rules: [],

  assignees: [],

  ownership_groups: [],
};


/* ==========================================================================
 * LIFECYCLE TRANSITIONS
 *
 * These values mirror backend AlertLifecycle rules.
 *
 * NEW
 *   -> acknowledged
 *   -> suppressed
 *
 * ACKNOWLEDGED
 *   -> investigating
 *   -> escalated
 *   -> resolved
 *
 * INVESTIGATING
 *   -> escalated
 *   -> resolved
 *
 * ESCALATED
 *   -> investigating
 *   -> resolved
 *
 * RESOLVED
 *   -> closed
 *   -> investigating
 *
 * CLOSED
 *   -> none
 *
 * SUPPRESSED
 *   -> none
 * ========================================================================== */

export const ALERT_LIFECYCLE_TRANSITIONS: Record<
  AlertStatus,
  AlertStatus[]
> = {
  new: [
    "acknowledged",
    "suppressed",
  ],

  acknowledged: [
    "investigating",
    "escalated",
    "resolved",
  ],

  investigating: [
    "escalated",
    "resolved",
  ],

  escalated: [
    "investigating",
    "resolved",
  ],

  resolved: [
    "closed",
    "investigating",
  ],

  closed: [],

  suppressed: [],
};


/* ==========================================================================
 * LIFECYCLE LABELS
 * ========================================================================== */

export const ALERT_STATUS_LABELS: Record<
  AlertStatus,
  string
> = {
  new: "New",

  acknowledged:
    "Acknowledged",

  investigating:
    "Investigating",

  escalated:
    "Escalated",

  resolved:
    "Resolved",

  closed:
    "Closed",

  suppressed:
    "Suppressed",
};


/* ==========================================================================
 * HELPERS
 * ========================================================================== */

/**
 * Return valid next lifecycle states.
 *
 * The backend remains authoritative.
 * This helper controls only UI presentation.
 */
export function getAlertLifecycleActions(
  status: AlertStatus,
): AlertStatus[] {
  return [
    ...(
      ALERT_LIFECYCLE_TRANSITIONS[
        status
      ] ?? []
    ),
  ];
}


/**
 * Return a human-readable lifecycle action label.
 */
export function getAlertLifecycleLabel(
  status: AlertStatus,
): string {
  return (
    ALERT_STATUS_LABELS[
      status
    ] ?? status
  );
}


/**
 * Check whether a lifecycle transition is allowed
 * by the frontend model.
 *
 * The backend must still validate the transition.
 */
export function canTransitionAlert(
  from: AlertStatus,
  to: AlertStatus,
): boolean {
  return (
    ALERT_LIFECYCLE_TRANSITIONS[
      from
    ]?.includes(to) ?? false
  );
}


/**
 * Calculate KPI statistics from the currently
 * loaded alert dataset.
 *
 * `totalOverride` is used when pagination means
 * the loaded page contains fewer records than
 * the backend total.
 */
export function calculateAlertStatistics(
  alerts: Alert[],
  totalOverride?: number,
): AlertStatistics {
  const statistics: AlertStatistics = {
    total:
      totalOverride ??
      alerts.length,

    new: 0,

    critical: 0,

    escalated: 0,

    acknowledged: 0,

    investigating: 0,

    resolved: 0,

    suppressed: 0,
  };


  for (const alert of alerts) {
    switch (
      alert.status
    ) {
      case "new":
        statistics.new += 1;
        break;

      case "acknowledged":
        statistics.acknowledged += 1;
        break;

      case "investigating":
        statistics.investigating += 1;
        break;

      case "escalated":
        statistics.escalated += 1;
        break;

      case "resolved":
        statistics.resolved += 1;
        break;

      case "suppressed":
        statistics.suppressed =
          (
            statistics.suppressed ??
            0
          ) + 1;

        break;

      case "closed":
        break;

      default:
        break;
    }


    if (
      alert.severity ===
      "critical"
    ) {
      statistics.critical += 1;
    }
  }


  return statistics;
}


/* ==========================================================================
 * TYPE GUARDS
 * ========================================================================== */

export function isAlertStatus(
  value: string,
): value is AlertStatus {
  return (
    DEFAULT_ALERT_STATUSES.includes(
      value as AlertStatus,
    )
  );
}


export function isAlertSeverity(
  value: string,
): value is AlertSeverity {
  return (
    DEFAULT_ALERT_SEVERITIES.includes(
      value as AlertSeverity,
    )
  );
}


export function isAlertSourceType(
  value: string,
): value is AlertSourceType {
  return (
    DEFAULT_ALERT_SOURCE_TYPES.includes(
      value as AlertSourceType,
    )
  );
}


/* ==========================================================================
 * DEFAULT EXPORT
 *
 * `Alert` is an interface/type, not a runtime value.
 *
 * With `verbatimModuleSyntax: true`, a type-only default export
 * must therefore use `export type`.
 * ========================================================================== */

export type {
  Alert as default,
};