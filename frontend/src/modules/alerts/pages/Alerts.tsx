import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

import { Panel } from "../../../components/ui/Panel";

import { alertsApi } from "../api";

import { AlertTable } from "../components/AlertTable";

import { usersApi } from "../../users/api";

import type {
  Alert,
  AlertAssignmentRequest,
  AlertFilterOptions,
  AlertFilters,
  AlertListParams,
  AlertStatistics,
  AlertStatus,
  AlertTransitionRequest,
} from "../types";

import type { User } from "../../users/types";

import "../Alerts.css";


/* ==========================================================================
 * SentinelSIEM — Alerts Module
 * Alert Management Page
 *
 * FINAL OPERATIONAL IMPLEMENTATION
 *
 * Backend is authoritative for:
 * - Alert list
 * - Pagination total
 * - KPI statistics
 * - Filter options
 * - Assignment validation
 * - Lifecycle transition validation
 *
 * Table actions:
 * - View Alert
 * - Assign / Reassign
 * - Change Status
 *
 * No:
 * - Delete
 * - Edit
 * - Escalate shortcut
 * - Add Note
 * - Link Incident
 *
 * IMPORTANT:
 * - No frontend KPI calculation.
 * - No local filter-option generation.
 * - No local lifecycle transition validation.
 * - No direct fetch().
 * - All mutations go through alertsApi.
 * ========================================================================== */


/* ==========================================================================
 * CONSTANTS
 * ========================================================================== */

const DEFAULT_PAGE = 1;
const DEFAULT_PAGE_SIZE = 25;

const ASSIGNABLE_ROLES = [
  "ADMIN",
  "SECURITY_ANALYST",
  "SOC_ANALYST",
] as const;

const STATUS_OPTIONS: AlertStatus[] = [
  "acknowledged",
  "investigating",
  "escalated",
  "resolved",
  "closed",
  "suppressed",
];


/* ==========================================================================
 * TYPES
 * ========================================================================== */

interface RequestLifecycle {
  cancelled: boolean;
}

type AssignableRole =
  (typeof ASSIGNABLE_ROLES)[number];

interface ActionMenuState {
  alert: Alert;
  open: boolean;
  top: number;
  left: number;
}

interface AssignmentState {
  alert: Alert | null;
  role: AssignableRole;
  assignee: string;
}

interface StatusState {
  alert: Alert | null;
  status: AlertStatus | "";
  reason: string;
}

interface AlertStatisticsResponse {
  total: number;
  new: number;
  critical: number;
  escalated: number;
  acknowledged: number;
  investigating: number;
  resolved: number;
  suppressed?: number;
}

interface BackendAlertApi {
  statistics?: (
    params?: Omit<
      AlertListParams,
      "page" | "page_size"
    >,
  ) => Promise<
    AlertStatisticsResponse
  >;

  filterOptions?: () =>
    Promise<AlertFilterOptions>;
}


/* ==========================================================================
 * HELPERS
 * ========================================================================== */

function getErrorMessage(
  error: unknown,
): string {
  if (error instanceof Error) {
    return error.message;
  }

  if (
    typeof error === "string" &&
    error.trim()
  ) {
    return error;
  }

  return "An unexpected error occurred.";
}


function normalizeString(
  value?: string | null,
): string {
  return value?.trim() ?? "";
}


function formatUserRole(
  role?: string | null,
): string {
  const normalized = normalizeString(role);

  switch (normalized) {
    case "ADMIN":
      return "Admin";
    case "SECURITY_ANALYST":
      return "Security Analyst";
    case "SOC_ANALYST":
      return "SOC Analyst";
    case "INVESTIGATOR":
      return "Investigator";
    case "VIEWER":
      return "Viewer";
    default:
      return formatLabel(normalized || "User");
  }
}


function getUserDisplayName(
  user: User,
): string {
  return (
    normalizeString(user.display_name) ||
    normalizeString(user.username) ||
    "Unknown User"
  );
}


function getUserRole(
  user: User,
): string {
  return formatUserRole(
    user.roles?.[0]
      ? String(user.roles[0])
      : null,
  );
}


function getAssigneeLabel(
  userId: string | null | undefined,
  users: User[],
): string {
  const normalizedId =
    normalizeString(userId);

  if (!normalizedId) {
    return "Unassigned";
  }

  const user = users.find(
    (candidate) =>
      candidate.user_id === normalizedId,
  );

  if (!user) {
    return "Unknown User";
  }

  return `${getUserDisplayName(user)} — ${getUserRole(user)}`;
}


function formatLabel(
  value: string,
): string {
  return value
    .replace(
      /_/g,
      " ",
    )
    .replace(
      /\b\w/g,
      (character) =>
        character.toUpperCase(),
    );
}


function buildEmptyFilterOptions(): AlertFilterOptions {
  return {
    statuses: [],
    severities: [],
    priorities: [],
    source_types: [],
    sources: [],
    rules: [],
    assignees: [],
    ownership_groups: [],
  };
}


function buildEmptyStatistics(): AlertStatistics {
  return {
    total: 0,
    new: 0,
    critical: 0,
    escalated: 0,
    acknowledged: 0,
    investigating: 0,
    resolved: 0,
    suppressed: 0,
  };
}


function buildAlertListParams(
  filters: AlertFilters,
  page: number,
  pageSize: number,
): AlertListParams {
  const params: AlertListParams = {
    page,
    page_size: pageSize,
  };

  const query =
    normalizeString(
      filters.query,
    );

  if (query) {
    params.query = query;
  }

  if (filters.status) {
    params.status =
      filters.status;
  }

  if (filters.severity) {
    params.severity =
      filters.severity;
  }

  if (filters.priority) {
    params.priority =
      filters.priority;
  }

  if (filters.source_type) {
    params.source_type =
      filters.source_type;
  }

  const sourceId =
    normalizeString(
      filters.source_id,
    );

  if (sourceId) {
    params.source_id =
      sourceId;
  }

  const ruleId =
    normalizeString(
      filters.rule_id,
    );

  if (ruleId) {
    params.rule_id =
      ruleId;
  }

  const assignedTo =
    normalizeString(
      filters.assigned_to,
    );

  if (assignedTo) {
    params.assigned_to =
      assignedTo;
  }

  const ownershipGroup =
    normalizeString(
      filters.ownership_group,
    );

  if (ownershipGroup) {
    params.ownership_group =
      ownershipGroup;
  }

  const startTime =
    normalizeString(
      filters.start_time,
    );

  if (startTime) {
    params.start_time =
      startTime;
  }

  const endTime =
    normalizeString(
      filters.end_time,
    );

  if (endTime) {
    params.end_time =
      endTime;
  }

  return params;
}


function buildStatisticsParams(
  filters: AlertFilters,
): Omit<
  AlertListParams,
  "page" | "page_size"
> {
  return buildAlertListParams(
    filters,
    DEFAULT_PAGE,
    DEFAULT_PAGE_SIZE,
  );
}


/* ==========================================================================
 * INLINE ICONS
 * ========================================================================== */

function SearchIcon() {
  return (
    <svg
      width="17"
      height="17"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <circle
        cx="11"
        cy="11"
        r="7"
      />

      <path
        d="m20 20-4-4"
      />
    </svg>
  );
}


function RefreshIcon({
  spinning = false,
}: {
  spinning?: boolean;
}) {
  return (
    <svg
      className={
        spinning
          ? "alerts-refresh-icon is-spinning"
          : "alerts-refresh-icon"
      }
      width="17"
      height="17"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path
        d="M21 12a9 9 0 1 1-2.64-6.36"
      />

      <path
        d="M21 3v6h-6"
      />
    </svg>
  );
}


function ResetIcon() {
  return (
    <svg
      width="15"
      height="15"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path
        d="M3 12a9 9 0 1 0 3-6.7"
      />

      <path
        d="M3 4v5h5"
      />
    </svg>
  );
}


function CloseIcon() {
  return (
    <svg
      width="17"
      height="17"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M6 6l12 12" />
      <path d="M18 6 6 18" />
    </svg>
  );
}


/* ==========================================================================
 * KPI ICON
 * ========================================================================== */

function KpiIcon({
  type,
}: {
  type:
    | "total"
    | "new"
    | "critical"
    | "escalated"
    | "acknowledged"
    | "investigating"
    | "resolved";
}) {
  const common = {
    width: 22,
    height: 22,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.8,
    strokeLinecap:
      "round" as const,
    strokeLinejoin:
      "round" as const,
    "aria-hidden": true,
  };

  switch (type) {
    case "total":
      return (
        <svg {...common}>
          <path d="M4 19V5" />
          <path d="M4 19h16" />
          <path d="m7 15 3-4 3 2 5-7" />
          <circle
            cx="18"
            cy="6"
            r="1.5"
          />
        </svg>
      );

    case "new":
      return (
        <svg {...common}>
          <path d="M12 3v18" />
          <path d="M3 12h18" />
        </svg>
      );

    case "critical":
      return (
        <svg {...common}>
          <path d="M12 3 2.8 19h18.4L12 3Z" />
          <path d="M12 9v4" />
          <path d="M12 16h.01" />
        </svg>
      );

    case "escalated":
      return (
        <svg {...common}>
          <path d="M12 19V5" />
          <path d="m6 11 6-6 6 6" />
          <path d="M5 19h14" />
        </svg>
      );

    case "acknowledged":
      return (
        <svg {...common}>
          <path d="m5 12 4 4L19 6" />
        </svg>
      );

    case "investigating":
      return (
        <svg {...common}>
          <circle
            cx="11"
            cy="11"
            r="6"
          />
          <path d="m16 16 4 4" />
          <path d="M11 8v3l2 1" />
        </svg>
      );

    case "resolved":
      return (
        <svg {...common}>
          <circle
            cx="12"
            cy="12"
            r="9"
          />
          <path d="m8 12 2.7 2.7L16.5 9" />
        </svg>
      );

    default:
      return null;
  }
}


/* ==========================================================================
 * KPI CARD
 * ========================================================================== */

function KpiCard({
  label,
  value,
  icon,
  tone = "default",
  loading,
}: {
  label: string;
  value: number;
  icon:
    | "total"
    | "new"
    | "critical"
    | "escalated"
    | "acknowledged"
    | "investigating"
    | "resolved";
  tone?:
    | "default"
    | "critical"
    | "danger"
    | "warning"
    | "info"
    | "success";
  loading: boolean;
}) {
  return (
    <div
      className={
        `alerts-kpi-card alerts-kpi-card-${tone}`
      }
    >
      <div className="alerts-kpi-icon">
        <KpiIcon type={icon} />
      </div>

      <div className="alerts-kpi-content">
        <span className="alerts-kpi-card-label">
          {label}
        </span>

        <strong
          className="alerts-kpi-card-value"
          aria-live="polite"
        >
          {loading
            ? "—"
            : value.toLocaleString()}
        </strong>
      </div>
    </div>
  );
}


/* ==========================================================================
 * FILTER SELECT
 * ========================================================================== */

function FilterSelect({
  label,
  value,
  options,
  onChange,
  disabled = false,
}: {
  label: string;
  value: string;
  options: string[];
  onChange: (
    value: string,
  ) => void;
  disabled?: boolean;
}) {
  return (
    <label className="alerts-filter-control">
      <span className="alerts-filter-label">
        {label}
      </span>

      <select
        className="alerts-filter-select"
        value={value}
        disabled={disabled}
        onChange={(event) =>
          onChange(
            event.target.value,
          )
        }
      >
        <option value="">
          All
        </option>

        {(Array.isArray(options) ? options : []).map(
          (option) => (
            <option
              key={option}
              value={option}
            >
              {formatLabel(option)}
            </option>
          ),
        )}
      </select>
    </label>
  );
}


/* ==========================================================================
 * SEARCH
 * ========================================================================== */

function AssigneeFilterSelect({
  label,
  value,
  options,
  users,
  onChange,
  disabled = false,
}: {
  label: string;
  value: string;
  options: string[];
  users: User[];
  onChange: (
    value: string,
  ) => void;
  disabled?: boolean;
}) {
  return (
    <label className="alerts-filter-control">
      <span className="alerts-filter-label">
        {label}
      </span>

      <select
        className="alerts-filter-select"
        value={value}
        disabled={disabled}
        onChange={(event) =>
          onChange(
            event.target.value,
          )
        }
      >
        <option value="">
          All
        </option>

        {options.map((userId) => (
          <option
            key={userId}
            value={userId}
          >
            {getAssigneeLabel(
              userId,
              users,
            )}
          </option>
        ))}
      </select>
    </label>
  );
}


function SearchField({
  value,
  onChange,
  disabled,
}: {
  value: string;
  onChange: (
    value: string,
  ) => void;
  disabled: boolean;
}) {
  return (
    <label className="alerts-search-control">
      <span className="alerts-filter-label">
        Search
      </span>

      <div className="alerts-search-wrapper">
        <SearchIcon />

        <input
          type="search"
          className="alerts-search-input"
          placeholder="Search alerts..."
          value={value}
          disabled={disabled}
          onChange={(event) =>
            onChange(
              event.target.value,
            )
          }
          aria-label="Search alerts"
        />
      </div>
    </label>
  );
}


/* ==========================================================================
 * ACTION MENU
 * ========================================================================== */

function AlertActionMenu({
  alert,
  onView,
  onAssign,
  onStatus,
  onClose,
}: {
  alert: Alert;
  onView: (
    alert: Alert,
  ) => void;
  onAssign: (
    alert: Alert,
  ) => void;
  onStatus: (
    alert: Alert,
  ) => void;
  onClose: () => void;
}) {
  return (
    <div
      className="alerts-action-menu"
      role="menu"
      aria-label={`Actions for ${alert.title}`}
    >
      <button
        type="button"
        role="menuitem"
        onClick={() => {
          onClose();
          onView(alert);
        }}
      >
        <span aria-hidden="true">
          👁
        </span>

        <span>
          View Alert
        </span>
      </button>

      <button
        type="button"
        role="menuitem"
        onClick={() => {
          onClose();
          onAssign(alert);
        }}
      >
        <span aria-hidden="true">
          👤
        </span>

        <span>
          Assign / Reassign
        </span>
      </button>

      <button
        type="button"
        role="menuitem"
        onClick={() => {
          onClose();
          onStatus(alert);
        }}
      >
        <span aria-hidden="true">
          🔄
        </span>

        <span>
          Change Status
        </span>
      </button>
    </div>
  );
}


/* ==========================================================================
 * PAGINATION
 * ========================================================================== */

function PaginationControls({
  page,
  pageSize,
  total,
  loading,
  onPageChange,
}: {
  page: number;
  pageSize: number;
  total: number;
  loading: boolean;
  onPageChange: (
    page: number,
  ) => void;
}) {
  if (total <= 0) {
    return null;
  }

  const totalPages =
    Math.max(
      1,
      Math.ceil(
        total / pageSize,
      ),
    );

  const start =
    (page - 1) *
      pageSize +
    1;

  const end =
    Math.min(
      page * pageSize,
      total,
    );

  return (
    <div
      className="alerts-pagination"
      aria-label="Alert pagination"
    >
      <div className="alerts-pagination-content">
        <div className="alerts-pagination-info">
          <strong>
            {start.toLocaleString()}
          </strong>

          {"–"}

          <strong>
            {end.toLocaleString()}
          </strong>

          <span className="alerts-pagination-label">
            Alerts
          </span>

          <span className="alerts-pagination-separator">
            /
          </span>

          <span className="alerts-pagination-total">
            Total{" "}
            {total.toLocaleString()}
          </span>

          <span className="alerts-pagination-divider">
            •
          </span>

          <span className="alerts-pagination-page">
            Page{" "}
            <strong>
              {page}
            </strong>{" "}
            of{" "}
            <strong>
              {totalPages}
            </strong>
          </span>
        </div>

        <div className="alerts-pagination-controls">
          <button
            type="button"
            className="alerts-pagination-button"
            disabled={
              loading ||
              page <= 1
            }
            onClick={() =>
              onPageChange(
                page - 1,
              )
            }
          >
            Previous
          </button>

          <button
            type="button"
            className="alerts-pagination-button"
            disabled={
              loading ||
              page >= totalPages
            }
            onClick={() =>
              onPageChange(
                page + 1,
              )
            }
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}


/* ==========================================================================
 * DETAILS DRAWER
 * ========================================================================== */

function AlertDetailsDrawer({
  alertId,
  users,
  onClose,
}: {
  alertId: string;
  users: User[];
  onClose: () => void;
}) {
  const [
    alert,
    setAlert,
  ] = useState<Alert | null>(
    null,
  );

  const [
    audit,
    setAudit,
  ] = useState<
    Awaited<
      ReturnType<
        typeof alertsApi.audit
      >
    >
  >([]);

  const [
    loading,
    setLoading,
  ] = useState(true);

  const [
    auditLoading,
    setAuditLoading,
  ] = useState(true);

  const [
    error,
    setError,
  ] = useState<string | null>(
    null,
  );

  const [
    auditError,
    setAuditError,
  ] = useState<string | null>(
    null,
  );


  const load = useCallback(
    async (
      lifecycle: RequestLifecycle,
    ) => {
      try {
        setLoading(true);
        setError(null);

        const result =
          await alertsApi.get(
            alertId,
          );

        if (
          lifecycle.cancelled
        ) {
          return;
        }

        setAlert(result);
      } catch (err) {
        if (
          lifecycle.cancelled
        ) {
          return;
        }

        setAlert(null);

        setError(
          getErrorMessage(err),
        );
      } finally {
        if (
          !lifecycle.cancelled
        ) {
          setLoading(false);
        }
      }
    },
    [alertId],
  );


  const loadAudit = useCallback(
    async (
      lifecycle: RequestLifecycle,
    ) => {
      try {
        setAuditLoading(
          true,
        );

        setAuditError(
          null,
        );

        const result =
          await alertsApi.audit(
            alertId,
          );

        if (
          lifecycle.cancelled
        ) {
          return;
        }

        setAudit(result);
      } catch (err) {
        if (
          lifecycle.cancelled
        ) {
          return;
        }

        setAudit([]);

        setAuditError(
          getErrorMessage(err),
        );
      } finally {
        if (
          !lifecycle.cancelled
        ) {
          setAuditLoading(
            false,
          );
        }
      }
    },
    [alertId],
  );


  useEffect(() => {
    const lifecycle: RequestLifecycle = {
      cancelled: false,
    };

    void load(lifecycle);
    void loadAudit(lifecycle);

    return () => {
      lifecycle.cancelled = true;
    };
  }, [
    load,
    loadAudit,
  ]);


  const formatDate =
    (
      value?: string | null,
    ): string => {
      if (!value) {
        return "—";
      }

      const date =
        new Date(value);

      if (
        Number.isNaN(
          date.getTime(),
        )
      ) {
        return value;
      }

      return date.toLocaleString();
    };


  return (
    <>
      <button
        type="button"
        className="alerts-drawer-backdrop"
        onClick={onClose}
        aria-label="Close alert details"
      />

      <aside
        className="alerts-details-drawer"
        role="dialog"
        aria-modal="true"
        aria-label="Alert details"
      >
        <div className="alerts-details-drawer-header">
          <div className="alerts-details-drawer-heading">
            <span className="alerts-details-drawer-eyebrow">
              Alert
            </span>

            <h2 className="alerts-details-drawer-title">
              Alert Details
            </h2>

            <span className="alerts-details-drawer-id">
              {alertId}
            </span>
          </div>

          <button
            type="button"
            className="alerts-details-drawer-close"
            onClick={onClose}
            aria-label="Close alert details"
          >
            <CloseIcon />
          </button>
        </div>

        <div className="alerts-details-drawer-body">
          {loading && (
            <div
              className="alerts-drawer-state"
              role="status"
              aria-live="polite"
            >
              <span
                className="alerts-loading-spinner"
                aria-hidden="true"
              />

              <strong>
                Loading alert
              </strong>

              <span>
                Retrieving persisted alert details.
              </span>
            </div>
          )}

          {!loading &&
            error && (
              <div
                className="alerts-drawer-state"
                role="alert"
              >
                <span
                  className="alerts-state-icon alerts-error-icon"
                  aria-hidden="true"
                >
                  !
                </span>

                <strong>
                  Unable to load alert
                </strong>

                <span>
                  {error}
                </span>
              </div>
            )}

          {!loading &&
            !error &&
            alert && (
              <div className="alerts-drawer-content">
                <section className="alerts-drawer-section">
                  <div className="alerts-drawer-section-heading">
                    <span aria-hidden="true" />

                    <h3>
                      Overview
                    </h3>
                  </div>

                  <div className="alerts-drawer-grid">
                    <DrawerField
                      label="Title"
                      value={
                        alert.title
                      }
                      wide
                    />

                    <DrawerField
                      label="Severity"
                      value={
                        alert.severity
                      }
                    />

                    <DrawerField
                      label="Status"
                      value={
                        alert.status
                      }
                    />

                    <DrawerField
                      label="Priority"
                      value={
                        alert.priority
                      }
                    />

                    <DrawerField
                      label="Risk Score"
                      value={
                        alert.risk_score
                      }
                    />

                    <DrawerField
                      label="Occurrences"
                      value={
                        alert.occurrence_count
                      }
                    />

                    <DrawerField
                      label="Description"
                      value={
                        alert.description ||
                        "No description provided."
                      }
                      wide
                    />
                  </div>
                </section>

                <section className="alerts-drawer-section">
                  <div className="alerts-drawer-section-heading">
                    <span aria-hidden="true" />

                    <h3>
                      Detection
                    </h3>
                  </div>

                  <div className="alerts-drawer-grid">
                    <DrawerField
                      label="Rule"
                      value={
                        alert.rule_id
                      }
                    />

                    <DrawerField
                      label="Source Type"
                      value={
                        alert.source_type
                      }
                    />

                    <DrawerField
                      label="Source ID"
                      value={
                        alert.source_id
                      }
                      wide
                      code
                    />

                    <DrawerField
                      label="Asset ID"
                      value={
                        alert.asset_id ??
                        "—"
                      }
                      wide
                      code
                    />

                    <DrawerField
                      label="User ID"
                      value={
                        alert.user_id ??
                        "—"
                      }
                      wide
                      code
                    />
                  </div>
                </section>

                <section className="alerts-drawer-section">
                  <div className="alerts-drawer-section-heading">
                    <span aria-hidden="true" />

                    <h3>
                      Assignment
                    </h3>
                  </div>

                  <div className="alerts-drawer-grid">
                    <DrawerField
                      label="Assignee"
                      value={getAssigneeLabel(
                        alert.assigned_to,
                        users,
                      )}
                    />

                    <DrawerField
                      label="Ownership Group"
                      value={
                        alert.ownership_group ??
                        "—"
                      }
                    />
                  </div>
                </section>

                <section className="alerts-drawer-section">
                  <div className="alerts-drawer-section-heading">
                    <span aria-hidden="true" />

                    <h3>
                      Lifecycle
                    </h3>
                  </div>

                  <div className="alerts-drawer-grid">
                    <DrawerField
                      label="First Seen"
                      value={formatDate(
                        alert.first_seen_at,
                      )}
                    />

                    <DrawerField
                      label="Last Seen"
                      value={formatDate(
                        alert.last_seen_at,
                      )}
                    />

                    <DrawerField
                      label="Acknowledged"
                      value={formatDate(
                        alert.acknowledged_at,
                      )}
                    />

                    <DrawerField
                      label="Investigating"
                      value={formatDate(
                        alert.investigating_at,
                      )}
                    />

                    <DrawerField
                      label="Escalated"
                      value={formatDate(
                        alert.escalated_at,
                      )}
                    />

                    <DrawerField
                      label="Resolved"
                      value={formatDate(
                        alert.resolved_at,
                      )}
                    />

                    <DrawerField
                      label="Closed"
                      value={formatDate(
                        alert.closed_at,
                      )}
                    />

                    <DrawerField
                      label="Suppressed"
                      value={formatDate(
                        alert.suppressed_at,
                      )}
                    />
                  </div>
                </section>

                <section className="alerts-drawer-section">
                  <div className="alerts-drawer-section-heading">
                    <span aria-hidden="true" />

                    <h3>
                      Evidence
                    </h3>
                  </div>

                  {alert.evidence_ids.length >
                  0 ? (
                    <div className="alerts-drawer-evidence">
                      {alert.evidence_ids.map(
                        (evidenceId) => (
                          <code
                            key={
                              evidenceId
                            }
                          >
                            {
                              evidenceId
                            }
                          </code>
                        ),
                      )}
                    </div>
                  ) : (
                    <div className="alerts-drawer-empty">
                      No evidence linked.
                    </div>
                  )}
                </section>

                <section className="alerts-drawer-section">
                  <div className="alerts-drawer-section-heading">
                    <span aria-hidden="true" />

                    <h3>
                      Audit History
                    </h3>
                  </div>

                  {auditLoading && (
                    <div className="alerts-drawer-empty">
                      Loading audit history...
                    </div>
                  )}

                  {!auditLoading &&
                    auditError && (
                      <div
                        className="alerts-drawer-empty"
                        role="alert"
                      >
                        {auditError}
                      </div>
                    )}

                  {!auditLoading &&
                    !auditError &&
                    audit.length ===
                      0 && (
                      <div className="alerts-drawer-empty">
                        No audit history available.
                      </div>
                    )}

                  {!auditLoading &&
                    !auditError &&
                    audit.length >
                      0 && (
                      <div className="alerts-audit-list">
                        {audit.map(
                          (entry) => (
                            <div
                              key={
                                entry.audit_id
                              }
                              className="alerts-audit-entry"
                            >
                              <div className="alerts-audit-entry-header">
                                <strong>
                                  {formatLabel(
                                    entry.action,
                                  )}
                                </strong>

                                <span>
                                  {formatDate(
                                    entry.created_at,
                                  )}
                                </span>
                              </div>

                              <div className="alerts-audit-entry-body">
                                <span>
                                  Actor:{" "}
                                  {
                                    entry.actor
                                  }
                                </span>

                                {entry.from_status && (
                                  <span>
                                    From:{" "}
                                    {
                                      entry.from_status
                                    }
                                  </span>
                                )}

                                {entry.to_status && (
                                  <span>
                                    To:{" "}
                                    {
                                      entry.to_status
                                    }
                                  </span>
                                )}

                                {entry.reason && (
                                  <span>
                                    Reason:{" "}
                                    {
                                      entry.reason
                                    }
                                  </span>
                                )}
                              </div>
                            </div>
                          ),
                        )}
                      </div>
                    )}
                </section>

                <section className="alerts-drawer-section">
                  <div className="alerts-drawer-section-heading">
                    <span aria-hidden="true" />

                    <h3>
                      Identifiers
                    </h3>
                  </div>

                  <div className="alerts-drawer-grid">
                    <DrawerField
                      label="Alert ID"
                      value={
                        alert.alert_id
                      }
                      wide
                      code
                    />

                    <DrawerField
                      label="Source ID"
                      value={
                        alert.source_id
                      }
                      wide
                      code
                    />
                  </div>
                </section>
              </div>
            )}
        </div>
      </aside>
    </>
  );
}


/* ==========================================================================
 * DRAWER FIELD
 * ========================================================================== */

function DrawerField({
  label,
  value,
  wide = false,
  code = false,
}: {
  label: string;
  value: string | number;
  wide?: boolean;
  code?: boolean;
}) {
  return (
    <div
      className={
        `alerts-drawer-field${
          wide
            ? " alerts-drawer-field-wide"
            : ""
        }`
      }
    >
      <span>
        {label}
      </span>

      {code ? (
        <code>
          {String(value)}
        </code>
      ) : (
        <strong>
          {String(value)}
        </strong>
      )}
    </div>
  );
}


/* ==========================================================================
 * ASSIGN MODAL
 * ========================================================================== */

function AssignAlertModal({
  state,
  users,
  loading,
  error,
  onRoleChange,
  onAssigneeChange,
  onSubmit,
  onClose,
}: {
  state: AssignmentState;
  users: User[];
  loading: boolean;
  error: string | null;
  onRoleChange: (
    role: AssignableRole,
  ) => void;
  onAssigneeChange: (
    userId: string,
  ) => void;
  onSubmit: () => void;
  onClose: () => void;
}) {
  const availableUsers =
    users.filter(
      (user) =>
        user.is_active &&
        !user.is_locked &&
        user.roles.some(
          (role) =>
            String(role) ===
            state.role,
        ),
    );

  return (
    <>
      <button
        type="button"
        className="alerts-modal-backdrop"
        onClick={onClose}
        aria-label="Close assignment dialog"
      />

      <div
        className="alerts-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="assign-alert-title"
      >
        <div className="alerts-modal-header">
          <div>
            <span className="alerts-modal-eyebrow">
              Alert Assignment
            </span>

            <h2
              id="assign-alert-title"
              className="alerts-modal-title"
            >
              Assign / Reassign
            </h2>

            <p className="alerts-modal-subtitle">
              {state.alert?.title ??
                "Selected alert"}
            </p>
          </div>

          <button
            type="button"
            className="alerts-modal-close"
            onClick={onClose}
            aria-label="Close"
          >
            <CloseIcon />
          </button>
        </div>

        <div className="alerts-modal-body">
          <label className="alerts-modal-field">
            <span>
              Role
            </span>

            <select
              value={
                state.role
              }
              disabled={loading}
              onChange={(event) =>
                onRoleChange(
                  event.target
                    .value as AssignableRole,
                )
              }
            >
              {ASSIGNABLE_ROLES.map(
                (role) => (
                  <option
                    key={role}
                    value={role}
                  >
                    {formatLabel(
                      role,
                    )}
                  </option>
                ),
              )}
            </select>
          </label>

          <label className="alerts-modal-field">
            <span>
              Active / Unlocked User
            </span>

            <select
              value={
                state.assignee
              }
              disabled={
                loading ||
                availableUsers.length ===
                  0
              }
              onChange={(event) =>
                onAssigneeChange(
                  event.target
                    .value,
                )
              }
            >
              <option value="">
                Select user
              </option>

              {availableUsers.map(
                (user) => (
                  <option
                    key={
                      user.user_id
                    }
                    value={
                      user.user_id
                    }
                  >
                    {getUserDisplayName(user)}
                    {" — "}
                    {getUserRole(user)}
                  </option>
                ),
              )}
            </select>
          </label>

          {availableUsers.length ===
            0 && (
            <div
              className="alerts-modal-info"
              role="status"
            >
              No active and unlocked users
              are available for the selected
              role.
            </div>
          )}

          {error && (
            <div
              className="alerts-modal-error"
              role="alert"
            >
              {error}
            </div>
          )}
        </div>

        <div className="alerts-modal-footer">
          <button
            type="button"
            className="alerts-modal-secondary"
            disabled={loading}
            onClick={onClose}
          >
            Cancel
          </button>

          <button
            type="button"
            className="alerts-modal-primary"
            disabled={
              loading ||
              !state.assignee
            }
            onClick={onSubmit}
          >
            {loading
              ? "Assigning..."
              : "Assign Alert"}
          </button>
        </div>
      </div>
    </>
  );
}


/* ==========================================================================
 * STATUS MODAL
 * ========================================================================== */

function ChangeStatusModal({
  state,
  loading,
  error,
  onStatusChange,
  onReasonChange,
  onSubmit,
  onClose,
}: {
  state: StatusState;
  loading: boolean;
  error: string | null;
  onStatusChange: (
    status: AlertStatus,
  ) => void;
  onReasonChange: (
    reason: string,
  ) => void;
  onSubmit: () => void;
  onClose: () => void;
}) {
  return (
    <>
      <button
        type="button"
        className="alerts-modal-backdrop"
        onClick={onClose}
        aria-label="Close status dialog"
      />

      <div
        className="alerts-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="change-status-title"
      >
        <div className="alerts-modal-header">
          <div>
            <span className="alerts-modal-eyebrow">
              Alert Lifecycle
            </span>

            <h2
              id="change-status-title"
              className="alerts-modal-title"
            >
              Change Status
            </h2>

            <p className="alerts-modal-subtitle">
              {state.alert?.title ??
                "Selected alert"}
            </p>
          </div>

          <button
            type="button"
            className="alerts-modal-close"
            onClick={onClose}
            aria-label="Close"
          >
            <CloseIcon />
          </button>
        </div>

        <div className="alerts-modal-body">
          <div className="alerts-modal-current-status">
            <span>
              Current status
            </span>

            <strong>
              {state.alert
                ? formatLabel(
                    state.alert.status,
                  )
                : "—"}
            </strong>
          </div>

          <label className="alerts-modal-field">
            <span>
              New Status
            </span>

            <select
              value={
                state.status
              }
              disabled={loading}
              onChange={(event) =>
                onStatusChange(
                  event.target
                    .value as AlertStatus,
                )
              }
            >
              <option value="">
                Select status
              </option>

              {STATUS_OPTIONS.map(
                (status) => (
                  <option
                    key={status}
                    value={status}
                    disabled={
                      status ===
                      state.alert?.status
                    }
                  >
                    {formatLabel(
                      status,
                    )}
                  </option>
                ),
              )}
            </select>
          </label>

          <label className="alerts-modal-field">
            <span>
              Reason
            </span>

            <textarea
              rows={4}
              value={
                state.reason
              }
              disabled={loading}
              placeholder="Optional transition reason..."
              onChange={(event) =>
                onReasonChange(
                  event.target.value,
                )
              }
            />
          </label>

          <div className="alerts-modal-info">
            The backend is authoritative for
            lifecycle transition validation.
            Invalid transitions will be rejected
            by the API.
          </div>

          {error && (
            <div
              className="alerts-modal-error"
              role="alert"
            >
              {error}
            </div>
          )}
        </div>

        <div className="alerts-modal-footer">
          <button
            type="button"
            className="alerts-modal-secondary"
            disabled={loading}
            onClick={onClose}
          >
            Cancel
          </button>

          <button
            type="button"
            className="alerts-modal-primary"
            disabled={
              loading ||
              !state.status ||
              state.status ===
                state.alert?.status
            }
            onClick={onSubmit}
          >
            {loading
              ? "Updating..."
              : "Change Status"}
          </button>
        </div>
      </div>
    </>
  );
}


/* ==========================================================================
 * PAGE
 * ========================================================================== */

export default function Alerts() {
  const [
    alerts,
    setAlerts,
  ] = useState<Alert[]>([]);

  const [
    total,
    setTotal,
  ] = useState(0);

  const [
    loading,
    setLoading,
  ] = useState(true);

  const [
    statisticsLoading,
    setStatisticsLoading,
  ] = useState(true);

  const [
    error,
    setError,
  ] = useState<string | null>(
    null,
  );

  const [
    statisticsError,
    setStatisticsError,
  ] = useState<string | null>(
    null,
  );

  const [
    statistics,
    setStatistics,
  ] = useState<AlertStatistics>(
    buildEmptyStatistics(),
  );

  const [
    filterOptions,
    setFilterOptions,
  ] = useState<AlertFilterOptions>(
    buildEmptyFilterOptions(),
  );

  const [
    filterOptionsLoading,
    setFilterOptionsLoading,
  ] = useState(true);

  const [
    filterOptionsError,
    setFilterOptionsError,
  ] = useState<string | null>(
    null,
  );

  const [
    page,
    setPage,
  ] = useState(
    DEFAULT_PAGE,
  );

  const pageSize =
    DEFAULT_PAGE_SIZE;

  const [
    filters,
    setFilters,
  ] = useState<AlertFilters>({});

  const [
    selectedAlertId,
    setSelectedAlertId,
  ] = useState<
    string | null
  >(null);

  // Defensive UI reset: never enter Alerts with a stale drawer/modal state.
  useEffect(() => {
    setSelectedAlertId(null);
    setActionMenu(null);
    setAssignment(null);
    setStatusState(null);
  }, []);

  const [
    actionMenu,
    setActionMenu,
  ] = useState<
    ActionMenuState | null
  >(null);

  const [
    assignment,
    setAssignment,
  ] = useState<
    AssignmentState | null
  >(null);

  const [
    assignmentUsers,
    setAssignmentUsers,
  ] = useState<User[]>([]);

  const [
    assigneeDirectory,
    setAssigneeDirectory,
  ] = useState<User[]>([]);

  const [
    assigneeDirectoryLoading,
    setAssigneeDirectoryLoading,
  ] = useState(true);

  const [
    assigneeDirectoryError,
    setAssigneeDirectoryError,
  ] = useState<string | null>(null);

  const [
    assignmentUsersLoading,
    setAssignmentUsersLoading,
  ] = useState(false);

  const [
    assignmentLoading,
    setAssignmentLoading,
  ] = useState(false);

  const [
    assignmentError,
    setAssignmentError,
  ] = useState<string | null>(
    null,
  );

  const [
    statusState,
    setStatusState,
  ] = useState<
    StatusState | null
  >(null);

  const [
    statusLoading,
    setStatusLoading,
  ] = useState(false);

  const [
    statusError,
    setStatusError,
  ] = useState<string | null>(
    null,
  );

  const [
    mutationError,
    setMutationError,
  ] = useState<string | null>(
    null,
  );


  /* ========================================================================
   * API CONTRACT
   * ====================================================================== */

  const alertsApiWithOperations =
    alertsApi as typeof alertsApi &
      BackendAlertApi;


  /* ========================================================================
   * LOAD ALERTS
   * ====================================================================== */

  const loadAlerts =
    useCallback(
      async (
        lifecycle?: RequestLifecycle,
      ): Promise<void> => {
        try {
          setLoading(true);
          setError(null);

          const params =
            buildAlertListParams(
              filters,
              page,
              pageSize,
            );

          const response =
            await alertsApi.listFiltered(
              params,
            );

          if (
            lifecycle?.cancelled
          ) {
            return;
          }

          setAlerts(
            response.items,
          );

          setTotal(
            Number.isFinite(
              response.pagination.total,
            )
              ? response.pagination.total
              : 0,
          );
        } catch (err) {
          if (
            lifecycle?.cancelled
          ) {
            return;
          }

          setAlerts([]);
          setTotal(0);

          setError(
            getErrorMessage(err),
          );
        } finally {
          if (
            !lifecycle?.cancelled
          ) {
            setLoading(false);
          }
        }
      },
      [
        filters,
        page,
        pageSize,
      ],
    );


  /* ========================================================================
   * LOAD STATISTICS
   *
   * Backend only.
   *
   * NEVER calculate KPI values from alerts[]
   * or from pagination total.
   * ====================================================================== */

  const loadStatistics =
    useCallback(
      async (
        lifecycle?: RequestLifecycle,
      ): Promise<void> => {
        if (
          typeof alertsApiWithOperations.statistics !==
          "function"
        ) {
          setStatistics(
            buildEmptyStatistics(),
          );

          setStatisticsError(
            "Alert statistics API is not configured.",
          );

          setStatisticsLoading(
            false,
          );

          return;
        }

        try {
          setStatisticsLoading(
            true,
          );

          setStatisticsError(
            null,
          );

          const params =
            buildStatisticsParams(
              filters,
            );

          const result =
            await alertsApiWithOperations.statistics(
              params,
            );

          if (
            lifecycle?.cancelled
          ) {
            return;
          }

          setStatistics({
            total:
              Number.isFinite(
                result.total,
              )
                ? result.total
                : 0,

            new:
              Number.isFinite(
                result.new,
              )
                ? result.new
                : 0,

            critical:
              Number.isFinite(
                result.critical,
              )
                ? result.critical
                : 0,

            escalated:
              Number.isFinite(
                result.escalated,
              )
                ? result.escalated
                : 0,

            acknowledged:
              Number.isFinite(
                result.acknowledged,
              )
                ? result.acknowledged
                : 0,

            investigating:
              Number.isFinite(
                result.investigating,
              )
                ? result.investigating
                : 0,

            resolved:
              Number.isFinite(
                result.resolved,
              )
                ? result.resolved
                : 0,

            suppressed:
              Number.isFinite(
                result.suppressed,
              )
                ? result.suppressed
                : 0,
          });
        } catch (err) {
          if (
            lifecycle?.cancelled
          ) {
            return;
          }

          setStatistics(
            buildEmptyStatistics(),
          );

          setStatisticsError(
            getErrorMessage(err),
          );
        } finally {
          if (
            !lifecycle?.cancelled
          ) {
            setStatisticsLoading(
              false,
            );
          }
        }
      },
      [
        alertsApiWithOperations,
        filters,
      ],
    );


  /* ========================================================================
   * LOAD FILTER OPTIONS
   *
   * Backend only.
   *
   * NEVER derive options from currently loaded alerts.
   * ====================================================================== */

  const loadFilterOptions =
    useCallback(
      async (
        lifecycle?: RequestLifecycle,
      ): Promise<void> => {
        if (
          typeof alertsApiWithOperations.filterOptions !==
          "function"
        ) {
          setFilterOptions(
            buildEmptyFilterOptions(),
          );

          setFilterOptionsError(
            "Alert filter-options API is not configured.",
          );

          setFilterOptionsLoading(
            false,
          );

          return;
        }

        try {
          setFilterOptionsLoading(
            true,
          );

          setFilterOptionsError(
            null,
          );

          const result =
            await alertsApiWithOperations.filterOptions();

          if (
            lifecycle?.cancelled
          ) {
            return;
          }

          setFilterOptions(
            result,
          );
        } catch (err) {
          if (
            lifecycle?.cancelled
          ) {
            return;
          }

          setFilterOptions(
            buildEmptyFilterOptions(),
          );

          setFilterOptionsError(
            getErrorMessage(err),
          );
        } finally {
          if (
            !lifecycle?.cancelled
          ) {
            setFilterOptionsLoading(
              false,
            );
          }
        }
      },
      [
        alertsApiWithOperations,
      ],
    );


  /* ========================================================================
   * ASSIGNEE DIRECTORY
   *
   * Backend User Management is the source of truth for:
   * - display name
   * - role
   * - active/locked state
   *
   * Alert payloads and filters continue to use UUIDs.
   * ====================================================================== */

  const loadAssigneeDirectory =
    useCallback(
      async (
        lifecycle?: RequestLifecycle,
      ): Promise<void> => {
        try {
          setAssigneeDirectoryLoading(
            true,
          );
          setAssigneeDirectoryError(
            null,
          );

          const response =
            await usersApi.list({
              limit: 200,
              offset: 0,
            });

          if (
            lifecycle?.cancelled
          ) {
            return;
          }

          setAssigneeDirectory(
            Array.isArray(
              response.users,
            )
              ? response.users
              : [],
          );
        } catch (err) {
          if (
            lifecycle?.cancelled
          ) {
            return;
          }

          setAssigneeDirectory([]);
          setAssigneeDirectoryError(
            getErrorMessage(err),
          );
        } finally {
          if (
            !lifecycle?.cancelled
          ) {
            setAssigneeDirectoryLoading(
              false,
            );
          }
        }
      },
      [],
    );


  /* ========================================================================
   * ASSIGNEE DIRECTORY EFFECT
   * ====================================================================== */

  useEffect(() => {
    const lifecycle: RequestLifecycle = {
      cancelled: false,
    };

    void loadAssigneeDirectory(
      lifecycle,
    );

    return () => {
      lifecycle.cancelled = true;
    };
  }, [loadAssigneeDirectory]);


  /* ========================================================================
   * ALERT LIST EFFECT
   * ====================================================================== */

  useEffect(() => {
    const lifecycle: RequestLifecycle = {
      cancelled: false,
    };

    void loadAlerts(
      lifecycle,
    );

    return () => {
      lifecycle.cancelled = true;
    };
  }, [loadAlerts]);


  /* ========================================================================
   * STATISTICS EFFECT
   * ====================================================================== */

  useEffect(() => {
    const lifecycle: RequestLifecycle = {
      cancelled: false,
    };

    void loadStatistics(
      lifecycle,
    );

    return () => {
      lifecycle.cancelled = true;
    };
  }, [loadStatistics]);


  /* ========================================================================
   * FILTER OPTIONS EFFECT
   * ====================================================================== */

  useEffect(() => {
    const lifecycle: RequestLifecycle = {
      cancelled: false,
    };

    void loadFilterOptions(
      lifecycle,
    );

    return () => {
      lifecycle.cancelled = true;
    };
  }, [loadFilterOptions]);


  /* ========================================================================
   * REFRESH
   * ====================================================================== */

  const handleRefresh =
    useCallback(
      (): void => {
        setMutationError(null);

        void loadAlerts();
        void loadStatistics();
        void loadFilterOptions();
        void loadAssigneeDirectory();
      },
      [
        loadAlerts,
        loadStatistics,
        loadFilterOptions,
        loadAssigneeDirectory,
      ],
    );


  /* ========================================================================
   * FILTER UPDATE
   * ====================================================================== */

  const updateFilter =
    useCallback(
      (
        key: keyof AlertFilters,
        value: string,
      ): void => {
        const normalized =
          normalizeString(
            value,
          );

        setPage(
          DEFAULT_PAGE,
        );

        setFilters(
          (current) => ({
            ...current,

            [key]:
              normalized ||
              undefined,
          }),
        );

        setSelectedAlertId(
          null,
        );

        setActionMenu(
          null,
        );
      },
      [],
    );


  /* ========================================================================
   * RESET FILTERS
   * ====================================================================== */

  const handleResetFilters =
    useCallback(
      (): void => {
        setPage(
          DEFAULT_PAGE,
        );

        setFilters({});

        setSelectedAlertId(
          null,
        );

        setActionMenu(
          null,
        );

        setMutationError(
          null,
        );
      },
      [],
    );


  /* ========================================================================
   * PAGINATION
   * ====================================================================== */

  const totalPages =
    Math.max(
      1,
      Math.ceil(
        total / pageSize,
      ),
    );

  const handlePageChange =
    useCallback(
      (
        nextPage: number,
      ): void => {
        if (
          nextPage < 1 ||
          nextPage > totalPages
        ) {
          return;
        }

        setPage(
          nextPage,
        );

        setSelectedAlertId(
          null,
        );

        setActionMenu(
          null,
        );
      },
      [totalPages],
    );


  /* ========================================================================
   * VIEW
   * ====================================================================== */

  const handleViewAlert =
    useCallback(
      (
        alert: Alert,
      ): void => {
        setActionMenu(
          null,
        );

        setSelectedAlertId(
          alert.alert_id,
        );
      },
      [],
    );


  /* ========================================================================
   * TABLE ACTION MENU
   * ====================================================================== */

  const handleTableAction =
    useCallback(
      (
        alert: Alert,
      ): void => {
        setSelectedAlertId(
          null,
        );

        setActionMenu(
          (current) => {
            if (
              current?.alert.alert_id ===
              alert.alert_id
            ) {
              return null;
            }

            /*
             * AlertTable intentionally keeps the action callback small
             * (`onAction(alert)`). The click button is still the active
             * element when this callback runs, so use its viewport rect
             * as the anchor for the floating menu.
             *
             * This avoids hardcoded/centered positioning and keeps the
             * menu attached to the exact action button that was clicked.
             */
            const activeElement =
              document.activeElement;

            const anchor =
              activeElement instanceof HTMLElement
                ? activeElement
                : null;

            const rect =
              anchor?.getBoundingClientRect();

            const menuWidth = 210;
            const menuHeight = 132;
            const gap = 6;
            const viewportPadding = 8;

            let left =
              rect
                ? rect.right - menuWidth
                : window.innerWidth -
                  menuWidth -
                  viewportPadding;

            let top =
              rect
                ? rect.bottom + gap
                : viewportPadding;

            if (
              left <
              viewportPadding
            ) {
              left =
                viewportPadding;
            }

            if (
              left + menuWidth >
              window.innerWidth -
                viewportPadding
            ) {
              left =
                window.innerWidth -
                menuWidth -
                viewportPadding;
            }

            if (
              rect &&
              top + menuHeight >
                window.innerHeight -
                  viewportPadding
            ) {
              top =
                rect.top -
                menuHeight -
                gap;
            }

            if (
              top <
              viewportPadding
            ) {
              top =
                viewportPadding;
            }

            return {
              alert,
              open: true,
              top,
              left,
            };
          },
        );
      },
      [],
    );


  /* ========================================================================
   * ASSIGNMENT — LOAD USERS
   * ====================================================================== */

  const loadAssignableUsers =
    useCallback(
      async (
        role: AssignableRole,
      ): Promise<void> => {
        try {
          setAssignmentUsersLoading(
            true,
          );

          setAssignmentError(
            null,
          );

          const response =
            await usersApi.list({
              limit: 200,
              offset: 0,
            });

          const users =
            Array.isArray(
              response.users,
            )
              ? response.users
              : [];

          const eligible =
            users.filter(
              (user) =>
                user.is_active &&
                !user.is_locked &&
                user.roles.some(
                  (userRole) =>
                    String(
                      userRole,
                    ) === role,
                ),
            );

          setAssignmentUsers(
            eligible,
          );
        } catch (err) {
          setAssignmentUsers(
            [],
          );

          setAssignmentError(
            getErrorMessage(err),
          );
        } finally {
          setAssignmentUsersLoading(
            false,
          );
        }
      },
      [],
    );


  /* ========================================================================
   * OPEN ASSIGNMENT
   * ====================================================================== */

  const handleAssignAlert =
    useCallback(
      (
        alert: Alert,
      ): void => {
        const sourceAlert =
          alerts.find(
            (candidate) =>
              candidate.alert_id ===
              alert.alert_id,
          ) ?? alert;

        const assignedUser =
          assigneeDirectory.find(
            (user) =>
              user.user_id ===
              sourceAlert.assigned_to,
          );

        const role =
          ASSIGNABLE_ROLES.find(
            (candidate) =>
              assignedUser?.roles?.some(
                (userRole) =>
                  String(userRole) ===
                  candidate,
              ),
          ) ??
          "SOC_ANALYST";

        setAssignment({
          alert: sourceAlert,
          role,
          assignee:
            sourceAlert.assigned_to ??
            "",
        });

        setAssignmentUsers(
          [],
        );

        setAssignmentError(
          null,
        );

        void loadAssignableUsers(
          role,
        );
      },
      [
        alerts,
        assigneeDirectory,
        loadAssignableUsers,
      ],
    );


  /* ========================================================================
   * ASSIGNMENT ROLE CHANGE
   * ====================================================================== */

  const handleAssignmentRoleChange =
    useCallback(
      (
        role: AssignableRole,
      ): void => {
        setAssignment(
          (current) =>
            current
              ? {
                  ...current,
                  role,
                  assignee: "",
                }
              : current,
        );

        setAssignmentUsers(
          [],
        );

        setAssignmentError(
          null,
        );

        void loadAssignableUsers(
          role,
        );
      },
      [loadAssignableUsers],
    );


  /* ========================================================================
   * ASSIGNMENT SUBMIT
   * ====================================================================== */

  const handleAssignmentSubmit =
    useCallback(
      async (): Promise<void> => {
        if (
          !assignment?.alert ||
          !assignment.assignee
        ) {
          return;
        }

        try {
          setAssignmentLoading(
            true,
          );

          setAssignmentError(
            null,
          );

          const payload: AlertAssignmentRequest = {
            assignee:
              assignment.assignee,
          };

          await alertsApi.assign(
            assignment.alert.alert_id,
            payload,
          );

          setAssignment(
            null,
          );

          setMutationError(
            null,
          );

          await Promise.all([
            loadAlerts(),
            loadStatistics(),
          ]);

          if (
            selectedAlertId ===
            assignment.alert.alert_id
          ) {
            setSelectedAlertId(
              assignment.alert.alert_id,
            );
          }
        } catch (err) {
          setAssignmentError(
            getErrorMessage(err),
          );
        } finally {
          setAssignmentLoading(
            false,
          );
        }
      },
      [
        assignment,
        loadAlerts,
        loadStatistics,
        selectedAlertId,
      ],
    );


  /* ========================================================================
   * OPEN STATUS MODAL
   * ====================================================================== */

  const handleChangeStatus =
    useCallback(
      (
        alert: Alert,
      ): void => {
        setStatusState({
          alert,
          status: "",
          reason: "",
        });

        setStatusError(
          null,
        );
      },
      [],
    );


  /* ========================================================================
   * STATUS SUBMIT
   *
   * No local transition validation.
   * ====================================================================== */

  const handleStatusSubmit =
    useCallback(
      async (): Promise<void> => {
        if (
          !statusState?.alert ||
          !statusState.status
        ) {
          return;
        }

        try {
          setStatusLoading(
            true,
          );

          setStatusError(
            null,
          );

          const request: AlertTransitionRequest =
            {
              status:
                statusState.status,
              reason:
                normalizeString(
                  statusState.reason,
                ) ||
                undefined,
            };

          await alertsApi.transition(
            statusState.alert.alert_id,
            request,
          );

          const alertId =
            statusState.alert.alert_id;

          setStatusState(
            null,
          );

          setMutationError(
            null,
          );

          await Promise.all([
            loadAlerts(),
            loadStatistics(),
          ]);

          if (
            selectedAlertId ===
            alertId
          ) {
            setSelectedAlertId(
              null,
            );

            setSelectedAlertId(
              alertId,
            );
          }
        } catch (err) {
          setStatusError(
            getErrorMessage(err),
          );
        } finally {
          setStatusLoading(
            false,
          );
        }
      },
      [
        statusState,
        loadAlerts,
        loadStatistics,
        selectedAlertId,
      ],
    );


  /* ========================================================================
   * TABLE DISPLAY MODEL
   *
   * The backend Alert model still contains assigned_to UUID.
   * AlertTable receives a display-only copy so the table never exposes UUIDs.
   * Mutations always resolve the original alert by alert_id before calling
   * alertsApi.
   * ====================================================================== */

  const tableAlerts =
    useMemo(
      () =>
        alerts.map(
          (alert) => ({
            ...alert,
            assigned_to:
              alert.assigned_to
                ? getAssigneeLabel(
                    alert.assigned_to,
                    assigneeDirectory,
                  )
                : null,
          }),
        ),
      [
        alerts,
        assigneeDirectory,
      ],
    );


  /* ========================================================================
   * ACTIVE FILTER COUNT
   * ====================================================================== */

  const activeFilterCount =
    useMemo(
      () =>
        Object.values(
          filters,
        ).filter(
          (value) =>
            Boolean(
              normalizeString(
                value,
              ),
            ),
        ).length,
      [filters],
    );

  const hasActiveFilters =
    activeFilterCount > 0;


  /* ========================================================================
   * QUEUE SUBTITLE
   * ====================================================================== */

  const queueSubtitle =
    loading
      ? "Loading alert data..."
      : error
        ? "Alert data is currently unavailable"
        : `${total.toLocaleString()} alert${
            total === 1
              ? ""
              : "s"
          } requiring attention`;


  /* ========================================================================
   * RENDER
   * ====================================================================== */

  return (
    <>
      <div
          className="alerts-page"
          style={{
            position: "relative",
            zIndex: 1,
            isolation: "isolate",
          }}
        >
        {/* ================================================================
         * PAGE HEADER
         * ================================================================ */}

        <div className="alerts-page-header">
          <div className="alerts-page-heading">
            <span className="alerts-page-eyebrow">
              Security Operations
            </span>

            <h2 className="alerts-page-title">
              Alert Management
            </h2>

            <p className="alerts-page-description">
              Detection and correlation
              alerts requiring analyst
              attention.
            </p>
          </div>

          <div className="alerts-page-actions">
            <button
              type="button"
              className="alerts-refresh-button"
              onClick={
                handleRefresh
              }
              disabled={
                loading ||
                statisticsLoading ||
                filterOptionsLoading
              }
              aria-label="Refresh alerts"
            >
              <RefreshIcon
                spinning={
                  loading
                }
              />

              {loading
                ? "Loading..."
                : "Refresh"}
            </button>
          </div>
        </div>


        {/* ================================================================
         * MUTATION ERROR
         * ================================================================ */}

        {mutationError && (
          <div
            className="alerts-queue-state"
            role="alert"
          >
            <div className="alerts-queue-state-content">
              <span
                className="alerts-state-icon alerts-error-icon"
                aria-hidden="true"
              >
                !
              </span>

              <strong className="alerts-state-title">
                Alert operation failed
              </strong>

              <span className="alerts-state-description">
                {mutationError}
              </span>
            </div>
          </div>
        )}


        {/* ================================================================
         * KPI GRID
         * ================================================================ */}

        <div className="alerts-kpi-grid">
          <KpiCard
            label="Total Alerts"
            value={
              statistics.total
            }
            icon="total"
            loading={
              statisticsLoading
            }
          />

          <KpiCard
            label="New"
            value={
              statistics.new
            }
            tone="info"
            icon="new"
            loading={
              statisticsLoading
            }
          />

          <KpiCard
            label="Critical"
            value={
              statistics.critical
            }
            tone="critical"
            icon="critical"
            loading={
              statisticsLoading
            }
          />

          <KpiCard
            label="Escalated"
            value={
              statistics.escalated
            }
            tone="danger"
            icon="escalated"
            loading={
              statisticsLoading
            }
          />

          <KpiCard
            label="Acknowledged"
            value={
              statistics.acknowledged
            }
            tone="warning"
            icon="acknowledged"
            loading={
              statisticsLoading
            }
          />

          <KpiCard
            label="Investigating"
            value={
              statistics.investigating
            }
            tone="warning"
            icon="investigating"
            loading={
              statisticsLoading
            }
          />

          <KpiCard
            label="Resolved"
            value={
              statistics.resolved
            }
            tone="success"
            icon="resolved"
            loading={
              statisticsLoading
            }
          />
        </div>


        {/* ================================================================
         * KPI ERROR
         * ================================================================ */}

        {statisticsError && (
          <div
            className="alerts-inline-warning"
            role="status"
          >
            KPI data unavailable:
            {" "}
            {statisticsError}
          </div>
        )}


        {/* ================================================================
         * ALERT QUEUE
         * ================================================================ */}

        <div className="alerts-queue">
          <Panel
            title="Alert Queue"
            subtitle={
              queueSubtitle
            }
          >
            {/* ============================================================
             * FILTER BAR
             * ========================================================== */}

            <div className="alerts-filter-bar">
              <SearchField
                value={
                  filters.query ??
                  ""
                }
                disabled={
                  loading
                }
                onChange={(value) =>
                  updateFilter(
                    "query",
                    value,
                  )
                }
              />

              <FilterSelect
                label="Status"
                value={
                  filters.status ??
                  ""
                }
                options={
                  filterOptions.statuses
                }
                disabled={
                  loading ||
                  filterOptionsLoading
                }
                onChange={(value) =>
                  updateFilter(
                    "status",
                    value,
                  )
                }
              />

              <FilterSelect
                label="Severity"
                value={
                  filters.severity ??
                  ""
                }
                options={
                  filterOptions.severities
                }
                disabled={
                  loading ||
                  filterOptionsLoading
                }
                onChange={(value) =>
                  updateFilter(
                    "severity",
                    value,
                  )
                }
              />

              <FilterSelect
                label="Priority"
                value={
                  filters.priority ??
                  ""
                }
                options={
                  filterOptions.priorities
                }
                disabled={
                  loading ||
                  filterOptionsLoading
                }
                onChange={(value) =>
                  updateFilter(
                    "priority",
                    value,
                  )
                }
              />

              <FilterSelect
                label="Source"
                value={
                  filters.source_type ??
                  ""
                }
                options={
                  filterOptions.source_types
                }
                disabled={
                  loading ||
                  filterOptionsLoading
                }
                onChange={(value) =>
                  updateFilter(
                    "source_type",
                    value,
                  )
                }
              />

              <FilterSelect
                label="Rule"
                value={
                  filters.rule_id ??
                  ""
                }
                options={
                  filterOptions.rules
                }
                disabled={
                  loading ||
                  filterOptionsLoading
                }
                onChange={(value) =>
                  updateFilter(
                    "rule_id",
                    value,
                  )
                }
              />

              <AssigneeFilterSelect
                label="Assignee"
                value={
                  filters.assigned_to ??
                  ""
                }
                options={
                  filterOptions.assignees
                }
                users={
                  assigneeDirectory
                }
                disabled={
                  loading ||
                  filterOptionsLoading ||
                  assigneeDirectoryLoading
                }
                onChange={(value) =>
                  updateFilter(
                    "assigned_to",
                    value,
                  )
                }
              />

              <button
                type="button"
                className="alerts-filter-reset-button"
                onClick={
                  handleResetFilters
                }
                disabled={
                  loading ||
                  !hasActiveFilters
                }
                aria-label="Reset alert filters"
              >
                <ResetIcon />

                <span>
                  Reset
                </span>

                {activeFilterCount >
                  0 && (
                  <span
                    aria-label={`${activeFilterCount} filters applied`}
                  >
                    ({activeFilterCount})
                  </span>
                )}
              </button>
            </div>


            {/* ============================================================
             * FILTER OPTION ERROR
             * ========================================================== */}

            {filterOptionsError && (
              <div
                className="alerts-inline-warning"
                role="status"
              >
                Filter options unavailable:
                {" "}
                {
                  filterOptionsError
                }
              </div>
            )}

            {assigneeDirectoryError && (
              <div
                className="alerts-inline-warning"
                role="status"
              >
                Assignee names unavailable:
                {" "}
                {assigneeDirectoryError}
              </div>
            )}


            {/* ============================================================
             * ERROR
             * ========================================================== */}

            {!loading &&
              error && (
                <div
                  className="alerts-queue-state"
                  role="alert"
                >
                  <div className="alerts-queue-state-content">
                    <span
                      className="alerts-state-icon alerts-error-icon"
                      aria-hidden="true"
                    >
                      !
                    </span>

                    <strong className="alerts-state-title">
                      Unable to load alerts
                    </strong>

                    <span className="alerts-state-description">
                      {error}
                    </span>

                    <button
                      type="button"
                      className="alerts-refresh-button"
                      onClick={
                        handleRefresh
                      }
                    >
                      Try again
                    </button>
                  </div>
                </div>
              )}


            {/* ============================================================
             * LOADING
             * ========================================================== */}

            {loading && (
              <div
                className="alerts-queue-state"
                role="status"
                aria-live="polite"
              >
                <div className="alerts-queue-state-content">
                  <span
                    className="alerts-loading-spinner"
                    aria-hidden="true"
                  />

                  <strong className="alerts-state-title">
                    Loading alerts
                  </strong>

                  <span className="alerts-state-description">
                    Retrieving detection and
                    correlation alerts.
                  </span>
                </div>
              </div>
            )}


            {/* ============================================================
             * TABLE
             * ========================================================== */}

            {!loading &&
              !error &&
              alerts.length >
                0 && (
                <>
                  <AlertTable
                    alerts={
                      tableAlerts
                    }
                    onSelectAlert={
                      handleViewAlert
                    }
                    onAction={
                      handleTableAction
                    }
                    selectedAlertId={
                      selectedAlertId
                    }
                    disabled={
                      loading
                    }
                  />

                  <PaginationControls
                    page={
                      page
                    }
                    pageSize={
                      pageSize
                    }
                    total={
                      total
                    }
                    loading={
                      loading
                    }
                    onPageChange={
                      handlePageChange
                    }
                  />
                </>
              )}


            {/* ============================================================
             * EMPTY
             * ========================================================== */}

            {!loading &&
              !error &&
              alerts.length ===
                0 && (
                <div
                  className="alerts-queue-state"
                  role="status"
                >
                  <div className="alerts-queue-state-content">
                    <span
                      className="alerts-state-icon"
                      aria-hidden="true"
                    >
                      —
                    </span>

                    <strong className="alerts-state-title">
                      No alerts found
                    </strong>

                    <span className="alerts-state-description">
                      No alerts match the
                      current filters.
                    </span>

                    {hasActiveFilters && (
                      <button
                        type="button"
                        className="alerts-refresh-button"
                        onClick={
                          handleResetFilters
                        }
                      >
                        <ResetIcon />

                        Clear filters
                      </button>
                    )}
                  </div>
                </div>
              )}
          </Panel>
        </div>


        {/* ================================================================
         * ACTION MENU
         * ================================================================ */}

        {actionMenu?.open && (
          <div
            className="alerts-floating-action-layer"
            onClick={() =>
              setActionMenu(
                null,
              )
            }
            role="presentation"
          >
            <div
              className="alerts-floating-action-menu-anchor"
              style={{
                top: `${actionMenu.top}px`,
                left: `${actionMenu.left}px`,
              }}
              onClick={(event) =>
                event.stopPropagation()
              }
            >
              <AlertActionMenu
                alert={
                  actionMenu.alert
                }
                onView={
                  handleViewAlert
                }
                onAssign={
                  handleAssignAlert
                }
                onStatus={
                  handleChangeStatus
                }
                onClose={() =>
                  setActionMenu(
                    null,
                  )
                }
              />
            </div>
          </div>
        )}


        {/* ================================================================
         * DETAILS DRAWER
         * ================================================================ */}

        {selectedAlertId && (
          <AlertDetailsDrawer
            alertId={
              selectedAlertId
            }
            users={
              assigneeDirectory
            }
            onClose={() =>
              setSelectedAlertId(
                null,
              )
            }
          />
        )}


        {/* ================================================================
         * ASSIGNMENT MODAL
         * ================================================================ */}

        {assignment && (
          <AssignAlertModal
            state={
              assignment
            }
            users={
              assignmentUsers
            }
            loading={
              assignmentLoading ||
              assignmentUsersLoading
            }
            error={
              assignmentError
            }
            onRoleChange={
              handleAssignmentRoleChange
            }
            onAssigneeChange={(
              userId,
            ) =>
              setAssignment(
                (current) =>
                  current
                    ? {
                        ...current,
                        assignee:
                          userId,
                      }
                    : current,
              )
            }
            onSubmit={
              handleAssignmentSubmit
            }
            onClose={() =>
              setAssignment(
                null,
              )
            }
          />
        )}


        {/* ================================================================
         * STATUS MODAL
         * ================================================================ */}

        {statusState && (
          <ChangeStatusModal
            state={
              statusState
            }
            loading={
              statusLoading
            }
            error={
              statusError
            }
            onStatusChange={(
              status,
            ) =>
              setStatusState(
                (current) =>
                  current
                    ? {
                        ...current,
                        status,
                      }
                    : current,
              )
            }
            onReasonChange={(
              reason,
            ) =>
              setStatusState(
                (current) =>
                  current
                    ? {
                        ...current,
                        reason,
                      }
                    : current,
              )
            }
            onSubmit={
              handleStatusSubmit
            }
            onClose={() =>
              setStatusState(
                null,
              )
            }
          />
        )}
      </div>


      {/* ==================================================================
       * PAGE-LOCAL STRUCTURAL CSS
       *
       * Existing Alerts.css remains the visual base.
       * These rules only cover controls introduced by this page.
       * ================================================================== */}

      <style>
        {`
          .alerts-inline-warning {
            box-sizing: border-box;
            width: 100%;
            margin: 0 0 12px;
            padding: 9px 12px;
            border: 1px solid rgba(208, 170, 103, 0.25);
            border-radius: 6px;
            background: rgba(208, 170, 103, 0.06);
            color: #b99d6a;
            font-size: 10px;
            line-height: 15px;
          }

          .alerts-floating-action-layer {
            position: fixed;
            inset: 0;
            z-index: 10000;
            pointer-events: auto;
          }

          .alerts-floating-action-menu-anchor {
            position: fixed;
            width: 210px;
            pointer-events: auto;
          }

          .alerts-action-menu {
            display: flex;
            flex-direction: column;
            width: 210px;
            min-width: 210px;
            box-sizing: border-box;
            padding: 6px;
            border: 1px solid #163249;
            border-radius: 8px;
            background: #081725;
            box-shadow:
              0 18px 45px rgba(0, 0, 0, 0.45);
          }

          .alerts-action-menu button {
            display: flex;
            align-items: center;
            gap: 10px;
            width: 100%;
            min-height: 38px;
            padding: 0 10px;
            border: 0;
            border-radius: 5px;
            background: transparent;
            color: #a6b9c9;
            font: inherit;
            font-size: 11px;
            text-align: left;
            cursor: pointer;
          }

          .alerts-action-menu button:hover {
            background: #0c2031;
            color: #dbe7f1;
          }

          .alerts-action-menu button:focus-visible {
            outline: 2px solid #36bdf5;
            outline-offset: -2px;
          }

          /* ==================================================================
           * ASSIGN / STATUS SIDE DRAWERS
           *
           * View Alert already uses the right-side details drawer.
           * Assign / Reassign and Change Status must use the same UX instead
           * of opening a centered modal.
           * ================================================================== */

          .alerts-modal-backdrop {
            position: fixed;
            inset: 0;
            z-index: 1100;
            border: 0;
            padding: 0;
            background: rgba(2, 9, 15, 0.52);
            cursor: default;
          }

          .alerts-modal {
            position: fixed;
            top: 0;
            right: 0;
            bottom: 0;
            z-index: 1101;
            display: flex;
            flex-direction: column;
            width: min(460px, 100vw);
            max-width: 100vw;
            max-height: 100vh;
            overflow: hidden;
            box-sizing: border-box;
            border: 0;
            border-left: 1px solid #163249;
            border-radius: 0;
            background: #071522;
            box-shadow:
              -18px 0 55px rgba(0, 0, 0, 0.45);
            animation: alerts-side-drawer-in 180ms ease-out;
          }

          @keyframes alerts-side-drawer-in {
            from {
              transform: translateX(100%);
            }
            to {
              transform: translateX(0);
            }
          }

          .alerts-modal-header {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 16px;
            padding: 18px;
            border-bottom: 1px solid rgba(22, 50, 73, 0.8);
          }

          .alerts-modal-eyebrow {
            display: block;
            margin-bottom: 5px;
            color: #55748a;
            font-size: 9px;
            font-weight: 750;
            letter-spacing: 0.13em;
            text-transform: uppercase;
          }

          .alerts-modal-title {
            margin: 0;
            color: #e7f0f8;
            font-size: 17px;
            font-weight: 680;
          }

          .alerts-modal-subtitle {
            max-width: 390px;
            margin: 5px 0 0;
            overflow: hidden;
            color: #607b90;
            font-size: 10px;
            line-height: 15px;
            text-overflow: ellipsis;
            white-space: nowrap;
          }

          .alerts-modal-close {
            display: grid;
            place-items: center;
            width: 32px;
            height: 32px;
            padding: 0;
            border: 1px solid #163249;
            border-radius: 6px;
            background: #081927;
            color: #71899b;
            cursor: pointer;
          }

          .alerts-modal-close:hover {
            border-color: #286080;
            color: #dbe7f1;
          }

          .alerts-modal-body {
            display: flex;
            flex-direction: column;
            gap: 14px;
            padding: 18px;
          }

          .alerts-modal-field {
            display: flex;
            flex-direction: column;
            gap: 7px;
          }

          .alerts-modal-field > span {
            color: #607b90;
            font-size: 9px;
            font-weight: 750;
            letter-spacing: 0.08em;
            text-transform: uppercase;
          }

          .alerts-modal-field select,
          .alerts-modal-field textarea {
            width: 100%;
            box-sizing: border-box;
            border: 1px solid #163249;
            border-radius: 6px;
            outline: none;
            background: #081927;
            color: #c8d7e3;
            font: inherit;
            font-size: 11px;
          }

          .alerts-modal-field select {
            min-height: 38px;
            padding: 0 10px;
          }

          .alerts-modal-field textarea {
            min-height: 92px;
            padding: 10px;
            resize: vertical;
          }

          .alerts-modal-field select:focus,
          .alerts-modal-field textarea:focus {
            border-color: #286080;
            box-shadow: 0 0 0 1px #286080;
          }

          .alerts-modal-current-status {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            padding: 11px 12px;
            border: 1px solid rgba(22, 50, 73, 0.75);
            border-radius: 6px;
            background: #081725;
          }

          .alerts-modal-current-status span {
            color: #526b80;
            font-size: 9px;
            text-transform: uppercase;
          }

          .alerts-modal-current-status strong {
            color: #a6b9c9;
            font-size: 10px;
          }

          .alerts-modal-info {
            padding: 9px 10px;
            border: 1px solid rgba(43, 96, 128, 0.28);
            border-radius: 6px;
            background: rgba(43, 96, 128, 0.07);
            color: #68869b;
            font-size: 9px;
            line-height: 14px;
          }

          .alerts-modal-error {
            padding: 9px 10px;
            border: 1px solid rgba(255, 93, 115, 0.25);
            border-radius: 6px;
            background: rgba(255, 93, 115, 0.07);
            color: #d98b96;
            font-size: 10px;
            line-height: 15px;
          }

          .alerts-modal-footer {
            display: flex;
            justify-content: flex-end;
            gap: 8px;
            padding: 14px 18px;
            border-top: 1px solid rgba(22, 50, 73, 0.8);
          }

          .alerts-modal-secondary,
          .alerts-modal-primary {
            min-height: 34px;
            padding: 0 13px;
            border-radius: 6px;
            font: inherit;
            font-size: 10px;
            font-weight: 650;
            cursor: pointer;
          }

          .alerts-modal-secondary {
            border: 1px solid #163249;
            background: #081927;
            color: #71899b;
          }

          .alerts-modal-primary {
            border: 1px solid #286080;
            background: #0c2637;
            color: #c8e8f7;
          }

          .alerts-modal-secondary:hover:not(:disabled),
          .alerts-modal-primary:hover:not(:disabled) {
            border-color: #36bdf5;
          }

          .alerts-modal-secondary:disabled,
          .alerts-modal-primary:disabled,
          .alerts-modal-close:disabled {
            opacity: 0.45;
            cursor: not-allowed;
          }

          .alerts-audit-list {
            display: flex;
            flex-direction: column;
            gap: 8px;
          }

          .alerts-audit-entry {
            padding: 10px;
            border: 1px solid rgba(22, 50, 73, 0.7);
            border-radius: 6px;
            background: #081725;
          }

          .alerts-audit-entry-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 6px;
          }

          .alerts-audit-entry-header strong {
            color: #a6b9c9;
            font-size: 10px;
          }

          .alerts-audit-entry-header span {
            color: #526b80;
            font-size: 9px;
          }

          .alerts-audit-entry-body {
            display: flex;
            flex-direction: column;
            gap: 3px;
            color: #607b90;
            font-size: 9px;
            line-height: 14px;
          }

          .alerts-page {
            min-width: 0;
            overflow-x: hidden;
          }

          .alerts-queue {
            min-width: 0;
            overflow-x: hidden;
          }

          .alerts-queue .alerts-table,
          .alerts-queue .alerts-table-container,
          .alerts-queue .alerts-table-wrapper {
            width: 100%;
            max-width: 100%;
            min-width: 0;
            overflow-x: hidden;
          }

          @media (max-width: 900px) {
            .alerts-filter-bar {
              grid-template-columns:
                repeat(2, minmax(0, 1fr));
            }
          }

          @media (max-width: 600px) {
            .alerts-filter-bar {
              grid-template-columns: 1fr;
            }

            .alerts-modal {
              width: min(100vw, 420px);
            }

            .alerts-modal-footer {
              flex-direction: column-reverse;
            }

            .alerts-modal-secondary,
            .alerts-modal-primary {
              width: 100%;
            }
          }

          @media (prefers-reduced-motion: reduce) {
            .alerts-modal,
            .alerts-action-menu {
              transition: none !important;
            }
          }
        `}
      </style>
    </>
  );
}