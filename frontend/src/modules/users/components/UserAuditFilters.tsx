/**
 * ============================================================================
 * SentinelSIEM — Individual User Audit Filters
 * ============================================================================
 *
 * Individual User Audit filter contract:
 *
 *   Action
 *   Outcome
 *   Target
 *   Source IP
 *   From
 *   To
 *
 * Rules:
 *
 *   - No Actor filter
 *   - No Apply button
 *   - Changes are applied immediately
 *   - Target users come from backend user data
 *   - Reset remains available
 *
 * ============================================================================
 */

import {
  CalendarDays,
  Filter,
  RotateCcw,
  Shield,
  Target,
} from "lucide-react";

import type {
  ChangeEvent,
} from "react";

import type {
  User,
  UserAuditAction,
  UserAuditListParams,
  UserAuditOutcome,
} from "../types";

/* ============================================================================
 * Props
 * ========================================================================== */

export interface UserAuditFiltersProps {
  filters: UserAuditListParams;

  onChange: (
    filters: UserAuditListParams,
  ) => void;

  onReset?: () => void;

  targetUsers: User[];

  targetUsersLoading?: boolean;

  disabled?: boolean;
}

/* ============================================================================
 * Options
 * ========================================================================== */

const ACTION_OPTIONS: ReadonlyArray<{
  value: UserAuditAction;
  label: string;
}> = [
  {
    value: "user.created",
    label: "User Created",
  },
  {
    value: "user.updated",
    label: "User Updated",
  },
  {
    value: "user.role_changed",
    label: "Role Changed",
  },
  {
    value: "user.enabled",
    label: "User Enabled",
  },
  {
    value: "user.disabled",
    label: "User Disabled",
  },
  {
    value: "user.locked",
    label: "User Locked",
  },
  {
    value: "user.unlocked",
    label: "User Unlocked",
  },
  {
    value: "user.password_reset",
    label: "Password Reset",
  },
  {
    value: "user.sessions_revoked",
    label: "Sessions Revoked",
  },
];

const OUTCOME_OPTIONS: ReadonlyArray<{
  value: UserAuditOutcome;
  label: string;
}> = [
  {
    value: "success",
    label: "Success",
  },
  {
    value: "failure",
    label: "Failure",
  },
  {
    value: "denied",
    label: "Denied",
  },
];

/* ============================================================================
 * Component
 * ========================================================================== */

export default function UserAuditFilters({
  filters,
  onChange,
  onReset,
  targetUsers,
  targetUsersLoading = false,
  disabled = false,
}: UserAuditFiltersProps) {
  /* --------------------------------------------------------------------------
   * Filter Update
   * ------------------------------------------------------------------------ */

  function updateFilter(
    key: keyof UserAuditListParams,
    value: string | undefined,
  ) {
    const nextFilters: UserAuditListParams = {
      ...filters,
      page: 1,
    };

    if (value) {
      if (key === "action") {
        nextFilters.action =
          value as UserAuditAction;
      } else if (key === "outcome") {
        nextFilters.outcome =
          value as UserAuditOutcome;
      } else if (key === "target_user_id") {
        nextFilters.target_user_id =
          value;
      } else if (key === "source_ip") {
        nextFilters.source_ip =
          value;
      } else if (key === "date_from") {
        nextFilters.date_from =
          value;
      } else if (key === "date_to") {
        nextFilters.date_to =
          value;
      }
    } else {
      delete nextFilters[key];
    }

    onChange(nextFilters);
  }

  /* --------------------------------------------------------------------------
   * Action
   * ------------------------------------------------------------------------ */

  function handleActionChange(
    event: ChangeEvent<HTMLSelectElement>,
  ) {
    updateFilter(
      "action",
      event.target.value.trim() || undefined,
    );
  }

  /* --------------------------------------------------------------------------
   * Outcome
   * ------------------------------------------------------------------------ */

  function handleOutcomeChange(
    event: ChangeEvent<HTMLSelectElement>,
  ) {
    updateFilter(
      "outcome",
      event.target.value.trim() || undefined,
    );
  }

  /* --------------------------------------------------------------------------
   * Target
   * ------------------------------------------------------------------------ */

  function handleTargetChange(
    event: ChangeEvent<HTMLSelectElement>,
  ) {
    updateFilter(
      "target_user_id",
      event.target.value.trim() || undefined,
    );
  }

  /* --------------------------------------------------------------------------
   * Source IP
   * ------------------------------------------------------------------------ */

  function handleSourceIpChange(
    event: ChangeEvent<HTMLInputElement>,
  ) {
    updateFilter(
      "source_ip",
      event.target.value.trim() || undefined,
    );
  }

  /* --------------------------------------------------------------------------
   * From
   * ------------------------------------------------------------------------ */

  function handleDateFromChange(
    event: ChangeEvent<HTMLInputElement>,
  ) {
    const value =
      event.target.value;

    updateFilter(
      "date_from",
      value
        ? toISODateStart(value)
        : undefined,
    );
  }

  /* --------------------------------------------------------------------------
   * To
   * ------------------------------------------------------------------------ */

  function handleDateToChange(
    event: ChangeEvent<HTMLInputElement>,
  ) {
    const value =
      event.target.value;

    updateFilter(
      "date_to",
      value
        ? toISODateEnd(value)
        : undefined,
    );
  }

  /* --------------------------------------------------------------------------
   * Reset
   * ------------------------------------------------------------------------ */

  function handleReset() {
    if (disabled) {
      return;
    }

    if (onReset) {
      onReset();
      return;
    }

    onChange({
      page: 1,
      page_size: 30,
    });
  }

  /* --------------------------------------------------------------------------
   * Active Filter Count
   * ------------------------------------------------------------------------ */

  const activeFilterCount =
    getActiveFilterCount(filters);

  const filtersActive =
    activeFilterCount > 0;

  /* ==========================================================================
   * Render
   * ======================================================================== */

  return (
    <section
      className="user-audit-filters"
      aria-labelledby="user-audit-filters-title"
    >
      {/* ======================================================================
       * Header
       * ==================================================================== */}

      <header className="user-audit-filters-header">
        <div className="user-audit-filters-title-group">
          <div
            className="user-audit-filters-icon"
            aria-hidden="true"
          >
            <Filter size={17} />
          </div>

          <div className="user-audit-filters-title-copy">
            <span className="user-audit-filters-eyebrow">
              FILTERS
            </span>

            <h4 id="user-audit-filters-title">
              Audit Filters
            </h4>

            <p>
              Narrow this user's audit activity
              by action, outcome, target, source,
              or time range.
            </p>
          </div>
        </div>

        {filtersActive && (
          <span
            className="user-audit-filter-count"
            aria-label={`${activeFilterCount} active ${
              activeFilterCount === 1
                ? "filter"
                : "filters"
            }`}
          >
            {activeFilterCount}{" "}
            {activeFilterCount === 1
              ? "filter"
              : "filters"}{" "}
            active
          </span>
        )}
      </header>

      {/* ======================================================================
       * Filter Body
       * ==================================================================== */}

      <div className="user-audit-filters-body">
        <div className="user-audit-filter-grid">

          {/* ------------------------------------------------------------------
           * Action
           * ---------------------------------------------------------------- */}

          <div className="user-audit-filter-field">
            <label htmlFor="user-audit-action">
              <Shield
                size={13}
                aria-hidden="true"
              />

              <span>Action</span>
            </label>

            <div className="user-audit-filter-control">
              <select
                id="user-audit-action"
                value={filters.action ?? ""}
                onChange={handleActionChange}
                disabled={disabled}
              >
                <option value="">
                  All Actions
                </option>

                {ACTION_OPTIONS.map(
                  (option) => (
                    <option
                      key={option.value}
                      value={option.value}
                    >
                      {option.label}
                    </option>
                  ),
                )}
              </select>
            </div>
          </div>

          {/* ------------------------------------------------------------------
           * Outcome
           * ---------------------------------------------------------------- */}

          <div className="user-audit-filter-field">
            <label htmlFor="user-audit-outcome">
              <Shield
                size={13}
                aria-hidden="true"
              />

              <span>Outcome</span>
            </label>

            <div className="user-audit-filter-control">
              <select
                id="user-audit-outcome"
                value={filters.outcome ?? ""}
                onChange={handleOutcomeChange}
                disabled={disabled}
              >
                <option value="">
                  All Outcomes
                </option>

                {OUTCOME_OPTIONS.map(
                  (option) => (
                    <option
                      key={option.value}
                      value={option.value}
                    >
                      {option.label}
                    </option>
                  ),
                )}
              </select>
            </div>
          </div>

          {/* ------------------------------------------------------------------
           * Target
           * ---------------------------------------------------------------- */}

          <div className="user-audit-filter-field">
            <label htmlFor="user-audit-target">
              <Target
                size={13}
                aria-hidden="true"
              />

              <span>Target</span>
            </label>

            <div className="user-audit-filter-control">
              <select
                id="user-audit-target"
                value={
                  filters.target_user_id ?? ""
                }
                onChange={handleTargetChange}
                disabled={
                  disabled ||
                  targetUsersLoading
                }
              >
                <option value="">
                  {targetUsersLoading
                    ? "Loading Targets..."
                    : "All Targets"}
                </option>

                {targetUsers.map(
                  (user) => (
                    <option
                      key={user.user_id}
                      value={user.user_id}
                    >
                      {getUserDisplayName(user)}
                    </option>
                  ),
                )}
              </select>
            </div>
          </div>

          {/* ------------------------------------------------------------------
           * Source IP
           * ---------------------------------------------------------------- */}

          <div className="user-audit-filter-field">
            <label htmlFor="user-audit-source-ip">
              <span>Source IP</span>

              <small>
                Optional
              </small>
            </label>

            <div className="user-audit-filter-input">
              <input
                id="user-audit-source-ip"
                type="text"
                value={
                  filters.source_ip ?? ""
                }
                onChange={handleSourceIpChange}
                placeholder="e.g. 192.168.1.10"
                disabled={disabled}
                autoComplete="off"
                spellCheck={false}
              />
            </div>
          </div>

          {/* ------------------------------------------------------------------
           * From
           * ---------------------------------------------------------------- */}

          <div className="user-audit-filter-field">
            <label htmlFor="user-audit-date-from">
              <CalendarDays
                size={13}
                aria-hidden="true"
              />

              <span>From</span>
            </label>

            <div className="user-audit-filter-input user-audit-date-input">
              <CalendarDays
                size={14}
                aria-hidden="true"
              />

              <input
                id="user-audit-date-from"
                type="date"
                value={getDateInputValue(
                  filters.date_from,
                )}
                onChange={handleDateFromChange}
                disabled={disabled}
              />
            </div>
          </div>

          {/* ------------------------------------------------------------------
           * To
           * ---------------------------------------------------------------- */}

          <div className="user-audit-filter-field">
            <label htmlFor="user-audit-date-to">
              <CalendarDays
                size={13}
                aria-hidden="true"
              />

              <span>To</span>
            </label>

            <div className="user-audit-filter-input user-audit-date-input">
              <CalendarDays
                size={14}
                aria-hidden="true"
              />

              <input
                id="user-audit-date-to"
                type="date"
                value={getDateInputValue(
                  filters.date_to,
                )}
                onChange={handleDateToChange}
                disabled={disabled}
              />
            </div>
          </div>
        </div>

        {/* ====================================================================
         * Filter Footer
         * ================================================================== */}

        <div
          className="user-audit-filters-footer"
          aria-live="polite"
        >
          <div className="user-audit-filter-summary">
            <Filter
              size={14}
              aria-hidden="true"
            />

            <span>
              {filtersActive
                ? `${activeFilterCount} ${
                    activeFilterCount === 1
                      ? "filter"
                      : "filters"
                  } selected — audit results update automatically.`
                : "No filters selected — showing all available audit events."}
            </span>
          </div>

          <button
            type="button"
            className="user-audit-reset-button"
            onClick={handleReset}
            disabled={
              disabled ||
              !filtersActive
            }
            title={
              filtersActive
                ? "Reset all audit filters"
                : "No active filters"
            }
          >
            <RotateCcw
              size={14}
              aria-hidden="true"
            />

            <span>
              Reset Filters
            </span>
          </button>
        </div>
      </div>
    </section>
  );
}

/* ============================================================================
 * Helpers
 * ========================================================================== */

function getActiveFilterCount(
  filters: UserAuditListParams,
): number {
  let count = 0;

  if (filters.action) {
    count += 1;
  }

  if (filters.outcome) {
    count += 1;
  }

  if (filters.target_user_id) {
    count += 1;
  }

  if (filters.source_ip) {
    count += 1;
  }

  if (filters.date_from) {
    count += 1;
  }

  if (filters.date_to) {
    count += 1;
  }

  return count;
}

/* ============================================================================
 * User Display Name
 * ========================================================================== */

function getUserDisplayName(
  user: User,
): string {
  const displayName =
    user.display_name?.trim();

  if (displayName) {
    return displayName;
  }

  const username =
    user.username?.trim();

  if (username) {
    return username;
  }

  const email =
    user.email?.trim();

  if (email) {
    return email;
  }

  return user.user_id;
}

/* ============================================================================
 * Date Helpers
 * ========================================================================== */

function getDateInputValue(
  value: string | undefined,
): string {
  if (!value) {
    return "";
  }

  const date = new Date(value);

  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    return "";
  }

  const year =
    date.getFullYear();

  const month =
    String(
      date.getMonth() + 1,
    ).padStart(2, "0");

  const day =
    String(
      date.getDate(),
    ).padStart(2, "0");

  return `${year}-${month}-${day}`;
}

function toISODateStart(
  value: string,
): string {
  const [
    yearText,
    monthText,
    dayText,
  ] = value.split("-");

  const date = new Date(
    Number(yearText),
    Number(monthText) - 1,
    Number(dayText),
    0,
    0,
    0,
    0,
  );

  return date.toISOString();
}

function toISODateEnd(
  value: string,
): string {
  const [
    yearText,
    monthText,
    dayText,
  ] = value.split("-");

  const date = new Date(
    Number(yearText),
    Number(monthText) - 1,
    Number(dayText),
    23,
    59,
    59,
    999,
  );

  return date.toISOString();
}