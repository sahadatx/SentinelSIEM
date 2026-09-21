/**
 * ============================================================================
 * SentinelSIEM — Global Audit Filters
 * ============================================================================
 *
 * Automatic filter controls for Global Audit.
 *
 * Locked workflow
 * ---------------
 *
 * Action        -> canonical backend action dropdown
 * Outcome       -> canonical backend outcome dropdown
 * Actor         -> human-readable user dropdown
 * Target        -> human-readable user dropdown
 * Source IP     -> text input
 * From          -> date picker
 * To            -> date picker
 *
 * Search is intentionally removed.
 *
 * Filter behavior
 * ---------------
 *
 * Filters are applied automatically whenever a control changes.
 * There is no Apply Filters button.
 *
 * Footer
 * ------
 *
 * Left  -> Showing all audit events / Filters applied
 * Right -> Reset Filters
 *
 * ============================================================================
 */

import {
  AlertCircle,
  CalendarDays,
  Filter,
  RotateCcw,
} from "lucide-react";

import {
  useEffect,
  useMemo,
  useState,
} from "react";

import type {
  AuditListParams,
} from "../types";


/* ============================================================================
 * User Option
 * ========================================================================== */

export interface AuditUserOption {
  user_id: string;
  display_name?: string | null;
  username: string;
  role?: string | null;
}


/* ============================================================================
 * Props
 * ========================================================================== */

export interface AuditFiltersProps {
  filters: AuditListParams;

  onChange: (
    filters: AuditListParams,
  ) => void;

  onReset?: () => void;

  actors?: AuditUserOption[];

  targets?: AuditUserOption[];

  disabled?: boolean;
}


/* ============================================================================
 * Canonical Backend Audit Actions
 * ========================================================================== */

const ACTION_OPTIONS = [
  {
    value: "authentication.login_success",
    label: "Login Success",
  },
  {
    value: "authentication.login_failure",
    label: "Login Failure",
  },
  {
    value: "authentication.logout",
    label: "Logout",
  },
  {
    value: "authentication.token_validation",
    label: "Token Validation Failure",
  },
  {
    value: "authentication.session_created",
    label: "Session Created",
  },
  {
    value: "authentication.session_revoked",
    label: "Session Revoked",
  },
  {
    value: "authentication.sessions_revoked",
    label: "Sessions Revoked",
  },
  {
    value: "authentication.password_changed",
    label: "Password Changed",
  },
  {
    value: "authentication.password_change_failure",
    label: "Password Change Failure",
  },
  {
    value: "users.password_reset",
    label: "Password Reset",
  },
  {
    value: "authentication.password_reset_failure",
    label: "Password Reset Failure",
  },
  {
    value: "authentication.force_password_change",
    label: "Force Password Change",
  },
  {
    value: "users.created",
    label: "User Created",
  },
  {
    value: "users.updated",
    label: "User Updated",
  },
  {
    value: "users.enabled",
    label: "User Enabled",
  },
  {
    value: "users.disabled",
    label: "User Disabled",
  },
  {
    value: "users.locked",
    label: "User Locked",
  },
  {
    value: "users.unlocked",
    label: "User Unlocked",
  },
  {
    value: "users.deleted",
    label: "User Deleted",
  },
  {
    value: "users.role_changed",
    label: "Role Changed",
  },
  {
    value: "role.created",
    label: "Role Created",
  },
  {
    value: "role.updated",
    label: "Role Updated",
  },
  {
    value: "role.deleted",
    label: "Role Deleted",
  },
  {
    value: "role.permissions_changed",
    label: "Permissions Changed",
  },
  {
    value: "users.listed",
    label: "Users Listed",
  },
  {
    value: "users.viewed",
    label: "User Viewed",
  },
  {
    value: "users.statistics_viewed",
    label: "User Statistics Viewed",
  },
  {
    value: "authorization.permission_denied",
    label: "Permission Denied",
  },
  {
    value: "authorization.denied",
    label: "Authorization Denied",
  },
] as const;


/* ============================================================================
 * Canonical Backend Outcomes
 * ========================================================================== */

const OUTCOME_OPTIONS = [
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
] as const;


/* ============================================================================
 * Component
 * ========================================================================== */

export default function AuditFilters({
  filters,
  onChange,
  onReset,
  actors = [],
  targets = [],
  disabled = false,
}: AuditFiltersProps) {

  /* ==========================================================================
   * Draft
   * ========================================================================= */

  const [
    draftFilters,
    setDraftFilters,
  ] = useState<AuditListParams>(
    () =>
      normalizeFilters(
        filters,
      ),
  );


  /* ==========================================================================
   * Validation
   * ========================================================================= */

  const [
    validationError,
    setValidationError,
  ] = useState<string | null>(
    null,
  );


  /* ==========================================================================
   * Parent Synchronization
   * ========================================================================= */

  useEffect(() => {
    setDraftFilters(
      normalizeFilters(
        filters,
      ),
    );

    setValidationError(
      null,
    );
  }, [filters]);


  /* ==========================================================================
   * User Options
   * ========================================================================= */

  const actorOptions = useMemo(
    () =>
      sortUserOptions(
        actors,
      ),
    [actors],
  );


  const targetOptions = useMemo(
    () =>
      sortUserOptions(
        targets,
      ),
    [targets],
  );


  /* ==========================================================================
   * Active Filter Count
   * ========================================================================= */

  const activeFilterCount = useMemo(
    () =>
      countActiveFilters(
        draftFilters,
      ),
    [draftFilters],
  );


  const hasActiveFilters =
    activeFilterCount > 0;


  /* ==========================================================================
   * Automatic Filter Update
   * ========================================================================= */

  function updateDraftFilter<
    K extends keyof AuditListParams,
  >(
    key: K,
    value: AuditListParams[K],
  ): void {

    if (disabled) {
      return;
    }

    const nextFilters =
      normalizeFilters({
        ...draftFilters,
        [key]: value,
      });

    const nextDateValidation =
      validateDateRange(
        nextFilters.date_from,
        nextFilters.date_to,
      );

    if (nextDateValidation) {
      setDraftFilters(
        nextFilters,
      );

      setValidationError(
        nextDateValidation,
      );

      return;
    }

    setValidationError(
      null,
    );

    setDraftFilters(
      nextFilters,
    );

    /*
     * Automatic filtering:
     *
     * Every filter change is immediately propagated
     * to the parent container.
     */
    onChange(
      nextFilters,
    );
  }


  /* ==========================================================================
   * Action
   * ========================================================================= */

  function handleActionChange(
    value: string,
  ): void {

    updateDraftFilter(
      "action",
      normalizeText(
        value,
      ),
    );
  }


  /* ==========================================================================
   * Outcome
   * ========================================================================= */

  function handleOutcomeChange(
    value: string,
  ): void {

    updateDraftFilter(
      "outcome",
      normalizeText(
        value,
      ),
    );
  }


  /* ==========================================================================
   * Actor
   * ========================================================================= */

  function handleActorChange(
    value: string,
  ): void {

    updateDraftFilter(
      "actor_user_id",
      normalizeText(
        value,
      ),
    );
  }


  /* ==========================================================================
   * Target
   * ========================================================================= */

  function handleTargetChange(
    value: string,
  ): void {

    updateDraftFilter(
      "target_user_id",
      normalizeText(
        value,
      ),
    );
  }


  /* ==========================================================================
   * Source IP
   * ========================================================================= */

  function handleSourceIpChange(
    value: string,
  ): void {

    updateDraftFilter(
      "source_ip",
      normalizeText(
        value,
      ),
    );
  }


  /* ==========================================================================
   * From Date
   * ========================================================================= */

  function handleDateFromChange(
    value: string,
  ): void {

    updateDraftFilter(
      "date_from",
      value
        ? toISODateStart(
            value,
          )
        : undefined,
    );
  }


  /* ==========================================================================
   * To Date
   * ========================================================================= */

  function handleDateToChange(
    value: string,
  ): void {

    updateDraftFilter(
      "date_to",
      value
        ? toISODateEnd(
            value,
          )
        : undefined,
    );
  }


  /* ==========================================================================
   * Reset
   * ========================================================================= */

  function handleReset(): void {

    if (disabled) {
      return;
    }

    const emptyFilters:
      AuditListParams = {};

    setDraftFilters(
      emptyFilters,
    );

    setValidationError(
      null,
    );

    if (onReset) {
      onReset();
      return;
    }

    onChange(
      emptyFilters,
    );
  }


  /* ==========================================================================
   * Render
   * ========================================================================= */

  return (
    <section
      className="audit-filters"
      aria-label="Audit filters"
    >

      {/* ====================================================================
          Header
          ==================================================================== */}

      <div className="form-heading">

        <div>

          <span className="audit-section-kicker">
            FILTERS
          </span>

          <h4>
            Audit Filters
          </h4>

          <p>
            Narrow audit activity by action,
            outcome, identity, source,
            or time range.
          </p>

        </div>

        <Filter
          size={18}
          aria-hidden="true"
        />

      </div>


      {/* ====================================================================
          Validation
          ==================================================================== */}

      {validationError && (

        <div
          className="notice warning"
          role="alert"
        >

          <AlertCircle
            size={15}
            aria-hidden="true"
          />

          <span>
            {validationError}
          </span>

        </div>

      )}


      {/* ====================================================================
          Filter Grid
          ==================================================================== */}

      <div className="audit-filter-grid">

        {/* ==================================================================
            ACTION
            ================================================================== */}

        <div className="form-field">

          <label htmlFor="audit-action">
            Action
          </label>

          <select
            id="audit-action"
            name="action"
            value={
              draftFilters.action ??
              ""
            }
            onChange={(
              event,
            ) =>
              handleActionChange(
                event.target.value,
              )
            }
            disabled={
              disabled
            }
          >

            <option value="">
              All Actions
            </option>

            {ACTION_OPTIONS.map(
              (
                action,
              ) => (

                <option
                  key={
                    action.value
                  }
                  value={
                    action.value
                  }
                >
                  {
                    action.label
                  }
                </option>

              ),
            )}

          </select>

        </div>


        {/* ==================================================================
            OUTCOME
            ================================================================== */}

        <div className="form-field">

          <label htmlFor="audit-outcome">
            Outcome
          </label>

          <select
            id="audit-outcome"
            name="outcome"
            value={
              draftFilters.outcome ??
              ""
            }
            onChange={(
              event,
            ) =>
              handleOutcomeChange(
                event.target.value,
              )
            }
            disabled={
              disabled
            }
          >

            <option value="">
              All Outcomes
            </option>

            {OUTCOME_OPTIONS.map(
              (
                outcome,
              ) => (

                <option
                  key={
                    outcome.value
                  }
                  value={
                    outcome.value
                  }
                >
                  {
                    outcome.label
                  }
                </option>

              ),
            )}

          </select>

        </div>


        {/* ==================================================================
            ACTOR
            ================================================================== */}

        <div className="form-field">

          <label htmlFor="audit-actor">
            Actor
          </label>

          <select
            id="audit-actor"
            name="actor_user_id"
            value={
              draftFilters.actor_user_id ??
              ""
            }
            onChange={(
              event,
            ) =>
              handleActorChange(
                event.target.value,
              )
            }
            disabled={
              disabled
            }
          >

            <option value="">
              All Actors
            </option>

            {actorOptions.map(
              (
                actor,
              ) => (

                <option
                  key={
                    actor.user_id
                  }
                  value={
                    actor.user_id
                  }
                >
                  {
                    formatUserOption(
                      actor,
                    )
                  }
                </option>

              ),
            )}

          </select>

          {actorOptions.length === 0 && (

            <span className="field-hint">
              No actor identities available.
            </span>

          )}

        </div>


        {/* ==================================================================
            TARGET
            ================================================================== */}

        <div className="form-field">

          <label htmlFor="audit-target">
            Target
          </label>

          <select
            id="audit-target"
            name="target_user_id"
            value={
              draftFilters.target_user_id ??
              ""
            }
            onChange={(
              event,
            ) =>
              handleTargetChange(
                event.target.value,
              )
            }
            disabled={
              disabled
            }
          >

            <option value="">
              All Targets
            </option>

            {targetOptions.map(
              (
                target,
              ) => (

                <option
                  key={
                    target.user_id
                  }
                  value={
                    target.user_id
                  }
                >
                  {
                    formatUserOption(
                      target,
                    )
                  }
                </option>

              ),
            )}

          </select>

          {targetOptions.length === 0 && (

            <span className="field-hint">
              No target identities available.
            </span>

          )}

        </div>


        {/* ==================================================================
            SOURCE IP
            ================================================================== */}

        <div className="form-field">

          <label htmlFor="audit-source-ip">

            Source IP

            <span className="field-optional">
              Optional
            </span>

          </label>

          <input
            id="audit-source-ip"
            name="source_ip"
            type="text"
            value={
              draftFilters.source_ip ??
              ""
            }
            onChange={(
              event,
            ) =>
              handleSourceIpChange(
                event.target.value,
              )
            }
            placeholder="e.g. 192.168.1.10"
            autoComplete="off"
            spellCheck={false}
            inputMode="decimal"
            disabled={
              disabled
            }
          />

        </div>


        {/* ==================================================================
            FROM
            ================================================================== */}

        <div className="form-field">

          <label htmlFor="audit-date-from">
            From
          </label>

          <div className="audit-date-input">

            <CalendarDays
              size={15}
              aria-hidden="true"
            />

            <input
              id="audit-date-from"
              name="date_from"
              type="date"
              value={
                toInputDate(
                  draftFilters.date_from,
                )
              }
              onChange={(
                event,
              ) =>
                handleDateFromChange(
                  event.target.value,
                )
              }
              disabled={
                disabled
              }
            />

          </div>

        </div>


        {/* ==================================================================
            TO
            ================================================================== */}

        <div className="form-field">

          <label htmlFor="audit-date-to">
            To
          </label>

          <div className="audit-date-input">

            <CalendarDays
              size={15}
              aria-hidden="true"
            />

            <input
              id="audit-date-to"
              name="date_to"
              type="date"
              value={
                toInputDate(
                  draftFilters.date_to,
                )
              }
              onChange={(
                event,
              ) =>
                handleDateToChange(
                  event.target.value,
                )
              }
              disabled={
                disabled
              }
            />

          </div>

        </div>

      </div>


      {/* ====================================================================
          Filter Actions
          ==================================================================== */}

      <div
        className="audit-filter-actions"
        role="status"
        aria-live="polite"
      >

        {/* ------------------------------------------------------------------
            Left Status
            ------------------------------------------------------------------ */}

        <div className="audit-filter-actions-meta">

          {hasActiveFilters ? (

            <>
              <span
                className="audit-filter-active-indicator"
                aria-hidden="true"
              />

              <span>
                Filters applied
              </span>

              <span className="audit-filter-count">
                {activeFilterCount}
              </span>
            </>

          ) : (

            <span>
              Showing all audit events
            </span>

          )}

        </div>


        {/* ------------------------------------------------------------------
            Reset
            ------------------------------------------------------------------ */}

        <button
          type="button"
          className="secondary-button audit-filter-reset-button"
          onClick={
            handleReset
          }
          disabled={
            disabled ||
            !hasActiveFilters
          }
          title={
            hasActiveFilters
              ? "Reset all filters"
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

    </section>
  );
}


/* ============================================================================
 * User Formatting
 * ========================================================================== */

function formatUserOption(
  user: AuditUserOption,
): string {

  const displayName =
    normalizeNullableText(
      user.display_name,
    );

  const username =
    normalizeNullableText(
      user.username,
    );

  const role =
    normalizeNullableText(
      user.role,
    );

  const identity =
    displayName ||
    username ||
    "Unknown User";

  if (!role) {
    return `👤 ${identity}`;
  }

  return `👤 ${identity} — ${formatRole(role)}`;
}


/* ============================================================================
 * User Sorting + Deduplication
 * ========================================================================== */

function sortUserOptions(
  users: AuditUserOption[],
): AuditUserOption[] {

  const uniqueUsers =
    new Map<
      string,
      AuditUserOption
    >();

  for (
    const user of users
  ) {

    const userId =
      normalizeNullableText(
        user.user_id,
      );

    const username =
      normalizeNullableText(
        user.username,
      );

    if (
      !userId ||
      !username
    ) {
      continue;
    }

    uniqueUsers.set(
      userId,
      {
        user_id:
          userId,

        display_name:
          user.display_name ??
          null,

        username,

        role:
          user.role ??
          null,
      },
    );
  }

  return Array.from(
    uniqueUsers.values(),
  ).sort(
    (
      left,
      right,
    ) => {

      const leftLabel =
        (
          normalizeNullableText(
            left.display_name,
          ) ||
          left.username
        ).toLowerCase();

      const rightLabel =
        (
          normalizeNullableText(
            right.display_name,
          ) ||
          right.username
        ).toLowerCase();

      return leftLabel.localeCompare(
        rightLabel,
      );
    },
  );
}


/* ============================================================================
 * Role Formatting
 * ========================================================================== */

function formatRole(
  role: string,
): string {

  const normalized =
    role
      .trim()
      .replace(
        /[-_]+/g,
        " ",
      )
      .replace(
        /\s+/g,
        " ",
      );

  if (!normalized) {
    return "User";
  }

  return normalized.replace(
    /\b\w/g,
    (
      character,
    ) =>
      character.toUpperCase(),
  );
}


/* ============================================================================
 * Active Filter Counter
 * ========================================================================== */

function countActiveFilters(
  filters: AuditListParams,
): number {

  let count = 0;

  const values: Array<
    string | number | null | undefined
  > = [
    filters.action,
    filters.outcome,
    filters.actor_user_id,
    filters.target_user_id,
    filters.source_ip,
    filters.date_from,
    filters.date_to,
  ];

  for (
    const value of values
  ) {

    if (
      hasValue(value)
    ) {
      count += 1;
    }

  }

  return count;
}


/* ============================================================================
 * Filter Normalization
 * ========================================================================== */

function normalizeFilters(
  filters: AuditListParams,
): AuditListParams {

  const normalized:
    AuditListParams = {};


  /* --------------------------------------------------------------------------
   * Locked UI filters
   * ------------------------------------------------------------------------ */

  copyOptionalField(
    filters.action,
    (
      value,
    ) => {
      normalized.action =
        value;
    },
  );

  copyOptionalField(
    filters.outcome,
    (
      value,
    ) => {
      normalized.outcome =
        value;
    },
  );

  copyOptionalField(
    filters.actor_user_id,
    (
      value,
    ) => {
      normalized.actor_user_id =
        value;
    },
  );

  copyOptionalField(
    filters.target_user_id,
    (
      value,
    ) => {
      normalized.target_user_id =
        value;
    },
  );

  copyOptionalField(
    filters.source_ip,
    (
      value,
    ) => {
      normalized.source_ip =
        value;
    },
  );

  copyOptionalField(
    filters.date_from,
    (
      value,
    ) => {
      normalized.date_from =
        value;
    },
  );

  copyOptionalField(
    filters.date_to,
    (
      value,
    ) => {
      normalized.date_to =
        value;
    },
  );


  /* --------------------------------------------------------------------------
   * Compatibility fields
   * ------------------------------------------------------------------------ */

  copyOptionalField(
    filters.category,
    (
      value,
    ) => {
      normalized.category =
        value;
    },
  );

  copyOptionalField(
    filters.session_id,
    (
      value,
    ) => {
      normalized.session_id =
        value;
    },
  );

  copyOptionalField(
    filters.request_id,
    (
      value,
    ) => {
      normalized.request_id =
        value;
    },
  );


  /* --------------------------------------------------------------------------
   * Existing API aliases
   * ------------------------------------------------------------------------ */

  copyOptionalField(
    filters.actor,
    (
      value,
    ) => {
      normalized.actor =
        value;
    },
  );

  copyOptionalField(
    filters.target,
    (
      value,
    ) => {
      normalized.target =
        value;
    },
  );

  copyOptionalField(
    filters.result,
    (
      value,
    ) => {
      normalized.result =
        value;
    },
  );

  copyOptionalField(
    filters.source,
    (
      value,
    ) => {
      normalized.source =
        value;
    },
  );


  /* --------------------------------------------------------------------------
   * Pagination compatibility
   * ------------------------------------------------------------------------ */

  if (
    filters.page !== undefined
  ) {
    normalized.page =
      filters.page;
  }

  if (
    filters.page_size !== undefined
  ) {
    normalized.page_size =
      filters.page_size;
  }

  if (
    filters.limit !== undefined
  ) {
    normalized.limit =
      filters.limit;
  }

  if (
    filters.offset !== undefined
  ) {
    normalized.offset =
      filters.offset;
  }


  return normalized;
}


/* ============================================================================
 * Optional Field Copy
 * ========================================================================== */

function copyOptionalField(
  value:
    | string
    | undefined
    | null,
  assign: (
    value: string,
  ) => void,
): void {

  const normalized =
    normalizeOptionalString(
      value,
    );

  if (
    normalized !== undefined
  ) {
    assign(
      normalized,
    );
  }
}


/* ============================================================================
 * Nullable String
 * ========================================================================== */

function normalizeNullableText(
  value:
    | string
    | undefined
    | null,
): string | null {

  if (
    typeof value !== "string"
  ) {
    return null;
  }

  const normalized =
    value.trim();

  return normalized.length > 0
    ? normalized
    : null;
}


/* ============================================================================
 * Optional String
 * ========================================================================== */

function normalizeOptionalString(
  value:
    | string
    | undefined
    | null,
): string | undefined {

  if (
    typeof value !== "string"
  ) {
    return undefined;
  }

  const normalized =
    value.trim();

  return normalized.length > 0
    ? normalized
    : undefined;
}


/* ============================================================================
 * Text Normalization
 * ========================================================================== */

function normalizeText(
  value: string,
): string | undefined {

  return normalizeOptionalString(
    value,
  );
}


/* ============================================================================
 * Value Check
 * ========================================================================== */

function hasValue(
  value:
    | string
    | number
    | undefined
    | null,
): boolean {

  if (
    value === undefined ||
    value === null
  ) {
    return false;
  }

  if (
    typeof value === "string"
  ) {
    return value.trim().length > 0;
  }

  return true;
}


/* ============================================================================
 * Date Validation
 * ========================================================================== */

function validateDateRange(
  dateFrom:
    | string
    | undefined,

  dateTo:
    | string
    | undefined,
): string | null {

  if (
    !dateFrom ||
    !dateTo
  ) {
    return null;
  }

  const from =
    new Date(
      dateFrom,
    );

  const to =
    new Date(
      dateTo,
    );

  if (
    Number.isNaN(
      from.getTime(),
    ) ||
    Number.isNaN(
      to.getTime(),
    )
  ) {
    return "The selected date range is invalid.";
  }

  if (
    from.getTime() >
    to.getTime()
  ) {
    return "The From date cannot be later than the To date.";
  }

  return null;
}


/* ============================================================================
 * Date -> ISO Start
 * ========================================================================== */

function toISODateStart(
  value: string,
): string {

  const match =
    /^(\d{4})-(\d{2})-(\d{2})$/.exec(
      value,
    );

  if (!match) {
    return "";
  }

  const year =
    Number(
      match[1],
    );

  const month =
    Number(
      match[2],
    ) - 1;

  const day =
    Number(
      match[3],
    );

  const date =
    new Date(
      Date.UTC(
        year,
        month,
        day,
        0,
        0,
        0,
        0,
      ),
    );

  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    return "";
  }

  return date.toISOString();
}


/* ============================================================================
 * Date -> ISO End
 * ========================================================================== */

function toISODateEnd(
  value: string,
): string {

  const match =
    /^(\d{4})-(\d{2})-(\d{2})$/.exec(
      value,
    );

  if (!match) {
    return "";
  }

  const year =
    Number(
      match[1],
    );

  const month =
    Number(
      match[2],
    ) - 1;

  const day =
    Number(
      match[3],
    );

  const date =
    new Date(
      Date.UTC(
        year,
        month,
        day,
        23,
        59,
        59,
        999,
      ),
    );

  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    return "";
  }

  return date.toISOString();
}


/* ============================================================================
 * ISO -> Date Input
 * ========================================================================== */

function toInputDate(
  value:
    | string
    | undefined,
): string {

  if (!value) {
    return "";
  }

  const date =
    new Date(
      value,
    );

  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    return "";
  }

  const year =
    date.getUTCFullYear();

  const month =
    String(
      date.getUTCMonth() + 1,
    ).padStart(
      2,
      "0",
    );

  const day =
    String(
      date.getUTCDate(),
    ).padStart(
      2,
      "0",
    );

  return `${year}-${month}-${day}`;
}


/* ============================================================================
 * End of File
 * ============================================================================
 */