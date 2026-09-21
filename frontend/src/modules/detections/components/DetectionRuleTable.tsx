/* ==========================================================================
 * SentinelSIEM
 * Detection Rule Table
 *
 * Responsibility
 * ----------------------------------------------------------------------------
 * - Display backend-filtered Detection rules
 * - Display backend-provided runtime statistics
 * - Display condition count
 * - Provide rule selection
 * - Provide contextual rule actions
 * - Presentation only
 *
 * Locked columns
 * ----------------------------------------------------------------------------
 * Rule
 * Severity
 * Category
 * Status
 * Conditions
 * Matches
 * Suppressed
 * Last Match
 * Actions
 *
 * IMPORTANT
 * ----------------------------------------------------------------------------
 * - Filtering is owned by the parent/backend query layer.
 * - Pagination is owned by the parent/backend query layer.
 * - No API communication occurs here.
 * - No Detection KPI calculation occurs here.
 * - Runtime statistics come from backend-provided rule data.
 * - Missing backend counters are displayed as "—".
 * - Generated Alerts are not displayed as a table column.
 * - No local rule filtering or local pagination is performed.
 *
 * ACTION MENU
 * ----------------------------------------------------------------------------
 * - Rendered through React Portal.
 * - Menu is positioned relative to the viewport.
 * - Table overflow cannot clip the menu.
 * - Escape closes the menu.
 * - Pointer outside the menu closes the menu.
 * ========================================================================== */

import {
  useEffect,
  useRef,
  useState,
} from "react";

import {
  createPortal,
} from "react-dom";

import type {
  DetectionRule,
} from "../types";


/* ==========================================================================
 * Props
 * ========================================================================== */

interface DetectionRuleTableProps {
  /**
   * Backend-filtered and backend-paginated Detection rules.
   */
  rules: DetectionRule[];

  /**
   * Table loading state.
   */
  loading?: boolean;

  /**
   * Table-level error.
   */
  error?: string | null;

  /**
   * Open Rule Details.
   */
  onSelectRule?: (
    rule: DetectionRule,
  ) => void;

  /**
   * Open Edit Rule.
   */
  onEditRule?: (
    rule: DetectionRule,
  ) => void;

  /**
   * Enable / disable a rule.
   */
  onToggleRule?: (
    rule: DetectionRule,
  ) => void;

  /**
   * Delete a rule.
   */
  onDeleteRule?: (
    rule: DetectionRule,
  ) => void;

  /**
   * Optional Alerts navigation.
   *
   * Detection → Alert integration is not currently authoritative,
   * so this action is rendered only when the parent explicitly supplies it.
   */
  onViewAlerts?: (
    rule: DetectionRule,
  ) => void;
}


/* ==========================================================================
 * Helpers
 * ========================================================================== */

/**
 * Format a backend severity value for presentation.
 *
 * No severity values are created or inferred here.
 */
function formatSeverity(
  severity: string,
): string {
  const value =
    severity.trim();

  if (!value) {
    return "Unknown";
  }

  return (
    value.charAt(0).toUpperCase() +
    value.slice(1)
  );
}


/**
 * Build a safe severity CSS modifier.
 *
 * Presentation only.
 */
function getSeverityClass(
  severity: string,
): string {
  const normalized =
    severity
      .trim()
      .toLowerCase()
      .replace(
        /[^a-z0-9_-]/g,
        "-",
      );

  return normalized || "unknown";
}


/**
 * Format a backend-provided numeric counter.
 *
 * Missing / invalid values remain unavailable.
 */
function formatNumber(
  value:
    | number
    | null
    | undefined,
): string {
  if (
    typeof value !== "number" ||
    !Number.isFinite(value)
  ) {
    return "—";
  }

  return value.toLocaleString();
}


/**
 * Format a backend-provided timestamp.
 *
 * Invalid or missing timestamps remain unavailable.
 */
function formatLastMatch(
  value:
    | string
    | null
    | undefined,
): string {
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
    return "—";
  }

  return date.toLocaleString(
    undefined,
    {
      dateStyle: "medium",
      timeStyle: "short",
    },
  );
}


/**
 * Backend runtime statistics may be exposed either directly on the rule
 * or under rule.statistics.
 *
 * This helper only reads values already supplied by the backend.
 */
function getRuleStatistics(
  rule: DetectionRule,
): {
  matches:
    | number
    | null
    | undefined;

  suppressed:
    | number
    | null
    | undefined;

  lastMatchAt:
    | string
    | null
    | undefined;
} {
  return {
    matches:
      rule.statistics?.matches ??
      rule.matches,

    suppressed:
      rule.statistics?.suppressed ??
      rule.suppressed,

    lastMatchAt:
      rule.statistics?.last_match_at ??
      rule.last_match_at ??
      rule.last_match ??
      null,
  };
}


/**
 * Count conditions supplied by the backend.
 *
 * This is a direct presentation count of the backend-provided condition
 * collection. It is not a detection metric or KPI calculation.
 */
function getConditionCount(
  rule: DetectionRule,
): number {
  return Array.isArray(
    rule.conditions,
  )
    ? rule.conditions.length
    : 0;
}


/* ==========================================================================
 * Action Menu Position
 * ========================================================================== */

interface ActionMenuPosition {
  top: number;
  left: number;
}


/**
 * Approximate menu dimensions used only for viewport positioning.
 *
 * These values are presentation/layout values and do not represent
 * backend data.
 */
const ACTION_MENU_WIDTH = 188;
const ACTION_MENU_ESTIMATED_HEIGHT = 220;
const ACTION_MENU_GAP = 6;
const ACTION_MENU_VIEWPORT_PADDING = 8;


/* ==========================================================================
 * Action Menu
 * ========================================================================== */

interface ActionMenuProps {
  rule:
    DetectionRule;

  position:
    ActionMenuPosition;

  onSelectRule?:
    (
      rule: DetectionRule,
    ) => void;

  onEditRule?:
    (
      rule: DetectionRule,
    ) => void;

  onToggleRule?:
    (
      rule: DetectionRule,
    ) => void;

  onDeleteRule?:
    (
      rule: DetectionRule,
    ) => void;

  onViewAlerts?:
    (
      rule: DetectionRule,
    ) => void;

  onClose:
    () => void;
}


/**
 * Contextual Detection rule action menu.
 *
 * IMPORTANT
 * --------------------------------------------------------------------------
 * The menu is rendered into document.body using createPortal().
 *
 * This prevents the menu from being clipped by:
 *
 *   .detection-rule-table-wrapper {
 *     overflow-x: auto;
 *   }
 *
 * Positioning uses viewport coordinates because the menu is position: fixed.
 */
function DetectionRuleActionMenu({
  rule,
  position,
  onSelectRule,
  onEditRule,
  onToggleRule,
  onDeleteRule,
  onViewAlerts,
  onClose,
}: ActionMenuProps) {
  const menuRef =
    useRef<HTMLDivElement>(
      null,
    );

  const firstActionRef =
    useRef<HTMLButtonElement>(
      null,
    );


  /* ------------------------------------------------------------------------
   * Outside click
   * ---------------------------------------------------------------------- */

  useEffect(() => {
    function handlePointerDown(
      event: PointerEvent,
    ): void {
      const target =
        event.target;

      if (
        target instanceof Node &&
        menuRef.current?.contains(
          target,
        )
      ) {
        return;
      }

      onClose();
    }

    document.addEventListener(
      "pointerdown",
      handlePointerDown,
    );

    return () => {
      document.removeEventListener(
        "pointerdown",
        handlePointerDown,
      );
    };
  }, [onClose]);


  /* ------------------------------------------------------------------------
   * Keyboard / focus
   * ---------------------------------------------------------------------- */

  useEffect(() => {
    /*
     * Wait until the portal content is mounted before focusing.
     */
    const frame =
      window.requestAnimationFrame(() => {
        firstActionRef.current?.focus();
      });

    function handleKeyDown(
      event: KeyboardEvent,
    ): void {
      if (
        event.key === "Escape"
      ) {
        event.preventDefault();
        onClose();
      }
    }

    document.addEventListener(
      "keydown",
      handleKeyDown,
    );

    return () => {
      window.cancelAnimationFrame(
        frame,
      );

      document.removeEventListener(
        "keydown",
        handleKeyDown,
      );
    };
  }, [onClose]);


  /* ------------------------------------------------------------------------
   * Handlers
   * ---------------------------------------------------------------------- */

  function handleSelectRule(): void {
    onClose();
    onSelectRule?.(rule);
  }


  function handleViewAlerts(): void {
    onClose();
    onViewAlerts?.(rule);
  }


  function handleEditRule(): void {
    onClose();
    onEditRule?.(rule);
  }


  function handleToggleRule(): void {
    onClose();
    onToggleRule?.(rule);
  }


  function handleDeleteRule(): void {
    onClose();
    onDeleteRule?.(rule);
  }


  /* ------------------------------------------------------------------------
   * Render
   * ---------------------------------------------------------------------- */

  const menu =
    (
      <div
        ref={menuRef}
        className="detection-rule-actions-menu"
        role="menu"
        aria-label={`Actions for ${rule.name}`}
        style={{
          position: "fixed",
          top: `${position.top}px`,
          left: `${position.left}px`,
          width: `${ACTION_MENU_WIDTH}px`,
        }}
      >
        {onSelectRule ? (
          <button
            ref={firstActionRef}
            type="button"
            className="detection-rule-actions-menu-item"
            role="menuitem"
            onClick={handleSelectRule}
          >
            <span className="detection-rule-actions-menu-item-label">
              View
            </span>

            <span className="detection-rule-actions-menu-item-hint">
              Details
            </span>
          </button>
        ) : null}


        {onViewAlerts ? (
          <button
            type="button"
            className="detection-rule-actions-menu-item"
            role="menuitem"
            onClick={handleViewAlerts}
          >
            <span className="detection-rule-actions-menu-item-label">
              View Alerts
            </span>

            <span className="detection-rule-actions-menu-item-hint">
              Alerts
            </span>
          </button>
        ) : null}


        {onEditRule ? (
          <button
            type="button"
            className="detection-rule-actions-menu-item"
            role="menuitem"
            onClick={handleEditRule}
          >
            <span className="detection-rule-actions-menu-item-label">
              Edit
            </span>

            <span className="detection-rule-actions-menu-item-hint">
              Modify
            </span>
          </button>
        ) : null}


        {onToggleRule ? (
          <button
            type="button"
            className="detection-rule-actions-menu-item"
            role="menuitem"
            onClick={handleToggleRule}
          >
            <span className="detection-rule-actions-menu-item-label">
              {rule.enabled
                ? "Disable"
                : "Enable"}
            </span>

            <span className="detection-rule-actions-menu-item-hint">
              {rule.enabled
                ? "Deactivate"
                : "Activate"}
            </span>
          </button>
        ) : null}


        {onDeleteRule ? (
          <>
            <div
              className="detection-rule-actions-menu-divider"
              role="separator"
            />

            <button
              type="button"
              className={[
                "detection-rule-actions-menu-item",
                "detection-rule-actions-menu-item-danger",
              ].join(" ")}
              role="menuitem"
              onClick={handleDeleteRule}
            >
              <span className="detection-rule-actions-menu-item-label">
                Delete
              </span>

              <span className="detection-rule-actions-menu-item-hint">
                Remove
              </span>
            </button>
          </>
        ) : null}
      </div>
    );


  /*
   * Portal is intentionally guarded for environments where document is not
   * available during server-side rendering.
   */
  if (
    typeof document === "undefined"
  ) {
    return null;
  }

  return createPortal(
    menu,
    document.body,
  );
}


/* ==========================================================================
 * Action Trigger
 * ========================================================================== */

interface ActionTriggerProps {
  rule:
    DetectionRule;

  open:
    boolean;

  onToggle:
    (
      position: ActionMenuPosition,
    ) => void;
}


/**
 * Kebab action trigger.
 */
function ActionTrigger({
  rule,
  open,
  onToggle,
}: ActionTriggerProps) {
  function handleClick(
    event: React.MouseEvent<HTMLButtonElement>,
  ): void {
    event.stopPropagation();

    const trigger =
      event.currentTarget;

    const rect =
      trigger.getBoundingClientRect();

    const viewportWidth =
      window.innerWidth;

    const viewportHeight =
      window.innerHeight;


    /* ----------------------------------------------------------------------
     * Horizontal positioning
     *
     * Prefer opening aligned to the right edge of the trigger.
     * Keep the menu inside the viewport.
     * -------------------------------------------------------------------- */

    let left =
      rect.right -
      ACTION_MENU_WIDTH;

    if (
      left <
      ACTION_MENU_VIEWPORT_PADDING
    ) {
      left =
        rect.left;
    }

    if (
      left +
        ACTION_MENU_WIDTH >
      viewportWidth -
        ACTION_MENU_VIEWPORT_PADDING
    ) {
      left =
        viewportWidth -
        ACTION_MENU_WIDTH -
        ACTION_MENU_VIEWPORT_PADDING;
    }

    left =
      Math.max(
        ACTION_MENU_VIEWPORT_PADDING,
        left,
      );


    /* ----------------------------------------------------------------------
     * Vertical positioning
     *
     * Prefer opening below the trigger.
     * If there is insufficient room, open upward.
     * -------------------------------------------------------------------- */

    const spaceBelow =
      viewportHeight -
      rect.bottom;

    const spaceAbove =
      rect.top;

    let top: number;

    if (
      spaceBelow >=
      ACTION_MENU_ESTIMATED_HEIGHT +
        ACTION_MENU_GAP
    ) {
      top =
        rect.bottom +
        ACTION_MENU_GAP;
    } else if (
      spaceAbove >=
      ACTION_MENU_ESTIMATED_HEIGHT +
        ACTION_MENU_GAP
    ) {
      top =
        rect.top -
        ACTION_MENU_ESTIMATED_HEIGHT -
        ACTION_MENU_GAP;
    } else {
      /*
       * If neither side has enough room, clamp the menu inside
       * the viewport.
       */
      top =
        Math.min(
          Math.max(
            ACTION_MENU_VIEWPORT_PADDING,
            rect.bottom +
              ACTION_MENU_GAP,
          ),
          viewportHeight -
            ACTION_MENU_ESTIMATED_HEIGHT -
            ACTION_MENU_VIEWPORT_PADDING,
        );
    }

    onToggle({
      top,
      left,
    });
  }


  return (
    <button
      type="button"
      className={[
        "detection-rule-actions-trigger",
        open
          ? "detection-rule-actions-trigger-open"
          : "",
      ]
        .filter(Boolean)
        .join(" ")}
      aria-label={`Open actions for ${rule.name}`}
      aria-haspopup="menu"
      aria-expanded={open}
      title="Rule actions"
      onClick={handleClick}
    >
      <span
        className="detection-rule-actions-trigger-dots"
        aria-hidden="true"
      >
        ⋮
      </span>
    </button>
  );
}


/* ==========================================================================
 * Loading State
 * ========================================================================== */

function DetectionRuleTableLoading() {
  return (
    <section
      className="detection-rule-table"
      aria-label="Detection rules"
      aria-busy="true"
    >
      <div className="detection-rule-table-header">
        <div className="detection-rule-table-header-content">
          <h2 className="detection-rule-table-title">
            Detection Rules
          </h2>

          <p className="detection-rule-table-description">
            Loading detection rules...
          </p>
        </div>

        <span className="detection-rule-table-state detection-rule-table-state-loading">
          Loading
        </span>
      </div>


      <div className="detection-rule-table-wrapper">
        <table>
          <thead>
            <tr>
              <th scope="col">
                Rule
              </th>

              <th scope="col">
                Severity
              </th>

              <th scope="col">
                Category
              </th>

              <th scope="col">
                Status
              </th>

              <th scope="col">
                Conditions
              </th>

              <th
                scope="col"
                className="detection-rule-column-number"
              >
                Matches
              </th>

              <th
                scope="col"
                className="detection-rule-column-number"
              >
                Suppressed
              </th>

              <th scope="col">
                Last Match
              </th>

              <th
                scope="col"
                className="detection-rule-column-actions"
              >
                Actions
              </th>
            </tr>
          </thead>

          <tbody>
            {Array.from(
              { length: 5 },
              (_, index) => (
                <tr
                  key={`loading-${index}`}
                  className="detection-rule-row-loading"
                >
                  <td>
                    <span className="detection-table-skeleton detection-table-skeleton-wide" />
                  </td>

                  <td>
                    <span className="detection-table-skeleton detection-table-skeleton-small" />
                  </td>

                  <td>
                    <span className="detection-table-skeleton detection-table-skeleton-medium" />
                  </td>

                  <td>
                    <span className="detection-table-skeleton detection-table-skeleton-small" />
                  </td>

                  <td>
                    <span className="detection-table-skeleton detection-table-skeleton-small" />
                  </td>

                  <td>
                    <span className="detection-table-skeleton detection-table-skeleton-small" />
                  </td>

                  <td>
                    <span className="detection-table-skeleton detection-table-skeleton-small" />
                  </td>

                  <td>
                    <span className="detection-table-skeleton detection-table-skeleton-medium" />
                  </td>

                  <td className="detection-rule-actions-cell">
                    <span className="detection-table-skeleton detection-table-skeleton-small" />
                  </td>
                </tr>
              ),
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}


/* ==========================================================================
 * Error State
 * ========================================================================== */

function DetectionRuleTableError({
  error,
}: {
  error: string;
}) {
  return (
    <section
      className="detection-rule-table detection-rule-table-error"
      aria-label="Detection rules"
      role="alert"
    >
      <div className="detection-rule-table-header">
        <div className="detection-rule-table-header-content">
          <h2 className="detection-rule-table-title">
            Detection Rules
          </h2>

          <p className="detection-rule-table-description">
            Detection rules could not be loaded.
          </p>
        </div>

        <span className="detection-rule-table-state detection-rule-table-state-error">
          Error
        </span>
      </div>

      <div className="detection-rule-table-error-content">
        <span className="detection-rule-table-error-label">
          Unable to load rules
        </span>

        <span className="detection-rule-table-error-message">
          {error}
        </span>
      </div>
    </section>
  );
}


/* ==========================================================================
 * Empty State
 * ========================================================================== */

function DetectionRuleTableEmpty() {
  return (
    <section
      className="detection-rule-table"
      aria-label="Detection rules"
    >
      <div className="detection-rule-table-header">
        <div className="detection-rule-table-header-content">
          <h2 className="detection-rule-table-title">
            Detection Rules
          </h2>

          <p className="detection-rule-table-description">
            No Detection rules match the current filters.
          </p>
        </div>

        <span className="detection-rule-table-state detection-rule-table-state-empty">
          Empty
        </span>
      </div>

      <div className="detection-rule-empty">
        <div
          className="detection-rule-empty-icon"
          aria-hidden="true"
        >
          —
        </div>

        <strong className="detection-rule-empty-title">
          No Detection Rules Found
        </strong>

        <p className="detection-rule-empty-description">
          No rules match the current filters.
        </p>
      </div>
    </section>
  );
}


/* ==========================================================================
 * Main Component
 * ========================================================================== */

export function DetectionRuleTable({
  rules,
  loading = false,
  error = null,
  onSelectRule,
  onEditRule,
  onToggleRule,
  onDeleteRule,
  onViewAlerts,
}: DetectionRuleTableProps) {
  const [
    openActionRuleId,
    setOpenActionRuleId,
  ] = useState<string | null>(
    null,
  );

  const [
    actionMenuPosition,
    setActionMenuPosition,
  ] = useState<ActionMenuPosition | null>(
    null,
  );


  /* ------------------------------------------------------------------------
   * Close action menu when the backend result set changes.
   * ---------------------------------------------------------------------- */

  useEffect(() => {
    setOpenActionRuleId(null);
    setActionMenuPosition(null);
  }, [rules]);


  /* ------------------------------------------------------------------------
   * Close menu when viewport changes.
   *
   * Repositioning is intentionally not attempted here because the trigger
   * can move during responsive layout changes. Closing avoids stale
   * viewport coordinates.
   * ---------------------------------------------------------------------- */

  useEffect(() => {
    if (
      openActionRuleId === null
    ) {
      return;
    }

    function handleViewportChange(): void {
      setOpenActionRuleId(null);
      setActionMenuPosition(null);
    }

    window.addEventListener(
      "resize",
      handleViewportChange,
    );

    window.addEventListener(
      "scroll",
      handleViewportChange,
      true,
    );

    return () => {
      window.removeEventListener(
        "resize",
        handleViewportChange,
      );

      window.removeEventListener(
        "scroll",
        handleViewportChange,
        true,
      );
    };
  }, [openActionRuleId]);


  /* ------------------------------------------------------------------------
   * Loading
   * ---------------------------------------------------------------------- */

  if (loading) {
    return (
      <DetectionRuleTableLoading />
    );
  }


  /* ------------------------------------------------------------------------
   * Error
   * ---------------------------------------------------------------------- */

  if (error) {
    return (
      <DetectionRuleTableError
        error={error}
      />
    );
  }


  /* ------------------------------------------------------------------------
   * Empty
   * ---------------------------------------------------------------------- */

  if (rules.length === 0) {
    return (
      <DetectionRuleTableEmpty />
    );
  }


  /* ------------------------------------------------------------------------
   * Render
   *
   * No local filtering.
   * No local pagination.
   * No KPI aggregation.
   * ---------------------------------------------------------------------- */

  return (
    <section
      className="detection-rule-table"
      aria-label="Detection rules"
    >
      {/* ================================================================
       * HEADER
       * ================================================================ */}

      <div className="detection-rule-table-header">
        <div className="detection-rule-table-header-content">
          <h2 className="detection-rule-table-title">
            Detection Rules
          </h2>

          <p className="detection-rule-table-description">
            Registered rules and runtime detection activity.
          </p>
        </div>

        <span className="detection-rule-table-count">
          {rules.length.toLocaleString()}{" "}
          {rules.length === 1
            ? "Rule"
            : "Rules"}
        </span>
      </div>


      {/* ================================================================
       * TABLE
       * ================================================================ */}

      <div className="detection-rule-table-wrapper">
        <table>
          <thead>
            <tr>
              <th
                scope="col"
                className="detection-rule-column-rule"
              >
                Rule
              </th>

              <th scope="col">
                Severity
              </th>

              <th scope="col">
                Category
              </th>

              <th scope="col">
                Status
              </th>

              <th scope="col">
                Conditions
              </th>

              <th
                scope="col"
                className="detection-rule-column-number"
              >
                Matches
              </th>

              <th
                scope="col"
                className="detection-rule-column-number"
              >
                Suppressed
              </th>

              <th scope="col">
                Last Match
              </th>

              <th
                scope="col"
                className="detection-rule-column-actions"
              >
                Actions
              </th>
            </tr>
          </thead>


          <tbody>
            {rules.map((rule) => {
              const conditionCount =
                getConditionCount(rule);

              const statistics =
                getRuleStatistics(rule);

              const selectable =
                typeof onSelectRule ===
                "function";

              const severityClass =
                getSeverityClass(
                  rule.severity,
                );

              const menuOpen =
                openActionRuleId ===
                rule.id;


              function handleRowKeyDown(
                event: React.KeyboardEvent<HTMLTableRowElement>,
              ): void {
                /*
                 * Interactive descendants own their own keyboard behavior.
                 */
                if (
                  event.target !==
                  event.currentTarget
                ) {
                  return;
                }

                if (
                  event.key ===
                    "Enter" ||
                  event.key ===
                    " "
                ) {
                  event.preventDefault();
                  onSelectRule?.(rule);
                }
              }


              function handleActionToggle(
                position: ActionMenuPosition,
              ): void {
                if (menuOpen) {
                  setOpenActionRuleId(
                    null,
                  );

                  setActionMenuPosition(
                    null,
                  );

                  return;
                }

                setOpenActionRuleId(
                  rule.id,
                );

                setActionMenuPosition(
                  position,
                );
              }


              return (
                <tr
                  key={rule.id}
                  className={
                    selectable
                      ? "detection-rule-row-selectable"
                      : undefined
                  }
                  onClick={
                    selectable
                      ? () =>
                          onSelectRule?.(
                            rule,
                          )
                      : undefined
                  }
                  onKeyDown={
                    selectable
                      ? handleRowKeyDown
                      : undefined
                  }
                  tabIndex={
                    selectable
                      ? 0
                      : undefined
                  }
                  role={
                    selectable
                      ? "button"
                      : undefined
                  }
                  aria-label={
                    selectable
                      ? `View Detection rule ${rule.name}`
                      : undefined
                  }
                >
                  {/* ==================================================
                   * RULE
                   * ================================================== */}
                  <td className="detection-rule-cell-rule">
                    <div className="detection-rule-name">
                      <strong>{rule.name}</strong>
                    </div>

                    {rule.description ? (
                      <p
                        className="detection-rule-description"
                        title={rule.description}
                      >
                        {rule.description}
                      </p>
                    ) : null}
                  </td>


                  {/* ==================================================
                   * SEVERITY
                   * ================================================== */}

                  <td>
                    <span
                      className={[
                        "detection-severity",
                        `detection-severity-${severityClass}`,
                      ].join(" ")}
                    >
                      {formatSeverity(
                        rule.severity,
                      )}
                    </span>
                  </td>


                  {/* ==================================================
                   * CATEGORY
                   * ================================================== */}

                  <td>
                    <span className="detection-rule-category">
                      {rule.category ||
                        "Unknown"}
                    </span>
                  </td>


                  {/* ==================================================
                   * STATUS
                   * ================================================== */}

                  <td>
                    <span
                      className={
                        rule.enabled
                          ? "detection-rule-status detection-rule-status-enabled"
                          : "detection-rule-status detection-rule-status-disabled"
                      }
                    >
                      <span
                        className="detection-rule-status-dot"
                        aria-hidden="true"
                      />

                      <span>
                        {rule.enabled
                          ? "Enabled"
                          : "Disabled"}
                      </span>
                    </span>
                  </td>


                  {/* ==================================================
                   * CONDITIONS
                   * ================================================== */}

                  <td className="detection-rule-number-cell detection-rule-condition-cell">
                    <strong className="detection-rule-metric">
                      {conditionCount.toLocaleString()}
                    </strong>
                  </td>


                  {/* ==================================================
                   * MATCHES
                   * ================================================== */}

                  <td className="detection-rule-number-cell">
                    <strong className="detection-rule-metric">
                      {formatNumber(
                        statistics.matches,
                      )}
                    </strong>
                  </td>


                  {/* ==================================================
                   * SUPPRESSED
                   * ================================================== */}

                  <td className="detection-rule-number-cell">
                    <strong className="detection-rule-metric">
                      {formatNumber(
                        statistics.suppressed,
                      )}
                    </strong>
                  </td>


                  {/* ==================================================
                   * LAST MATCH
                   * ================================================== */}

                  <td>
                    <span className="detection-rule-last-match">
                      {formatLastMatch(
                        statistics.lastMatchAt,
                      )}
                    </span>
                  </td>


                  {/* ==================================================
                   * ACTIONS
                   * ================================================== */}

                  <td
                    className={[
                      "detection-rule-actions-cell",
                      menuOpen
                        ? "detection-rule-actions-cell-open"
                        : "",
                    ]
                      .filter(Boolean)
                      .join(" ")}
                    onClick={(event) => {
                      event.stopPropagation();
                    }}
                  >
                    <div className="detection-rule-actions">
                      <ActionTrigger
                        rule={rule}
                        open={menuOpen}
                        onToggle={
                          handleActionToggle
                        }
                      />

                      {menuOpen &&
                      actionMenuPosition ? (
                        <DetectionRuleActionMenu
                          rule={rule}
                          position={
                            actionMenuPosition
                          }
                          onSelectRule={
                            onSelectRule
                          }
                          onEditRule={
                            onEditRule
                          }
                          onToggleRule={
                            onToggleRule
                          }
                          onDeleteRule={
                            onDeleteRule
                          }
                          onViewAlerts={
                            onViewAlerts
                          }
                          onClose={() => {
                            setOpenActionRuleId(
                              null,
                            );

                            setActionMenuPosition(
                              null,
                            );
                          }}
                        />
                      ) : null}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}


/* ==========================================================================
 * Default Export
 * ========================================================================== */

export default DetectionRuleTable;