import type {
  CSSProperties,
  KeyboardEvent,
  MouseEvent,
} from "react";

import { SeverityBadge } from "../../../components/ui/SeverityBadge";

import type {
  Alert,
  AlertStatus,
} from "../types";


/* ==========================================================================
 * SentinelSIEM — Alerts
 * AlertTable
 *
 * FINAL LOCKED TABLE ORDER
 *
 * 1. Alert
 * 2. Rule
 * 3. Source
 * 4. Severity
 * 5. Status
 * 6. Occurrences
 * 7. Assignee
 * 8. Last Seen
 * 9. Actions
 *
 * DESIGN RULES
 * - Table always uses available parent width
 * - No fixed pixel table width
 * - No horizontal scrolling
 * - Backend remains source of truth
 * - Assignee is display-only here
 * - Parent supplies human-readable assignee
 * - Text is truncated with ellipsis where required
 * - Actions cell allows dropdown overflow
 * ========================================================================== */


/* ==========================================================================
 * TYPES
 * ========================================================================== */

export interface AlertTableProps {
  alerts: Alert[];

  onSelectAlert?: (
    alert: Alert,
  ) => void;

  onAction?: (
    alert: Alert,
  ) => void;

  selectedAlertId?: string | null;

  disabled?: boolean;
}


/* ==========================================================================
 * CONSTANTS
 * ========================================================================== */

const EMPTY_VALUE = "—";


/**
 * Final table column geometry.
 *
 * Total:
 *
 * 24 + 14 + 13 + 8 + 10 + 8 + 11 + 7 + 5 = 100%
 *
 * Alert
 * Rule
 * Source
 * Severity
 * Status
 * Occurrences
 * Assignee
 * Last Seen
 * Actions
 */
const COLUMN_WIDTHS = {
  alert: "24%",
  rule: "14%",
  source: "13%",
  severity: "8%",
  status: "10%",
  occurrences: "8%",
  assignee: "11%",
  lastSeen: "7%",
  actions: "5%",
} as const;


/* ==========================================================================
 * HELPERS
 * ========================================================================== */

function displayValue(
  value?: string | number | null,
): string {
  if (
    value === null ||
    value === undefined
  ) {
    return EMPTY_VALUE;
  }

  const normalized =
    String(value).trim();

  return normalized || EMPTY_VALUE;
}


/* ==========================================================================
 * ASSIGNEE HELPERS
 * ========================================================================== */

/**
 * Parent page is expected to provide:
 *
 * "Rahim Hossain — SOC Analyst"
 *
 * or:
 *
 * "Unassigned"
 */
function displayAssignee(
  value?: string | null,
): string {
  const normalized =
    value?.trim();

  return normalized || "Unassigned";
}


function parseAssignee(
  value?: string | null,
): {
  name: string;
  role: string | null;
} {
  const normalized =
    displayAssignee(value);

  if (
    normalized ===
    "Unassigned"
  ) {
    return {
      name: "Unassigned",
      role: null,
    };
  }

  const separator =
    normalized.indexOf(
      " — ",
    );

  if (
    separator === -1
  ) {
    return {
      name: normalized,
      role: null,
    };
  }

  return {
    name:
      normalized.slice(
        0,
        separator,
      ),

    role:
      normalized.slice(
        separator + 3,
      ) || null,
  };
}


/* ==========================================================================
 * TIME HELPERS
 * ========================================================================== */

function formatRelativeTime(
  value?: string | null,
): string {
  if (!value) {
    return EMPTY_VALUE;
  }

  const timestamp =
    new Date(value).getTime();

  if (
    Number.isNaN(timestamp)
  ) {
    return displayValue(value);
  }

  const difference =
    Math.max(
      0,
      Date.now() - timestamp,
    );

  const seconds =
    Math.floor(
      difference / 1000,
    );

  if (
    seconds < 60
  ) {
    return "Just now";
  }

  const minutes =
    Math.floor(
      seconds / 60,
    );

  if (
    minutes < 60
  ) {
    return `${minutes}m ago`;
  }

  const hours =
    Math.floor(
      minutes / 60,
    );

  if (
    hours < 24
  ) {
    return `${hours}h ago`;
  }

  const days =
    Math.floor(
      hours / 24,
    );

  if (
    days < 7
  ) {
    return `${days}d ago`;
  }

  const date =
    new Date(value);

  const currentYear =
    new Date().getFullYear();

  return date.toLocaleDateString(
    undefined,
    {
      month: "short",
      day: "numeric",
      year:
        date.getFullYear() !==
        currentYear
          ? "numeric"
          : undefined,
    },
  );
}


/* ==========================================================================
 * STATUS HELPERS
 * ========================================================================== */

function formatStatusLabel(
  status: AlertStatus,
): string {
  return status
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


function statusClassName(
  status: AlertStatus,
): string {
  return [
    "sentinel-alerts-status",
    `sentinel-alerts-status-${status}`,
  ].join(" ");
}


/* ==========================================================================
 * TABLE STYLES
 * ========================================================================== */

const tableStyle: CSSProperties = {
  width: "100%",

  minWidth: 0,

  maxWidth: "100%",

  margin: 0,

  padding: 0,

  border: 0,

  borderCollapse: "collapse",

  borderSpacing: 0,

  tableLayout: "fixed",

  background: "#071522",

  fontFamily: "inherit",
};


const headerCellStyle: CSSProperties = {
  boxSizing: "border-box",

  height: "42px",

  margin: 0,

  padding: "0 7px",

  border: 0,

  borderBottom:
    "1px solid rgba(22, 50, 73, 0.9)",

  background: "#081927",

  color: "#58748a",

  fontFamily: "inherit",

  fontSize: "9px",

  fontWeight: 750,

  letterSpacing: "0.075em",

  lineHeight: "1",

  textAlign: "left",

  verticalAlign: "middle",

  textTransform: "uppercase",

  whiteSpace: "nowrap",

  overflow: "hidden",

  textOverflow: "ellipsis",
};


const bodyCellStyle: CSSProperties = {
  boxSizing: "border-box",

  height: "68px",

  margin: 0,

  padding: "9px 7px",

  border: 0,

  borderBottom:
    "1px solid rgba(22, 50, 73, 0.65)",

  background: "transparent",

  color: "#a6b9c9",

  fontFamily: "inherit",

  fontSize: "10px",

  lineHeight: "1.4",

  textAlign: "left",

  verticalAlign: "middle",

  whiteSpace: "nowrap",

  overflow: "hidden",
};


function columnStyle(
  width: string,
  options?: {
    paddingLeft?: string;
    paddingRight?: string;
    textAlign?:
      | "left"
      | "center"
      | "right";
  },
): CSSProperties {
  return {
    width,

    minWidth: 0,

    maxWidth: width,

    paddingLeft:
      options?.paddingLeft,

    paddingRight:
      options?.paddingRight,

    textAlign:
      options?.textAlign,
  };
}


/* ==========================================================================
 * ALERT IDENTITY
 * ========================================================================== */

function AlertIdentity({
  title,
  description,
}: {
  title?: string | null;

  description?: string | null;
}) {
  const titleText =
    displayValue(title);

  const descriptionText =
    displayValue(description);

  return (
    <div
      className="sentinel-alerts-identity"
      style={{
        display: "block",

        width: "100%",

        minWidth: 0,

        maxWidth: "100%",

        overflow: "hidden",
      }}
    >
      <span
        className="sentinel-alerts-identity-title"
        style={{
          display: "block",

          width: "100%",

          minWidth: 0,

          maxWidth: "100%",

          overflow: "hidden",

          color: "#dbe7f1",

          fontSize: "10px",

          fontWeight: 650,

          lineHeight: "16px",

          whiteSpace: "nowrap",

          textOverflow: "ellipsis",
        }}
        title={titleText}
      >
        {titleText}
      </span>

      <span
        className="sentinel-alerts-identity-description"
        style={{
          display: "block",

          width: "100%",

          minWidth: 0,

          maxWidth: "100%",

          marginTop: "2px",

          overflow: "hidden",

          color: "#526b80",

          fontSize: "8px",

          fontWeight: 400,

          lineHeight: "12px",

          whiteSpace: "nowrap",

          textOverflow: "ellipsis",
        }}
        title={descriptionText}
      >
        {descriptionText}
      </span>
    </div>
  );
}


/* ==========================================================================
 * TEXT CELL
 * ========================================================================== */

function TextCell({
  value,
  mono = false,
  muted = false,
  align = "left",
}: {
  value?: string | number | null;

  mono?: boolean;

  muted?: boolean;

  align?:
    | "left"
    | "center"
    | "right";
}) {
  const text =
    displayValue(value);

  return (
    <span
      className="sentinel-alerts-text-cell"
      style={{
        display: "block",

        width: "100%",

        minWidth: 0,

        maxWidth: "100%",

        overflow: "hidden",

        color:
          muted
            ? "#526b80"
            : "#a6b9c9",

        fontFamily:
          mono
            ? '"SFMono-Regular", "Cascadia Code", "Roboto Mono", Consolas, "Liberation Mono", monospace'
            : "inherit",

        fontSize: "9px",

        fontWeight: 400,

        lineHeight: "16px",

        textAlign: align,

        whiteSpace: "nowrap",

        textOverflow: "ellipsis",
      }}
      title={text}
    >
      {text}
    </span>
  );
}


/* ==========================================================================
 * SOURCE CELL
 * ========================================================================== */

function SourceCell({
  sourceType,
  sourceId,
}: {
  sourceType:
    | string
    | null
    | undefined;

  sourceId:
    | string
    | null
    | undefined;
}) {
  const sourceTypeText =
    displayValue(sourceType);

  const sourceIdText =
    displayValue(sourceId);

  return (
    <div
      className="sentinel-alerts-source"
      style={{
        display: "block",

        width: "100%",

        minWidth: 0,

        maxWidth: "100%",

        overflow: "hidden",
      }}
    >
      <span
        style={{
          display: "block",

          width: "100%",

          minWidth: 0,

          overflow: "hidden",

          color: "#9ab0c0",

          fontSize: "9px",

          fontWeight: 550,

          lineHeight: "15px",

          whiteSpace: "nowrap",

          textOverflow: "ellipsis",

          textTransform: "capitalize",
        }}
        title={sourceTypeText}
      >
        {sourceTypeText}
      </span>

      <span
        style={{
          display: "block",

          width: "100%",

          minWidth: 0,

          marginTop: "1px",

          overflow: "hidden",

          color: "#526b80",

          fontFamily:
            '"SFMono-Regular", "Cascadia Code", "Roboto Mono", Consolas, "Liberation Mono", monospace',

          fontSize: "7px",

          fontWeight: 400,

          lineHeight: "12px",

          whiteSpace: "nowrap",

          textOverflow: "ellipsis",
        }}
        title={sourceIdText}
      >
        {sourceIdText}
      </span>
    </div>
  );
}


/* ==========================================================================
 * ASSIGNEE CELL
 * ========================================================================== */

function AssigneeCell({
  value,
}: {
  value?: string | null;
}) {
  const assignee =
    parseAssignee(value);

  const isUnassigned =
    assignee.name ===
    "Unassigned";

  return (
    <div
      className="sentinel-alerts-assignee"
      style={{
        display: "block",

        width: "100%",

        minWidth: 0,

        maxWidth: "100%",

        overflow: "hidden",
      }}
      title={
        assignee.role
          ? `${assignee.name} — ${assignee.role}`
          : assignee.name
      }
    >
      <span
        style={{
          display: "block",

          width: "100%",

          minWidth: 0,

          overflow: "hidden",

          color:
            isUnassigned
              ? "#526b80"
              : "#d1dee8",

          fontSize: "9px",

          fontWeight:
            isUnassigned
              ? 400
              : 600,

          lineHeight: "15px",

          whiteSpace: "nowrap",

          textOverflow: "ellipsis",
        }}
      >
        {assignee.name}
      </span>

      {assignee.role && (
        <span
          style={{
            display: "block",

            width: "100%",

            minWidth: 0,

            marginTop: "1px",

            overflow: "hidden",

            color: "#607b8f",

            fontSize: "7px",

            fontWeight: 500,

            lineHeight: "11px",

            whiteSpace: "nowrap",

            textOverflow: "ellipsis",
          }}
        >
          {assignee.role}
        </span>
      )}
    </div>
  );
}


/* ==========================================================================
 * STATUS BADGE
 * ========================================================================== */

function AlertStatusBadge({
  status,
}: {
  status: AlertStatus;
}) {
  const label =
    formatStatusLabel(status);

  return (
    <span
      className={
        statusClassName(status)
      }
      style={{
        display: "inline-flex",

        alignItems: "center",

        justifyContent: "center",

        gap: "4px",

        minHeight: "20px",

        maxWidth: "100%",

        padding: "3px 6px",

        boxSizing: "border-box",

        border:
          "1px solid rgba(69, 105, 128, 0.22)",

        borderRadius: "5px",

        background:
          "rgba(31, 60, 80, 0.22)",

        color: "#8199aa",

        fontSize: "7px",

        fontWeight: 650,

        lineHeight: "1",

        textTransform: "uppercase",

        whiteSpace: "nowrap",

        overflow: "hidden",

        textOverflow: "ellipsis",
      }}
      title={label}
    >
      <span
        aria-hidden="true"
        style={{
          width: "4px",

          height: "4px",

          flex: "0 0 4px",

          borderRadius: "50%",

          background: "currentColor",

          opacity: 0.85,
        }}
      />

      <span
        style={{
          minWidth: 0,

          overflow: "hidden",

          textOverflow: "ellipsis",

          whiteSpace: "nowrap",
        }}
      >
        {label}
      </span>
    </span>
  );
}


/* ==========================================================================
 * LAST SEEN
 * ========================================================================== */

function LastSeen({
  value,
}: {
  value:
    | string
    | null
    | undefined;
}) {
  const relative =
    formatRelativeTime(value);

  const fullDate =
    value
      ? new Date(value).toLocaleString()
      : EMPTY_VALUE;

  return (
    <span
      className="sentinel-alerts-last-seen"
      style={{
        display: "block",

        width: "100%",

        minWidth: 0,

        maxWidth: "100%",

        overflow: "hidden",

        color: "#9ab0c0",

        fontSize: "8px",

        fontWeight: 500,

        lineHeight: "15px",

        whiteSpace: "nowrap",

        textOverflow: "ellipsis",
      }}
      title={fullDate}
    >
      {relative}
    </span>
  );
}


/* ==========================================================================
 * ACTION BUTTON
 * ========================================================================== */

function ActionButton({
  onClick,
  disabled,
  label,
}: {
  onClick: (
    event: MouseEvent<HTMLButtonElement>,
  ) => void;

  disabled: boolean;

  label: string;
}) {
  return (
    <button
      type="button"
      className="sentinel-alerts-row-action"
      onClick={onClick}
      disabled={disabled}
      aria-label={label}
      title={label}
      style={{
        display: "inline-grid",

        placeItems: "center",

        width: "26px",

        height: "26px",

        padding: 0,

        boxSizing: "border-box",

        border:
          "1px solid rgba(43, 74, 96, 0.8)",

        borderRadius: "6px",

        background: "#081927",

        color: "#71899b",

        cursor:
          disabled
            ? "not-allowed"
            : "pointer",

        opacity:
          disabled
            ? 0.45
            : 1,

        transition:
          "border-color 140ms ease, background-color 140ms ease, color 140ms ease",
      }}
    >
      <svg
        width="13"
        height="13"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <circle
          cx="12"
          cy="5"
          r="1"
        />

        <circle
          cx="12"
          cy="12"
          r="1"
        />

        <circle
          cx="12"
          cy="19"
          r="1"
        />
      </svg>
    </button>
  );
}


/* ==========================================================================
 * EMPTY STATE
 * ========================================================================== */

function EmptyState() {
  return (
    <div
      className="sentinel-alerts-empty-state"
      role="status"
      style={{
        display: "flex",

        alignItems: "center",

        justifyContent: "center",

        flexDirection: "column",

        minHeight: "220px",

        gap: "8px",

        padding: "28px 20px",

        boxSizing: "border-box",

        background: "#071522",

        textAlign: "center",
      }}
    >
      <span
        aria-hidden="true"
        style={{
          display: "grid",

          placeItems: "center",

          width: "40px",

          height: "40px",

          border:
            "1px solid #163249",

          borderRadius: "10px",

          background: "#0a1b2a",

          color: "#4d697d",

          fontSize: "15px",
        }}
      >
        —
      </span>

      <strong
        style={{
          color: "#a6b9c9",

          fontSize: "12px",

          fontWeight: 650,
        }}
      >
        No alerts available
      </strong>

      <span
        style={{
          maxWidth: "360px",

          color: "#526b80",

          fontSize: "10px",

          lineHeight: "1.5",
        }}
      >
        No detection or correlation
        alerts match the current
        selection.
      </span>
    </div>
  );
}


/* ==========================================================================
 * ALERT ROW
 * ========================================================================== */

function AlertRow({
  alert,
  selected,
  disabled,
  onSelect,
  onAction,
}: {
  alert: Alert;

  selected: boolean;

  disabled: boolean;

  onSelect?: (
    alert: Alert,
  ) => void;

  onAction?: (
    alert: Alert,
  ) => void;
}) {
  const handleSelect =
    (): void => {
      if (
        disabled ||
        !onSelect
      ) {
        return;
      }

      onSelect(alert);
    };


  const handleKeyDown =
    (
      event:
        KeyboardEvent<HTMLTableRowElement>,
    ): void => {
      if (
        disabled ||
        !onSelect
      ) {
        return;
      }

      if (
        event.key === "Enter" ||
        event.key === " "
      ) {
        event.preventDefault();

        onSelect(alert);
      }
    };


  const handleAction =
    (
      event:
        MouseEvent<HTMLButtonElement>,
    ): void => {
      event.stopPropagation();

      if (
        disabled ||
        !onAction
      ) {
        return;
      }

      onAction(alert);
    };


  return (
    <tr
      className={[
        "sentinel-alerts-table-row",
        "sentinel-alerts-table-row-clickable",
        selected
          ? "is-selected"
          : "",
      ]
        .filter(Boolean)
        .join(" ")}
      tabIndex={
        disabled ||
        !onSelect
          ? undefined
          : 0
      }
      aria-selected={selected}
      onClick={handleSelect}
      onKeyDown={handleKeyDown}
      style={{
        height: "68px",

        background:
          selected
            ? "#0c2031"
            : "#071522",

        cursor:
          disabled ||
          !onSelect
            ? "default"
            : "pointer",

        transition:
          "background-color 140ms ease",
      }}
    >

      {/* ================================================================
       * 1. ALERT
       * ================================================================ */}

      <td
        className="sentinel-alerts-table-alert"
        style={{
          ...bodyCellStyle,

          ...columnStyle(
            COLUMN_WIDTHS.alert,
            {
              paddingLeft: "11px",
            },
          ),
        }}
      >
        <AlertIdentity
          title={alert.title}
          description={
            alert.description
          }
        />
      </td>


      {/* ================================================================
       * 2. RULE
       * ================================================================ */}

      <td
        className="sentinel-alerts-table-rule"
        style={{
          ...bodyCellStyle,

          ...columnStyle(
            COLUMN_WIDTHS.rule,
          ),
        }}
      >
        <TextCell
          value={alert.rule_id}
          mono
        />
      </td>


      {/* ================================================================
       * 3. SOURCE
       * ================================================================ */}

      <td
        className="sentinel-alerts-table-source"
        style={{
          ...bodyCellStyle,

          ...columnStyle(
            COLUMN_WIDTHS.source,
          ),
        }}
      >
        <SourceCell
          sourceType={
            alert.source_type
          }
          sourceId={
            alert.source_id
          }
        />
      </td>


      {/* ================================================================
       * 4. SEVERITY
       * ================================================================ */}

      <td
        className="sentinel-alerts-table-severity"
        style={{
          ...bodyCellStyle,

          ...columnStyle(
            COLUMN_WIDTHS.severity,
          ),
        }}
      >
        <SeverityBadge
          severity={
            alert.severity
          }
        />
      </td>


      {/* ================================================================
       * 5. STATUS
       * ================================================================ */}

      <td
        className="sentinel-alerts-table-status"
        style={{
          ...bodyCellStyle,

          ...columnStyle(
            COLUMN_WIDTHS.status,
          ),
        }}
      >
        <AlertStatusBadge
          status={
            alert.status
          }
        />
      </td>


      {/* ================================================================
       * 6. OCCURRENCES
       * ================================================================ */}

      <td
        className="sentinel-alerts-table-occurrences"
        style={{
          ...bodyCellStyle,

          ...columnStyle(
            COLUMN_WIDTHS.occurrences,
            {
              textAlign: "center",
            },
          ),
        }}
      >
        <TextCell
          value={
            alert.occurrence_count
          }
          mono
          align="center"
        />
      </td>


      {/* ================================================================
       * 7. ASSIGNEE
       * ================================================================ */}

      <td
        className="sentinel-alerts-table-assignee"
        style={{
          ...bodyCellStyle,

          ...columnStyle(
            COLUMN_WIDTHS.assignee,
          ),
        }}
      >
        <AssigneeCell
          value={
            alert.assigned_to
          }
        />
      </td>


      {/* ================================================================
       * 8. LAST SEEN
       * ================================================================ */}

      <td
        className="sentinel-alerts-table-last-seen"
        style={{
          ...bodyCellStyle,

          ...columnStyle(
            COLUMN_WIDTHS.lastSeen,
          ),
        }}
      >
        <LastSeen
          value={
            alert.last_seen_at
          }
        />
      </td>


      {/* ================================================================
       * 9. ACTIONS
       * ================================================================ */}

      <td
        className="sentinel-alerts-table-actions"
        style={{
          ...bodyCellStyle,

          ...columnStyle(
            COLUMN_WIDTHS.actions,
            {
              paddingLeft: "2px",

              paddingRight: "4px",

              textAlign: "center",
            },
          ),
        }}
      >
        <div
          className="sentinel-alerts-actions-wrapper"
        >
          <ActionButton
            onClick={
              handleAction
            }
            disabled={
              disabled ||
              !onAction
            }
            label={
              `Open actions for ${displayValue(
                alert.title,
              )}`
            }
          />
        </div>
      </td>

    </tr>
  );
}


/* ==========================================================================
 * MAIN ALERT TABLE
 * ========================================================================== */

export function AlertTable({
  alerts,
  onSelectAlert,
  onAction,
  selectedAlertId = null,
  disabled = false,
}: AlertTableProps) {

  if (
    alerts.length === 0
  ) {
    return (
      <EmptyState />
    );
  }


  return (
    <>
      {/* ====================================================================
       * ALERT TABLE CSS
       * ================================================================== */}

      <style>
        {`
          /* ================================================================
           * TABLE ROW
           * ================================================================ */

          .sentinel-alerts-table-row {
            position: relative;
          }


          .sentinel-alerts-table-row:hover {
            background:
              #0b1d2d !important;
          }


          .sentinel-alerts-table-row.is-selected {
            background:
              #0c2031 !important;
          }


          .sentinel-alerts-table-row:focus-visible {
            outline:
              2px solid #36bdf5;

            outline-offset:
              -2px;
          }


          .sentinel-alerts-table-row:hover td {
            background:
              transparent !important;
          }


          .sentinel-alerts-table-row.is-selected td {
            background:
              transparent !important;
          }


          /* ================================================================
           * TABLE CONTAINER
           * ================================================================ */

          .sentinel-alerts-table-container {
            position: relative;

            display: block;

            width: 100%;

            min-width: 0;

            max-width: 100%;

            margin: 0;

            padding: 0;

            overflow: visible;

            box-sizing: border-box;
          }


          /* ================================================================
           * TABLE AREA
           * ================================================================ */

          .sentinel-alerts-table-scroll {
            position: relative;

            display: block;

            width: 100%;

            min-width: 0;

            max-width: 100%;

            margin: 0;

            padding: 0;

            overflow: visible;

            box-sizing: border-box;
          }


          /* ================================================================
           * TABLE
           * ================================================================ */

          .sentinel-alerts-table {
            width: 100% !important;

            min-width: 0 !important;

            max-width: 100% !important;

            table-layout: fixed !important;

            border-collapse: collapse !important;

            border-spacing: 0 !important;

            box-sizing: border-box;
          }


          /* ================================================================
           * CELLS
           * ================================================================ */

          .sentinel-alerts-table th,
          .sentinel-alerts-table td {
            box-sizing: border-box;

            max-width: 0;
          }


          /* ================================================================
           * NORMAL CELLS
           * ================================================================ */

          .sentinel-alerts-table td:not(
            .sentinel-alerts-table-actions
          ) {
            overflow: hidden;
          }


          /* ================================================================
           * ACTIONS CELL
           *
           * IMPORTANT:
           * Dropdown menus rendered from Actions must be able to escape
           * the table cell.
           * ================================================================ */

          .sentinel-alerts-table-actions {
            position: relative !important;

            overflow: visible !important;

            z-index: 20;
          }


          .sentinel-alerts-actions-wrapper {
            position: relative;

            display: inline-flex;

            align-items: center;

            justify-content: center;

            width: auto;

            min-width: 26px;

            height: 28px;

            vertical-align: middle;
          }


          /* ================================================================
           * ACTION BUTTON
           * ================================================================ */

          .sentinel-alerts-row-action {
            position: relative;

            z-index: 30;

            flex: 0 0 auto;
          }


          .sentinel-alerts-row-action:hover:not(:disabled) {
            border-color:
              #286080 !important;

            background:
              #0c2031 !important;

            color:
              #dbe7f1 !important;
          }


          .sentinel-alerts-row-action:focus-visible {
            outline:
              2px solid #36bdf5;

            outline-offset:
              2px;
          }


          /* ================================================================
           * STATUS COLORS
           * ================================================================ */

          .sentinel-alerts-status-new {
            color:
              #6fb5d6 !important;
          }


          .sentinel-alerts-status-acknowledged {
            color:
              #8aa8bc !important;
          }


          .sentinel-alerts-status-investigating {
            color:
              #d0aa67 !important;
          }


          .sentinel-alerts-status-escalated {
            color:
              #e07d86 !important;
          }


          .sentinel-alerts-status-resolved {
            color:
              #71b88c !important;
          }


          .sentinel-alerts-status-closed {
            color:
              #687f90 !important;
          }


          .sentinel-alerts-status-suppressed {
            color:
              #807d9f !important;
          }


          /* ================================================================
           * ASSIGNEE
           * ================================================================ */

          .sentinel-alerts-assignee {
            overflow: hidden;
          }


          /* ================================================================
           * ACTION DROPDOWN SUPPORT
           *
           * If the parent Actions menu uses these classes, it will anchor
           * to the Actions button instead of appearing in the table center.
           * ================================================================ */

          .sentinel-alerts-actions-menu {
            position: absolute;

            top: calc(100% + 6px);

            right: 0;

            z-index: 1000;

            width: 190px;

            min-width: 190px;

            max-width: 190px;

            box-sizing: border-box;

            padding: 6px;

            border:
              1px solid rgba(38, 76, 101, 0.95);

            border-radius: 8px;

            background:
              #081927;

            box-shadow:
              0 12px 30px rgba(0, 0, 0, 0.38),
              0 2px 8px rgba(0, 0, 0, 0.24);

            overflow: hidden;
          }


          .sentinel-alerts-actions-menu-item {
            display: flex;

            align-items: center;

            width: 100%;

            min-height: 34px;

            box-sizing: border-box;

            margin: 0;

            padding: 7px 9px;

            border: 0;

            border-radius: 5px;

            background: transparent;

            color: #9ab0c0;

            font-family: inherit;

            font-size: 10px;

            font-weight: 500;

            line-height: 1.2;

            text-align: left;

            white-space: nowrap;

            cursor: pointer;

            transition:
              background-color 140ms ease,
              color 140ms ease;
          }


          .sentinel-alerts-actions-menu-item:hover {
            background:
              #0c2031;

            color:
              #dbe7f1;
          }


          .sentinel-alerts-actions-menu-item:focus-visible {
            outline:
              2px solid #36bdf5;

            outline-offset:
              -2px;
          }


          .sentinel-alerts-actions-menu-item-icon {
            display: inline-flex;

            align-items: center;

            justify-content: center;

            width: 20px;

            min-width: 20px;

            margin-right: 7px;

            line-height: 1;
          }


          .sentinel-alerts-actions-menu-item-text {
            min-width: 0;

            overflow: hidden;

            text-overflow: ellipsis;

            white-space: nowrap;
          }


          /* ================================================================
           * NARROW LAPTOP
           * ================================================================ */

          @media (max-width: 1100px) {

            .sentinel-alerts-table th,
            .sentinel-alerts-table td {
              padding-left:
                5px !important;

              padding-right:
                5px !important;
            }


            .sentinel-alerts-table-alert {
              padding-left:
                8px !important;
            }


            .sentinel-alerts-table-actions {
              padding-left:
                2px !important;

              padding-right:
                3px !important;
            }


            .sentinel-alerts-row-action {
              width:
                25px !important;

              height:
                25px !important;
            }


            .sentinel-alerts-identity-title {
              font-size:
                9px !important;
            }


            .sentinel-alerts-identity-description {
              font-size:
                7px !important;
            }
          }


          /* ================================================================
           * SMALL SCREEN
           * ================================================================ */

          @media (max-width: 900px) {

            .sentinel-alerts-table th,
            .sentinel-alerts-table td {
              padding-left:
                3px !important;

              padding-right:
                3px !important;
            }


            .sentinel-alerts-table-alert {
              padding-left:
                5px !important;
            }


            .sentinel-alerts-table th {
              font-size:
                7px !important;

              letter-spacing:
                0.04em !important;
            }


            .sentinel-alerts-table td {
              font-size:
                9px !important;
            }


            .sentinel-alerts-row-action {
              width:
                23px !important;

              height:
                23px !important;
            }


            .sentinel-alerts-row-action svg {
              width:
                12px;

              height:
                12px;
            }


            .sentinel-alerts-actions-menu {
              width:
                175px;

              min-width:
                175px;

              max-width:
                175px;
            }
          }


          /* ================================================================
           * REDUCED MOTION
           * ================================================================ */

          @media (prefers-reduced-motion: reduce) {

            .sentinel-alerts-table-row,
            .sentinel-alerts-row-action,
            .sentinel-alerts-actions-menu-item {
              transition:
                none !important;
            }
          }
        `}
      </style>


      {/* ====================================================================
       * TABLE CONTAINER
       * ================================================================== */}

      <div
        className="sentinel-alerts-table-container"
      >

        <div
          className="sentinel-alerts-table-scroll"
        >

          <table
            className="sentinel-alerts-table"
            style={tableStyle}
          >

            {/* ==============================================================
             * COLUMN DEFINITIONS
             * ============================================================== */}

            <colgroup>

              <col
                style={{
                  width:
                    COLUMN_WIDTHS.alert,
                }}
              />

              <col
                style={{
                  width:
                    COLUMN_WIDTHS.rule,
                }}
              />

              <col
                style={{
                  width:
                    COLUMN_WIDTHS.source,
                }}
              />

              <col
                style={{
                  width:
                    COLUMN_WIDTHS.severity,
                }}
              />

              <col
                style={{
                  width:
                    COLUMN_WIDTHS.status,
                }}
              />

              <col
                style={{
                  width:
                    COLUMN_WIDTHS.occurrences,
                }}
              />

              <col
                style={{
                  width:
                    COLUMN_WIDTHS.assignee,
                }}
              />

              <col
                style={{
                  width:
                    COLUMN_WIDTHS.lastSeen,
                }}
              />

              <col
                style={{
                  width:
                    COLUMN_WIDTHS.actions,
                }}
              />

            </colgroup>


            {/* ==============================================================
             * HEADER
             * ============================================================== */}

            <thead>

              <tr
                style={{
                  height: "42px",

                  background: "#081927",
                }}
              >

                {/* 1. ALERT */}

                <th
                  scope="col"
                  className="sentinel-alerts-table-alert"
                  style={{
                    ...headerCellStyle,

                    ...columnStyle(
                      COLUMN_WIDTHS.alert,
                      {
                        paddingLeft:
                          "11px",
                      },
                    ),
                  }}
                >
                  Alert
                </th>


                {/* 2. RULE */}

                <th
                  scope="col"
                  className="sentinel-alerts-table-rule"
                  style={{
                    ...headerCellStyle,

                    ...columnStyle(
                      COLUMN_WIDTHS.rule,
                    ),
                  }}
                >
                  Rule
                </th>


                {/* 3. SOURCE */}

                <th
                  scope="col"
                  className="sentinel-alerts-table-source"
                  style={{
                    ...headerCellStyle,

                    ...columnStyle(
                      COLUMN_WIDTHS.source,
                    ),
                  }}
                >
                  Source
                </th>


                {/* 4. SEVERITY */}

                <th
                  scope="col"
                  className="sentinel-alerts-table-severity"
                  style={{
                    ...headerCellStyle,

                    ...columnStyle(
                      COLUMN_WIDTHS.severity,
                    ),
                  }}
                >
                  Severity
                </th>


                {/* 5. STATUS */}

                <th
                  scope="col"
                  className="sentinel-alerts-table-status"
                  style={{
                    ...headerCellStyle,

                    ...columnStyle(
                      COLUMN_WIDTHS.status,
                    ),
                  }}
                >
                  Status
                </th>


                {/* 6. OCCURRENCES */}

                <th
                  scope="col"
                  className="sentinel-alerts-table-occurrences"
                  style={{
                    ...headerCellStyle,

                    ...columnStyle(
                      COLUMN_WIDTHS.occurrences,
                      {
                        textAlign:
                          "center",
                      },
                    ),
                  }}
                >
                  Occurrences
                </th>


                {/* 7. ASSIGNEE */}

                <th
                  scope="col"
                  className="sentinel-alerts-table-assignee"
                  style={{
                    ...headerCellStyle,

                    ...columnStyle(
                      COLUMN_WIDTHS.assignee,
                    ),
                  }}
                >
                  Assignee
                </th>


                {/* 8. LAST SEEN */}

                <th
                  scope="col"
                  className="sentinel-alerts-table-last-seen"
                  style={{
                    ...headerCellStyle,

                    ...columnStyle(
                      COLUMN_WIDTHS.lastSeen,
                    ),
                  }}
                >
                  Last Seen
                </th>


                {/* 9. ACTIONS */}

                <th
                  scope="col"
                  className="sentinel-alerts-table-actions"
                  style={{
                    ...headerCellStyle,

                    ...columnStyle(
                      COLUMN_WIDTHS.actions,
                      {
                        paddingLeft:
                          "2px",

                        paddingRight:
                          "4px",

                        textAlign:
                          "center",
                      },
                    ),
                  }}
                >
                  Actions
                </th>

              </tr>

            </thead>


            {/* ==============================================================
             * BODY
             * ============================================================== */}

            <tbody>

              {alerts.map(
                (alert) => (
                  <AlertRow
                    key={
                      alert.alert_id
                    }
                    alert={alert}
                    selected={
                      selectedAlertId ===
                      alert.alert_id
                    }
                    disabled={
                      disabled
                    }
                    onSelect={
                      onSelectAlert
                    }
                    onAction={
                      onAction
                    }
                  />
                ),
              )}

            </tbody>

          </table>

        </div>

      </div>
    </>
  );
}


/* ==========================================================================
 * DEFAULT EXPORT
 * ========================================================================== */

export default AlertTable;