import type {
  CSSProperties,
  KeyboardEvent,
} from "react";

import type { SecurityEvent } from "../types";

/* ==========================================================================
 * SentinelSIEM — Events
 * EventTable
 *
 * CANONICAL / FINAL IMPLEMENTATION
 *
 * Layout guarantees:
 * - Exactly 9 columns
 * - Fixed 1240px table width
 * - Explicit column widths
 * - Semantic HTML table
 * - Horizontal scrolling handled by wrapper
 * - Timestamp + Event ID ALWAYS stacked
 * - Source + Source Type ALWAYS stacked
 * - No nth-child dependency
 * - No generic table CSS dependency
 * - No flex layout on table rows/cells
 * - Inline structural styles prevent external layout conflicts
 * ========================================================================== */


/* ==========================================================================
 * CONSTANTS
 * ========================================================================== */

const COLUMN_COUNT = 9;

const EMPTY_VALUE = "—";

const MONO_FONT =
  '"SFMono-Regular", "Cascadia Code", "Roboto Mono", Consolas, "Liberation Mono", monospace';


/* ==========================================================================
 * COLUMN CONFIGURATION
 *
 * 230 + 190 + 130 + 130 + 120 + 110 + 110 + 110 + 110
 * --------------------------------------------------------------------------
 * TOTAL = 1240px
 * ========================================================================== */

const COLUMN_WIDTHS = {
  timestamp: 230,
  source: 190,
  sourceIp: 130,
  destination: 130,
  user: 120,
  action: 110,
  outcome: 110,
  severity: 110,
  category: 110,
} as const;

const TABLE_WIDTH =
  COLUMN_WIDTHS.timestamp +
  COLUMN_WIDTHS.source +
  COLUMN_WIDTHS.sourceIp +
  COLUMN_WIDTHS.destination +
  COLUMN_WIDTHS.user +
  COLUMN_WIDTHS.action +
  COLUMN_WIDTHS.outcome +
  COLUMN_WIDTHS.severity +
  COLUMN_WIDTHS.category;


/* ==========================================================================
 * TYPES
 * ========================================================================== */

export interface EventTableProps {
  events: SecurityEvent[];
  loading?: boolean;
  error?: string | null;
  onSelect?: (event: SecurityEvent) => void;
}


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

  const normalized = String(value).trim();

  return normalized.length > 0
    ? normalized
    : EMPTY_VALUE;
}


function formatDate(
  value?: string | null,
): string {
  if (!value) {
    return EMPTY_VALUE;
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return EMPTY_VALUE;
  }

  return date.toLocaleString();
}


function normalizeSeverity(
  value?: string | null,
): string {
  const normalized =
    value?.trim().toLowerCase();

  return normalized || "unknown";
}


function formatSeverity(
  value?: string | null,
): string {
  const normalized =
    normalizeSeverity(value);

  if (normalized === "unknown") {
    return "Unknown";
  }

  return normalized
    .replace(/[-_]+/g, " ")
    .replace(/\b\w/g, (character) =>
      character.toUpperCase(),
    );
}


function activateRow(
  keyboardEvent: KeyboardEvent<HTMLTableRowElement>,
  event: SecurityEvent,
  onSelect?: (event: SecurityEvent) => void,
): void {
  if (!onSelect) {
    return;
  }

  if (
    keyboardEvent.key !== "Enter" &&
    keyboardEvent.key !== " "
  ) {
    return;
  }

  keyboardEvent.preventDefault();

  onSelect(event);
}


/* ==========================================================================
 * STRUCTURAL STYLES
 * ========================================================================== */

const tableContainerStyle: CSSProperties = {
  position: "relative",

  display: "block",

  width: "100%",
  minWidth: 0,
  maxWidth: "100%",

  margin: 0,
  padding: 0,

  overflow: "hidden",

  background: "#071522",
};


const tableScrollStyle: CSSProperties = {
  display: "block",

  width: "100%",
  minWidth: 0,
  maxWidth: "100%",

  margin: 0,
  padding: 0,

  overflowX: "auto",
  overflowY: "hidden",

  WebkitOverflowScrolling: "touch",

  scrollbarWidth: "thin",
  scrollbarColor: "#1b3c53 transparent",
};


const tableStyle: CSSProperties = {
  display: "table",

  width: `${TABLE_WIDTH}px`,
  minWidth: `${TABLE_WIDTH}px`,
  maxWidth: `${TABLE_WIDTH}px`,

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

  height: "44px",

  margin: 0,
  padding: "0 12px",

  border: 0,
  borderBottom:
    "1px solid rgba(22, 50, 73, 0.9)",

  background: "#081927",
  color: "#58748a",

  fontFamily: "inherit",
  fontSize: "9px",
  fontWeight: 700,

  letterSpacing: "0.075em",
  lineHeight: "1",

  textAlign: "left",
  verticalAlign: "middle",

  textTransform: "uppercase",

  whiteSpace: "nowrap",

  overflow: "hidden",
};


const bodyCellStyle: CSSProperties = {
  boxSizing: "border-box",

  height: "68px",

  margin: 0,
  padding: "10px 12px",

  border: 0,
  borderBottom:
    "1px solid rgba(22, 50, 73, 0.65)",

  background: "#071522",
  color: "#a6b9c9",

  fontFamily: "inherit",
  fontSize: "11px",
  lineHeight: "1.4",

  textAlign: "left",
  verticalAlign: "middle",

  whiteSpace: "nowrap",

  overflow: "hidden",
};


/* ==========================================================================
 * COLUMN STYLE
 * ========================================================================== */

function columnStyle(
  width: number,
  options?: {
    paddingLeft?: string;
    paddingRight?: string;
  },
): CSSProperties {
  return {
    boxSizing: "border-box",

    width: `${width}px`,
    minWidth: `${width}px`,
    maxWidth: `${width}px`,

    ...(options?.paddingLeft
      ? {
          paddingLeft:
            options.paddingLeft,
        }
      : {}),

    ...(options?.paddingRight
      ? {
          paddingRight:
            options.paddingRight,
        }
      : {}),
  };
}


/* ==========================================================================
 * IDENTITY STACK
 *
 * IMPORTANT:
 *
 * This intentionally uses TWO explicit block-level DIVs.
 *
 * Timestamp:
 *   timestamp
 *   event id
 *
 * Source:
 *   source
 *   source type
 *
 * There is no flex layout here.
 * ========================================================================== */

function IdentityStack({
  primary,
  secondary,
  secondaryMono = false,
}: {
  primary: string;
  secondary: string;
  secondaryMono?: boolean;
}) {
  const wrapperStyle: CSSProperties = {
    display: "block",

    width: "100%",
    minWidth: 0,
    maxWidth: "100%",

    margin: 0,
    padding: 0,

    overflow: "hidden",

    boxSizing: "border-box",
  };


  const primaryStyle: CSSProperties = {
    display: "block",

    width: "100%",
    minWidth: 0,
    maxWidth: "100%",

    margin: 0,
    padding: 0,

    overflow: "hidden",

    boxSizing: "border-box",

    color: "#dbe7f1",

    fontFamily: "inherit",
    fontSize: "11px",
    fontWeight: 650,
    lineHeight: "17px",

    textAlign: "left",

    whiteSpace: "nowrap",
    textOverflow: "ellipsis",
  };


  const secondaryStyle: CSSProperties = {
    display: "block",

    width: "100%",
    minWidth: 0,
    maxWidth: "100%",

    margin: "3px 0 0",
    padding: 0,

    overflow: "hidden",

    boxSizing: "border-box",

    color: "#526b80",

    fontFamily:
      secondaryMono
        ? MONO_FONT
        : "inherit",

    fontSize: "9px",
    fontWeight: 400,
    lineHeight: "13px",

    textAlign: "left",

    whiteSpace: "nowrap",
    textOverflow: "ellipsis",
  };


  return (
    <div
      className="sentinel-events-identity"
      style={wrapperStyle}
    >
      <div
        className="sentinel-events-identity-primary"
        style={primaryStyle}
      >
        {primary}
      </div>

      <div
        className="sentinel-events-identity-secondary"
        style={secondaryStyle}
      >
        {secondary}
      </div>
    </div>
  );
}


/* ==========================================================================
 * NORMAL CELL VALUE
 * ========================================================================== */

function CellValue({
  value,
  mono = false,
}: {
  value?: string | number | null;
  mono?: boolean;
}) {
  const style: CSSProperties = {
    display: "block",

    width: "100%",
    minWidth: 0,
    maxWidth: "100%",

    margin: 0,
    padding: 0,

    overflow: "hidden",

    boxSizing: "border-box",

    color: "#a6b9c9",

    fontFamily:
      mono
        ? MONO_FONT
        : "inherit",

    fontSize: "11px",
    fontWeight: 400,
    lineHeight: "17px",

    textAlign: "left",

    whiteSpace: "nowrap",
    textOverflow: "ellipsis",
  };


  return (
    <div
      className="sentinel-events-cell-value"
      style={style}
    >
      {displayValue(value)}
    </div>
  );
}


/* ==========================================================================
 * SEVERITY BADGE
 * ========================================================================== */

function SeverityBadge({
  value,
}: {
  value?: string | null;
}) {
  const normalized =
    normalizeSeverity(value);


  let color = "#7d94a6";

  let background =
    "rgba(113, 136, 155, 0.08)";

  let border =
    "rgba(113, 136, 155, 0.18)";


  switch (normalized) {
    case "info":
      color = "#51c7f5";

      background =
        "rgba(81, 199, 245, 0.11)";

      border =
        "rgba(81, 199, 245, 0.19)";

      break;


    case "low":
      color = "#32d99a";

      background =
        "rgba(50, 217, 154, 0.11)";

      border =
        "rgba(50, 217, 154, 0.20)";

      break;


    case "medium":
      color = "#d6a744";

      background =
        "rgba(242, 184, 75, 0.08)";

      border =
        "rgba(242, 184, 75, 0.18)";

      break;


    case "high":
      color = "#f2b84b";

      background =
        "rgba(242, 184, 75, 0.11)";

      border =
        "rgba(242, 184, 75, 0.22)";

      break;


    case "critical":
      color = "#ff5d73";

      background =
        "rgba(255, 93, 115, 0.11)";

      border =
        "rgba(255, 93, 115, 0.24)";

      break;


    default:
      break;
  }


  const badgeStyle: CSSProperties = {
    display: "inline-flex",

    alignItems: "center",
    justifyContent: "center",

    boxSizing: "border-box",

    maxWidth: "100%",
    minHeight: "23px",

    gap: "6px",

    padding: "0 8px",

    border:
      `1px solid ${border}`,

    borderRadius: "6px",

    background,
    color,

    fontSize: "9px",
    fontWeight: 750,

    letterSpacing: "0.045em",
    lineHeight: "1",

    textTransform: "uppercase",

    whiteSpace: "nowrap",

    overflow: "hidden",
  };


  const dotStyle: CSSProperties = {
    display: "block",

    width: "5px",
    height: "5px",

    flex: "0 0 5px",

    borderRadius: "50%",

    background: "currentColor",

    boxShadow:
      "0 0 7px currentColor",
  };


  return (
    <span
      className="sentinel-events-severity"
      style={badgeStyle}
    >
      <span
        className="sentinel-events-severity-dot"
        style={dotStyle}
        aria-hidden="true"
      />

      {formatSeverity(value)}
    </span>
  );
}


/* ==========================================================================
 * CATEGORY BADGE
 * ========================================================================== */

function CategoryBadge({
  value,
}: {
  value?: string | null;
}) {
  const style: CSSProperties = {
    display: "inline-flex",

    alignItems: "center",

    boxSizing: "border-box",

    minHeight: "22px",
    maxWidth: "100%",

    padding: "3px 7px",

    overflow: "hidden",

    border:
      "1px solid rgba(69, 105, 128, 0.22)",

    borderRadius: "5px",

    background:
      "rgba(31, 60, 80, 0.22)",

    color: "#8199aa",

    fontSize: "9px",
    fontWeight: 650,
    lineHeight: "1",

    whiteSpace: "nowrap",
    textOverflow: "ellipsis",
  };


  return (
    <span
      className="sentinel-events-category"
      style={style}
    >
      {displayValue(value)}
    </span>
  );
}


/* ==========================================================================
 * STATE STYLES
 * ========================================================================== */

const stateCellStyle: CSSProperties = {
  boxSizing: "border-box",

  border: 0,

  background: "#071522",

  textAlign: "center",
  verticalAlign: "middle",
};


/* ==========================================================================
 * LOADING STATE
 * ========================================================================== */

function LoadingState() {
  return (
    <tr>
      <td
        colSpan={COLUMN_COUNT}
        style={{
          ...stateCellStyle,

          height: "220px",

          padding: "32px 24px",
        }}
      >
        <div
          style={{
            display: "inline-flex",

            alignItems: "center",
            justifyContent: "center",

            gap: "10px",

            textAlign: "left",
          }}
        >
          <span
            aria-hidden="true"
            style={{
              display: "block",

              width: "18px",
              height: "18px",

              flex: "0 0 18px",

              border:
                "2px solid rgba(55, 183, 235, 0.18)",

              borderTopColor:
                "#36bdf5",

              borderRadius: "50%",

              animation:
                "sentinel-events-spin 800ms linear infinite",
            }}
          />

          <div
            style={{
              display: "block",
            }}
          >
            <strong
              style={{
                display: "block",

                margin: 0,
                marginBottom: "3px",

                color: "#c8d7e3",

                fontSize: "12px",
                fontWeight: 650,
                lineHeight: "16px",
              }}
            >
              Loading security events
            </strong>

            <span
              style={{
                display: "block",

                color: "#607b90",

                fontSize: "10px",
                lineHeight: "15px",
              }}
            >
              Retrieving normalized events from
              the platform.
            </span>
          </div>
        </div>
      </td>
    </tr>
  );
}


/* ==========================================================================
 * ERROR STATE
 * ========================================================================== */

function ErrorState({
  message,
}: {
  message: string;
}) {
  return (
    <tr>
      <td
        colSpan={COLUMN_COUNT}
        style={{
          ...stateCellStyle,

          height: "180px",

          padding: "32px 24px",
        }}
      >
        <div
          style={{
            display: "inline-flex",

            alignItems: "center",
            justifyContent: "center",

            gap: "10px",

            textAlign: "left",
          }}
        >
          <span
            aria-hidden="true"
            style={{
              display: "grid",
              placeItems: "center",

              width: "30px",
              height: "30px",

              flex: "0 0 30px",

              border:
                "1px solid rgba(255, 93, 115, 0.20)",

              borderRadius: "7px",

              background:
                "rgba(255, 93, 115, 0.11)",

              color: "#ff5d73",

              fontSize: "13px",
              fontWeight: 700,
            }}
          >
            !
          </span>

          <div
            style={{
              display: "block",
              minWidth: 0,
            }}
          >
            <strong
              style={{
                display: "block",

                margin: 0,
                marginBottom: "3px",

                color: "#c8d7e3",

                fontSize: "12px",
                fontWeight: 650,
              }}
            >
              Unable to load events
            </strong>

            <span
              style={{
                display: "block",

                color: "#607b90",

                fontSize: "10px",
                lineHeight: "1.5",

                overflowWrap: "anywhere",
              }}
            >
              {displayValue(message)}
            </span>
          </div>
        </div>
      </td>
    </tr>
  );
}


/* ==========================================================================
 * EMPTY STATE
 * ========================================================================== */

function EmptyState() {
  return (
    <tr>
      <td
        colSpan={COLUMN_COUNT}
        style={{
          ...stateCellStyle,

          height: "200px",

          padding: "32px 24px",
        }}
      >
        <div
          style={{
            display: "flex",

            alignItems: "center",
            justifyContent: "center",

            flexDirection: "column",

            gap: "6px",
          }}
        >
          <span
            aria-hidden="true"
            style={{
              display: "grid",
              placeItems: "center",

              width: "40px",
              height: "40px",

              marginBottom: "4px",

              border:
                "1px solid #163249",

              borderRadius: "10px",

              background: "#0a1b2a",
              color: "#4d697d",

              fontSize: "16px",
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
            No security events
          </strong>

          <span
            style={{
              color: "#526b80",

              fontSize: "10px",
              lineHeight: "1.5",
            }}
          >
            No events are available for the
            current selection.
          </span>
        </div>
      </td>
    </tr>
  );
}


/* ==========================================================================
 * EVENT ROW
 * ========================================================================== */

function EventRow({
  event,
  onSelect,
}: {
  event: SecurityEvent;
  onSelect?: (event: SecurityEvent) => void;
}) {
  const interactive =
    typeof onSelect === "function";


  return (
    <tr
      className={
        interactive
          ? "sentinel-events-row sentinel-events-row-clickable"
          : "sentinel-events-row"
      }
      onClick={
        interactive
          ? () => onSelect(event)
          : undefined
      }
      onKeyDown={
        interactive
          ? (
              keyboardEvent,
            ) =>
              activateRow(
                keyboardEvent,
                event,
                onSelect,
              )
          : undefined
      }
      tabIndex={
        interactive ? 0 : undefined
      }
      aria-label={
        interactive
          ? `View event ${displayValue(
              event.event_id,
            )}`
          : undefined
      }
      style={{
        display: "table-row",

        width: `${TABLE_WIDTH}px`,

        height: "68px",

        background: "#071522",
      }}
    >

      {/* ================================================================
       * TIMESTAMP + EVENT ID
       * ================================================================ */}

      <td
        style={{
          ...bodyCellStyle,

          ...columnStyle(
            COLUMN_WIDTHS.timestamp,
            {
              paddingLeft: "20px",
            },
          ),
        }}
      >
        <IdentityStack
          primary={formatDate(
            event.timestamp,
          )}
          secondary={displayValue(
            event.event_id,
          )}
          secondaryMono
        />
      </td>


      {/* ================================================================
       * SOURCE + SOURCE TYPE
       * ================================================================ */}

      <td
        style={{
          ...bodyCellStyle,

          ...columnStyle(
            COLUMN_WIDTHS.source,
          ),
        }}
      >
        <IdentityStack
          primary={displayValue(
            event.source,
          )}
          secondary={displayValue(
            event.source_type,
          )}
        />
      </td>


      {/* ================================================================
       * SOURCE IP
       * ================================================================ */}

      <td
        style={{
          ...bodyCellStyle,

          ...columnStyle(
            COLUMN_WIDTHS.sourceIp,
          ),
        }}
      >
        <CellValue
          value={event.source_ip}
          mono
        />
      </td>


      {/* ================================================================
       * DESTINATION
       * ================================================================ */}

      <td
        style={{
          ...bodyCellStyle,

          ...columnStyle(
            COLUMN_WIDTHS.destination,
          ),
        }}
      >
        <CellValue
          value={event.destination_ip}
          mono
        />
      </td>


      {/* ================================================================
       * USER
       * ================================================================ */}

      <td
        style={{
          ...bodyCellStyle,

          ...columnStyle(
            COLUMN_WIDTHS.user,
          ),
        }}
      >
        <CellValue
          value={event.username}
        />
      </td>


      {/* ================================================================
       * ACTION
       * ================================================================ */}

      <td
        style={{
          ...bodyCellStyle,

          ...columnStyle(
            COLUMN_WIDTHS.action,
          ),
        }}
      >
        <CellValue
          value={event.action}
        />
      </td>


      {/* ================================================================
       * OUTCOME
       * ================================================================ */}

      <td
        style={{
          ...bodyCellStyle,

          ...columnStyle(
            COLUMN_WIDTHS.outcome,
          ),
        }}
      >
        <CellValue
          value={event.outcome}
        />
      </td>


      {/* ================================================================
       * SEVERITY
       * ================================================================ */}

      <td
        style={{
          ...bodyCellStyle,

          ...columnStyle(
            COLUMN_WIDTHS.severity,
          ),
        }}
      >
        <SeverityBadge
          value={event.severity}
        />
      </td>


      {/* ================================================================
       * CATEGORY
       * ================================================================ */}

      <td
        style={{
          ...bodyCellStyle,

          ...columnStyle(
            COLUMN_WIDTHS.category,
            {
              paddingRight: "20px",
            },
          ),
        }}
      >
        <CategoryBadge
          value={event.category}
        />
      </td>
    </tr>
  );
}


/* ==========================================================================
 * MAIN EVENT TABLE
 * ========================================================================== */

export default function EventTable({
  events,
  loading = false,
  error = null,
  onSelect,
}: EventTableProps) {
  const hasEvents =
    events.length > 0;


  return (
    <>
      {/* ================================================================
       * ISOLATED EVENT TABLE CSS
       *
       * Only sentinel-events-* selectors are used here.
       * No legacy events-* selectors.
       * No nth-child selectors.
       * ================================================================ */}

      <style>
        {`
          @keyframes sentinel-events-spin {
            to {
              transform: rotate(360deg);
            }
          }

          .sentinel-events-table-container {
            display: block !important;
            width: 100% !important;
            min-width: 0 !important;
            max-width: 100% !important;
            overflow: hidden !important;
          }

          .sentinel-events-table-scroll {
            display: block !important;
            width: 100% !important;
            min-width: 0 !important;
            max-width: 100% !important;
            overflow-x: auto !important;
            overflow-y: hidden !important;
          }

          .sentinel-events-table {
            display: table !important;

            width: 1240px !important;
            min-width: 1240px !important;
            max-width: 1240px !important;

            table-layout: fixed !important;

            margin: 0 !important;
            padding: 0 !important;

            border: 0 !important;
            border-collapse: collapse !important;
            border-spacing: 0 !important;
          }

          .sentinel-events-table col {
            box-sizing: border-box !important;
          }

          .sentinel-events-identity {
            display: block !important;

            width: 100% !important;
            min-width: 0 !important;
            max-width: 100% !important;

            margin: 0 !important;
            padding: 0 !important;

            overflow: hidden !important;
          }

          .sentinel-events-identity-primary {
            display: block !important;

            width: 100% !important;
            min-width: 0 !important;
            max-width: 100% !important;

            margin: 0 !important;
            padding: 0 !important;

            overflow: hidden !important;

            white-space: nowrap !important;
            text-overflow: ellipsis !important;
          }

          .sentinel-events-identity-secondary {
            display: block !important;

            width: 100% !important;
            min-width: 0 !important;
            max-width: 100% !important;

            margin: 3px 0 0 !important;
            padding: 0 !important;

            overflow: hidden !important;

            white-space: nowrap !important;
            text-overflow: ellipsis !important;
          }

          .sentinel-events-row {
            display: table-row !important;

            height: 68px !important;

            background: #071522 !important;

            transition:
              background-color 140ms ease;
          }

          .sentinel-events-row:hover {
            background:
              #0b1d2d !important;
          }

          .sentinel-events-row-clickable {
            cursor: pointer !important;
          }

          .sentinel-events-row-clickable:hover {
            background:
              rgba(18, 82, 112, 0.24) !important;
          }

          .sentinel-events-row-clickable:focus-visible {
            outline:
              2px solid #36bdf5 !important;

            outline-offset:
              -2px !important;

            background:
              rgba(18, 82, 112, 0.30) !important;
          }

          .sentinel-events-row-clickable:active {
            background:
              rgba(18, 82, 112, 0.36) !important;
          }

          .sentinel-events-severity {
            box-sizing: border-box !important;
          }

          .sentinel-events-category {
            box-sizing: border-box !important;
          }

          .sentinel-events-cell-value {
            display: block !important;

            width: 100% !important;
            min-width: 0 !important;
            max-width: 100% !important;

            overflow: hidden !important;

            white-space: nowrap !important;
            text-overflow: ellipsis !important;
          }

          .sentinel-events-table-scroll::-webkit-scrollbar {
            width: 7px;
            height: 7px;
          }

          .sentinel-events-table-scroll::-webkit-scrollbar-track {
            background: transparent;
          }

          .sentinel-events-table-scroll::-webkit-scrollbar-thumb {
            background: #1b3c53;
            border-radius: 999px;
          }

          .sentinel-events-table-scroll::-webkit-scrollbar-thumb:hover {
            background: #2a526c;
          }

          @media (prefers-reduced-motion: reduce) {
            .sentinel-events-row {
              transition: none !important;
            }
          }
        `}
      </style>


      {/* ================================================================
       * OUTER CONTAINER
       * ================================================================ */}

      <div
        className="sentinel-events-table-container"
        style={tableContainerStyle}
      >
        {/* ==============================================================
         * SCROLL WRAPPER
         * ============================================================== */}

        <div
          className="sentinel-events-table-scroll"
          style={tableScrollStyle}
        >
          {/* ============================================================
           * TABLE
           * ============================================================ */}

          <table
            className="sentinel-events-table"
            style={tableStyle}
          >

            {/* ========================================================
             * COLUMN DEFINITIONS
             * ======================================================== */}

            <colgroup>
              <col
                style={{
                  width:
                    `${COLUMN_WIDTHS.timestamp}px`,
                }}
              />

              <col
                style={{
                  width:
                    `${COLUMN_WIDTHS.source}px`,
                }}
              />

              <col
                style={{
                  width:
                    `${COLUMN_WIDTHS.sourceIp}px`,
                }}
              />

              <col
                style={{
                  width:
                    `${COLUMN_WIDTHS.destination}px`,
                }}
              />

              <col
                style={{
                  width:
                    `${COLUMN_WIDTHS.user}px`,
                }}
              />

              <col
                style={{
                  width:
                    `${COLUMN_WIDTHS.action}px`,
                }}
              />

              <col
                style={{
                  width:
                    `${COLUMN_WIDTHS.outcome}px`,
                }}
              />

              <col
                style={{
                  width:
                    `${COLUMN_WIDTHS.severity}px`,
                }}
              />

              <col
                style={{
                  width:
                    `${COLUMN_WIDTHS.category}px`,
                }}
              />
            </colgroup>


            {/* ========================================================
             * HEADER
             * ======================================================== */}

            <thead>
              <tr
                style={{
                  display: "table-row",

                  height: "44px",

                  background: "#081927",
                }}
              >
                <th
                  scope="col"
                  style={{
                    ...headerCellStyle,

                    ...columnStyle(
                      COLUMN_WIDTHS.timestamp,
                      {
                        paddingLeft: "20px",
                      },
                    ),
                  }}
                >
                  Timestamp
                </th>

                <th
                  scope="col"
                  style={{
                    ...headerCellStyle,

                    ...columnStyle(
                      COLUMN_WIDTHS.source,
                    ),
                  }}
                >
                  Source
                </th>

                <th
                  scope="col"
                  style={{
                    ...headerCellStyle,

                    ...columnStyle(
                      COLUMN_WIDTHS.sourceIp,
                    ),
                  }}
                >
                  Source IP
                </th>

                <th
                  scope="col"
                  style={{
                    ...headerCellStyle,

                    ...columnStyle(
                      COLUMN_WIDTHS.destination,
                    ),
                  }}
                >
                  Destination
                </th>

                <th
                  scope="col"
                  style={{
                    ...headerCellStyle,

                    ...columnStyle(
                      COLUMN_WIDTHS.user,
                    ),
                  }}
                >
                  User
                </th>

                <th
                  scope="col"
                  style={{
                    ...headerCellStyle,

                    ...columnStyle(
                      COLUMN_WIDTHS.action,
                    ),
                  }}
                >
                  Action
                </th>

                <th
                  scope="col"
                  style={{
                    ...headerCellStyle,

                    ...columnStyle(
                      COLUMN_WIDTHS.outcome,
                    ),
                  }}
                >
                  Outcome
                </th>

                <th
                  scope="col"
                  style={{
                    ...headerCellStyle,

                    ...columnStyle(
                      COLUMN_WIDTHS.severity,
                    ),
                  }}
                >
                  Severity
                </th>

                <th
                  scope="col"
                  style={{
                    ...headerCellStyle,

                    ...columnStyle(
                      COLUMN_WIDTHS.category,
                      {
                        paddingRight: "20px",
                      },
                    ),
                  }}
                >
                  Category
                </th>
              </tr>
            </thead>


            {/* ========================================================
             * BODY
             * ======================================================== */}

            <tbody>
              {/* Loading */}

              {loading && (
                <LoadingState />
              )}


              {/* Error */}

              {!loading &&
                error && (
                  <ErrorState
                    message={error}
                  />
                )}


              {/* Events */}

              {!loading &&
                !error &&
                hasEvents &&
                events.map(
                  (event, index) => (
                    <EventRow
                      key={
                        event.event_id
                          ? `${event.event_id}-${index}`
                          : `event-${index}`
                      }
                      event={event}
                      onSelect={onSelect}
                    />
                  ),
                )}


              {/* Empty */}

              {!loading &&
                !error &&
                !hasEvents && (
                  <EmptyState />
                )}
            </tbody>

          </table>
        </div>
      </div>
    </>
  );
}