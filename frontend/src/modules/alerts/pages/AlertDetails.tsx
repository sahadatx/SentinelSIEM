import {
  Link,
  useParams,
} from "react-router-dom";

import {
  useEffect,
  useState,
} from "react";

import { Panel } from "../../../components/ui/Panel";

import { SeverityBadge } from "../../../components/ui/SeverityBadge";

import { alertsApi } from "../api";

import type {
  Alert,
  AlertStatus,
} from "../types";

import "../Alerts.css";


/* ==========================================================================
 * SentinelSIEM — Alerts Module
 * AlertDetails Page
 *
 * FINAL ISOLATED IMPLEMENTATION
 *
 * Responsibilities:
 * - Resolve alert ID from route
 * - Load a single persisted alert
 * - Handle loading / error / missing-ID states
 * - Render operational alert details
 * - Render source / detection information
 * - Render ownership information
 * - Render timeline information
 * - Render evidence identifiers
 * - Preserve accessibility
 *
 * Backend:
 * - GET /api/v1/alerts/{alert_id}
 *
 * IMPORTANT:
 * - Lifecycle mutation is intentionally NOT performed here.
 * - Assignment / transition controls belong to the alert workflow layer.
 * - This page remains a read-only detail view.
 * ========================================================================== */


/* ==========================================================================
 * CONSTANTS
 * ========================================================================== */

const EMPTY_VALUE = "—";

const MONO_FONT =
  '"SFMono-Regular", "Cascadia Code", "Roboto Mono", Consolas, "Liberation Mono", monospace';


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


function formatDateTime(
  value?: string | null,
): string {
  if (!value) {
    return EMPTY_VALUE;
  }

  const date =
    new Date(value);

  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    return displayValue(value);
  }

  return date.toLocaleString();
}


function formatStatus(
  status?: AlertStatus | string | null,
): string {
  if (!status) {
    return EMPTY_VALUE;
  }

  return String(status)
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


function formatSourceType(
  sourceType?: string | null,
): string {
  if (!sourceType) {
    return EMPTY_VALUE;
  }

  return String(sourceType)
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


/* ==========================================================================
 * DETAIL FIELD
 * ========================================================================== */

function DetailField({
  label,
  children,
  mono = false,
}: {
  label: string;
  children: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div
      className="sentinel-alert-detail-field"
      style={{
        display:
          "flex",

        flexDirection:
          "column",

        minWidth:
          0,

        gap:
          "7px",

        padding:
          "14px 15px",

        border:
          "1px solid rgba(22, 50, 73, 0.75)",

        borderRadius:
          "8px",

        background:
          "#081725",
      }}
    >
      <span
        className="sentinel-alert-detail-label"
        style={{
          display:
            "block",

          color:
            "#526b80",

          fontSize:
            "9px",

          fontWeight:
            700,

          letterSpacing:
            "0.075em",

          lineHeight:
            "13px",

          textTransform:
            "uppercase",
        }}
      >
        {label}
      </span>

      <div
        className={
          mono
            ? "sentinel-alert-detail-value sentinel-alert-detail-value-mono"
            : "sentinel-alert-detail-value"
        }
        style={{
          display:
            "block",

          minWidth:
            0,

          maxWidth:
            "100%",

          overflow:
            "hidden",

          color:
            "#c8d7e3",

          fontFamily:
            mono
              ? MONO_FONT
              : "inherit",

          fontSize:
            "11px",

          fontWeight:
            500,

          lineHeight:
            "17px",

          overflowWrap:
            mono
              ? "anywhere"
              : "break-word",
        }}
      >
        {children}
      </div>
    </div>
  );
}


/* ==========================================================================
 * SECTION
 * ========================================================================== */

function DetailSection({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section
      className="sentinel-alert-detail-section"
      style={{
        display:
          "block",

        width:
          "100%",

        minWidth:
          0,

        margin:
          0,

        padding:
          0,
      }}
    >
      <div
        style={{
          display:
            "flex",

          alignItems:
            "center",

          gap:
            "8px",

          marginBottom:
            "11px",
        }}
      >
        <span
          aria-hidden="true"
          style={{
            display:
              "block",

            width:
              "3px",

            height:
              "14px",

            flex:
              "0 0 3px",

            borderRadius:
              "999px",

            background:
              "#36bdf5",
          }}
        />

        <h3
          style={{
            margin:
              0,

            color:
              "#a6b9c9",

            fontSize:
              "10px",

            fontWeight:
              750,

            letterSpacing:
              "0.09em",

            lineHeight:
              "14px",

            textTransform:
              "uppercase",
          }}
        >
          {title}
        </h3>
      </div>

      {children}
    </section>
  );
}


/* ==========================================================================
 * LOADING STATE
 * ========================================================================== */

function LoadingState() {
  return (
    <div
      className="sentinel-alert-details-state"
      role="status"
      aria-live="polite"
      style={{
        display:
          "flex",

        alignItems:
          "center",

        justifyContent:
          "center",

        minHeight:
          "260px",

        padding:
          "32px 24px",

        background:
          "#071522",
      }}
    >
      <div
        style={{
          display:
            "inline-flex",

          alignItems:
            "center",

          gap:
            "10px",

          textAlign:
            "left",
        }}
      >
        <span
          aria-hidden="true"
          style={{
            display:
              "block",

            width:
              "18px",

            height:
              "18px",

            flex:
              "0 0 18px",

            border:
              "2px solid rgba(55, 183, 235, 0.18)",

            borderTopColor:
              "#36bdf5",

            borderRadius:
              "50%",

            animation:
              "sentinel-alert-details-spin 800ms linear infinite",
          }}
        />

        <span>
          <strong
            style={{
              display:
                "block",

              marginBottom:
                "3px",

              color:
                "#c8d7e3",

              fontSize:
                "12px",

              fontWeight:
                650,

              lineHeight:
                "16px",
            }}
          >
            Loading alert
          </strong>

          <span
            style={{
              display:
                "block",

              color:
                "#607b90",

              fontSize:
                "10px",

              lineHeight:
                "15px",
            }}
          >
            Retrieving persisted alert
            details from the platform.
          </span>
        </span>
      </div>
    </div>
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
    <div
      className="sentinel-alert-details-state"
      role="alert"
      style={{
        display:
          "flex",

        alignItems:
          "center",

        justifyContent:
          "center",

        minHeight:
          "230px",

        padding:
          "32px 24px",

        background:
          "#071522",
      }}
    >
      <div
        style={{
          display:
            "inline-flex",

          alignItems:
            "center",

          gap:
            "10px",

          maxWidth:
            "650px",

          textAlign:
            "left",
        }}
      >
        <span
          aria-hidden="true"
          style={{
            display:
              "grid",

            placeItems:
              "center",

            width:
              "30px",

            height:
              "30px",

            flex:
              "0 0 30px",

            border:
              "1px solid rgba(255, 93, 115, 0.20)",

            borderRadius:
              "7px",

            background:
              "rgba(255, 93, 115, 0.11)",

            color:
              "#ff5d73",

            fontSize:
              "13px",

            fontWeight:
              700,
          }}
        >
          !
        </span>

        <span
          style={{
            display:
              "block",

            minWidth:
              0,
          }}
        >
          <strong
            style={{
              display:
                "block",

              marginBottom:
                "3px",

              color:
                "#c8d7e3",

              fontSize:
                "12px",

              fontWeight:
                650,
            }}
          >
            Unable to load alert
          </strong>

          <span
            style={{
              display:
                "block",

              color:
                "#607b90",

              fontSize:
                "10px",

              lineHeight:
                "1.5",

              overflowWrap:
                "anywhere",
            }}
          >
            {displayValue(message)}
          </span>
        </span>
      </div>
    </div>
  );
}


/* ==========================================================================
 * MISSING ALERT ID
 * ========================================================================== */

function MissingAlertState() {
  return (
    <div
      className="sentinel-alert-details-state"
      role="alert"
      style={{
        display:
          "flex",

        alignItems:
          "center",

        justifyContent:
          "center",

        minHeight:
          "230px",

        padding:
          "32px 24px",

        background:
          "#071522",
      }}
    >
      <div
        style={{
          display:
            "flex",

          alignItems:
            "center",

          justifyContent:
            "center",

          flexDirection:
            "column",

          gap:
            "7px",

          textAlign:
            "center",
        }}
      >
        <span
          aria-hidden="true"
          style={{
            display:
              "grid",

            placeItems:
              "center",

            width:
              "40px",

            height:
              "40px",

            marginBottom:
              "3px",

            border:
              "1px solid #163249",

            borderRadius:
              "10px",

            background:
              "#0a1b2a",

            color:
              "#4d697d",

            fontSize:
              "15px",
          }}
        >
          !
        </span>

        <strong
          style={{
            color:
              "#a6b9c9",

            fontSize:
              "12px",

            fontWeight:
              650,
          }}
        >
          Alert ID is missing
        </strong>

        <span
          style={{
            maxWidth:
              "360px",

            color:
              "#526b80",

            fontSize:
              "10px",

            lineHeight:
              "1.5",
          }}
        >
          A valid alert identifier is
          required to load this alert.
        </span>
      </div>
    </div>
  );
}


/* ==========================================================================
 * NOT FOUND STATE
 * ========================================================================== */

function NotFoundState() {
  return (
    <div
      className="sentinel-alert-details-state"
      role="alert"
      style={{
        display:
          "flex",

        alignItems:
          "center",

        justifyContent:
          "center",

        minHeight:
          "230px",

        padding:
          "32px 24px",

        background:
          "#071522",
      }}
    >
      <div
        style={{
          display:
            "flex",

          alignItems:
            "center",

          justifyContent:
            "center",

          flexDirection:
            "column",

          gap:
            "7px",

          textAlign:
            "center",
        }}
      >
        <span
          aria-hidden="true"
          style={{
            display:
              "grid",

            placeItems:
              "center",

            width:
              "40px",

            height:
              "40px",

            marginBottom:
              "3px",

            border:
              "1px solid #163249",

            borderRadius:
              "10px",

            background:
              "#0a1b2a",

            color:
              "#4d697d",

            fontSize:
              "15px",
          }}
        >
          ?
        </span>

        <strong
          style={{
            color:
              "#a6b9c9",

            fontSize:
              "12px",

            fontWeight:
              650,
          }}
        >
          Alert not found
        </strong>

        <span
          style={{
            maxWidth:
              "400px",

            color:
              "#526b80",

            fontSize:
              "10px",

            lineHeight:
              "1.5",
          }}
        >
          The requested alert does not
          exist in the persisted alert store.
        </span>
      </div>
    </div>
  );
}


/* ==========================================================================
 * STATUS DISPLAY
 * ========================================================================== */

function StatusDisplay({
  status,
}: {
  status: AlertStatus;
}) {
  return (
    <span
      className={
        `sentinel-alert-detail-status sentinel-alert-detail-status-${status}`
      }
      style={{
        display:
          "inline-flex",

        alignItems:
          "center",

        gap:
          "6px",

        minHeight:
          "24px",

        maxWidth:
          "100%",

        padding:
          "4px 9px",

        border:
          "1px solid rgba(69, 105, 128, 0.25)",

        borderRadius:
          "5px",

        background:
          "rgba(31, 60, 80, 0.22)",

        color:
          "#8199aa",

        fontSize:
          "9px",

        fontWeight:
          650,

        lineHeight:
          "1",

        textTransform:
          "uppercase",

        whiteSpace:
          "nowrap",

        overflow:
          "hidden",

        textOverflow:
          "ellipsis",
      }}
    >
      <span
        aria-hidden="true"
        style={{
          width:
            "5px",

          height:
            "5px",

          flex:
            "0 0 5px",

          borderRadius:
            "50%",

          background:
            "currentColor",
        }}
      />

      {formatStatus(status)}
    </span>
  );
}


/* ==========================================================================
 * EVIDENCE
 * ========================================================================== */

function EvidenceList({
  evidenceIds,
}: {
  evidenceIds:
    | string[]
    | undefined;
}) {
  const ids =
    Array.isArray(
      evidenceIds,
    )
      ? evidenceIds
      : [];


  if (ids.length === 0) {
    return (
      <div
        style={{
          padding:
            "14px 15px",

          border:
            "1px solid rgba(22, 50, 73, 0.75)",

          borderRadius:
            "8px",

          background:
            "#081725",

          color:
            "#526b80",

          fontSize:
            "10px",

          lineHeight:
            "15px",
        }}
      >
        No evidence linked to this alert.
      </div>
    );
  }


  return (
    <div
      style={{
        display:
          "flex",

        flexDirection:
          "column",

        gap:
          "7px",

        width:
          "100%",

        minWidth:
          0,

        padding:
          "14px 15px",

        border:
          "1px solid rgba(22, 50, 73, 0.75)",

        borderRadius:
          "8px",

        background:
          "#081725",
      }}
    >
      {ids.map(
        (
          evidenceId,
          index,
        ) => (
          <div
            key={
              `${evidenceId}-${index}`
            }
            style={{
              minWidth:
                0,
            }}
          >
            <code
              style={{
                display:
                  "block",

                width:
                  "100%",

                minWidth:
                  0,

                padding:
                  "8px 10px",

                border:
                  "1px solid rgba(22, 50, 73, 0.65)",

                borderRadius:
                  "6px",

                background:
                  "#071522",

                color:
                  "#8199aa",

                fontFamily:
                  MONO_FONT,

                fontSize:
                  "9px",

                lineHeight:
                  "14px",

                overflowWrap:
                  "anywhere",
              }}
            >
              {displayValue(
                evidenceId,
              )}
            </code>
          </div>
        ),
      )}
    </div>
  );
}


/* ==========================================================================
 * ALERT CONTENT
 * ========================================================================== */

function AlertContent({
  alert,
}: {
  alert: Alert;
}) {
  return (
    <div
      className="sentinel-alert-details-content"
      style={{
        display:
          "flex",

        flexDirection:
          "column",

        width:
          "100%",

        minWidth:
          0,

        gap:
          "24px",

        padding:
          "20px",

        background:
          "#071522",
      }}
    >
      {/* ==================================================================
       * OVERVIEW
       * ================================================================== */}

      <DetailSection title="Overview">
        <div
          className="sentinel-alert-details-grid-overview"
          style={{
            display:
              "grid",

            gridTemplateColumns:
              "minmax(0, 2fr) minmax(180px, 1fr)",

            gap:
              "10px",
          }}
        >
          <DetailField label="Title">
            <span
              style={{
                color:
                  "#dbe7f1",

                fontSize:
                  "12px",

                fontWeight:
                  650,

                lineHeight:
                  "18px",
              }}
            >
              {displayValue(
                alert.title,
              )}
            </span>
          </DetailField>

          <DetailField label="Severity">
            <SeverityBadge
              severity={
                alert.severity
              }
            />
          </DetailField>

          <div
            style={{
              gridColumn:
                "1 / -1",
            }}
          >
            <DetailField label="Description">
              <span
                style={{
                  color:
                    "#a6b9c9",

                  lineHeight:
                    "19px",

                  whiteSpace:
                    "pre-wrap",

                  overflowWrap:
                    "anywhere",
                }}
              >
                {displayValue(
                  alert.description,
                )}
              </span>
            </DetailField>
          </div>
        </div>
      </DetailSection>


      {/* ==================================================================
       * RISK & STATUS
       * ================================================================== */}

      <DetailSection title="Risk & Status">
        <div
          className="sentinel-alert-details-grid-four"
          style={{
            display:
              "grid",

            gridTemplateColumns:
              "repeat(4, minmax(0, 1fr))",

            gap:
              "10px",
          }}
        >
          <DetailField label="Risk Score">
            <span
              style={{
                fontFamily:
                  MONO_FONT,

                fontWeight:
                  600,
              }}
            >
              {displayValue(
                alert.risk_score,
              )}
            </span>
          </DetailField>

          <DetailField label="Priority">
            {displayValue(
              alert.priority,
            )}
          </DetailField>

          <DetailField label="Status">
            <StatusDisplay
              status={
                alert.status
              }
            />
          </DetailField>

          <DetailField label="Occurrences">
            <span
              style={{
                fontFamily:
                  MONO_FONT,

                fontWeight:
                  600,
              }}
            >
              {displayValue(
                alert.occurrence_count,
              )}
            </span>
          </DetailField>
        </div>
      </DetailSection>


      {/* ==================================================================
       * DETECTION
       * ================================================================== */}

      <DetailSection title="Detection">
        <div
          className="sentinel-alert-details-grid-three"
          style={{
            display:
              "grid",

            gridTemplateColumns:
              "repeat(3, minmax(0, 1fr))",

            gap:
              "10px",
          }}
        >
          <DetailField label="Rule ID" mono>
            {displayValue(
              alert.rule_id,
            )}
          </DetailField>

          <DetailField label="Source Type">
            {formatSourceType(
              alert.source_type,
            )}
          </DetailField>

          <DetailField label="Source ID" mono>
            {displayValue(
              alert.source_id,
            )}
          </DetailField>
        </div>
      </DetailSection>


      {/* ==================================================================
       * OWNERSHIP
       * ================================================================== */}

      <DetailSection title="Ownership & Context">
        <div
          className="sentinel-alert-details-grid-four"
          style={{
            display:
              "grid",

            gridTemplateColumns:
              "repeat(4, minmax(0, 1fr))",

            gap:
              "10px",
          }}
        >
          <DetailField label="Asset" mono>
            {displayValue(
              alert.asset_id,
            )}
          </DetailField>

          <DetailField label="User" mono>
            {displayValue(
              alert.user_id,
            )}
          </DetailField>

          <DetailField label="Assignee">
            {alert.assigned_to?.trim()
              ? alert.assigned_to
              : "Unassigned"}
          </DetailField>

          <DetailField label="Ownership Group">
            {displayValue(
              alert.ownership_group,
            )}
          </DetailField>
        </div>
      </DetailSection>


      {/* ==================================================================
       * TIMELINE
       * ================================================================== */}

      <DetailSection title="Timeline">
        <div
          className="sentinel-alert-details-grid-three"
          style={{
            display:
              "grid",

            gridTemplateColumns:
              "repeat(3, minmax(0, 1fr))",

            gap:
              "10px",
          }}
        >
          <DetailField label="First Seen">
            <span
              title={
                alert.first_seen_at
              }
            >
              {formatDateTime(
                alert.first_seen_at,
              )}
            </span>
          </DetailField>

          <DetailField label="Last Seen">
            <span
              title={
                alert.last_seen_at
              }
            >
              {formatDateTime(
                alert.last_seen_at,
              )}
            </span>
          </DetailField>

          <DetailField label="Updated">
            <span
              title={
                alert.updated_at
              }
            >
              {formatDateTime(
                alert.updated_at,
              )}
            </span>
          </DetailField>
        </div>
      </DetailSection>


      {/* ==================================================================
       * EVIDENCE
       * ================================================================== */}

      <DetailSection title="Evidence">
        <EvidenceList
          evidenceIds={
            alert.evidence_ids
          }
        />
      </DetailSection>


      {/* ==================================================================
       * IDENTIFIERS
       * ================================================================== */}

      <DetailSection title="Identifiers">
        <div
          className="sentinel-alert-details-grid-two"
          style={{
            display:
              "grid",

            gridTemplateColumns:
              "repeat(2, minmax(0, 1fr))",

            gap:
              "10px",
          }}
        >
          <DetailField
            label="Alert ID"
            mono
          >
            {displayValue(
              alert.alert_id,
            )}
          </DetailField>

          <DetailField
            label="Source ID"
            mono
          >
            {displayValue(
              alert.source_id,
            )}
          </DetailField>
        </div>
      </DetailSection>
    </div>
  );
}


/* ==========================================================================
 * MAIN PAGE
 * ========================================================================== */

export default function AlertDetails() {
  const {
    alertId,
  } = useParams<{
    alertId: string;
  }>();


  const [alert, setAlert] =
    useState<Alert | null>(
      null,
    );

  const [loading, setLoading] =
    useState<boolean>(
      true,
    );

  const [error, setError] =
    useState<string | null>(
      null,
    );


  /* ========================================================================
   * LOAD ALERT
   * ======================================================================== */

  useEffect(() => {
    let cancelled =
      false;


    const normalizedAlertId =
      alertId?.trim();


    if (!normalizedAlertId) {
      setAlert(null);

      setError(
        "Alert ID is missing.",
      );

      setLoading(false);

      return () => {
        cancelled = true;
      };
    }


    async function loadAlert(
      id: string,
    ): Promise<void> {
      try {
        setLoading(true);

        setError(null);

        setAlert(null);


        const result =
          await alertsApi.get(
            id,
          );


        if (cancelled) {
          return;
        }


        setAlert(result);
      } catch (err) {
        if (cancelled) {
          return;
        }


        setAlert(null);


        setError(
          err instanceof Error
            ? err.message
            : "Failed to load alert.",
        );
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }


    void loadAlert(
      normalizedAlertId,
    );


    return () => {
      cancelled = true;
    };
  }, [alertId]);


  /* ========================================================================
   * PANEL SUBTITLE
   * ======================================================================== */

  const panelSubtitle =
    loading
      ? "Loading alert data..."
      : alert
        ? `ID: ${alert.alert_id}`
        : alertId
          ? `ID: ${alertId}`
          : "Alert identifier unavailable";


  /* ========================================================================
   * RENDER
   * ======================================================================== */

  return (
    <div
      className="sentinel-alert-details-page"
      style={{
        width:
          "100%",

        minWidth:
          0,

        margin:
          0,

        padding:
          0,

        color:
          "#e7f0f8",
      }}
    >
      {/* ==================================================================
       * ISOLATED STYLES
       * ================================================================== */}

      <style>
        {`
          .sentinel-alert-details-page,
          .sentinel-alert-details-page *,
          .sentinel-alert-details-page *::before,
          .sentinel-alert-details-page *::after {
            box-sizing: border-box;
          }

          @keyframes sentinel-alert-details-spin {
            to {
              transform: rotate(360deg);
            }
          }

          .sentinel-alert-details-back {
            display: inline-flex;

            align-items: center;

            min-height: 32px;

            margin-bottom: 18px;

            padding: 0 10px;

            border:
              1px solid #163249;

            border-radius: 6px;

            background: #081725;

            color: #71889b;

            font-family: inherit;

            font-size: 10px;

            font-weight: 650;

            line-height: 1;

            text-decoration: none;

            transition:
              border-color 150ms ease,
              background-color 150ms ease,
              color 150ms ease;
          }

          .sentinel-alert-details-back:hover {
            border-color: #1d4662;

            background: #0c2031;

            color: #dbe7f1;
          }

          .sentinel-alert-details-back:focus-visible {
            outline:
              2px solid #36bdf5;

            outline-offset:
              2px;
          }

          .sentinel-alert-details-header {
            display: flex;

            align-items: flex-end;

            justify-content: space-between;

            width: 100%;

            min-width: 0;

            gap: 24px;

            margin: 0 0 24px;
          }

          .sentinel-alert-details-heading {
            min-width: 0;

            flex: 1 1 auto;
          }

          .sentinel-alert-details-eyebrow {
            display: block;

            margin: 0 0 7px;

            color: #55748a;

            font-size: 10px;

            font-weight: 700;

            letter-spacing: 0.16em;

            line-height: 13px;

            text-transform: uppercase;
          }

          .sentinel-alert-details-title {
            margin: 0;

            color: #e7f0f8;

            font-size: 28px;

            font-weight: 680;

            letter-spacing: -0.025em;

            line-height: 1.2;
          }

          .sentinel-alert-details-description {
            max-width: 760px;

            margin: 7px 0 0;

            color: #71889b;

            font-size: 13px;

            line-height: 1.55;
          }

          .sentinel-alert-details-panel {
            width: 100%;

            min-width: 0;
          }

          .sentinel-alert-detail-status-new {
            color: #6fb5d6 !important;
          }

          .sentinel-alert-detail-status-acknowledged {
            color: #8aa8bc !important;
          }

          .sentinel-alert-detail-status-investigating {
            color: #d0aa67 !important;
          }

          .sentinel-alert-detail-status-escalated {
            color: #e07d86 !important;
          }

          .sentinel-alert-detail-status-resolved {
            color: #71b88c !important;
          }

          .sentinel-alert-detail-status-closed {
            color: #687f90 !important;
          }

          .sentinel-alert-detail-status-suppressed {
            color: #807d9f !important;
          }

          @media (max-width: 1000px) {
            .sentinel-alert-details-grid-four {
              grid-template-columns:
                repeat(2, minmax(0, 1fr)) !important;
            }

            .sentinel-alert-details-grid-three {
              grid-template-columns:
                repeat(2, minmax(0, 1fr)) !important;
            }
          }

          @media (max-width: 760px) {
            .sentinel-alert-details-header {
              align-items: flex-start;

              flex-direction: column;

              gap: 16px;
            }

            .sentinel-alert-details-title {
              font-size: 24px;
            }

            .sentinel-alert-details-grid-overview,
            .sentinel-alert-details-grid-four,
            .sentinel-alert-details-grid-three,
            .sentinel-alert-details-grid-two {
              grid-template-columns:
                1fr !important;
            }

            .sentinel-alert-details-grid-overview
            > div {
              grid-column:
                auto !important;
            }
          }

          @media (max-width: 520px) {
            .sentinel-alert-details-content {
              padding:
                14px !important;
            }

            .sentinel-alert-details-description {
              font-size:
                12px;
            }
          }

          @media (prefers-reduced-motion: reduce) {
            .sentinel-alert-details-page *,
            .sentinel-alert-details-page *::before,
            .sentinel-alert-details-page *::after {
              animation:
                none !important;

              transition:
                none !important;
            }
          }
        `}
      </style>


      {/* ==================================================================
       * BACK TO ALERTS
       * ================================================================== */}

      <Link
        to="/alerts"
        className="sentinel-alert-details-back"
        aria-label="Back to alerts"
      >
        ← Back to alerts
      </Link>


      {/* ==================================================================
       * PAGE HEADER
       * ================================================================== */}

      <div
        className="sentinel-alert-details-header"
      >
        <div
          className="sentinel-alert-details-heading"
        >
          <span
            className="sentinel-alert-details-eyebrow"
          >
            SentinelSIEM / Alerts
          </span>

          <h2
            className="sentinel-alert-details-title"
          >
            Alert Details
          </h2>

          <p
            className="sentinel-alert-details-description"
          >
            Persisted alert information,
            detection context, ownership,
            timeline, and evidence.
          </p>
        </div>
      </div>


      {/* ==================================================================
       * CONTENT
       * ================================================================== */}

      <div
        className="sentinel-alert-details-panel"
      >
        <Panel
          title="Alert"
          subtitle={
            panelSubtitle
          }
        >
          {/* ==============================================================
           * LOADING
           * ============================================================== */}

          {loading && (
            <LoadingState />
          )}


          {/* ==============================================================
           * ERROR
           * ============================================================== */}

          {!loading &&
            error && (
              <ErrorState
                message={
                  error
                }
              />
            )}


          {/* ==============================================================
           * MISSING ID
           * ============================================================== */}

          {!loading &&
            !error &&
            !alertId && (
              <MissingAlertState />
            )}


          {/* ==============================================================
           * NOT FOUND
           * ============================================================== */}

          {!loading &&
            !error &&
            alertId &&
            !alert && (
              <NotFoundState />
            )}


          {/* ==============================================================
           * ALERT
           * ============================================================== */}

          {!loading &&
            !error &&
            alert && (
              <AlertContent
                alert={
                  alert
                }
              />
            )}
        </Panel>
      </div>
    </div>
  );
}