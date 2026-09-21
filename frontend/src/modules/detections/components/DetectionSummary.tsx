/* ==========================================================================
 * SentinelSIEM
 * Detection Summary
 *
 * Responsibility
 * ----------------------------------------------------------------------------
 * Presentation-only rendering of the primary Detection KPIs.
 *
 * Canonical backend statistics:
 *
 *   total_rules
 *   enabled_rules
 *   disabled_rules
 *   total_plugins
 *   enabled_plugins
 *   total_evaluations
 *   detection_matches
 *   suppressed_matches
 *   evaluation_failures
 *   plugin_evaluations
 *   plugin_failures
 *
 * Locked KPI layout
 * ----------------------------------------------------------------------------
 *
 *   Engine Status
 *   Active Rules
 *   Detection Matches
 *   Generated Alerts
 *   Detector Plugins
 *   Total Evaluations
 *
 * IMPORTANT
 * ----------------------------------------------------------------------------
 * - Backend is the source of truth.
 * - No authoritative Detection metric is calculated here.
 * - Engine Status comes from DetectionCapability.status.
 * - Detection counters come from DetectionSummary backend data.
 * - Generated Alerts is intentionally unavailable because the Detection
 *   backend does not expose an authoritative generated_alerts field.
 * - Detection Matches MUST NOT be used as Generated Alerts.
 * - No API communication occurs in this component.
 * ========================================================================== */

import type {
  ReactNode,
} from "react";

import type {
  DetectionCapability,
  DetectionSummary as DetectionSummaryData,
} from "../types";


/* ==========================================================================
 * Props
 * ========================================================================== */

interface DetectionSummaryProps {
  /**
   * Backend-provided Detection summary/statistics.
   */
  summary:
    DetectionSummaryData | null;

  /**
   * Backend capability status.
   *
   * Engine status belongs to DetectionCapability, not
   * DetectionKpiStatistics.
   */
  engineStatus?:
    DetectionCapability["status"];

  /**
   * Section loading state.
   */
  loading?:
    boolean;

  /**
   * Section-level error.
   */
  error?:
    string | null;
}


/* ==========================================================================
 * Internal Types
 * ========================================================================== */

type EngineStatus =
  DetectionCapability["status"];

type MetricValue =
  | number
  | undefined;


/* ==========================================================================
 * Constants
 * ========================================================================== */

const KPI_LABELS = [
  "Engine Status",
  "Active Rules",
  "Detection Matches",
  "Generated Alerts",
  "Detector Plugins",
  "Total Evaluations",
] as const;


/* ==========================================================================
 * Formatting
 * ========================================================================== */

/**
 * Format a backend-provided numeric value.
 *
 * This function does not calculate a Detection metric.
 *
 * Missing or invalid values are displayed as "—".
 */
function formatMetric(
  value: MetricValue,
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
 * Read a backend counter safely.
 *
 * Missing values remain undefined.
 *
 * No security metric is derived here.
 */
function readCounter(
  value: unknown,
): number | undefined {
  if (
    typeof value !== "number" ||
    !Number.isFinite(value)
  ) {
    return undefined;
  }

  return value;
}


/* ==========================================================================
 * Engine Status Helpers
 * ========================================================================== */

/**
 * Convert backend capability status to a human-readable label.
 */
function getEngineStatusLabel(
  status:
    | EngineStatus
    | undefined,
): string {
  switch (status) {
    case "available":
      return "Operational";

    case "planned":
      return "Planned";

    case "unavailable":
      return "Unavailable";

    case "unknown":
    default:
      return "Unknown";
  }
}


/**
 * Build engine status badge class.
 */
function getEngineStatusClass(
  status:
    | EngineStatus
    | undefined,
): string {
  const modifier =
    status === "available"
      ? "available"
      : status === "planned"
        ? "planned"
        : status === "unavailable"
          ? "unavailable"
          : "unknown";

  return [
    "detection-kpi-status",
    `detection-kpi-status-${modifier}`,
  ].join(" ");
}


/**
 * Build engine status dot class.
 */
function getEngineStatusDotClass(
  status:
    | EngineStatus
    | undefined,
): string {
  const modifier =
    status === "available"
      ? "available"
      : status === "planned"
        ? "planned"
        : status === "unavailable"
          ? "unavailable"
          : "unknown";

  return [
    "detection-kpi-status-dot",
    `detection-kpi-status-dot-${modifier}`,
  ].join(" ");
}


/* ==========================================================================
 * Generic KPI Card
 * ========================================================================== */

interface KpiCardProps {
  label:
    string;

  value:
    ReactNode;

  meta?:
    ReactNode;

  className?:
    string;

  indicator?:
    boolean;

  ariaLabel?:
    string;
}


/**
 * Shared presentation-only KPI card.
 */
function KpiCard({
  label,
  value,
  meta,
  className = "",
  indicator = true,
  ariaLabel,
}: KpiCardProps) {
  return (
    <article
      className={[
        "detection-kpi-card",
        className,
      ]
        .filter(Boolean)
        .join(" ")}
      aria-label={
        ariaLabel
      }
    >

      <div className="detection-kpi-card-header">

        <span className="detection-kpi-label">
          {label}
        </span>

        {indicator ? (
          <span
            className="detection-kpi-indicator"
            aria-hidden="true"
          />
        ) : null}

      </div>


      <div className="detection-kpi-value-wrap">

        <strong className="detection-kpi-value">
          {value}
        </strong>

      </div>


      {meta ? (
        <div className="detection-kpi-meta">
          {meta}
        </div>
      ) : null}

    </article>
  );
}


/* ==========================================================================
 * Engine Status KPI
 * ========================================================================== */

function EngineStatusCard({
  status,
}: {
  status:
    | EngineStatus
    | undefined;
}) {
  const label =
    getEngineStatusLabel(
      status,
    );

  return (
    <article
      className="detection-kpi-card detection-kpi-card-engine"
      aria-label={
        `Engine Status: ${label}`
      }
    >

      <div className="detection-kpi-card-header">

        <span className="detection-kpi-label">
          Engine Status
        </span>

        <span
          className={getEngineStatusClass(
            status,
          )}
        >

          <span
            className={getEngineStatusDotClass(
              status,
            )}
            aria-hidden="true"
          />

          <span className="detection-kpi-status-label">
            {label}
          </span>

        </span>

      </div>


      <div className="detection-kpi-value-wrap">

        <strong className="detection-kpi-value detection-kpi-value-text">
          {label}
        </strong>

      </div>


      <div className="detection-kpi-meta">
        Detection engine
      </div>

    </article>
  );
}


/* ==========================================================================
 * Loading State
 * ========================================================================== */

function DetectionSummaryLoading() {
  return (
    <div
      className="detection-kpi-grid"
      aria-hidden="true"
    >

      {KPI_LABELS.map(
        (label) => (
          <article
            key={label}
            className="detection-kpi-card detection-kpi-card-loading"
          >

            <div className="detection-kpi-card-header">

              <span className="detection-kpi-label">
                {label}
              </span>

              <span
                className="detection-kpi-indicator"
                aria-hidden="true"
              />

            </div>


            <div className="detection-kpi-value-wrap">

              <span className="detection-kpi-value detection-kpi-value-placeholder">
                —
              </span>

            </div>


            <div className="detection-kpi-meta">
              Loading
            </div>

          </article>
        ),
      )}

    </div>
  );
}


/* ==========================================================================
 * Error State
 * ========================================================================== */

function DetectionSummaryError({
  error,
}: {
  error:
    string;
}) {
  return (
    <div
      className="detection-kpi-error"
      role="alert"
    >

      <div className="detection-kpi-error-content">

        <strong className="detection-kpi-error-title">
          Detection statistics unavailable
        </strong>

        <p className="detection-kpi-error-description">
          {error}
        </p>

      </div>


      <span className="detection-kpi-error-badge">
        Error
      </span>

    </div>
  );
}


/* ==========================================================================
 * Empty State
 * ========================================================================== */

function DetectionSummaryEmpty({
  engineStatus,
}: {
  engineStatus:
    | EngineStatus
    | undefined;
}) {
  return (
    <div className="detection-kpi-grid">

      {/* ================================================================
       * ENGINE STATUS
       * ================================================================ */}

      <EngineStatusCard
        status={
          engineStatus
        }
      />


      {/* ================================================================
       * ACTIVE RULES
       * ================================================================ */}

      <KpiCard
        label="Active Rules"
        value="—"
        meta="Data unavailable"
        ariaLabel="Active Rules: unavailable"
      />


      {/* ================================================================
       * DETECTION MATCHES
       * ================================================================ */}

      <KpiCard
        label="Detection Matches"
        value="—"
        meta="Data unavailable"
        ariaLabel="Detection Matches: unavailable"
      />


      {/* ================================================================
       * GENERATED ALERTS
       * ================================================================ */}

      <KpiCard
        label="Generated Alerts"
        value="—"
        meta="Not reported by Detection backend"
        ariaLabel="Generated Alerts: not reported by Detection backend"
      />


      {/* ================================================================
       * DETECTOR PLUGINS
       * ================================================================ */}

      <KpiCard
        label="Detector Plugins"
        value="—"
        meta="Data unavailable"
        ariaLabel="Detector Plugins: unavailable"
      />


      {/* ================================================================
       * TOTAL EVALUATIONS
       * ================================================================ */}

      <KpiCard
        label="Total Evaluations"
        value="—"
        meta="Data unavailable"
        ariaLabel="Total Evaluations: unavailable"
      />

    </div>
  );
}


/* ==========================================================================
 * Main Component
 * ========================================================================== */

export function DetectionSummary({
  summary,
  engineStatus = "unknown",
  loading = false,
  error = null,
}: DetectionSummaryProps) {

  /* ------------------------------------------------------------------------
   * Loading
   * ---------------------------------------------------------------------- */

  if (loading) {
    return (
      <DetectionSummaryShell
        label="Detection statistics"
        busy
      >
        <DetectionSummaryLoading />
      </DetectionSummaryShell>
    );
  }


  /* ------------------------------------------------------------------------
   * Error
   * ---------------------------------------------------------------------- */

  if (error) {
    return (
      <DetectionSummaryShell
        label="Detection statistics"
        error
      >
        <DetectionSummaryError
          error={error}
        />
      </DetectionSummaryShell>
    );
  }


  /* ------------------------------------------------------------------------
   * Empty
   * ---------------------------------------------------------------------- */

  if (!summary) {
    return (
      <DetectionSummaryShell
        label="Detection statistics"
      >
        <DetectionSummaryEmpty
          engineStatus={
            engineStatus
          }
        />
      </DetectionSummaryShell>
    );
  }


  /* ==========================================================================
   * Canonical Backend Counters
   * ========================================================================== */

  /**
   * Active Rules
   *
   * Backend:
   *   enabled_rules
   */
  const activeRules =
    readCounter(
      summary.enabled_rules,
    );


  /**
   * Detection Matches
   *
   * Backend:
   *   detection_matches
   */
  const detectionMatches =
    readCounter(
      summary.detection_matches,
    );


  /**
   * Enabled Detector Plugins
   *
   * Backend:
   *   enabled_plugins
   */
  const enabledPlugins =
    readCounter(
      summary.enabled_plugins,
    );


  /**
   * Total registered plugins.
   *
   * Supporting metadata only.
   */
  const totalPlugins =
    readCounter(
      summary.total_plugins,
    );


  /**
   * Total registered rules.
   *
   * Supporting metadata only.
   */
  const totalRules =
    readCounter(
      summary.total_rules,
    );


  /**
   * Total evaluations.
   *
   * Backend:
   *   total_evaluations
   */
  const totalEvaluations =
    readCounter(
      summary.total_evaluations,
    );


  /* ==========================================================================
   * Generated Alerts
   * --------------------------------------------------------------------------
   * The Detection backend does not currently expose generated_alerts.
   *
   * Therefore this remains unavailable.
   *
   * DO NOT replace this with detection_matches.
   * ========================================================================== */

  const generatedAlerts:
    undefined =
    undefined;


  /* ==========================================================================
   * Render
   * ========================================================================== */

  return (
    <DetectionSummaryShell
      label="Detection statistics"
    >

      <div className="detection-kpi-grid">

        {/* ================================================================
         * 01 — ENGINE STATUS
         * ============================================================== */}

        <EngineStatusCard
          status={
            engineStatus
          }
        />


        {/* ================================================================
         * 02 — ACTIVE RULES
         * ============================================================== */}

        <KpiCard
          label="Active Rules"
          value={formatMetric(
            activeRules,
          )}
          meta={
            typeof totalRules ===
            "number"
              ? (
                <>
                  <span className="detection-kpi-meta-primary">
                    {formatMetric(
                      activeRules,
                    )}
                    {" of "}
                    {formatMetric(
                      totalRules,
                    )}
                  </span>

                  <span className="detection-kpi-meta-secondary">
                    active / total rules
                  </span>
                </>
              )
              : "Enabled detection rules"
          }
          ariaLabel={
            `Active Rules: ${formatMetric(
              activeRules,
            )}`
          }
        />


        {/* ================================================================
         * 03 — DETECTION MATCHES
         * ============================================================== */}

        <KpiCard
          label="Detection Matches"
          value={formatMetric(
            detectionMatches,
          )}
          meta="Persisted detection results"
          ariaLabel={
            `Detection Matches: ${formatMetric(
              detectionMatches,
            )}`
          }
        />


        {/* ================================================================
         * 04 — GENERATED ALERTS
         * ============================================================== */}

        <KpiCard
          label="Generated Alerts"
          value={formatMetric(
            generatedAlerts,
          )}
          meta="Not reported by Detection backend"
          ariaLabel="Generated Alerts: not reported by Detection backend"
        />


        {/* ================================================================
         * 05 — DETECTOR PLUGINS
         * ============================================================== */}

        <KpiCard
          label="Detector Plugins"
          value={formatMetric(
            enabledPlugins,
          )}
          meta={
            typeof totalPlugins ===
            "number"
              ? (
                <>
                  <span className="detection-kpi-meta-primary">
                    {formatMetric(
                      enabledPlugins,
                    )}
                    {" of "}
                    {formatMetric(
                      totalPlugins,
                    )}
                  </span>

                  <span className="detection-kpi-meta-secondary">
                    enabled / registered
                  </span>
                </>
              )
              : "Enabled detector plugins"
          }
          ariaLabel={
            `Detector Plugins: ${formatMetric(
              enabledPlugins,
            )}`
          }
        />


        {/* ================================================================
         * 06 — TOTAL EVALUATIONS
         * ============================================================== */}

        <KpiCard
          label="Total Evaluations"
          value={formatMetric(
            totalEvaluations,
          )}
          meta="Detection engine evaluations"
          ariaLabel={
            `Total Evaluations: ${formatMetric(
              totalEvaluations,
            )}`
          }
        />

      </div>

    </DetectionSummaryShell>
  );
}


/* ==========================================================================
 * Section Shell
 * ========================================================================== */

function DetectionSummaryShell({
  children,
  label,
  busy = false,
  error = false,
}: {
  children:
    ReactNode;

  label:
    string;

  busy?:
    boolean;

  error?:
    boolean;
}) {
  const className = [
    "detection-kpi-section",
    error
      ? "detection-kpi-section-error"
      : "",
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <section
      className={className}
      aria-label={label}
      aria-busy={
        busy
          ? "true"
          : undefined
      }
    >
      {children}
    </section>
  );
}


/* ==========================================================================
 * Default Export
 * ========================================================================== */

export default DetectionSummary;