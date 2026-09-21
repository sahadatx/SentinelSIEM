/* ==========================================================================
 * SentinelSIEM
 * Detection Engine Health
 *
 * Responsibility
 * ----------------------------------------------------------------------------
 * Presentation-only health view for the Detection engine.
 *
 * Locked health matrix
 * ----------------------------------------------------------------------------
 *
 *   Engine Status       | Last Evaluation
 *   Rule Registry       | Rules Loaded
 *   Plugin Registry     | Plugins Enabled
 *   Alert Pipeline      | Evaluation Errors
 *
 * Data/API communication remains outside this component.
 *
 * Canonical backend Detection statistics:
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
 * The current backend does NOT expose:
 *
 *   last_evaluation_at
 *   alert_pipeline_status
 *
 * Therefore those values are never fabricated by this component.
 *
 * ========================================================================== */

import type {
  DetectionCapability,
  DetectionStatistics,
} from "../types";


/* ==========================================================================
 * Props
 * ========================================================================== */

interface DetectionStatusCardProps {
  /**
   * Detection capability response.
   *
   * Source:
   *   GET /api/v1/detections/capability
   */
  capability: DetectionCapability | null;

  /**
   * Canonical Detection runtime statistics.
   *
   * Source:
   *   GET /api/v1/detections/statistics
   */
  statistics?: DetectionStatistics | null;

  /**
   * Backward-compatible summary.
   *
   * Kept optional so existing parent integrations do not break.
   *
   * This component does not depend on summary when statistics
   * are available.
   */
  summary?: DetectionStatistics | null;

  /**
   * Loading state.
   */
  loading?: boolean;

  /**
   * Section-level error.
   */
  error?: string | null;
}


/* ==========================================================================
 * Internal Types
 * ========================================================================== */

type HealthState =
  | "available"
  | "warning"
  | "error"
  | "unknown";

type CapabilityStatus =
  DetectionCapability["status"];


/* ==========================================================================
 * Status Helpers
 * ========================================================================== */

/**
 * Convert backend capability status into a user-facing label.
 */
function getStatusLabel(
  status: CapabilityStatus | undefined,
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
 * Convert backend capability status into a visual state.
 */
function getStatusState(
  status: CapabilityStatus | undefined,
): HealthState {
  switch (status) {
    case "available":
      return "available";

    case "planned":
      return "warning";

    case "unavailable":
      return "error";

    case "unknown":
    default:
      return "unknown";
  }
}


/* ==========================================================================
 * Number Helpers
 * ========================================================================== */

/**
 * Format a backend numeric value safely.
 *
 * This function only formats a supplied value.
 * It does not derive or calculate a Detection metric.
 */
function formatNumber(
  value: number | undefined,
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
 * Normalize a backend numeric value for display.
 */
function normalizeNumber(
  value: number | undefined,
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
 * Timestamp Helpers
 * ========================================================================== */

/**
 * Format a backend timestamp safely.
 *
 * Current canonical DetectionStatistics does not expose
 * last_evaluation_at, so undefined remains "—".
 */
function formatTimestamp(
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


/* ==========================================================================
 * Capability Helpers
 * ========================================================================== */

/**
 * Convert an API availability flag into a status label.
 */
function getRegistryStatus(
  available:
    | boolean
    | undefined,
): string {
  if (available === true) {
    return "Operational";
  }

  if (available === false) {
    return "Unavailable";
  }

  return "Unknown";
}


/**
 * Convert an API availability flag into a health state.
 */
function getRegistryState(
  available:
    | boolean
    | undefined,
): HealthState {
  if (available === true) {
    return "available";
  }

  if (available === false) {
    return "error";
  }

  return "unknown";
}


/* ==========================================================================
 * Health Item
 * ========================================================================== */

interface HealthItemProps {
  label: string;

  value: string;

  meta?: string;

  state?: HealthState;
}


/**
 * Reusable health matrix item.
 */
function HealthItem({
  label,
  value,
  meta,
  state = "unknown",
}: HealthItemProps) {
  return (
    <div
      className={[
        "detection-health-item",
        `detection-health-item-${state}`,
      ].join(" ")}
      data-state={state}
    >

      <div className="detection-health-item-label">
        {label}
      </div>


      <div className="detection-health-item-content">

        <div
          className={[
            "detection-health-value",
            `detection-health-value-${state}`,
          ].join(" ")}
        >

          <span
            className="detection-health-dot"
            aria-hidden="true"
          />

          <strong>
            {value}
          </strong>

        </div>


        {meta ? (
          <div className="detection-health-item-meta">
            {meta}
          </div>
        ) : null}

      </div>

    </div>
  );
}


/* ==========================================================================
 * Loading Health Item
 * ========================================================================== */

function LoadingHealthItem({
  label,
}: {
  label: string;
}) {
  return (
    <div
      className="detection-health-item detection-health-item-loading"
      aria-hidden="true"
    >

      <div className="detection-health-item-label">
        {label}
      </div>


      <div className="detection-health-item-content">

        <div className="detection-health-value detection-health-value-loading">

          <span
            className="detection-health-dot"
            aria-hidden="true"
          />

          <strong>
            —
          </strong>

        </div>


        <div className="detection-health-item-meta">
          Loading
        </div>

      </div>

    </div>
  );
}


/* ==========================================================================
 * Loading Grid
 * ========================================================================== */

function HealthGridLoading() {
  const items = [
    "Engine Status",
    "Last Evaluation",
    "Rule Registry",
    "Rules Loaded",
    "Plugin Registry",
    "Plugins Enabled",
    "Alert Pipeline",
    "Evaluation Errors",
  ];

  return (
    <div
      className="detection-health-grid"
      aria-hidden="true"
    >

      {items.map(
        (label) => (
          <LoadingHealthItem
            key={label}
            label={label}
          />
        ),
      )}

    </div>
  );
}


/* ==========================================================================
 * Health Header
 * ========================================================================== */

function HealthHeader({
  badgeLabel,
  badgeState,
  description,
}: {
  badgeLabel: string;

  badgeState: HealthState;

  description: string;
}) {
  return (
    <div className="detection-health-header">

      <div className="detection-health-header-content">

        <h2 className="detection-health-title">
          Detection Engine Health
        </h2>

        <p className="detection-health-description">
          {description}
        </p>

      </div>


      <span
        className={[
          "detection-health-badge",
          `detection-health-badge-${badgeState}`,
        ].join(" ")}
      >

        <span
          className="detection-health-status-dot"
          aria-hidden="true"
        />

        <span>
          {badgeLabel}
        </span>

      </span>

    </div>
  );
}


/* ==========================================================================
 * Loading State
 * ========================================================================== */

function DetectionHealthLoading() {
  return (
    <section
      className="detection-health-card"
      aria-label="Detection Engine Health"
      aria-busy="true"
    >

      <HealthHeader
        badgeLabel="Checking"
        badgeState="unknown"
        description="Checking Detection engine health..."
      />

      <HealthGridLoading />

    </section>
  );
}


/* ==========================================================================
 * Error State
 * ========================================================================== */

function DetectionHealthError({
  error,
}: {
  error: string;
}) {
  return (
    <section
      className="detection-health-card detection-health-card-error"
      aria-label="Detection Engine Health"
      role="alert"
    >

      <HealthHeader
        badgeLabel="Error"
        badgeState="error"
        description="Detection engine health information could not be loaded."
      />


      <div className="detection-health-error-message">

        <span className="detection-health-error-label">
          Health check failed
        </span>

        <span className="detection-health-error-text">
          {error}
        </span>

      </div>

    </section>
  );
}


/* ==========================================================================
 * Unavailable State
 * ========================================================================== */

function DetectionHealthUnavailable() {
  const items: Array<{
    label: string;
    value: string;
    meta: string;
    state: HealthState;
  }> = [
    {
      label: "Engine Status",
      value: "Unknown",
      meta: "Capability not reported",
      state: "unknown",
    },
    {
      label: "Last Evaluation",
      value: "—",
      meta: "Not reported",
      state: "unknown",
    },
    {
      label: "Rule Registry",
      value: "—",
      meta: "Not reported",
      state: "unknown",
    },
    {
      label: "Rules Loaded",
      value: "—",
      meta: "Not reported",
      state: "unknown",
    },
    {
      label: "Plugin Registry",
      value: "—",
      meta: "Not reported",
      state: "unknown",
    },
    {
      label: "Plugins Enabled",
      value: "—",
      meta: "Not reported",
      state: "unknown",
    },
    {
      label: "Alert Pipeline",
      value: "—",
      meta: "Not reported",
      state: "unknown",
    },
    {
      label: "Evaluation Errors",
      value: "—",
      meta: "Not reported",
      state: "unknown",
    },
  ];

  return (
    <section
      className="detection-health-card"
      aria-label="Detection Engine Health"
    >

      <HealthHeader
        badgeLabel="Unknown"
        badgeState="unknown"
        description="Detection engine health information is currently unavailable."
      />


      <div className="detection-health-grid">

        {items.map(
          (item) => (
            <HealthItem
              key={item.label}
              label={item.label}
              value={item.value}
              meta={item.meta}
              state={item.state}
            />
          ),
        )}

      </div>

    </section>
  );
}


/* ==========================================================================
 * Main Component
 * ========================================================================== */

export function DetectionStatusCard({
  capability,
  statistics = null,
  summary = null,
  loading = false,
  error = null,
}: DetectionStatusCardProps) {

  /* ------------------------------------------------------------------------
   * Loading
   * ---------------------------------------------------------------------- */

  if (loading) {
    return (
      <DetectionHealthLoading />
    );
  }


  /* ------------------------------------------------------------------------
   * Error
   * ---------------------------------------------------------------------- */

  if (error) {
    return (
      <DetectionHealthError
        error={error}
      />
    );
  }


  /* ------------------------------------------------------------------------
   * Capability unavailable
   * ---------------------------------------------------------------------- */

  if (!capability) {
    return (
      <DetectionHealthUnavailable />
    );
  }


  /* ==========================================================================
   * Capability Status
   * ========================================================================== */

  const statusLabel =
    getStatusLabel(
      capability.status,
    );

  const engineState =
    getStatusState(
      capability.status,
    );


  /* ==========================================================================
   * Statistics Source
   * --------------------------------------------------------------------------
   * Prefer canonical DetectionStatistics.
   *
   * Summary exists only as a compatibility fallback.
   * ========================================================================== */

  const statisticsSource =
    statistics ??
    summary;


  /* ==========================================================================
   * Backend Runtime Values
   * ========================================================================== */

  const rulesLoaded =
    normalizeNumber(
      statisticsSource?.total_rules,
    );


  const pluginsEnabled =
    normalizeNumber(
      statisticsSource?.enabled_plugins,
    );


  const evaluationErrors =
    normalizeNumber(
      statisticsSource?.evaluation_failures,
    );


  /* ==========================================================================
   * Last Evaluation
   * --------------------------------------------------------------------------
   * IMPORTANT:
   *
   * The current backend does not expose last_evaluation_at.
   *
   * Do not derive it from:
   *
   *   matched_at
   *   last_match
   *   current time
   *   request time
   *
   * Therefore this remains null.
   * ========================================================================== */

  const lastEvaluationAt:
    | string
    | null =
    null;


  /* ==========================================================================
   * Rule Registry
   * ========================================================================== */

  const ruleRegistryState =
    getRegistryState(
      capability.rules_api,
    );

  const ruleRegistryStatus =
    getRegistryStatus(
      capability.rules_api,
    );


  /* ==========================================================================
   * Plugin Registry
   * ========================================================================== */

  const pluginRegistryState =
    getRegistryState(
      capability.plugins_api,
    );

  const pluginRegistryStatus =
    getRegistryStatus(
      capability.plugins_api,
    );


  /* ==========================================================================
   * Alert Pipeline
   * --------------------------------------------------------------------------
   * Current Detection backend does not expose a dedicated Alert Pipeline
   * health field.
   *
   * We therefore DO NOT claim that the actual Alert pipeline is healthy.
   *
   * The safest truthful state is:
   *
   *   "Not Reported"
   *
   * until Detection → Alert integration exposes a real backend status.
   * ========================================================================== */

  const alertPipelineState:
    HealthState =
    "unknown";

  const alertPipelineStatus =
    "Not Reported";


  /* ==========================================================================
   * Engine Error State
   * ========================================================================== */

  /**
   * Evaluation errors are directly supplied by:
   *
   *   statistics.evaluation_failures
   */
  const evaluationErrorState:
    HealthState =
    typeof evaluationErrors !==
    "number"
      ? "unknown"
      : evaluationErrors > 0
        ? "error"
        : "available";


  /* ==========================================================================
   * Rules Loaded State
   * ========================================================================== */

  const rulesLoadedState:
    HealthState =
    typeof rulesLoaded ===
    "number"
      ? "available"
      : "unknown";


  /* ==========================================================================
   * Plugins Enabled State
   * ========================================================================== */

  const pluginsEnabledState:
    HealthState =
    typeof pluginsEnabled ===
    "number"
      ? "available"
      : "unknown";


  /* ==========================================================================
   * Render
   * ========================================================================== */

  return (
    <section
      className="detection-health-card"
      aria-label="Detection Engine Health"
    >

      {/* ==================================================================
       * HEADER
       * ================================================================== */}

      <HealthHeader
        badgeLabel={statusLabel}
        badgeState={engineState}
        description="Runtime health of the Detection engine, registries, and evaluation subsystem."
      />


      {/* ==================================================================
       * HEALTH MATRIX
       * ================================================================== */}

      <div className="detection-health-grid">

        {/* ================================================================
         * ENGINE STATUS
         * ============================================================== */}

        <HealthItem
          label="Engine Status"
          value={statusLabel}
          meta="Detection capability"
          state={engineState}
        />


        {/* ================================================================
         * LAST EVALUATION
         * ============================================================== */}

        <HealthItem
          label="Last Evaluation"
          value={formatTimestamp(
            lastEvaluationAt,
          )}
          meta="Not reported by backend"
          state="unknown"
        />


        {/* ================================================================
         * RULE REGISTRY
         * ============================================================== */}

        <HealthItem
          label="Rule Registry"
          value={ruleRegistryStatus}
          meta={
            capability.rules_api === true
              ? "Rules API available"
              : capability.rules_api === false
                ? "Rules API unavailable"
                : "Not reported"
          }
          state={
            ruleRegistryState
          }
        />


        {/* ================================================================
         * RULES LOADED
         * ============================================================== */}

        <HealthItem
          label="Rules Loaded"
          value={formatNumber(
            rulesLoaded,
          )}
          meta={
            typeof rulesLoaded ===
            "number"
              ? "Registered Detection rules"
              : "Not reported"
          }
          state={
            rulesLoadedState
          }
        />


        {/* ================================================================
         * PLUGIN REGISTRY
         * ============================================================== */}

        <HealthItem
          label="Plugin Registry"
          value={pluginRegistryStatus}
          meta={
            capability.plugins_api === true
              ? "Plugin API available"
              : capability.plugins_api === false
                ? "Plugin API unavailable"
                : "Not reported"
          }
          state={
            pluginRegistryState
          }
        />


        {/* ================================================================
         * PLUGINS ENABLED
         * ============================================================== */}

        <HealthItem
          label="Plugins Enabled"
          value={formatNumber(
            pluginsEnabled,
          )}
          meta={
            typeof pluginsEnabled ===
            "number"
              ? "Enabled detector plugins"
              : "Not reported"
          }
          state={
            pluginsEnabledState
          }
        />


        {/* ================================================================
         * ALERT PIPELINE
         * ============================================================== */}

        <HealthItem
          label="Alert Pipeline"
          value={
            alertPipelineStatus
          }
          meta="Dedicated alert pipeline health is not exposed"
          state={
            alertPipelineState
          }
        />


        {/* ================================================================
         * EVALUATION ERRORS
         * ============================================================== */}

        <HealthItem
          label="Evaluation Errors"
          value={formatNumber(
            evaluationErrors,
          )}
          meta={
            typeof evaluationErrors !==
            "number"
              ? "Not reported"
              : evaluationErrors > 0
                ? "Detection evaluation failures recorded"
                : "No evaluation failures recorded"
          }
          state={
            evaluationErrorState
          }
        />

      </div>

    </section>
  );
}


/* ==========================================================================
 * Default Export
 * ========================================================================== */

export default DetectionStatusCard;