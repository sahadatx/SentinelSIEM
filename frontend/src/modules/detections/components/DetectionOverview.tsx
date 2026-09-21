import type {
  DetectionCapability,
  DetectionStatistics,
  DetectionSummary,
} from "../types";

/* ==========================================================================
 * SentinelSIEM
 * Detection Overview
 *
 * Responsibility
 * ----------------------------------------------------------------------------
 * - Present concise Detection subsystem context
 * - Present current operational state
 * - Present compact operational statistics
 * - Present Rules / Results / Plugins capability state
 * - Handle loading / error / unavailable states
 *
 * Detailed engine health belongs to:
 *
 *   DetectionStatusCard
 *
 * This component intentionally avoids:
 *   - rule evaluation logic
 *   - detection result calculations
 *   - alert calculations
 *   - incident calculations
 *   - frontend-derived KPI values
 *   - raw backend implementation messages
 *   - duplicate engine-health details
 *
 * Backend remains the source of truth for all Detection counters.
 * ========================================================================== */


/* ==========================================================================
 * Props
 * ========================================================================== */

interface DetectionOverviewProps {
  /**
   * Backend capability state.
   *
   * Source:
   *   GET /api/v1/detections/capability
   */
  capability: DetectionCapability | null;

  /**
   * Backend Detection summary.
   *
   * Kept for compatibility with the existing Detection page.
   *
   * Source:
   *   GET /api/v1/detections/summary
   */
  summary?: DetectionSummary | null;

  /**
   * Backend Detection statistics.
   *
   * Source:
   *   GET /api/v1/detections/statistics
   *
   * This is preferred for runtime counters.
   */
  statistics?: DetectionStatistics | null;

  /**
   * Section loading state.
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

type OverviewState =
  | "available"
  | "warning"
  | "error"
  | "unknown";

type CapabilityStatus =
  DetectionCapability["status"];


/* ==========================================================================
 * Constants
 * ========================================================================== */

/**
 * Current Detection capability surface.
 *
 * These are capability interfaces exposed by the backend:
 *
 *   1. Rules API
 *   2. Results API
 *   3. Plugins API
 *
 * This constant describes the UI surface, not a security metric.
 */
const TOTAL_DETECTION_APIS = 3;


/* ==========================================================================
 * Status Helpers
 * ========================================================================== */

/**
 * Convert backend Detection status into a user-facing label.
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
 * Convert backend Detection status into a visual state.
 */
function getStatusState(
  status: CapabilityStatus | undefined,
): OverviewState {
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


/**
 * Concise operational description.
 *
 * Keep this user-facing and implementation-agnostic.
 */
function getOperationalDescription(
  status: CapabilityStatus | undefined,
): string {
  switch (status) {
    case "available":
      return "Detection services are ready for operational use.";

    case "planned":
      return "Detection capability is planned but not operational.";

    case "unavailable":
      return "Detection services are currently unavailable.";

    case "unknown":
    default:
      return "Detection service state is currently unknown.";
  }
}


/* ==========================================================================
 * Number Helpers
 * ========================================================================== */

/**
 * Format a backend numeric value safely.
 *
 * Undefined / invalid values become an em dash.
 *
 * Zero remains a valid backend value.
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

  return value
    .toLocaleString();
}


/**
 * Normalize a backend counter only for display safety.
 *
 * IMPORTANT:
 * This does not calculate a metric.
 *
 * It only prevents invalid backend values from being rendered.
 */
function normalizeCount(
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
 * Capability Helpers
 * ========================================================================== */

/**
 * Convert an optional capability flag into a display label.
 */
function getCapabilityLabel(
  available: boolean | undefined,
): string {
  if (available === true) {
    return "Available";
  }

  if (available === false) {
    return "Unavailable";
  }

  return "Unknown";
}


/**
 * Convert an optional capability flag into a visual state.
 */
function getCapabilityState(
  available: boolean | undefined,
): OverviewState {
  if (available === true) {
    return "available";
  }

  if (available === false) {
    return "error";
  }

  return "unknown";
}


/* ==========================================================================
 * Overview Status
 * ========================================================================== */

interface OverviewStatusProps {
  label: string;

  state: OverviewState;
}


/**
 * Main overview status badge.
 */
function OverviewStatus({
  label,
  state,
}: OverviewStatusProps) {
  return (
    <span
      className={[
        "detection-overview-status",
        `detection-overview-status-${state}`,
      ].join(" ")}
    >
      <span
        className="detection-overview-status-dot"
        aria-hidden="true"
      />

      <span className="detection-overview-status-label">
        {label}
      </span>
    </span>
  );
}


/* ==========================================================================
 * Capability Item
 * ========================================================================== */

interface CapabilityItemProps {
  label: string;

  available: boolean | undefined;
}


/**
 * Compact capability indicator.
 *
 * Example:
 *
 *   Rules                         ● Available
 *   Results                       ● Available
 *   Plugins                       ● Available
 */
function CapabilityItem({
  label,
  available,
}: CapabilityItemProps) {
  const state =
    getCapabilityState(
      available,
    );

  const status =
    getCapabilityLabel(
      available,
    );

  return (
    <div
      className={[
        "detection-overview-capability",
        `detection-overview-capability-${state}`,
      ].join(" ")}
    >
      <span className="detection-overview-capability-label">
        {label}
      </span>

      <span
        className={[
          "detection-overview-capability-state",
          `detection-overview-capability-state-${state}`,
        ].join(" ")}
      >
        <span
          className="detection-overview-capability-dot"
          aria-hidden="true"
        />

        <span className="detection-overview-capability-state-label">
          {status}
        </span>
      </span>
    </div>
  );
}


/* ==========================================================================
 * Statistic Card
 * ========================================================================== */

interface OverviewStatProps {
  label: string;

  value: string;

  meta: string;

  loading?: boolean;
}


/**
 * Reusable overview statistic.
 *
 * Value and supporting metadata are deliberately separated.
 */
function OverviewStat({
  label,
  value,
  meta,
  loading = false,
}: OverviewStatProps) {
  return (
    <div
      className={[
        "detection-overview-stat",
        loading
          ? "detection-overview-stat-loading"
          : "",
      ]
        .filter(Boolean)
        .join(" ")}
    >
      <span className="detection-overview-stat-label">
        {label}
      </span>

      <strong className="detection-overview-stat-value">
        {value}
      </strong>

      <span className="detection-overview-stat-meta">
        {meta}
      </span>
    </div>
  );
}


/* ==========================================================================
 * Loading State
 * ========================================================================== */

function DetectionOverviewLoading() {
  return (
    <section
      className="detection-overview"
      aria-label="Detection overview"
      aria-busy="true"
    >
      <div className="detection-overview-header">
        <div className="detection-overview-header-content">
          <h2 className="detection-overview-title">
            Detection Overview
          </h2>

          <p className="detection-overview-description">
            Loading Detection subsystem status...
          </p>
        </div>

        <OverviewStatus
          label="Checking"
          state="unknown"
        />
      </div>

      <div className="detection-overview-stats">
        <OverviewStat
          label="Active Rules"
          value="—"
          meta="Loading"
          loading
        />

        <OverviewStat
          label="Detector Plugins"
          value="—"
          meta="Loading"
          loading
        />

        <OverviewStat
          label="Detection APIs"
          value="—"
          meta="Loading"
          loading
        />
      </div>

      <div
        className="detection-overview-capabilities"
        aria-hidden="true"
      >
        <div className="detection-overview-loading-item" />

        <div className="detection-overview-loading-item" />

        <div className="detection-overview-loading-item" />
      </div>
    </section>
  );
}


/* ==========================================================================
 * Error State
 * ========================================================================== */

function DetectionOverviewError({
  error,
}: {
  error: string;
}) {
  return (
    <section
      className="detection-overview detection-overview-error"
      aria-label="Detection overview"
      role="alert"
    >
      <div className="detection-overview-header">
        <div className="detection-overview-header-content">
          <h2 className="detection-overview-title">
            Detection Overview
          </h2>

          <p className="detection-overview-description">
            Detection subsystem information could not be loaded.
          </p>
        </div>

        <OverviewStatus
          label="Error"
          state="error"
        />
      </div>

      <div className="detection-overview-error-content">
        <span className="detection-overview-error-label">
          Unable to load overview
        </span>

        <span className="detection-overview-error-message">
          {error}
        </span>
      </div>
    </section>
  );
}


/* ==========================================================================
 * Capability Unavailable State
 * ========================================================================== */

function DetectionOverviewUnavailable() {
  return (
    <section
      className="detection-overview"
      aria-label="Detection overview"
    >
      <div className="detection-overview-header">
        <div className="detection-overview-header-content">
          <h2 className="detection-overview-title">
            Detection Overview
          </h2>

          <p className="detection-overview-description">
            Detection subsystem status is currently unavailable.
          </p>
        </div>

        <OverviewStatus
          label="Unknown"
          state="unknown"
        />
      </div>

      <div className="detection-overview-stats">
        <OverviewStat
          label="Active Rules"
          value="—"
          meta="Not reported"
        />

        <OverviewStat
          label="Detector Plugins"
          value="—"
          meta="Not reported"
        />

        <OverviewStat
          label="Detection APIs"
          value="—"
          meta="Not reported"
        />
      </div>

      <div
        className="detection-overview-capabilities"
        aria-label="Detection capabilities"
      >
        <CapabilityItem
          label="Rules"
          available={undefined}
        />

        <CapabilityItem
          label="Results"
          available={undefined}
        />

        <CapabilityItem
          label="Plugins"
          available={undefined}
        />
      </div>
    </section>
  );
}


/* ==========================================================================
 * Main Component
 * ========================================================================== */

export function DetectionOverview({
  capability,
  summary = null,
  statistics = null,
  loading = false,
  error = null,
}: DetectionOverviewProps) {
  /* ------------------------------------------------------------------------
   * Loading
   * ---------------------------------------------------------------------- */

  if (loading) {
    return (
      <DetectionOverviewLoading />
    );
  }


  /* ------------------------------------------------------------------------
   * Error
   * ---------------------------------------------------------------------- */

  if (error) {
    return (
      <DetectionOverviewError
        error={error}
      />
    );
  }


  /* ------------------------------------------------------------------------
   * Capability unavailable
   * ---------------------------------------------------------------------- */

  if (!capability) {
    return (
      <DetectionOverviewUnavailable />
    );
  }


  /* ==========================================================================
   * Derived status
   * ========================================================================== */

  const statusLabel =
    getStatusLabel(
      capability.status,
    );

  const statusState =
    getStatusState(
      capability.status,
    );

  const description =
    getOperationalDescription(
      capability.status,
    );


  /* ==========================================================================
   * Backend Statistics
   * --------------------------------------------------------------------------
   * DetectionStatistics is the authoritative runtime statistics source.
   *
   * Backend:
   *
   *   enabled_rules
   *   total_rules
   *   enabled_plugins
   *   total_plugins
   *
   * No frontend metric calculation is performed.
   * ========================================================================== */

  const statisticsTotalRules =
    normalizeCount(
      statistics?.total_rules,
    );

  const statisticsEnabledRules =
    normalizeCount(
      statistics?.enabled_rules,
    );

  const statisticsTotalPlugins =
    normalizeCount(
      statistics?.total_plugins,
    );

  const statisticsEnabledPlugins =
    normalizeCount(
      statistics?.enabled_plugins,
    );


  /* ==========================================================================
   * Backward-Compatible Summary Fallback
   * --------------------------------------------------------------------------
   * Summary remains supported because the existing page may still provide it.
   *
   * Statistics always wins when present.
   * ========================================================================== */

  const totalRules =
    typeof statisticsTotalRules === "number"
      ? statisticsTotalRules
      : normalizeCount(
          summary?.total_rules,
        );

  const enabledRules =
    typeof statisticsEnabledRules === "number"
      ? statisticsEnabledRules
      : normalizeCount(
          summary?.enabled_rules,
        );

  const totalPlugins =
    typeof statisticsTotalPlugins === "number"
      ? statisticsTotalPlugins
      : normalizeCount(
          summary?.total_plugins,
        );

  const enabledPlugins =
    typeof statisticsEnabledPlugins === "number"
      ? statisticsEnabledPlugins
      : normalizeCount(
          summary?.enabled_plugins,
        );


  /* ==========================================================================
   * API Capability State
   * --------------------------------------------------------------------------
   * Capability endpoint is the source of truth for API availability.
   *
   * This display only reflects the three explicit backend capability flags.
   * ========================================================================== */

  const apiAvailability: Array<boolean | undefined> = [
    capability.rules_api,
    capability.results_api,
    capability.plugins_api,
  ];

  /**
   * Count the explicitly available capability interfaces.
   *
   * This is presentation of backend capability flags, not a Detection KPI.
   */
  const availableApis =
    apiAvailability.reduce(
      (count, available) =>
        available === true
          ? count + 1
          : count,
      0,
    );


  /* ==========================================================================
   * Render
   * ========================================================================== */

  return (
    <section
      className="detection-overview"
      aria-label="Detection overview"
    >
      {/* ==================================================================
       * HEADER
       * ================================================================== */}

      <div className="detection-overview-header">
        <div className="detection-overview-header-content">
          <h2 className="detection-overview-title">
            Detection Overview
          </h2>

          <p className="detection-overview-description">
            {description}
          </p>
        </div>

        <OverviewStatus
          label={statusLabel}
          state={statusState}
        />
      </div>


      {/* ==================================================================
       * OPERATIONAL STATISTICS
       * ================================================================== */}

      <div className="detection-overview-stats">

        {/* ----------------------------------------------------------------
         * Active Rules
         * ----------------------------------------------------------------
         *
         * Backend source:
         *
         *   statistics.enabled_rules
         *
         * No frontend calculation.
         * -------------------------------------------------------------- */}

        <OverviewStat
          label="Active Rules"
          value={formatNumber(
            enabledRules,
          )}
          meta={
            typeof totalRules === "number"
              ? `of ${formatNumber(totalRules)} rules`
              : "Registered rules"
          }
        />


        {/* ----------------------------------------------------------------
         * Detector Plugins
         * ----------------------------------------------------------------
         *
         * Backend source:
         *
         *   statistics.enabled_plugins
         *
         * No frontend calculation.
         * -------------------------------------------------------------- */}

        <OverviewStat
          label="Detector Plugins"
          value={formatNumber(
            enabledPlugins,
          )}
          meta={
            typeof totalPlugins === "number"
              ? `of ${formatNumber(totalPlugins)} registered`
              : "Enabled plugins"
          }
        />


        {/* ----------------------------------------------------------------
         * Detection APIs
         * ----------------------------------------------------------------
         *
         * Backend source:
         *
         *   capability.rules_api
         *   capability.results_api
         *   capability.plugins_api
         *
         * This represents capability availability, not detection activity.
         * -------------------------------------------------------------- */}

        <OverviewStat
          label="Detection APIs"
          value={`${availableApis} / ${TOTAL_DETECTION_APIS}`}
          meta="Available interfaces"
        />

      </div>


      {/* ==================================================================
       * CAPABILITY STATUS
       * ================================================================== */}

      <div
        className="detection-overview-capabilities"
        aria-label="Detection capabilities"
      >
        <CapabilityItem
          label="Rules"
          available={
            capability.rules_api
          }
        />

        <CapabilityItem
          label="Results"
          available={
            capability.results_api
          }
        />

        <CapabilityItem
          label="Plugins"
          available={
            capability.plugins_api
          }
        />
      </div>
    </section>
  );
}


/* ==========================================================================
 * Default Export
 * ========================================================================== */

export default DetectionOverview;