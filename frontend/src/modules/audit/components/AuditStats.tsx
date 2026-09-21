/**
 * ============================================================================
 * SentinelSIEM — Global Audit Statistics
 * ============================================================================
 *
 * Phase 18 — Global Audit Frontend
 *
 * Backend contract:
 *
 * GET /audit/statistics
 *
 * {
 *   "total": 12458,
 *   "success": 11216,
 *   "failure": 1242,
 *   "denied": 0,
 *   "unique_actors": 156,
 *   "unique_targets": 342
 * }
 *
 * Responsibilities:
 *
 * - Present global audit statistics
 * - Match backend AuditStatisticsResponse
 * - Format audit event counts
 * - Calculate success/failure/denied percentages
 * - Present unique actor/target counts
 * - Provide accessible metric information
 * - Provide loading/skeleton presentation
 *
 * Architecture:
 *
 *     Audit Page
 *          |
 *          v
 *     AuditStats
 *          |
 *          v
 *     AuditStatistics
 *
 * This component:
 *
 * - does NOT fetch data
 * - does NOT perform authorization
 * - does NOT modify audit records
 * - does NOT define backend statistics rules
 *
 * ============================================================================
 */

import {
  Activity,
  AlertCircle,
  CheckCircle2,
  ShieldAlert,
  Target,
  Users,
} from "lucide-react";

import type { LucideIcon } from "lucide-react";

import type { AuditStatistics } from "../types";


/* ============================================================================
 * Props
 * ========================================================================== */

export interface AuditStatsProps {
  /**
   * Statistics returned by:
   *
   *     GET /audit/statistics
   *
   * null means statistics are currently unavailable.
   */
  statistics: AuditStatistics | null;

  /**
   * Whether statistics are currently loading.
   */
  loading?: boolean;
}


/* ============================================================================
 * Component
 * ========================================================================== */

export default function AuditStats({
  statistics,
  loading = false,
}: AuditStatsProps) {
  /* --------------------------------------------------------------------------
   * Loading State
   * ------------------------------------------------------------------------ */

  if (loading) {
    return (
      <section
        className="metrics-grid"
        aria-label="Audit statistics"
        aria-busy="true"
      >
        <MetricCard
          label="Total Events"
          value="—"
          description="All audit events"
          icon={Activity}
          loading
        />

        <MetricCard
          label="Successful"
          value="—"
          description="Successful operations"
          icon={CheckCircle2}
          tone="success"
          loading
        />

        <MetricCard
          label="Failed"
          value="—"
          description="Failed operations"
          icon={AlertCircle}
          tone="danger"
          loading
        />

        <MetricCard
          label="Denied"
          value="—"
          description="Denied operations"
          icon={ShieldAlert}
          tone="danger"
          loading
        />

        <MetricCard
          label="Unique Actors"
          value="—"
          description="Users who performed actions"
          icon={Users}
          loading
        />

        <MetricCard
          label="Unique Targets"
          value="—"
          description="Users/resources affected"
          icon={Target}
          loading
        />
      </section>
    );
  }


  /* --------------------------------------------------------------------------
   * Statistics Unavailable
   * ------------------------------------------------------------------------ */

  if (!statistics) {
    return (
      <section
        className="metrics-grid"
        aria-label="Audit statistics"
        aria-busy="false"
      >
        <MetricCard
          label="Total Events"
          value="—"
          description="All audit events"
          icon={Activity}
        />

        <MetricCard
          label="Successful"
          value="—"
          description="Successful operations"
          icon={CheckCircle2}
          tone="success"
        />

        <MetricCard
          label="Failed"
          value="—"
          description="Failed operations"
          icon={AlertCircle}
          tone="danger"
        />

        <MetricCard
          label="Denied"
          value="—"
          description="Denied operations"
          icon={ShieldAlert}
          tone="danger"
        />

        <MetricCard
          label="Unique Actors"
          value="—"
          description="Users who performed actions"
          icon={Users}
        />

        <MetricCard
          label="Unique Targets"
          value="—"
          description="Users/resources affected"
          icon={Target}
        />
      </section>
    );
  }


  /* ==========================================================================
   * Normalize Backend Statistics
   * ======================================================================== */

  /**
   * IMPORTANT:
   *
   * These names intentionally match the backend:
   *
   *     success
   *     failure
   *     denied
   *     unique_actors
   *     unique_targets
   *
   * Do NOT change them to:
   *
   *     successful
   *     failed
   *
   * unless the backend contract is changed as well.
   */

  const total = normalizeCount(
    statistics.total,
  );

  const success = normalizeCount(
    statistics.success,
  );

  const failure = normalizeCount(
    statistics.failure,
  );

  const denied = normalizeCount(
    statistics.denied,
  );

  const uniqueActors = normalizeCount(
    statistics.unique_actors,
  );

  const uniqueTargets = normalizeCount(
    statistics.unique_targets,
  );


  /* ==========================================================================
   * Derived Percentages
   * ======================================================================== */

  const successPercentage =
    calculatePercentage(
      success,
      total,
    );

  const failurePercentage =
    calculatePercentage(
      failure,
      total,
    );

  const deniedPercentage =
    calculatePercentage(
      denied,
      total,
    );


  /* ==========================================================================
   * Render
   * ======================================================================== */

  return (
    <section
      className="metrics-grid"
      aria-label="Audit statistics"
      aria-busy="false"
    >
      {/* ----------------------------------------------------------------------
       * Total
       * -------------------------------------------------------------------- */}

      <MetricCard
        label="Total Events"
        value={formatNumber(total)}
        description="All audit events"
        icon={Activity}
      />


      {/* ----------------------------------------------------------------------
       * Successful
       * -------------------------------------------------------------------- */}

      <MetricCard
        label="Successful"
        value={formatNumber(success)}
        description={`${formatPercentage(
          successPercentage,
        )} of total`}
        icon={CheckCircle2}
        tone="success"
      />


      {/* ----------------------------------------------------------------------
       * Failed
       * -------------------------------------------------------------------- */}

      <MetricCard
        label="Failed"
        value={formatNumber(failure)}
        description={`${formatPercentage(
          failurePercentage,
        )} of total`}
        icon={AlertCircle}
        tone="danger"
      />


      {/* ----------------------------------------------------------------------
       * Denied
       * -------------------------------------------------------------------- */}

      <MetricCard
        label="Denied"
        value={formatNumber(denied)}
        description={`${formatPercentage(
          deniedPercentage,
        )} of total`}
        icon={ShieldAlert}
        tone="danger"
      />


      {/* ----------------------------------------------------------------------
       * Unique Actors
       * -------------------------------------------------------------------- */}

      <MetricCard
        label="Unique Actors"
        value={formatNumber(uniqueActors)}
        description="Users who performed actions"
        icon={Users}
      />


      {/* ----------------------------------------------------------------------
       * Unique Targets
       * -------------------------------------------------------------------- */}

      <MetricCard
        label="Unique Targets"
        value={formatNumber(uniqueTargets)}
        description="Users/resources affected"
        icon={Target}
      />
    </section>
  );
}


/* ============================================================================
 * Metric Card
 * ========================================================================== */

interface MetricCardProps {
  /**
   * Metric title.
   */
  label: string;

  /**
   * Primary metric value.
   */
  value: string;

  /**
   * Supporting description.
   */
  description: string;

  /**
   * Lucide icon.
   */
  icon: LucideIcon;

  /**
   * Visual semantic tone.
   */
  tone?: MetricTone;

  /**
   * Loading/skeleton state.
   */
  loading?: boolean;
}


type MetricTone =
  | "default"
  | "success"
  | "danger"
  | "info";


/* ============================================================================
 * Metric Card Component
 * ========================================================================== */

function MetricCard({
  label,
  value,
  description,
  icon: Icon,
  tone = "default",
  loading = false,
}: MetricCardProps) {
  /**
   * Shared components.css contract:
   *
   *     .metric-card
   *     .metric-card.success
   *     .metric-card.danger
   *     .metric-card.info
   *
   * The semantic tone is therefore represented as
   * a modifier class.
   */

  const className = [
    "metric-card",
    tone !== "default"
      ? tone
      : "",
    loading
      ? "metric-card-loading"
      : "",
  ]
    .filter(Boolean)
    .join(" ");


  return (
    <article
      className={className}
      aria-label={`${label}: ${value}`}
      aria-busy={loading}
    >
      {/* ----------------------------------------------------------------------
       * Icon
       * -------------------------------------------------------------------- */}

      <div
        className="metric-icon"
        aria-hidden="true"
      >
        <Icon
          size={18}
          strokeWidth={1.9}
        />
      </div>


      {/* ----------------------------------------------------------------------
       * Content
       * -------------------------------------------------------------------- */}

      <div className="metric-content">
        <span className="metric-card-label">
          {label}
        </span>


        {loading ? (
          <>
            <span
              className="metric-card-value metric-value-skeleton"
              aria-hidden="true"
            >
              &nbsp;
            </span>

            <span
              className="metric-card-meta metric-description-skeleton"
              aria-hidden="true"
            >
              &nbsp;
            </span>
          </>
        ) : (
          <>
            <strong className="metric-card-value">
              {value}
            </strong>

            <span className="metric-card-meta">
              {description}
            </span>
          </>
        )}
      </div>
    </article>
  );
}


/* ============================================================================
 * Number Normalization
 * ========================================================================== */

/**
 * Normalize a backend statistic count.
 *
 * Prevents:
 *
 * - NaN
 * - Infinity
 * - negative values
 * - fractional event counts
 */
function normalizeCount(
  value: number | null | undefined,
): number {
  if (
    value === null ||
    value === undefined ||
    !Number.isFinite(value)
  ) {
    return 0;
  }

  return Math.max(
    0,
    Math.floor(value),
  );
}


/* ============================================================================
 * Number Formatting
 * ========================================================================== */

/**
 * Format numbers using US decimal grouping.
 *
 * Example:
 *
 *     12458 -> 12,458
 */
function formatNumber(
  value: number,
): string {
  return new Intl.NumberFormat(
    "en-US",
    {
      maximumFractionDigits: 0,
    },
  ).format(value);
}


/* ============================================================================
 * Percentage Calculation
 * ========================================================================== */

/**
 * Safely calculate a percentage.
 *
 * Rules:
 *
 * - total <= 0 -> 0
 * - value <= 0 -> 0
 * - result is constrained to 0–100
 */
function calculatePercentage(
  value: number,
  total: number,
): number {
  if (
    total <= 0 ||
    value <= 0
  ) {
    return 0;
  }

  const percentage =
    (value / total) * 100;

  return Math.min(
    100,
    Math.max(
      0,
      percentage,
    ),
  );
}


/* ============================================================================
 * Percentage Formatting
 * ========================================================================== */

/**
 * Format percentage for SOC presentation.
 *
 * Examples:
 *
 *     90   -> 90.0%
 *     10   -> 10.0%
 *     0    -> 0.0%
 */
function formatPercentage(
  value: number,
): string {
  return `${value.toFixed(1)}%`;
}