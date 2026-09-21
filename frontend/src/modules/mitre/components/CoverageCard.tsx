/**
 * ============================================================================
 * SentinelSIEM — MITRE ATT&CK Coverage Card
 * ============================================================================
 *
 * Purpose
 * -------
 * Presentation-only coverage component for the MITRE ATT&CK module.
 *
 * Data ownership
 * --------------
 *
 * MITRE ATT&CK knowledge:
 *   - Owned by the MITRE dataset / PostgreSQL importer.
 *
 * SentinelSIEM coverage:
 *   - Owned by the backend coverage / analytics services.
 *
 * Source priority
 * --------------
 *
 * 1. `analytics`
 *      Primary and authoritative source for the complete coverage summary.
 *
 * 2. `coverage`
 *      Fallback source when analytics is unavailable.
 *
 * IMPORTANT
 * ---------
 *
 * When analytics is available, this component uses ONLY analytics fields for
 * the coverage summary.
 *
 * It intentionally does NOT combine:
 *
 *   coverage.total_techniques
 *
 * with:
 *
 *   analytics.full_techniques
 *   analytics.partial_techniques
 *   analytics.unmapped_techniques
 *
 * This prevents mixing different backend coverage semantics.
 *
 * This component NEVER:
 * - calculates coverage percentages
 * - derives coverage state
 * - infers Full / Partial / Unmapped
 * - calculates Total from individual counters
 * - filters MITRE techniques
 * - creates MITRE knowledge
 * - modifies MITRE knowledge
 * - performs MITRE CRUD
 * - creates mappings
 * - modifies mappings
 * - deletes mappings
 *
 * Backend-authoritative analytics fields:
 *   analytics.total_techniques
 *   analytics.full_techniques
 *   analytics.partial_techniques
 *   analytics.unmapped_techniques
 *   analytics.coverage_percent
 *
 * Backend-authoritative fallback coverage fields:
 *   coverage.total_techniques
 *   coverage.coverage_percent
 *
 * Related APIs
 * ------------
 *
 * GET /api/v1/mitre/coverage
 * GET /api/v1/mitre/analytics
 *
 * ============================================================================
 */

import type {
  MitreAnalytics,
  MitreCoverage,
} from "../types";


/* ============================================================================
 * Props
 * ========================================================================== */

export interface CoverageCardProps {
  /**
   * Backend-authoritative coverage response.
   *
   * Used only when analytics is unavailable.
   */
  coverage: MitreCoverage | null;

  /**
   * Backend-authoritative analytics response.
   *
   * When available, this is the single source of truth for the complete
   * coverage summary.
   */
  analytics?: MitreAnalytics | null;

  /**
   * Indicates whether the parent workspace is loading.
   */
  loading?: boolean;

  /**
   * Optional request error.
   */
  error?: string | null;
}


/* ============================================================================
 * Constants
 * ========================================================================== */

const MIN_PERCENT = 0;
const MAX_PERCENT = 100;


/* ============================================================================
 * Utility Helpers
 * ========================================================================== */

/**
 * Normalize a backend count for safe presentation.
 *
 * This is display validation only.
 *
 * It does NOT calculate a metric.
 */
function normalizeCount(
  value: unknown,
): number {
  const numeric =
    Number(value);

  if (
    !Number.isFinite(
      numeric,
    )
  ) {
    return 0;
  }

  return Math.max(
    0,
    Math.floor(
      numeric,
    ),
  );
}


/**
 * Normalize a backend-provided percentage for visual rendering.
 *
 * This does NOT calculate coverage.
 *
 * It only prevents an invalid backend value from producing an invalid
 * progress-bar width or ARIA value.
 */
function normalizeCoveragePercent(
  value: unknown,
): number {
  const numeric =
    Number(value);

  if (
    !Number.isFinite(
      numeric,
    )
  ) {
    return 0;
  }

  return Math.min(
    MAX_PERCENT,
    Math.max(
      MIN_PERCENT,
      numeric,
    ),
  );
}


/**
 * Consistent percentage formatting.
 */
function formatPercent(
  value: number,
): string {
  return `${value.toFixed(1)}%`;
}


/**
 * Convert an unknown error into a safe user-facing message.
 */
function getDisplayError(
  error: unknown,
): string {
  if (
    typeof error === "string"
  ) {
    const message =
      error.trim();

    if (message) {
      return message;
    }
  }

  if (
    error instanceof Error
  ) {
    const message =
      error.message.trim();

    if (message) {
      return message;
    }
  }

  return (
    "Unable to load MITRE ATT&CK coverage."
  );
}


/* ============================================================================
 * Coverage Header
 * ========================================================================== */

interface CoverageHeaderProps {
  coveragePercent?: number;
}

function CoverageHeader({
  coveragePercent,
}: CoverageHeaderProps) {
  return (
    <header
      className="resource-card__header"
    >
      <div>
        <h2
          className="resource-card__title"
        >
          MITRE ATT&amp;CK Coverage
        </h2>

        <p
          className="resource-card__description"
        >
          Detection coverage across ATT&amp;CK
          techniques.
        </p>
      </div>

      {coveragePercent !==
        undefined && (
        <div
          className="resource-card__metric"
          aria-label={`Coverage ${formatPercent(
            coveragePercent,
          )}`}
        >
          {formatPercent(
            coveragePercent,
          )}
        </div>
      )}
    </header>
  );
}


/* ============================================================================
 * Loading State
 * ========================================================================== */

function CoverageLoadingState() {
  return (
    <section
      className="resource-card mitre-coverage-card"
      aria-label="MITRE ATT&CK Coverage"
      aria-busy="true"
    >
      <CoverageHeader />

      <div className="resource-card__body">
        <div
          className="resource-card__loading"
          role="status"
          aria-live="polite"
        >
          Loading coverage...
        </div>
      </div>
    </section>
  );
}


/* ============================================================================
 * Error State
 * ========================================================================== */

interface CoverageErrorStateProps {
  error: unknown;
}

function CoverageErrorState({
  error,
}: CoverageErrorStateProps) {
  return (
    <section
      className="resource-card mitre-coverage-card"
      aria-label="MITRE ATT&CK Coverage"
      role="alert"
    >
      <CoverageHeader />

      <div className="resource-card__body">
        <p className="resource-card__error">
          {getDisplayError(
            error,
          )}
        </p>
      </div>
    </section>
  );
}


/* ============================================================================
 * Empty State
 * ========================================================================== */

function CoverageEmptyState() {
  return (
    <section
      className="resource-card mitre-coverage-card"
      aria-label="MITRE ATT&CK Coverage"
    >
      <CoverageHeader />

      <div className="resource-card__body">
        <p className="resource-card__empty">
          MITRE coverage data is currently
          unavailable.
        </p>
      </div>
    </section>
  );
}


/* ============================================================================
 * Analytics Unavailable
 * ========================================================================== */

interface AnalyticsUnavailableProps {
  coveragePercent: number;
  totalTechniques: number;
}

function AnalyticsUnavailable({
  coveragePercent,
  totalTechniques,
}: AnalyticsUnavailableProps) {
  return (
    <div
      className="mitre-coverage-card__analytics-unavailable"
      role="status"
      aria-live="polite"
    >
      <p
        className="mitre-coverage-card__summary-text"
      >
        Overall MITRE ATT&amp;CK coverage is{" "}
        <strong>
          {formatPercent(
            coveragePercent,
          )}
        </strong>
        .
      </p>

      <p
        className="mitre-coverage-card__muted"
      >
        Detailed Full / Partial / Unmapped
        metrics are unavailable because
        coverage analytics has not loaded.
      </p>

      <p
        className="mitre-coverage-card__muted"
      >
        Backend-reported technique total:{" "}
        <strong>
          {totalTechniques}
        </strong>
        .
      </p>
    </div>
  );
}


/* ============================================================================
 * Coverage Metric
 * ========================================================================== */

type CoverageMetricTone =
  | "full"
  | "partial"
  | "unmapped"
  | "neutral";

interface CoverageMetricProps {
  label: string;
  value: number;
  tone?: CoverageMetricTone;
}

function CoverageMetric({
  label,
  value,
  tone = "neutral",
}: CoverageMetricProps) {
  return (
    <div
      className={[
        "mitre-coverage-card__stat",
        `mitre-coverage-card__stat--${tone}`,
      ].join(" ")}
    >
      <span
        className="mitre-coverage-card__stat-label"
      >
        {label}
      </span>

      <strong
        className="mitre-coverage-card__stat-value"
      >
        {value}
      </strong>
    </div>
  );
}


/* ============================================================================
 * Progress Bar
 * ========================================================================== */

interface CoverageProgressProps {
  coveragePercent: number;
}

function CoverageProgress({
  coveragePercent,
}: CoverageProgressProps) {
  return (
    <div
      className="mitre-coverage-card__progress"
      aria-label="MITRE ATT&CK detection coverage"
    >
      <div
        className="mitre-coverage-card__progress-track"
        role="progressbar"
        aria-valuemin={
          MIN_PERCENT
        }
        aria-valuemax={
          MAX_PERCENT
        }
        aria-valuenow={
          coveragePercent
        }
        aria-valuetext={formatPercent(
          coveragePercent,
        )}
      >
        <div
          className="mitre-coverage-card__progress-fill"
          style={{
            width: `${coveragePercent}%`,
          }}
        />
      </div>
    </div>
  );
}


/* ============================================================================
 * Coverage Statistics
 * ========================================================================== */

interface CoverageStatisticsProps {
  full: number;
  partial: number;
  unmapped: number;
  total: number;
}

function CoverageStatistics({
  full,
  partial,
  unmapped,
  total,
}: CoverageStatisticsProps) {
  return (
    <div
      className="mitre-coverage-card__statistics"
      aria-label="MITRE coverage statistics"
    >
      <CoverageMetric
        label="Full"
        value={full}
        tone="full"
      />

      <CoverageMetric
        label="Partial"
        value={partial}
        tone="partial"
      />

      <CoverageMetric
        label="Unmapped"
        value={unmapped}
        tone="unmapped"
      />

      <CoverageMetric
        label="Total"
        value={total}
        tone="neutral"
      />
    </div>
  );
}


/* ============================================================================
 * Coverage Summary
 * ========================================================================== */

interface CoverageSummaryProps {
  full: number;
  partial: number;
  unmapped: number;
}

function CoverageSummary({
  full,
  partial,
  unmapped,
}: CoverageSummaryProps) {
  return (
    <div
      className="mitre-coverage-card__summary"
      aria-label="MITRE ATT&CK coverage summary"
    >
      <div>
        <span>
          Full coverage
        </span>

        <strong>
          {full}
        </strong>
      </div>

      <div>
        <span>
          Partial coverage
        </span>

        <strong>
          {partial}
        </strong>
      </div>

      <div>
        <span>
          Unmapped
        </span>

        <strong>
          {unmapped}
        </strong>
      </div>
    </div>
  );
}


/* ============================================================================
 * Accessible Coverage Summary
 * ========================================================================== */

interface AccessibleCoverageSummaryProps {
  full: number;
  partial: number;
  unmapped: number;
  total: number;
}

function AccessibleCoverageSummary({
  full,
  partial,
  unmapped,
  total,
}: AccessibleCoverageSummaryProps) {
  return (
    <p
      className="mitre-coverage-card__summary-text"
    >
      {full} fully covered,{" "}
      {partial} partially covered, and{" "}
      {unmapped} unmapped out of{" "}
      {total} ATT&amp;CK techniques.
    </p>
  );
}


/* ============================================================================
 * Analytics View
 * ========================================================================== */

/**
 * Render the complete analytics-authoritative coverage view.
 *
 * All five displayed metrics originate from the same backend response.
 */
function AnalyticsCoverageView({
  analytics,
}: {
  analytics: MitreAnalytics;
}) {
  const totalTechniques =
    normalizeCount(
      analytics.total_techniques,
    );

  const fullTechniques =
    normalizeCount(
      analytics.full_techniques,
    );

  const partialTechniques =
    normalizeCount(
      analytics.partial_techniques,
    );

  const unmappedTechniques =
    normalizeCount(
      analytics.unmapped_techniques,
    );

  /**
   * Backend-provided percentage.
   *
   * No frontend calculation is performed.
   */
  const coveragePercent =
    normalizeCoveragePercent(
      analytics.coverage_percent,
    );

  return (
    <section
      className="resource-card mitre-coverage-card"
      aria-label="MITRE ATT&CK Coverage"
    >
      <CoverageHeader
        coveragePercent={
          coveragePercent
        }
      />

      <div className="resource-card__body">
        <CoverageProgress
          coveragePercent={
            coveragePercent
          }
        />

        <CoverageStatistics
          full={
            fullTechniques
          }
          partial={
            partialTechniques
          }
          unmapped={
            unmappedTechniques
          }
          total={
            totalTechniques
          }
        />

        <CoverageSummary
          full={
            fullTechniques
          }
          partial={
            partialTechniques
          }
          unmapped={
            unmappedTechniques
          }
        />

        <AccessibleCoverageSummary
          full={
            fullTechniques
          }
          partial={
            partialTechniques
          }
          unmapped={
            unmappedTechniques
          }
          total={
            totalTechniques
          }
        />
      </div>
    </section>
  );
}


/* ============================================================================
 * Coverage-Only View
 * ========================================================================== */

/**
 * Render the coverage fallback.
 *
 * Only total + percentage are available from the fallback response.
 *
 * Full / Partial / Unmapped are deliberately not fabricated.
 */
function CoverageFallbackView({
  coverage,
}: {
  coverage: MitreCoverage;
}) {
  const totalTechniques =
    normalizeCount(
      coverage.total_techniques,
    );

  /**
   * Backend-provided fallback percentage.
   *
   * No calculation occurs here.
   */
  const coveragePercent =
    normalizeCoveragePercent(
      coverage.coverage_percent,
    );

  return (
    <section
      className="resource-card mitre-coverage-card"
      aria-label="MITRE ATT&CK Coverage"
    >
      <CoverageHeader
        coveragePercent={
          coveragePercent
        }
      />

      <div className="resource-card__body">
        <CoverageProgress
          coveragePercent={
            coveragePercent
          }
        />

        <AnalyticsUnavailable
          coveragePercent={
            coveragePercent
          }
          totalTechniques={
            totalTechniques
          }
        />
      </div>
    </section>
  );
}


/* ============================================================================
 * Main Component
 * ========================================================================== */

export function CoverageCard({
  coverage,
  analytics = null,
  loading = false,
  error = null,
}: CoverageCardProps) {
  /* ==========================================================================
   * Loading
   * ======================================================================== */

  if (loading) {
    return (
      <CoverageLoadingState />
    );
  }


  /* ==========================================================================
   * Error
   * ======================================================================== */

  if (error) {
    return (
      <CoverageErrorState
        error={error}
      />
    );
  }


  /* ==========================================================================
   * Analytics — Primary Source
   *
   * IMPORTANT:
   *
   * Analytics wins over coverage whenever it exists.
   *
   * This guarantees that:
   *
   *   total
   *   full
   *   partial
   *   unmapped
   *   percentage
   *
   * all originate from the same backend response.
   * ======================================================================== */

  if (analytics) {
    return (
      <AnalyticsCoverageView
        analytics={
          analytics
        }
      />
    );
  }


  /* ==========================================================================
   * Coverage — Fallback Source
   * ======================================================================== */

  if (coverage) {
    return (
      <CoverageFallbackView
        coverage={
          coverage
        }
      />
    );
  }


  /* ==========================================================================
   * Empty
   * ======================================================================== */

  return (
    <CoverageEmptyState />
  );
}


/* ============================================================================
 * Default Export
 * ========================================================================== */

export default CoverageCard;


/* ============================================================================
 * End of File
 * ============================================================================
 */