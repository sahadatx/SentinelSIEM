import React from "react";

import type { MitreStatistics } from "../types";
import "../Mitre.css";

interface MitreStatsCardsProps {
  statistics: MitreStatistics | null;
  loading?: boolean;
  error?: string | null;
}

interface StatCardProps {
  label: string;
  value: string;
  description: string;
  icon: React.ReactNode;
  loading: boolean;
}

/* ============================================================================
 * Formatting Helpers
 * ========================================================================== */

function normalizeCount(value: unknown): number {
  const parsed = Number(value);

  if (!Number.isFinite(parsed) || parsed < 0) {
    return 0;
  }

  return Math.floor(parsed);
}

function normalizePercentage(value: unknown): number {
  const parsed = Number(value);

  if (!Number.isFinite(parsed)) {
    return 0;
  }

  return Math.min(100, Math.max(0, parsed));
}

function formatNumber(value: number): string {
  return new Intl.NumberFormat("en-US").format(value);
}

function formatPercentage(value: number): string {
  return `${value.toFixed(2)}%`;
}

/* ============================================================================
 * Icons
 * ========================================================================== */

function TacticsIcon(): React.ReactElement {
  return (
    <svg
      className="mitre-stats-card__icon-svg"
      width="20"
      height="20"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      preserveAspectRatio="xMidYMid meet"
    >
      <path d="M12 3L4.5 7.25L12 11.5L19.5 7.25L12 3Z" />
      <path d="M4.5 12L12 16.25L19.5 12" />
      <path d="M4.5 16.75L12 21L19.5 16.75" />
    </svg>
  );
}

function TechniquesIcon(): React.ReactElement {
  return (
    <svg
      className="mitre-stats-card__icon-svg"
      width="20"
      height="20"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      preserveAspectRatio="xMidYMid meet"
    >
      <rect
        x="4"
        y="4"
        width="16"
        height="16"
        rx="2"
      />

      <path d="M8 8H16" />
      <path d="M8 12H16" />
      <path d="M8 16H13" />
    </svg>
  );
}

function SubTechniquesIcon(): React.ReactElement {
  return (
    <svg
      className="mitre-stats-card__icon-svg"
      width="20"
      height="20"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      preserveAspectRatio="xMidYMid meet"
    >
      <path d="M5 5H19" />
      <path d="M5 12H14" />
      <path d="M5 19H11" />

      <circle
        cx="5"
        cy="5"
        r="2"
      />

      <circle
        cx="5"
        cy="12"
        r="2"
      />

      <circle
        cx="5"
        cy="19"
        r="2"
      />

      <circle
        cx="18"
        cy="12"
        r="2"
      />

      <circle
        cx="15"
        cy="19"
        r="2"
      />
    </svg>
  );
}

function CoverageIcon(): React.ReactElement {
  return (
    <svg
      className="mitre-stats-card__icon-svg"
      width="20"
      height="20"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      preserveAspectRatio="xMidYMid meet"
    >
      <circle
        cx="12"
        cy="12"
        r="8.5"
      />

      <path d="M12 7V12L15.5 14" />
    </svg>
  );
}

/* ============================================================================
 * Stat Card
 * ========================================================================== */

function StatCard({
  label,
  value,
  description,
  icon,
  loading,
}: StatCardProps): React.ReactElement {
  return (
    <article className="mitre-stats-card">
      <div className="mitre-stats-card__content">
        <div className="mitre-stats-card__text">
          <p className="mitre-stats-card__label">
            {label}
          </p>

          {loading ? (
            <div
              className="mitre-stats-card__skeleton"
              role="status"
              aria-label={`Loading ${label}`}
            />
          ) : (
            <p className="mitre-stats-card__value">
              {value}
            </p>
          )}

          <p className="mitre-stats-card__description">
            {description}
          </p>
        </div>

        <div
          className="mitre-stats-card__icon"
          aria-hidden="true"
        >
          {icon}
        </div>
      </div>
    </article>
  );
}

/* ============================================================================
 * Main Component
 * ========================================================================== */

export default function MitreStatsCards({
  statistics,
  loading = false,
  error = null,
}: MitreStatsCardsProps): React.ReactElement {
  /*
   * Error is shown only when there is no usable statistics object.
   * If previous statistics are available while a refresh fails,
   * the existing values remain visible.
   */
  if (error && !statistics && !loading) {
    return (
      <section
        className="mitre-stats-error"
        role="alert"
        aria-label="MITRE statistics error"
      >
        <strong className="mitre-stats-error__title">
          Failed to load MITRE statistics
        </strong>

        <span className="mitre-stats-error__message">
          {error}
        </span>
      </section>
    );
  }

  /*
   * These values come directly from the backend statistics response.
   *
   * No client-side ATT&CK coverage calculation is performed here.
   */
  const tactics = normalizeCount(
    statistics?.tactics,
  );

  const techniques = normalizeCount(
    statistics?.techniques,
  );

  const subtechniques = normalizeCount(
    statistics?.subtechniques,
  );

  const coveragePercent = normalizePercentage(
    statistics?.coverage_percent,
  );

  const cards: StatCardProps[] = [
    {
      label: "Tactics",
      value: formatNumber(tactics),
      description: "MITRE ATT&CK tactics",
      icon: <TacticsIcon />,
      loading,
    },
    {
      label: "Techniques",
      value: formatNumber(techniques),
      description: "Top-level techniques",
      icon: <TechniquesIcon />,
      loading,
    },
    {
      label: "Sub-techniques",
      value: formatNumber(subtechniques),
      description: "Technique sub-techniques",
      icon: <SubTechniquesIcon />,
      loading,
    },
    {
      label: "Coverage",
      value: formatPercentage(coveragePercent),
      description: "Backend-reported ATT&CK coverage",
      icon: <CoverageIcon />,
      loading,
    },
  ];

  return (
    <section
      className="mitre-stats"
      aria-label="MITRE ATT&CK statistics"
    >
      {cards.map((card) => (
        <StatCard
          key={card.label}
          label={card.label}
          value={card.value}
          description={card.description}
          icon={card.icon}
          loading={card.loading}
        />
      ))}
    </section>
  );
}