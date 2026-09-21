/*
 * ============================================================================
 * Asset Statistics
 * SentinelSIEM SOC Dashboard
 * ============================================================================
 */

import {
  Activity,
  AlertTriangle,
  Boxes,
  CircleOff,
  ShieldAlert,
} from "lucide-react";

import type {
  AssetStatisticsResponse,
} from "../types";

/*
 * ============================================================================
 * Props
 * ============================================================================
 */

interface AssetStatisticsProps {
  statistics: AssetStatisticsResponse | null;

  loading?: boolean;

  error?: string | null;
}

/*
 * ============================================================================
 * Component
 * ============================================================================
 */

export default function AssetStatistics({
  statistics,
  loading = false,
  error = null,
}: AssetStatisticsProps) {
  /*
   * ==========================================================================
   * Loading State
   * ==========================================================================
   */

  if (loading) {
    return (
      <section
        aria-label="Loading asset statistics"
        aria-busy="true"
        className="space-y-4"
      >
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 4 }).map(
            (_, index) => (
              <div
                key={index}
                className="h-28 animate-pulse rounded-xl border border-slate-800 bg-slate-900/60"
              />
            ),
          )}
        </div>
      </section>
    );
  }

  /*
   * ==========================================================================
   * Error State
   * ==========================================================================
   */

  if (error) {
    return (
      <section aria-label="Asset statistics error">
        <div
          role="alert"
          className="rounded-xl border border-red-500/20 bg-red-500/5 px-4 py-3 text-sm text-red-400"
        >
          <span className="font-medium">
            Unable to load asset statistics:
          </span>{" "}
          {error}
        </div>
      </section>
    );
  }

  /*
   * ==========================================================================
   * Empty State
   * ==========================================================================
   */

  if (!statistics) {
    return (
      <section aria-label="Asset statistics">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 px-4 py-6 text-center text-sm text-slate-500">
          No asset statistics available.
        </div>
      </section>
    );
  }

  /*
   * ==========================================================================
   * Statistic Cards
   * ==========================================================================
   *
   * These values map directly to the Assets backend statistics contract:
   *
   *   total
   *   enabled
   *   disabled
   *   critical
   */

  const cards = [
    {
      label: "Total Assets",
      value: statistics.total,
      icon: Boxes,
      description: "All managed assets",
      iconClass:
        "bg-sky-500/10 text-sky-400",
    },

    {
      label: "Enabled",
      value: statistics.enabled,
      icon: Activity,
      description:
        "Currently enabled assets",
      iconClass:
        "bg-emerald-500/10 text-emerald-400",
    },

    {
      label: "Disabled",
      value: statistics.disabled,
      icon: CircleOff,
      description:
        "Currently disabled assets",
      iconClass:
        "bg-slate-500/10 text-slate-400",
    },

    {
      label: "Critical Risk",
      value: statistics.critical,
      icon: ShieldAlert,
      description:
        "Assets with critical risk",
      iconClass:
        "bg-red-500/10 text-red-400",
    },
  ] as const;

  /*
   * ==========================================================================
   * Render
   * ==========================================================================
   */

  return (
    <section
      aria-label="Asset statistics"
      className="space-y-4"
    >
      {/* ======================================================================
          Primary Statistics
          ====================================================================== */}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {cards.map((card) => {
          const Icon = card.icon;

          return (
            <article
              key={card.label}
              className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 transition-colors hover:border-slate-700"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
                    {card.label}
                  </p>

                  <p className="mt-2 text-2xl font-semibold tabular-nums text-slate-100">
                    {card.value.toLocaleString()}
                  </p>

                  <p className="mt-1 text-xs text-slate-500">
                    {card.description}
                  </p>
                </div>

                <div
                  className={[
                    "flex h-9 w-9 shrink-0 items-center justify-center rounded-lg",
                    card.iconClass,
                  ].join(" ")}
                >
                  <Icon
                    size={18}
                    strokeWidth={1.8}
                    aria-hidden="true"
                  />
                </div>
              </div>
            </article>
          );
        })}
      </div>

      {/* ======================================================================
          Critical Risk Information
          ====================================================================== */}

      {statistics.critical > 0 && (
        <div className="flex items-center gap-3 rounded-xl border border-red-500/20 bg-red-500/5 px-4 py-3">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-red-500/10 text-red-400">
            <AlertTriangle
              size={16}
              strokeWidth={1.8}
              aria-hidden="true"
            />
          </div>

          <div className="min-w-0">
            <p className="text-sm font-medium text-red-300">
              Critical risk assets
            </p>

            <p className="text-xs text-slate-500">
              {statistics.critical.toLocaleString()}{" "}
              asset
              {statistics.critical === 1
                ? ""
                : "s"}{" "}
              currently classified as
              critical risk.
            </p>
          </div>
        </div>
      )}
    </section>
  );
}