import React, { useMemo } from "react";
import type {
  MitreCoverageState,
  MitreMatrix as MitreMatrixData,
  MitreMatrixTactic,
  MitreMatrixTechnique,
} from "../types";

interface MitreMatrixProps {
  matrix: MitreMatrixData | null;
  loading?: boolean;
  error?: string | null;
  onTechniqueSelect?: (technique: MitreMatrixTechnique) => void;
}

/**
 * Normalize numeric values for presentation only.
 *
 * The backend remains authoritative for all MITRE coverage values.
 * This helper only prevents invalid UI values such as NaN or negatives.
 */
function normalizeCount(value: unknown): number {
  const parsed = Number(value);

  if (!Number.isFinite(parsed) || parsed < 0) {
    return 0;
  }

  return Math.floor(parsed);
}

/**
 * Normalize a percentage for safe visual rendering.
 *
 * This does not calculate coverage. It only constrains the backend-
 * supplied value to the range supported by the progress UI.
 */
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

function coverageLabel(state: MitreCoverageState): string {
  switch (state) {
    case "full":
      return "Full";

    case "partial":
      return "Partial";

    case "unmapped":
    default:
      return "Unmapped";
  }
}

function coverageClasses(state: MitreCoverageState): string {
  switch (state) {
    case "full":
      return [
        "border-emerald-200 bg-emerald-50",
        "dark:border-emerald-900/50 dark:bg-emerald-950/20",
      ].join(" ");

    case "partial":
      return [
        "border-amber-200 bg-amber-50",
        "dark:border-amber-900/50 dark:bg-amber-950/20",
      ].join(" ");

    case "unmapped":
    default:
      return [
        "border-slate-200 bg-white",
        "dark:border-slate-800 dark:bg-slate-900",
      ].join(" ");
  }
}

function coverageBadgeClasses(state: MitreCoverageState): string {
  switch (state) {
    case "full":
      return [
        "bg-emerald-100 text-emerald-700",
        "dark:bg-emerald-900/40 dark:text-emerald-300",
      ].join(" ");

    case "partial":
      return [
        "bg-amber-100 text-amber-700",
        "dark:bg-amber-900/40 dark:text-amber-300",
      ].join(" ");

    case "unmapped":
    default:
      return [
        "bg-slate-100 text-slate-600",
        "dark:bg-slate-800 dark:text-slate-300",
      ].join(" ");
  }
}

function TacticIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      aria-hidden="true"
      className="h-5 w-5"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
    >
      <path
        d="M12 3 4.5 7.2 12 11.4l7.5-4.2L12 3Z"
        strokeLinecap="round"
        strokeLinejoin="round"
      />

      <path
        d="m4.5 12 7.5 4.2 7.5-4.2M4.5 16.8l7.5 4.2 7.5-4.2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function ChevronIcon({ open }: { open: boolean }) {
  return (
    <svg
      viewBox="0 0 20 20"
      aria-hidden="true"
      className={[
        "h-4 w-4 transition-transform",
        open ? "rotate-180" : "",
      ].join(" ")}
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
    >
      <path
        d="m5 7.5 5 5 5-5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function TechniqueCard({
  technique,
  onSelect,
}: {
  technique: MitreMatrixTechnique;
  onSelect?: (technique: MitreMatrixTechnique) => void;
}) {
  const externalId = technique.external_id ?? "—";

  /**
   * MitreMatrixTechnique.coverage is the complete backend coverage
   * object. The visual helpers require only its state.
   *
   * IMPORTANT:
   * Do not pass the complete MitreTechniqueCoverage object into
   * coverageClasses(), coverageBadgeClasses(), or coverageLabel().
   */
  const state: MitreCoverageState =
    technique.coverage?.state ?? "unmapped";

  const subtechniques = useMemo(
    () =>
      Array.isArray(technique.subtechniques)
        ? technique.subtechniques
        : [],
    [technique.subtechniques],
  );

  /**
   * Matrix mapping/detection counts are represented by the backend
   * relationship ID arrays. We only normalize them for display.
   */
  const mappingCount = normalizeCount(
    technique.mapping_ids?.length ?? 0,
  );

  const detectionCount = normalizeCount(
    technique.detection_ids?.length ?? 0,
  );

  const subtechniqueCount = normalizeCount(
    subtechniques.length,
  );

  return (
    <button
      type="button"
      onClick={() => onSelect?.(technique)}
      disabled={!onSelect}
      className={[
        "w-full rounded-lg border p-4 text-left transition",
        coverageClasses(state),
        onSelect
          ? [
              "cursor-pointer",
              "hover:border-slate-400",
              "hover:shadow-sm",
              "dark:hover:border-slate-600",
            ].join(" ")
          : "cursor-default",
      ].join(" ")}
      aria-label={`View MITRE technique ${externalId} ${technique.name}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs font-semibold text-slate-500 dark:text-slate-400">
              {externalId}
            </span>

            <span
              className={[
                "rounded-full px-2 py-0.5 text-[11px] font-medium",
                coverageBadgeClasses(state),
              ].join(" ")}
            >
              {coverageLabel(state)}
            </span>

            {technique.type === "SUB_TECHNIQUE" && (
              <span className="rounded-full bg-slate-100 px-2 py-0.5 text-[11px] font-medium text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                Sub-technique
              </span>
            )}
          </div>

          <h4 className="mt-2 truncate text-sm font-semibold text-slate-900 dark:text-white">
            {technique.name}
          </h4>
        </div>

        {onSelect && (
          <span className="shrink-0 text-xs text-slate-400">
            View
          </span>
        )}
      </div>

      <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500 dark:text-slate-400">
        <span>
          Mappings{" "}
          <strong className="font-semibold text-slate-700 dark:text-slate-200">
            {mappingCount}
          </strong>
        </span>

        <span>
          Detections{" "}
          <strong className="font-semibold text-slate-700 dark:text-slate-200">
            {detectionCount}
          </strong>
        </span>

        <span>
          Sub-techniques{" "}
          <strong className="font-semibold text-slate-700 dark:text-slate-200">
            {formatNumber(subtechniqueCount)}
          </strong>
        </span>
      </div>
    </button>
  );
}

function TacticSection({
  tactic,
  onTechniqueSelect,
}: {
  tactic: MitreMatrixTactic;
  onTechniqueSelect?: (technique: MitreMatrixTechnique) => void;
}) {
  const [open, setOpen] = React.useState(true);

  const techniques = useMemo(
    () =>
      Array.isArray(tactic.techniques)
        ? tactic.techniques
        : [],
    [tactic.techniques],
  );

  const coveragePercent = normalizePercentage(
    tactic.coverage_percent,
  );

  const tacticId =
    tactic.external_id ??
    tactic.id;

  return (
    <section className="overflow-hidden rounded-xl border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
      <button
        type="button"
        onClick={() => setOpen((current) => !current)}
        className="flex w-full items-center justify-between gap-4 border-b border-slate-200 px-5 py-4 text-left hover:bg-slate-50 dark:border-slate-800 dark:hover:bg-slate-800/50"
        aria-expanded={open}
        aria-controls={`mitre-tactic-${tactic.id}`}
      >
        <div className="flex min-w-0 items-center gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-200">
            <TacticIcon />
          </div>

          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs font-semibold text-slate-500 dark:text-slate-400">
                {tacticId}
              </span>

              <h3 className="truncate text-sm font-semibold text-slate-900 dark:text-white">
                {tactic.name}
              </h3>
            </div>

            <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
              {formatNumber(techniques.length)} techniques
            </p>
          </div>
        </div>

        <div className="flex shrink-0 items-center gap-4">
          <div className="hidden w-32 sm:block">
            <div className="mb-1 flex items-center justify-between text-[11px] text-slate-500 dark:text-slate-400">
              <span>Coverage</span>

              <span>
                {formatPercentage(coveragePercent)}
              </span>
            </div>

            <div
              className="h-1.5 overflow-hidden rounded-full bg-slate-200 dark:bg-slate-700"
              aria-hidden="true"
            >
              <div
                className="h-full rounded-full bg-current transition-all"
                style={{
                  width: `${coveragePercent}%`,
                }}
              />
            </div>
          </div>

          <ChevronIcon open={open} />
        </div>
      </button>

      {open && (
        <div
          id={`mitre-tactic-${tactic.id}`}
          className="p-4"
        >
          {tactic.description && (
            <p className="mb-4 text-sm leading-6 text-slate-600 dark:text-slate-400">
              {tactic.description}
            </p>
          )}

          {techniques.length === 0 ? (
            <div className="rounded-lg border border-dashed border-slate-300 p-6 text-center dark:border-slate-700">
              <p className="text-sm text-slate-500 dark:text-slate-400">
                No techniques are available for this tactic.
              </p>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
              {techniques.map((technique) => (
                <TechniqueCard
                  key={technique.id}
                  technique={technique}
                  onSelect={onTechniqueSelect}
                />
              ))}
            </div>
          )}
        </div>
      )}
    </section>
  );
}

function MatrixLegend() {
  const items: Array<{
    state: MitreCoverageState;
    description: string;
  }> = [
    {
      state: "full",
      description: "Fully covered",
    },
    {
      state: "partial",
      description: "Partially covered",
    },
    {
      state: "unmapped",
      description: "No mapping",
    },
  ];

  return (
    <div
      className="flex flex-wrap items-center gap-3"
      aria-label="MITRE coverage legend"
    >
      {items.map(({ state, description }) => (
        <div
          key={state}
          className="flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400"
        >
          <span
            className={[
              "h-2.5 w-2.5 rounded-full",
              state === "full"
                ? "bg-emerald-500"
                : state === "partial"
                  ? "bg-amber-500"
                  : "bg-slate-400",
            ].join(" ")}
            aria-hidden="true"
          />

          <span>{description}</span>
        </div>
      ))}
    </div>
  );
}

function MatrixSummary({
  totalTechniques,
  fullTechniques,
  partialTechniques,
  unmappedTechniques,
  coveragePercent,
}: {
  totalTechniques: number;
  fullTechniques: number;
  partialTechniques: number;
  unmappedTechniques: number;
  coveragePercent: number;
}) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
      <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <h2 className="text-base font-semibold text-slate-900 dark:text-white">
            ATT&CK Matrix
          </h2>

          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            MITRE ATT&CK techniques organized by tactic and backend-reported coverage.
          </p>
        </div>

        <MatrixLegend />
      </div>

      <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded-lg bg-slate-50 p-3 dark:bg-slate-800/60">
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Total
          </p>

          <p className="mt-1 text-lg font-semibold text-slate-900 dark:text-white">
            {formatNumber(totalTechniques)}
          </p>
        </div>

        <div className="rounded-lg bg-emerald-50 p-3 dark:bg-emerald-950/20">
          <p className="text-xs text-emerald-700 dark:text-emerald-400">
            Full
          </p>

          <p className="mt-1 text-lg font-semibold text-emerald-800 dark:text-emerald-300">
            {formatNumber(fullTechniques)}
          </p>
        </div>

        <div className="rounded-lg bg-amber-50 p-3 dark:bg-amber-950/20">
          <p className="text-xs text-amber-700 dark:text-amber-400">
            Partial
          </p>

          <p className="mt-1 text-lg font-semibold text-amber-800 dark:text-amber-300">
            {formatNumber(partialTechniques)}
          </p>
        </div>

        <div className="rounded-lg bg-slate-50 p-3 dark:bg-slate-800/60">
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Unmapped
          </p>

          <p className="mt-1 text-lg font-semibold text-slate-700 dark:text-slate-200">
            {formatNumber(unmappedTechniques)}
          </p>
        </div>
      </div>

      <div className="mt-5">
        <div className="mb-2 flex items-center justify-between text-xs">
          <span className="font-medium text-slate-600 dark:text-slate-300">
            Overall coverage
          </span>

          <span className="font-semibold text-slate-800 dark:text-slate-200">
            {formatPercentage(coveragePercent)}
          </span>
        </div>

        <div
          className="h-2 overflow-hidden rounded-full bg-slate-200 dark:bg-slate-700"
          aria-label={`Overall coverage ${formatPercentage(coveragePercent)}`}
          role="progressbar"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={coveragePercent}
        >
          <div
            className="h-full rounded-full bg-current transition-all"
            style={{
              width: `${coveragePercent}%`,
            }}
          />
        </div>
      </div>
    </div>
  );
}

function MatrixLoadingState() {
  return (
    <section
      aria-label="MITRE ATT&CK matrix loading"
      aria-busy="true"
      className="space-y-4"
    >
      {[1, 2, 3].map((item) => (
        <div
          key={item}
          className="h-24 animate-pulse rounded-xl border border-slate-200 bg-slate-100 dark:border-slate-800 dark:bg-slate-800"
        />
      ))}
    </section>
  );
}

function MatrixErrorState({
  error,
}: {
  error: string;
}) {
  return (
    <section
      className="rounded-xl border border-red-200 bg-red-50 p-5 dark:border-red-900/50 dark:bg-red-950/20"
      role="alert"
    >
      <h3 className="text-sm font-semibold text-red-800 dark:text-red-300">
        Failed to load MITRE matrix
      </h3>

      <p className="mt-1 text-sm text-red-700 dark:text-red-400">
        {error}
      </p>
    </section>
  );
}

function MatrixEmptyState() {
  return (
    <section className="rounded-xl border border-slate-200 bg-white p-8 text-center dark:border-slate-800 dark:bg-slate-900">
      <p className="text-sm text-slate-500 dark:text-slate-400">
        No MITRE ATT&CK matrix data is available.
      </p>
    </section>
  );
}

export default function MitreMatrix({
  matrix,
  loading = false,
  error = null,
  onTechniqueSelect,
}: MitreMatrixProps) {
  if (loading && !matrix) {
    return <MatrixLoadingState />;
  }

  if (error && !matrix) {
    return <MatrixErrorState error={error} />;
  }

  if (!matrix) {
    return <MatrixEmptyState />;
  }

  const tactics = Array.isArray(matrix.tactics)
    ? matrix.tactics
    : [];

  const totalTechniques = normalizeCount(
    matrix.total_techniques,
  );

  const fullTechniques = normalizeCount(
    matrix.full_techniques,
  );

  const partialTechniques = normalizeCount(
    matrix.partial_techniques,
  );

  const unmappedTechniques = normalizeCount(
    matrix.unmapped_techniques,
  );

  const coveragePercent = normalizePercentage(
    matrix.coverage_percent,
  );

  return (
    <section
      aria-label="MITRE ATT&CK matrix"
      className="space-y-5"
    >
      <MatrixSummary
        totalTechniques={totalTechniques}
        fullTechniques={fullTechniques}
        partialTechniques={partialTechniques}
        unmappedTechniques={unmappedTechniques}
        coveragePercent={coveragePercent}
      />

      {error && (
        <div
          className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800 dark:border-amber-900/50 dark:bg-amber-950/20 dark:text-amber-300"
          role="status"
        >
          {error}
        </div>
      )}

      {loading && (
        <div
          className="rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-500 dark:border-slate-800 dark:bg-slate-900/60 dark:text-slate-400"
          role="status"
          aria-live="polite"
        >
          Refreshing MITRE matrix…
        </div>
      )}

      {tactics.length === 0 ? (
        <div className="rounded-xl border border-dashed border-slate-300 bg-white p-10 text-center dark:border-slate-700 dark:bg-slate-900">
          <p className="text-sm text-slate-500 dark:text-slate-400">
            No tactics are available in the MITRE matrix.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {tactics.map((tactic) => (
            <TacticSection
              key={tactic.id}
              tactic={tactic}
              onTechniqueSelect={onTechniqueSelect}
            />
          ))}
        </div>
      )}
    </section>
  );
}