/**
 * ============================================================================
 * SentinelSIEM — MITRE ATT&CK Technique Details
 * ============================================================================
 *
 * Purpose
 * -------
 * Read-only detail view for a single MITRE ATT&CK technique.
 *
 * Responsibilities
 * ----------------
 * - Present backend-returned technique metadata.
 * - Present backend-authoritative coverage state and metrics.
 * - Present tactics and platform context.
 * - Present sub-techniques.
 * - Present operational detection mappings.
 * - Present related SentinelSIEM detections, events, alerts, incidents,
 *   IOCs, and assets.
 * - Delegate navigation back to the parent page.
 *
 * Architecture
 * ------------
 * This is a presentation-only component.
 *
 * It does NOT:
 * - perform API requests
 * - perform authentication
 * - perform RBAC checks
 * - create MITRE techniques
 * - update MITRE techniques
 * - delete MITRE techniques
 * - create mappings
 * - update mappings
 * - delete mappings
 * - calculate global MITRE coverage
 *
 * Backend remains authoritative for:
 * - coverage.state
 * - coverage.mapping_count
 * - coverage.detection_count
 * - coverage.subtechnique_count
 * - coverage.mapped_subtechnique_count
 * - coverage.confidence
 *
 * Important distinction
 * --------------------
 * MITRE ATT&CK knowledge:
 *   - technique
 *   - tactics
 *   - platforms
 *   - sub-techniques
 *
 * SentinelSIEM operational intelligence:
 *   - detection mappings
 *   - detections
 *   - events
 *   - alerts
 *   - incidents
 *   - IOCs
 *   - assets
 *
 * Detection-to-MITRE mappings shown here are operational intelligence.
 * They are NOT MITRE knowledge CRUD.
 *
 * Sub-technique mapping display
 * -----------------------------
 * The backend currently provides mapping relationships but does not expose
 * a separate sub-technique coverage-state field in the detail contract.
 *
 * Therefore the sub-technique "Mapped / Unmapped" indicator is limited to
 * whether an operational mapping explicitly references that sub-technique.
 *
 * It must NOT be interpreted as a global coverage calculation.
 *
 * ============================================================================
 */

import type {
  ReactNode,
} from "react";

import type {
  MitreCoverageState,
  MitreTechniqueDetail,
} from "../types";

/* ============================================================================
 * Props
 * ========================================================================== */

export interface TechniqueDetailsProps {
  /**
   * Complete backend detail response.
   */
  technique: MitreTechniqueDetail | null;

  /**
   * Detail request loading state.
   */
  loading?: boolean;

  /**
   * Detail request error.
   */
  error?: string | null;

  /**
   * Optional parent navigation callback.
   */
  onBack?: () => void;
}

/* ============================================================================
 * Constants
 * ========================================================================== */

const COVERAGE_STATE_LABELS: Record<
  MitreCoverageState,
  string
> = {
  full: "Full",
  partial: "Partial",
  unmapped: "Unmapped",
};

const TECHNIQUE_TYPE_LABELS = {
  TECHNIQUE: "Technique",
  SUB_TECHNIQUE: "Sub-technique",
} as const;

/* ============================================================================
 * Generic Helpers
 * ========================================================================== */

/**
 * Normalize an identifier for safe display.
 */
function displayId(
  value: unknown,
): string {
  if (
    typeof value !== "string"
  ) {
    return "";
  }

  return value.trim();
}

/**
 * Normalize an optional string.
 */
function normalizeString(
  value: unknown,
): string {
  return typeof value === "string"
    ? value.trim()
    : "";
}

/**
 * Safely return an array.
 *
 * This protects the presentation layer from null/undefined payloads.
 */
function safeArray<T>(
  value: T[] | null | undefined,
): T[] {
  return Array.isArray(value)
    ? value
    : [];
}

/**
 * Safely normalize a backend numeric value for display.
 *
 * This does not calculate a metric.
 */
function safeNumber(
  value: unknown,
): number {
  const numeric =
    typeof value === "number"
      ? value
      : Number(value);

  if (
    !Number.isFinite(
      numeric,
    )
  ) {
    return 0;
  }

  return Math.max(
    0,
    numeric,
  );
}

/**
 * Format an integer-like backend count.
 */
function formatCount(
  value: unknown,
): string {
  return String(
    Math.floor(
      safeNumber(
        value,
      ),
    ),
  );
}

/**
 * Format a backend confidence value.
 *
 * Expected representation:
 *   0.0 → 1.0
 *
 * This only formats/clamps malformed display data.
 * It does not calculate confidence.
 */
function formatConfidence(
  value: unknown,
): string {
  const numeric =
    Number(value);

  if (
    !Number.isFinite(
      numeric,
    )
  ) {
    return "—";
  }

  const normalized =
    Math.min(
      1,
      Math.max(
        0,
        numeric,
      ),
    );

  return `${(
    normalized * 100
  ).toFixed(1)}%`;
}

/**
 * Convert coverage state into a display label.
 */
function getCoverageLabel(
  state: MitreCoverageState,
): string {
  return (
    COVERAGE_STATE_LABELS[state] ??
    "Unknown"
  );
}

/**
 * Build coverage-related CSS classes.
 *
 * The state comes from the backend.
 */
function getCoverageClass(
  state: string | undefined,
): string {
  const normalized =
    normalizeString(
      state,
    ) || "unknown";

  return [
    "mitre-technique-details__coverage",
    `mitre-technique-details__coverage--${normalized}`,
  ].join(" ");
}

/**
 * Format a list of identifiers.
 */
function formatIdentifierList(
  values: string[],
): string {
  return values
    .map(
      (value) =>
        displayId(value),
    )
    .filter(
      (value) =>
        value.length > 0,
    )
    .join(", ");
}

/**
 * Return a stable unique string list.
 */
function uniqueStrings(
  values: string[],
): string[] {
  const seen =
    new Set<string>();

  const result: string[] = [];

  for (
    const value of values
  ) {
    const normalized =
      displayId(value);

    if (!normalized) {
      continue;
    }

    if (
      seen.has(
        normalized,
      )
    ) {
      continue;
    }

    seen.add(
      normalized,
    );

    result.push(
      normalized,
    );
  }

  return result;
}

/* ============================================================================
 * Reference List
 * ========================================================================== */

interface ReferenceListProps {
  items: string[];

  emptyMessage: string;

  className?: string;
}

function ReferenceList({
  items,
  emptyMessage,
  className = "",
}: ReferenceListProps) {
  const normalizedItems =
    uniqueStrings(
      items,
    );

  if (
    normalizedItems.length === 0
  ) {
    return (
      <p className="mitre-technique-details__muted">
        {emptyMessage}
      </p>
    );
  }

  return (
    <div
      className={[
        "mitre-technique-details__reference-list",
        className,
      ]
        .filter(Boolean)
        .join(" ")}
    >
      {normalizedItems.map(
        (item) => (
          <code
            key={item}
            className="mitre-technique-details__reference"
          >
            {item}
          </code>
        ),
      )}
    </div>
  );
}

/* ============================================================================
 * Loading State
 * ========================================================================== */

function LoadingState() {
  return (
    <section
      className="resource-card mitre-technique-details"
      aria-label="MITRE ATT&CK technique details"
      aria-busy="true"
    >
      <header className="resource-card__header">
        <div>
          <h2 className="resource-card__title">
            Technique Details
          </h2>

          <p className="resource-card__description">
            Loading MITRE ATT&amp;CK technique intelligence...
          </p>
        </div>
      </header>

      <div className="resource-card__body">
        <div
          className="resource-card__loading"
          role="status"
          aria-live="polite"
        >
          Loading technique details...
        </div>
      </div>
    </section>
  );
}

/* ============================================================================
 * Error State
 * ========================================================================== */

interface ErrorStateProps {
  error: string;

  onBack?: () => void;
}

function ErrorState({
  error,
  onBack,
}: ErrorStateProps) {
  return (
    <section
      className="resource-card mitre-technique-details"
      aria-label="MITRE ATT&CK technique details"
      role="alert"
    >
      <header className="resource-card__header">
        <div>
          <h2 className="resource-card__title">
            Technique Details
          </h2>

          <p className="resource-card__description">
            Unable to load the requested technique.
          </p>
        </div>
      </header>

      <div className="resource-card__body">
        <p className="resource-card__error">
          {error}
        </p>

        {onBack && (
          <button
            type="button"
            className="mitre-technique-details__back"
            onClick={
              onBack
            }
          >
            ← Back to techniques
          </button>
        )}
      </div>
    </section>
  );
}

/* ============================================================================
 * Empty State
 * ========================================================================== */

function EmptyState({
  onBack,
}: {
  onBack?: () => void;
}) {
  return (
    <section
      className="resource-card mitre-technique-details"
      aria-label="MITRE ATT&CK technique details"
    >
      <header className="resource-card__header">
        <div>
          <h2 className="resource-card__title">
            Technique Details
          </h2>

          <p className="resource-card__description">
            Select a MITRE ATT&amp;CK technique to inspect
            its security intelligence.
          </p>
        </div>
      </header>

      <div className="resource-card__body">
        <div className="resource-card__empty">
          No technique selected.
        </div>

        {onBack && (
          <button
            type="button"
            className="mitre-technique-details__back"
            onClick={
              onBack
            }
          >
            ← Back to techniques
          </button>
        )}
      </div>
    </section>
  );
}

/* ============================================================================
 * Detail Metric
 * ========================================================================== */

interface DetailMetricProps {
  label: string;

  value: number | string;
}

function DetailMetric({
  label,
  value,
}: DetailMetricProps) {
  return (
    <div className="mitre-technique-details__metric">
      <span className="mitre-technique-details__metric-label">
        {label}
      </span>

      <strong className="mitre-technique-details__metric-value">
        {value}
      </strong>
    </div>
  );
}

/* ============================================================================
 * Detail Section
 * ========================================================================== */

interface DetailSectionProps {
  title: string;

  children: ReactNode;
}

function DetailSection({
  title,
  children,
}: DetailSectionProps) {
  return (
    <section className="mitre-technique-details__section">
      <h3 className="mitre-technique-details__heading">
        {title}
      </h3>

      {children}
    </section>
  );
}

/* ============================================================================
 * Field
 * ========================================================================== */

interface DetailFieldProps {
  label: string;

  children: ReactNode;
}

function DetailField({
  label,
  children,
}: DetailFieldProps) {
  return (
    <div className="mitre-technique-details__field">
      <span className="mitre-technique-details__label">
        {label}
      </span>

      <span className="mitre-technique-details__value">
        {children}
      </span>
    </div>
  );
}

/* ============================================================================
 * Component
 * ========================================================================== */

export function TechniqueDetails({
  technique,
  loading = false,
  error = null,
  onBack,
}: TechniqueDetailsProps) {
  /* --------------------------------------------------------------------------
   * Loading
   * ------------------------------------------------------------------------ */

  if (loading) {
    return <LoadingState />;
  }

  /* --------------------------------------------------------------------------
   * Error
   * ------------------------------------------------------------------------ */

  if (error) {
    return (
      <ErrorState
        error={error}
        onBack={onBack}
      />
    );
  }

  /* --------------------------------------------------------------------------
   * Empty
   * ------------------------------------------------------------------------ */

  if (!technique) {
    return (
      <EmptyState
        onBack={onBack}
      />
    );
  }

  /* --------------------------------------------------------------------------
   * Backend entities
   * ------------------------------------------------------------------------ */

  const techniqueData =
    technique.technique;

  const coverage =
    technique.coverage;

  /* --------------------------------------------------------------------------
   * Backend-authoritative coverage
   * ------------------------------------------------------------------------ */

  /**
   * The coverage state is consumed exactly as returned by the backend.
   */
  const coverageState =
    coverage.state;

  const coverageText =
    getCoverageLabel(
      coverageState,
    );

  const mappingCount =
    safeNumber(
      coverage.mapping_count,
    );

  const detectionCount =
    safeNumber(
      coverage.detection_count,
    );

  const subtechniqueCount =
    safeNumber(
      coverage.subtechnique_count,
    );

  const mappedSubtechniqueCount =
    safeNumber(
      coverage.mapped_subtechnique_count,
    );

  const confidence =
    formatConfidence(
      coverage.confidence,
    );

  /* --------------------------------------------------------------------------
   * Related data
   * ------------------------------------------------------------------------ */

  const tacticIds =
    uniqueStrings(
      safeArray(
        techniqueData.tactic_ids,
      ),
    );

  const platformIds =
    uniqueStrings(
      safeArray(
        techniqueData.platform_ids,
      ),
    );

  const platforms =
    safeArray(
      techniqueData.platforms,
    );

  const mappings =
    safeArray(
      technique.mappings,
    );

  const detectionIds =
    uniqueStrings(
      safeArray(
        technique.detection_ids,
      ),
    );

  const eventIds =
    uniqueStrings(
      safeArray(
        technique.event_ids,
      ),
    );

  const alertIds =
    uniqueStrings(
      safeArray(
        technique.alert_ids,
      ),
    );

  const incidentIds =
    uniqueStrings(
      safeArray(
        technique.incident_ids,
      ),
    );

  const iocIds =
    uniqueStrings(
      safeArray(
        technique.ioc_ids,
      ),
    );

  const assetIds =
    uniqueStrings(
      safeArray(
        technique.asset_ids,
      ),
    );

  const subtechniques =
    safeArray(
      technique.subtechniques,
    );

  /* --------------------------------------------------------------------------
   * Technique identity
   * ------------------------------------------------------------------------ */

  const techniqueIdentifier =
    displayId(
      techniqueData.external_id,
    ) ||
    displayId(
      techniqueData.id,
    );

  const techniqueType =
    techniqueData.type ===
    "SUB_TECHNIQUE"
      ? TECHNIQUE_TYPE_LABELS.SUB_TECHNIQUE
      : TECHNIQUE_TYPE_LABELS.TECHNIQUE;

  /* ==========================================================================
   * Render
   * ======================================================================== */

  return (
    <section
      className="resource-card mitre-technique-details"
      aria-label={`MITRE ATT&CK technique ${techniqueIdentifier}`}
    >
      {/* ====================================================================
       * Header
       * ================================================================== */}

      <header className="resource-card__header">
        <div>
          {onBack && (
            <button
              type="button"
              className="mitre-technique-details__back"
              onClick={
                onBack
              }
            >
              ← Back to techniques
            </button>
          )}

          <div className="mitre-technique-details__title-row">
            <div>
              <h2 className="resource-card__title">
                {techniqueData.name}
              </h2>

              <p className="resource-card__description">
                MITRE ATT&amp;CK technique intelligence
              </p>
            </div>

            <code className="mitre-technique-details__id">
              {techniqueIdentifier}
            </code>
          </div>
        </div>

        <span
          className={[
            "mitre-technique-details__status",
            getCoverageClass(
              coverageState,
            ),
          ].join(" ")}
          aria-label={`Coverage: ${coverageText}`}
        >
          {coverageText}
        </span>
      </header>

      {/* ====================================================================
       * Body
       * ================================================================== */}

      <div className="resource-card__body">

        {/* ==================================================================
         * Overview
         * ================================================================ */}

        <DetailSection title="Overview">
          <div className="mitre-technique-details__overview">

            <DetailField label="Technique ID">
              <code>
                {techniqueIdentifier}
              </code>
            </DetailField>

            <DetailField label="Technique">
              {techniqueData.name}
            </DetailField>

            <DetailField label="Type">
              {techniqueType}
            </DetailField>

            <DetailField label="Coverage">
              <span
                className={[
                  "mitre-technique-details__coverage-badge",
                  getCoverageClass(
                    coverageState,
                  ),
                ].join(" ")}
              >
                {coverageText}
              </span>
            </DetailField>

          </div>

          {techniqueData.description ? (
            <p className="mitre-technique-details__description">
              {techniqueData.description}
            </p>
          ) : (
            <p className="mitre-technique-details__muted">
              No technique description is available.
            </p>
          )}
        </DetailSection>

        {/* ==================================================================
         * Tactics
         * ================================================================ */}

        <DetailSection title="Tactics">
          {tacticIds.length === 0 ? (
            <p className="mitre-technique-details__muted">
              No tactics are associated with this technique.
            </p>
          ) : (
            <div className="mitre-technique-details__tactic-ids">
              {tacticIds.map(
                (tacticId) => (
                  <code
                    key={
                      tacticId
                    }
                    className="mitre-technique-details__tactic-id"
                  >
                    {tacticId}
                  </code>
                ),
              )}
            </div>
          )}
        </DetailSection>

        {/* ==================================================================
         * Platforms
         * ================================================================ */}

        <DetailSection title="Platforms">
          {platforms.length === 0 &&
          platformIds.length === 0 ? (
            <p className="mitre-technique-details__muted">
              No platform information is available for this technique.
            </p>
          ) : (
            <div className="mitre-technique-details__platforms">

              {platforms.map(
                (platform, index) => {
                  const platformName =
                    typeof platform ===
                    "string"
                      ? normalizeString(
                          platform,
                        )
                      : normalizeString(
                          platform?.name,
                        );

                  const platformKey =
                    typeof platform ===
                    "string"
                      ? platform
                      : platform?.id ??
                        platform?.external_id ??
                        `${platformName}-${index}`;

                  if (!platformName) {
                    return null;
                  }

                  return (
                    <span
                      key={
                        platformKey
                      }
                      className="mitre-platform-chip"
                    >
                      {
                        platformName
                      }
                    </span>
                  );
                },
              )}

              {platformIds.map(
                (platformId) => (
                  <code
                    key={
                      `id-${platformId}`
                    }
                    className="mitre-technique-details__platform-id"
                  >
                    {platformId}
                  </code>
                ),
              )}

            </div>
          )}
        </DetailSection>

        {/* ==================================================================
         * Coverage
         * ================================================================ */}

        <DetailSection title="Coverage">
          <div className="mitre-technique-details__coverage-panel">

            <div className="mitre-technique-details__coverage-summary">
              <span
                className={[
                  "mitre-technique-details__coverage-badge",
                  getCoverageClass(
                    coverageState,
                  ),
                ].join(" ")}
              >
                {coverageText}
              </span>

              <span className="mitre-technique-details__coverage-summary-text">
                {coverageState ===
                "full"
                  ? "Backend reports full detection coverage for this technique."
                  : coverageState ===
                      "partial"
                    ? "Backend reports partial detection coverage for this technique."
                    : "Backend reports no current detection mapping for this technique."}
              </span>
            </div>

            <div className="mitre-technique-details__metrics">

              <DetailMetric
                label="Mappings"
                value={
                  formatCount(
                    mappingCount,
                  )
                }
              />

              <DetailMetric
                label="Detections"
                value={
                  formatCount(
                    detectionCount,
                  )
                }
              />

              <DetailMetric
                label="Sub-techniques"
                value={
                  formatCount(
                    subtechniqueCount,
                  )
                }
              />

              <DetailMetric
                label="Mapped Sub-techniques"
                value={
                  formatCount(
                    mappedSubtechniqueCount,
                  )
                }
              />

              <DetailMetric
                label="Confidence"
                value={
                  confidence
                }
              />

            </div>
          </div>
        </DetailSection>

        {/* ==================================================================
         * Sub-techniques
         * ================================================================ */}

        <DetailSection title="Sub-techniques">
          {subtechniques.length === 0 ? (
            <p className="mitre-technique-details__muted">
              No sub-techniques are registered under this technique.
            </p>
          ) : (
            <div className="mitre-technique-details__subtechniques">
              {subtechniques.map(
                (subtechnique) => {
                  /**
                   * Operational mapping relationship only.
                   *
                   * This does NOT establish global sub-technique coverage.
                   */
                  const isMapped =
                    mappings.some(
                      (mapping) =>
                        mapping.subtechnique_id ===
                        subtechnique.id ||
                        mapping.subtechnique_id ===
                        subtechnique.external_id,
                    );

                  const subtechniqueIdentifier =
                    displayId(
                      subtechnique.external_id,
                    ) ||
                    displayId(
                      subtechnique.id,
                    );

                  return (
                    <article
                      key={
                        subtechnique.id
                      }
                      className="mitre-technique-details__subtechnique"
                    >
                      <div className="mitre-technique-details__subtechnique-header">
                        <div>
                          <code>
                            {
                              subtechniqueIdentifier
                            }
                          </code>

                          <strong>
                            {
                              subtechnique.name
                            }
                          </strong>
                        </div>

                        <span
                          className={[
                            "mitre-technique-details__coverage-badge",
                            getCoverageClass(
                              isMapped
                                ? "full"
                                : "unmapped",
                            ),
                          ].join(" ")}
                        >
                          {isMapped
                            ? "Mapped"
                            : "Unmapped"}
                        </span>
                      </div>

                      {subtechnique.description && (
                        <p className="mitre-technique-details__subtechnique-description">
                          {
                            subtechnique.description
                          }
                        </p>
                      )}

                      {subtechnique.tactic_ids.length >
                        0 && (
                        <div className="mitre-technique-details__subtechnique-tactics">
                          {uniqueStrings(
                            subtechnique.tactic_ids,
                          ).map(
                            (tacticId) => (
                              <code
                                key={
                                  tacticId
                                }
                              >
                                {
                                  tacticId
                                }
                              </code>
                            ),
                          )}
                        </div>
                      )}
                    </article>
                  );
                },
              )}
            </div>
          )}
        </DetailSection>

        {/* ==================================================================
         * Detection Rules
         * ================================================================ */}

        <DetailSection title="Detection Rules">
          <ReferenceList
            items={
              detectionIds
            }
            emptyMessage="No detection rules are currently linked to this technique."
          />
        </DetailSection>

        {/* ==================================================================
         * Detection Mappings
         * ================================================================ */}

        <DetailSection title="Detection Mappings">
          {mappings.length === 0 ? (
            <p className="mitre-technique-details__muted">
              No SentinelSIEM detection mappings are currently associated
              with this technique.
            </p>
          ) : (
            <div className="mitre-technique-details__mapping-list">
              {mappings.map(
                (mapping) => {
                  const mappingTacticIds =
                    uniqueStrings(
                      safeArray(
                        mapping.tactic_ids,
                      ),
                    );

                  const mappingTechniqueId =
                    displayId(
                      mapping.technique_id,
                    );

                  const mappingSubtechniqueId =
                    displayId(
                      mapping.subtechnique_id,
                    );

                  const mappingDetectionId =
                    displayId(
                      mapping.detection_id,
                    );

                  return (
                    <article
                      key={
                        mapping.mapping_id
                      }
                      className="mitre-technique-details__mapping"
                    >
                      {/* --------------------------------------------------
                       * Mapping header
                       * ------------------------------------------------ */}

                      <div className="mitre-technique-details__mapping-header">
                        <code>
                          {
                            mapping.mapping_id
                          }
                        </code>

                        <span>
                          {
                            formatConfidence(
                              mapping.confidence,
                            )
                          }{" "}
                          confidence
                        </span>
                      </div>

                      {/* --------------------------------------------------
                       * Detection
                       * ------------------------------------------------ */}

                      <div className="mitre-technique-details__mapping-field">
                        <span>
                          Detection
                        </span>

                        <code>
                          {
                            mappingDetectionId ||
                            "—"
                          }
                        </code>
                      </div>

                      {/* --------------------------------------------------
                       * Technique
                       * ------------------------------------------------ */}

                      <div className="mitre-technique-details__mapping-field">
                        <span>
                          Technique
                        </span>

                        <code>
                          {
                            mappingTechniqueId ||
                            "—"
                          }
                        </code>
                      </div>

                      {/* --------------------------------------------------
                       * Sub-technique
                       * ------------------------------------------------ */}

                      {mappingSubtechniqueId && (
                        <div className="mitre-technique-details__mapping-field">
                          <span>
                            Sub-technique
                          </span>

                          <code>
                            {
                              mappingSubtechniqueId
                            }
                          </code>
                        </div>
                      )}

                      {/* --------------------------------------------------
                       * Tactics
                       * ------------------------------------------------ */}

                      {mappingTacticIds.length >
                        0 && (
                        <div className="mitre-technique-details__mapping-field">
                          <span>
                            Tactics
                          </span>

                          <span>
                            {
                              formatIdentifierList(
                                mappingTacticIds,
                              )
                            }
                          </span>
                        </div>
                      )}

                      {/* --------------------------------------------------
                       * Source
                       * ------------------------------------------------ */}

                      {mapping.source && (
                        <div className="mitre-technique-details__mapping-field">
                          <span>
                            Source
                          </span>

                          <span>
                            {
                              mapping.source
                            }
                          </span>
                        </div>
                      )}

                      {/* --------------------------------------------------
                       * Created
                       * ------------------------------------------------ */}

                      {mapping.created_at && (
                        <div className="mitre-technique-details__mapping-field">
                          <span>
                            Created
                          </span>

                          <time
                            dateTime={
                              mapping.created_at
                            }
                          >
                            {
                              mapping.created_at
                            }
                          </time>
                        </div>
                      )}

                      {/* --------------------------------------------------
                       * Description
                       * ------------------------------------------------ */}

                      {mapping.description && (
                        <p className="mitre-technique-details__mapping-description">
                          {
                            mapping.description
                          }
                        </p>
                      )}
                    </article>
                  );
                },
              )}
            </div>
          )}
        </DetailSection>

        {/* ==================================================================
         * Events
         * ================================================================ */}

        <DetailSection title="Events">
          <ReferenceList
            items={
              eventIds
            }
            emptyMessage="No events are currently linked to this technique."
          />
        </DetailSection>

        {/* ==================================================================
         * Alerts
         * ================================================================ */}

        <DetailSection title="Alerts">
          <ReferenceList
            items={
              alertIds
            }
            emptyMessage="No alerts are currently linked to this technique."
          />
        </DetailSection>

        {/* ==================================================================
         * Incidents
         * ================================================================ */}

        <DetailSection title="Incidents">
          <ReferenceList
            items={
              incidentIds
            }
            emptyMessage="No incidents are currently linked to this technique."
          />
        </DetailSection>

        {/* ==================================================================
         * IOCs
         * ================================================================ */}

        <DetailSection title="Related IOCs">
          <ReferenceList
            items={
              iocIds
            }
            emptyMessage="No IOCs are currently linked to this technique."
          />
        </DetailSection>

        {/* ==================================================================
         * Assets
         * ================================================================ */}

        <DetailSection title="Affected Assets">
          <ReferenceList
            items={
              assetIds
            }
            emptyMessage="No assets are currently linked to this technique."
          />
        </DetailSection>

        {/* ==================================================================
         * Relationship Summary
         * ================================================================ */}

        <DetailSection title="Relationship Summary">
          <div className="mitre-technique-details__metrics">

            <DetailMetric
              label="Detection Rules"
              value={
                detectionIds.length
              }
            />

            <DetailMetric
              label="Events"
              value={
                eventIds.length
              }
            />

            <DetailMetric
              label="Alerts"
              value={
                alertIds.length
              }
            />

            <DetailMetric
              label="Incidents"
              value={
                incidentIds.length
              }
            />

            <DetailMetric
              label="IOCs"
              value={
                iocIds.length
              }
            />

            <DetailMetric
              label="Assets"
              value={
                assetIds.length
              }
            />

          </div>
        </DetailSection>

      </div>
    </section>
  );
}

/* ============================================================================
 * Default Export
 * ========================================================================== */

export default TechniqueDetails;

/* ============================================================================
 * End of File
 * ============================================================================
 */