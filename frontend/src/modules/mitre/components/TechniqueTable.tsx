/**
 * ============================================================================
 * SentinelSIEM — MITRE ATT&CK Technique Table
 * ============================================================================
 *
 * Purpose
 * -------
 * Read-only presentation of the MITRE ATT&CK technique inventory.
 *
 * Responsibilities
 * ----------------
 * - Display backend-returned techniques.
 * - Display ATT&CK technique metadata.
 * - Expose canonical MITRE filters:
 *     search
 *     tactic
 *     platform
 *     type
 *     coverage
 * - Notify parent when filters change.
 * - Notify parent when a technique is selected.
 * - Display the currently loaded backend page.
 *
 * Architecture
 * ------------
 *
 *                         MITRE API
 *                            │
 *                            ▼
 *                     MitrePage.tsx
 *                            │
 *                  server-side filters
 *                  server-side pagination
 *                            │
 *                            ▼
 *                  TechniqueTable.tsx
 *
 * Filtering and pagination belong to the parent/API layer.
 *
 * This component MUST NOT locally filter the paginated `items`.
 *
 * MITRE knowledge is READ-ONLY.
 *
 * This component does NOT:
 * - create techniques
 * - update techniques
 * - delete techniques
 * - create mappings
 * - update mappings
 * - delete mappings
 * - calculate coverage
 * - calculate global statistics
 * - perform pagination
 *
 * Canonical filter contract:
 * - search
 * - tactic
 * - platform
 * - type
 * - coverage
 *
 * There is intentionally NO `tactic_id`.
 *
 * ============================================================================
 */

import {
  useMemo,
  type ChangeEvent,
} from "react";

import type {
  MitreCoverageState,
  MitrePlatform,
  MitreTactic,
  MitreTechnique,
  MitreTechniqueFilters,
} from "../types";


/* ============================================================================
 * Props
 * ========================================================================== */

export interface TechniqueTableProps {
  /**
   * Backend-returned techniques.
   *
   * This collection represents ONLY the currently loaded server page.
   */
  items: MitreTechnique[];

  /**
   * Backend-provided ATT&CK tactics.
   */
  tactics?: MitreTactic[];

  /**
   * Backend-provided ATT&CK platform catalog.
   */
  platforms?: MitrePlatform[];

  /**
   * Technique request loading state.
   */
  loading?: boolean;

  /**
   * Technique request error.
   */
  error?: string | null;

  /**
   * Current canonical filters.
   */
  filters: MitreTechniqueFilters;

  /**
   * Notify parent about filter changes.
   *
   * Parent owns:
   * - filter normalization
   * - pagination reset
   * - backend request
   * - result replacement
   */
  onFiltersChange: (
    filters: MitreTechniqueFilters,
  ) => void;

  /**
   * Notify parent about technique selection.
   */
  onTechniqueSelect: (
    technique: MitreTechnique,
  ) => void;
}


/* ============================================================================
 * Constants
 * ========================================================================== */

const COVERAGE_STATES: readonly MitreCoverageState[] = [
  "full",
  "partial",
  "unmapped",
];

const TECHNIQUE_TYPES = [
  "TECHNIQUE",
  "SUB_TECHNIQUE",
] as const;

type TechniqueType =
  (typeof TECHNIQUE_TYPES)[number];


/* ============================================================================
 * Labels
 * ========================================================================== */

const TYPE_LABELS: Record<
  TechniqueType,
  string
> = {
  TECHNIQUE: "Technique",
  SUB_TECHNIQUE: "Sub-technique",
};


/* ============================================================================
 * Generic Helpers
 * ========================================================================== */

/**
 * Safely normalize an optional string.
 */
function normalizeString(
  value:
    | string
    | null
    | undefined,
): string {
  return typeof value === "string"
    ? value.trim()
    : "";
}


/**
 * Determine whether any canonical filter is active.
 *
 * There is intentionally no `tactic_id`.
 */
function hasActiveFilters(
  filters: MitreTechniqueFilters,
): boolean {
  return Boolean(
    normalizeString(
      filters.search,
    ) ||
      normalizeString(
        filters.tactic,
      ) ||
      normalizeString(
        filters.platform,
      ) ||
      normalizeString(
        filters.type,
      ) ||
      normalizeString(
        filters.coverage,
      ),
  );
}


/* ============================================================================
 * Tactic Helpers
 * ========================================================================== */

/**
 * Return a human-readable tactic label.
 */
function getTacticLabel(
  tactic: MitreTactic,
): string {
  const name =
    normalizeString(
      tactic.name,
    );

  if (name) {
    return name;
  }

  const externalId =
    normalizeString(
      tactic.external_id,
    );

  if (externalId) {
    return externalId;
  }

  return (
    normalizeString(
      tactic.id,
    ) ||
    "Unknown"
  );
}


/**
 * Create tactic lookup map.
 *
 * Supports:
 * - PostgreSQL/internal UUID
 * - MITRE external ID
 */
function createTacticMap(
  tactics: MitreTactic[],
): Map<
  string,
  MitreTactic
> {
  const map =
    new Map<
      string,
      MitreTactic
    >();

  for (
    const tactic of tactics
  ) {
    const id =
      normalizeString(
        tactic.id,
      );

    if (id) {
      map.set(
        id,
        tactic,
      );

      map.set(
        id.toLowerCase(),
        tactic,
      );
    }

    const externalId =
      normalizeString(
        tactic.external_id,
      );

    if (externalId) {
      map.set(
        externalId,
        tactic,
      );

      map.set(
        externalId.toLowerCase(),
        tactic,
      );
    }
  }

  return map;
}


/**
 * Resolve technique tactic IDs to human-readable labels.
 */
function resolveTacticLabels(
  technique: MitreTechnique,
  tacticMap: Map<
    string,
    MitreTactic
  >,
): Array<{
  id: string;
  label: string;
}> {
  const result: Array<{
    id: string;
    label: string;
  }> = [];

  const tacticIds =
    Array.isArray(
      technique.tactic_ids,
    )
      ? technique.tactic_ids
      : [];

  for (
    const tacticId of tacticIds
  ) {
    const normalizedId =
      normalizeString(
        tacticId,
      );

    if (!normalizedId) {
      continue;
    }

    const tactic =
      tacticMap.get(
        normalizedId,
      ) ??
      tacticMap.get(
        normalizedId.toLowerCase(),
      );

    result.push({
      id: normalizedId,
      label:
        tactic
          ? getTacticLabel(
              tactic,
            )
          : normalizedId,
    });
  }

  return result;
}


/**
 * Remove duplicate tactic entries while preserving order.
 */
function uniqueTactics(
  entries: Array<{
    id: string;
    label: string;
  }>,
): Array<{
  id: string;
  label: string;
}> {
  const seen =
    new Set<string>();

  const result: Array<{
    id: string;
    label: string;
  }> = [];

  for (
    const entry of entries
  ) {
    const key =
      entry.id.toLowerCase();

    if (
      seen.has(
        key,
      )
    ) {
      continue;
    }

    seen.add(
      key,
    );

    result.push(
      entry,
    );
  }

  return result;
}


/* ============================================================================
 * Platform Helpers
 * ========================================================================== */

/**
 * Platform values can appear as:
 *
 * - string
 * - MitrePlatform
 *
 * The canonical frontend technique contract uses string[].
 *
 * This runtime helper tolerates object values so older/generated runtime
 * responses do not break rendering.
 */
type TechniquePlatformValue =
  | string
  | MitrePlatform;


/**
 * Create platform lookup map.
 */
function createPlatformMap(
  platforms: MitrePlatform[],
): Map<
  string,
  MitrePlatform
> {
  const map =
    new Map<
      string,
      MitrePlatform
    >();

  for (
    const platform of platforms
  ) {
    const id =
      normalizeString(
        platform.id,
      );

    if (id) {
      map.set(
        id,
        platform,
      );

      map.set(
        id.toLowerCase(),
        platform,
      );
    }

    const name =
      normalizeString(
        platform.name,
      );

    if (name) {
      map.set(
        name,
        platform,
      );

      map.set(
        name.toLowerCase(),
        platform,
      );
    }
  }

  return map;
}


/**
 * Normalize a runtime platform value.
 */
function normalizeTechniquePlatformValue(
  platform: TechniquePlatformValue,
): string {
  if (
    typeof platform === "string"
  ) {
    return normalizeString(
      platform,
    );
  }

  return (
    normalizeString(
      platform.name,
    ) ||
    normalizeString(
      platform.id,
    )
  );
}


/**
 * Resolve technique platforms to display values.
 *
 * Backend-provided technique platform names are preferred.
 *
 * If no platform names are available, platform IDs are resolved using the
 * backend-provided platform catalog.
 *
 * No filtering is performed here.
 */
function resolveTechniquePlatforms(
  technique: MitreTechnique,
  platformMap: Map<
    string,
    MitrePlatform
  >,
): Array<{
  value: string;
  label: string;
}> {
  const result: Array<{
    value: string;
    label: string;
  }> = [];

  const existingPlatforms =
    Array.isArray(
      technique.platforms,
    )
      ? (
          technique.platforms as unknown as TechniquePlatformValue[]
        )
      : [];

  for (
    const platform of existingPlatforms
  ) {
    const value =
      normalizeTechniquePlatformValue(
        platform,
      );

    if (!value) {
      continue;
    }

    const catalogPlatform =
      platformMap.get(
        value,
      ) ??
      platformMap.get(
        value.toLowerCase(),
      );

    result.push({
      value,
      label:
        catalogPlatform?.name ??
        value,
    });
  }

  /**
   * If no platform names are available, resolve platform IDs.
   */
  if (
    result.length === 0
  ) {
    const platformIds =
      Array.isArray(
        technique.platform_ids,
      )
        ? technique.platform_ids
        : [];

    for (
      const platformId of platformIds
    ) {
      const value =
        normalizeString(
          platformId,
        );

      if (!value) {
        continue;
      }

      const catalogPlatform =
        platformMap.get(
          value,
        ) ??
        platformMap.get(
          value.toLowerCase(),
        );

      result.push({
        value,
        label:
          catalogPlatform?.name ??
          value,
      });
    }
  }

  /**
   * Deduplicate while preserving order.
   */
  const seen =
    new Set<string>();

  return result.filter(
    (
      platform,
    ) => {
      const key =
        platform.value.toLowerCase();

      if (
        seen.has(
          key,
        )
      ) {
        return false;
      }

      seen.add(
        key,
      );

      return true;
    },
  );
}


/**
 * Build platform selector options.
 *
 * Primary source:
 *   backend platform catalog
 *
 * Fallback:
 *   currently loaded technique page
 *
 * This function does NOT filter the technique list.
 */
function getPlatformOptions(
  platforms: MitrePlatform[],
  items: MitreTechnique[],
): Array<{
  value: string;
  label: string;
}> {
  const options =
    new Map<
      string,
      {
        value: string;
        label: string;
      }
    >();

  /**
   * Prefer authoritative backend platform catalog.
   */
  for (
    const platform of platforms
  ) {
    const value =
      normalizeString(
        platform.id,
      ) ||
      normalizeString(
        platform.name,
      );

    const label =
      normalizeString(
        platform.name,
      ) ||
      value;

    if (!value) {
      continue;
    }

    const key =
      value.toLowerCase();

    if (
      !options.has(
        key,
      )
    ) {
      options.set(
        key,
        {
          value,
          label,
        },
      );
    }
  }

  /**
   * Fallback to values already present on the current backend page.
   */
  if (
    options.size === 0
  ) {
    const emptyPlatformMap =
      new Map<
        string,
        MitrePlatform
      >();

    for (
      const technique of items
    ) {
      const resolved =
        resolveTechniquePlatforms(
          technique,
          emptyPlatformMap,
        );

      for (
        const platform of resolved
      ) {
        const value =
          normalizeString(
            platform.value,
          );

        if (!value) {
          continue;
        }

        const key =
          value.toLowerCase();

        if (
          !options.has(
            key,
          )
        ) {
          options.set(
            key,
            {
              value,
              label:
                platform.label ||
                value,
            },
          );
        }
      }
    }
  }

  return Array.from(
    options.values(),
  ).sort(
    (
      first,
      second,
    ) =>
      first.label.localeCompare(
        second.label,
      ),
  );
}


/* ============================================================================
 * Component
 * ========================================================================== */

export function TechniqueTable({
  items,
  tactics = [],
  platforms = [],
  loading = false,
  error = null,
  filters,
  onFiltersChange,
  onTechniqueSelect,
}: TechniqueTableProps) {
  /* ==========================================================================
   * Lookup Maps
   * ======================================================================== */

  const tacticMap =
    useMemo(
      () =>
        createTacticMap(
          tactics,
        ),
      [tactics],
    );

  const platformMap =
    useMemo(
      () =>
        createPlatformMap(
          platforms,
        ),
      [platforms],
    );


  /* ==========================================================================
   * Backend Page
   * ======================================================================== */

  /**
   * `items` is already the backend-selected page.
   *
   * Never locally:
   * - search
   * - filter
   * - paginate
   */
  const displayItems =
    items;


  /* ==========================================================================
   * Platform Options
   * ======================================================================== */

  const platformOptions =
    useMemo(
      () =>
        getPlatformOptions(
          platforms,
          displayItems,
        ),
      [
        platforms,
        displayItems,
      ],
    );


  /* ==========================================================================
   * Filter Handlers
   * ======================================================================== */

  const handleSearchChange = (
    event: ChangeEvent<HTMLInputElement>,
  ) => {
    const value =
      event.target.value;

    onFiltersChange({
      ...filters,
      search:
        value.trim().length > 0
          ? value
          : undefined,
    });
  };


  const handleTacticChange = (
    event: ChangeEvent<HTMLSelectElement>,
  ) => {
    const value =
      event.target.value.trim();

    onFiltersChange({
      ...filters,
      tactic:
        value || undefined,
    });
  };


  const handlePlatformChange = (
    event: ChangeEvent<HTMLSelectElement>,
  ) => {
    const value =
      event.target.value.trim();

    onFiltersChange({
      ...filters,
      platform:
        value || undefined,
    });
  };


  const handleTypeChange = (
    event: ChangeEvent<HTMLSelectElement>,
  ) => {
    const value =
      event.target.value;

    const type =
      TECHNIQUE_TYPES.includes(
        value as TechniqueType,
      )
        ? (
            value as TechniqueType
          )
        : undefined;

    onFiltersChange({
      ...filters,
      type,
    });
  };


  const handleCoverageChange = (
    event: ChangeEvent<HTMLSelectElement>,
  ) => {
    const value =
      event.target.value;

    const coverage =
      COVERAGE_STATES.includes(
        value as MitreCoverageState,
      )
        ? (
            value as MitreCoverageState
          )
        : undefined;

    onFiltersChange({
      ...filters,
      coverage,
    });
  };


  const handleReset = () => {
    onFiltersChange({});
  };


  /* ==========================================================================
   * Selection
   * ======================================================================== */

  const handleTechniqueSelect = (
    technique: MitreTechnique,
  ) => {
    onTechniqueSelect(
      technique,
    );
  };


  /* ==========================================================================
   * Active Filter State
   * ======================================================================== */

  const activeFilters =
    hasActiveFilters(
      filters,
    );


  /* ==========================================================================
   * Render
   * ======================================================================== */

  return (
    <section
      className="mitre-technique-table"
      aria-label="MITRE ATT&CK techniques"
    >
      {/* ====================================================================
       * Header
       * ================================================================== */}

      <header
        className="mitre-technique-table-header"
      >
        <div>
          <h2>
            MITRE ATT&amp;CK Techniques
          </h2>

          <p>
            Browse ATT&amp;CK techniques and
            technique knowledge.
          </p>
        </div>

        <div
          className="mitre-technique-counts"
          aria-label="Current backend page"
        >
          <span>
            <strong>
              {
                displayItems.length
              }
            </strong>{" "}
            Loaded
          </span>
        </div>
      </header>


      {/* ====================================================================
       * Filters
       * ================================================================== */}

      <div
        className="mitre-technique-filters"
        role="search"
        aria-label="MITRE ATT&CK technique filters"
      >
        {/* ------------------------------------------------------------------
         * Search
         * ---------------------------------------------------------------- */}

        <div
          className="mitre-filter-field mitre-filter-search"
        >
          <label
            htmlFor="mitre-technique-search"
          >
            Search
          </label>

          <input
            id="mitre-technique-search"
            type="search"
            value={
              filters.search ??
              ""
            }
            onChange={
              handleSearchChange
            }
            placeholder="Search technique ID, name, or description..."
            autoComplete="off"
            spellCheck={false}
            aria-label="Search MITRE techniques"
          />
        </div>


        {/* ------------------------------------------------------------------
         * Tactic
         * ---------------------------------------------------------------- */}

        <div
          className="mitre-filter-field"
        >
          <label
            htmlFor="mitre-technique-tactic"
          >
            Tactic
          </label>

          <select
            id="mitre-technique-tactic"
            value={
              filters.tactic ??
              ""
            }
            onChange={
              handleTacticChange
            }
          >
            <option value="">
              All Tactics
            </option>

            {tactics.map(
              (
                tactic,
              ) => {
                const value =
                  normalizeString(
                    tactic.external_id,
                  ) ||
                  normalizeString(
                    tactic.id,
                  );

                if (!value) {
                  return null;
                }

                return (
                  <option
                    key={
                      tactic.id
                    }
                    value={
                      value
                    }
                  >
                    {
                      getTacticLabel(
                        tactic,
                      )
                    }
                  </option>
                );
              },
            )}
          </select>
        </div>


        {/* ------------------------------------------------------------------
         * Platform
         * ---------------------------------------------------------------- */}

        <div
          className="mitre-filter-field"
        >
          <label
            htmlFor="mitre-technique-platform"
          >
            Platform
          </label>

          <select
            id="mitre-technique-platform"
            value={
              filters.platform ??
              ""
            }
            onChange={
              handlePlatformChange
            }
          >
            <option value="">
              All Platforms
            </option>

            {platformOptions.map(
              (
                platform,
              ) => (
                <option
                  key={
                    platform.value
                  }
                  value={
                    platform.value
                  }
                >
                  {
                    platform.label
                  }
                </option>
              ),
            )}
          </select>
        </div>


        {/* ------------------------------------------------------------------
         * Type
         * ---------------------------------------------------------------- */}

        <div
          className="mitre-filter-field"
        >
          <label
            htmlFor="mitre-technique-type"
          >
            Type
          </label>

          <select
            id="mitre-technique-type"
            value={
              filters.type ??
              ""
            }
            onChange={
              handleTypeChange
            }
          >
            <option value="">
              All Types
            </option>

            <option value="TECHNIQUE">
              {
                TYPE_LABELS.TECHNIQUE
              }
            </option>

            <option value="SUB_TECHNIQUE">
              {
                TYPE_LABELS.SUB_TECHNIQUE
              }
            </option>
          </select>
        </div>


        {/* ------------------------------------------------------------------
         * Coverage
         * ---------------------------------------------------------------- */}

        <div
          className="mitre-filter-field"
        >
          <label
            htmlFor="mitre-technique-coverage"
          >
            Coverage
          </label>

          <select
            id="mitre-technique-coverage"
            value={
              filters.coverage ??
              ""
            }
            onChange={
              handleCoverageChange
            }
          >
            <option value="">
              All Coverage
            </option>

            <option value="full">
              Full
            </option>

            <option value="partial">
              Partial
            </option>

            <option value="unmapped">
              Unmapped
            </option>
          </select>
        </div>


        {/* ------------------------------------------------------------------
         * Reset
         * ---------------------------------------------------------------- */}

        <button
          type="button"
          className="mitre-filter-reset"
          onClick={
            handleReset
          }
          disabled={
            !activeFilters
          }
        >
          Reset
        </button>
      </div>


      {/* ====================================================================
       * Loading
       * ================================================================== */}

      {loading && (
        <div
          className="mitre-table-state"
          role="status"
          aria-live="polite"
        >
          <div
            className="mitre-table-spinner"
            aria-hidden="true"
          />

          <span>
            Loading MITRE ATT&amp;CK
            techniques...
          </span>
        </div>
      )}


      {/* ====================================================================
       * Error
       * ================================================================== */}

      {!loading &&
        error && (
          <div
            className="mitre-table-state mitre-table-error"
            role="alert"
          >
            <strong>
              Unable to load MITRE
              ATT&amp;CK techniques
            </strong>

            <span>
              {error}
            </span>
          </div>
        )}


      {/* ====================================================================
       * Empty
       * ================================================================== */}

      {!loading &&
        !error &&
        displayItems.length ===
          0 && (
          <div
            className="mitre-table-state"
            role="status"
          >
            <strong>
              No MITRE ATT&amp;CK techniques found
            </strong>

            <span>
              {activeFilters
                ? "Try changing or resetting the selected filters."
                : "No MITRE ATT&CK techniques are currently available."}
            </span>
          </div>
        )}


      {/* ====================================================================
       * Table
       * ================================================================== */}

      {!loading &&
        !error &&
        displayItems.length >
          0 && (
          <div
            className="mitre-table-wrapper"
          >
            <table
              className="mitre-technique-table-grid"
            >
              <thead>
                <tr>
                  <th scope="col">
                    Technique
                  </th>

                  <th scope="col">
                    Type
                  </th>

                  <th scope="col">
                    Tactic
                  </th>

                  <th scope="col">
                    Platform
                  </th>

                  <th scope="col">
                    Description
                  </th>

                  <th scope="col">
                    Action
                  </th>
                </tr>
              </thead>

              <tbody>
                {displayItems.map(
                  (
                    technique,
                  ) => {
                    /* ======================================================
                     * Identity
                     * ==================================================== */

                    const techniqueId =
                      normalizeString(
                        technique.external_id,
                      ) ||
                      normalizeString(
                        technique.id,
                      ) ||
                      "Unknown";

                    const techniqueName =
                      normalizeString(
                        technique.name,
                      ) ||
                      "Unnamed technique";


                    /* ======================================================
                     * Type
                     * ==================================================== */

                    const techniqueType =
                      technique.type;

                    const typeLabel =
                      TYPE_LABELS[
                        techniqueType
                      ] ??
                      techniqueType;


                    /* ======================================================
                     * Tactics
                     * ==================================================== */

                    const tacticsForTechnique =
                      uniqueTactics(
                        resolveTacticLabels(
                          technique,
                          tacticMap,
                        ),
                      );


                    /* ======================================================
                     * Platforms
                     * ==================================================== */

                    const platformsForTechnique =
                      resolveTechniquePlatforms(
                        technique,
                        platformMap,
                      );


                    /* ======================================================
                     * Description
                     * ==================================================== */

                    const description =
                      normalizeString(
                        technique.description,
                      );


                    /* ======================================================
                     * Row
                     * ==================================================== */

                    return (
                      <tr
                        key={
                          technique.id
                        }
                        className="mitre-technique-row"
                        onClick={() =>
                          handleTechniqueSelect(
                            technique,
                          )
                        }
                      >
                        {/* =================================================
                         * Technique
                         * =============================================== */}

                        <td>
                          <button
                            type="button"
                            className="mitre-technique-name-button"
                            onClick={(
                              event,
                            ) => {
                              event.stopPropagation();

                              handleTechniqueSelect(
                                technique,
                              );
                            }}
                            aria-label={`View ${techniqueId} ${techniqueName}`}
                            title={
                              description ||
                              `View ${techniqueId} ${techniqueName}`
                            }
                          >
                            <span className="mitre-technique-id">
                              {
                                techniqueId
                              }
                            </span>

                            <span className="mitre-technique-name">
                              {
                                techniqueName
                              }
                            </span>
                          </button>
                        </td>


                        {/* =================================================
                         * Type
                         * =============================================== */}

                        <td>
                          <span
                            className={[
                              "mitre-technique-type",
                              `mitre-technique-type-${techniqueType.toLowerCase()}`,
                            ].join(" ")}
                          >
                            {
                              typeLabel
                            }
                          </span>
                        </td>


                        {/* =================================================
                         * Tactic
                         * =============================================== */}

                        <td>
                          <div
                            className="mitre-technique-tactics"
                          >
                            {tacticsForTechnique.length >
                            0 ? (
                              tacticsForTechnique.map(
                                (
                                  tactic,
                                ) => (
                                  <span
                                    key={`${technique.id}-${tactic.id}`}
                                    className="mitre-tactic-chip"
                                    title={
                                      tactic.id
                                    }
                                  >
                                    {
                                      tactic.label
                                    }
                                  </span>
                                ),
                              )
                            ) : (
                              <span className="mitre-muted">
                                —
                              </span>
                            )}
                          </div>
                        </td>


                        {/* =================================================
                         * Platform
                         * =============================================== */}

                        <td>
                          <div
                            className="mitre-technique-platforms"
                          >
                            {platformsForTechnique.length >
                            0 ? (
                              platformsForTechnique.map(
                                (
                                  platform,
                                ) => (
                                  <span
                                    key={`${technique.id}-${platform.value}`}
                                    className="mitre-platform-chip"
                                  >
                                    {
                                      platform.label
                                    }
                                  </span>
                                ),
                              )
                            ) : (
                              <span className="mitre-muted">
                                —
                              </span>
                            )}
                          </div>
                        </td>


                        {/* =================================================
                         * Description
                         * =============================================== */}

                        <td>
                          <div
                            className="mitre-technique-description-cell"
                            title={
                              description ||
                              undefined
                            }
                          >
                            {
                              description ||
                              "—"
                            }
                          </div>
                        </td>


                        {/* =================================================
                         * Action
                         * =============================================== */}

                        <td>
                          <button
                            type="button"
                            className="mitre-view-button"
                            onClick={(
                              event,
                            ) => {
                              event.stopPropagation();

                              handleTechniqueSelect(
                                technique,
                              );
                            }}
                            aria-label={`View details for ${techniqueId}`}
                          >
                            View
                          </button>
                        </td>
                      </tr>
                    );
                  },
                )}
              </tbody>
            </table>
          </div>
        )}
    </section>
  );
}


/* ============================================================================
 * Default Export
 * ========================================================================== */

export default TechniqueTable;


/* ============================================================================
 * End of File
 * ============================================================================
 */