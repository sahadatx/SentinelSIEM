/**
 * ============================================================================
 * SentinelSIEM — MITRE ATT&CK Module Page
 * ============================================================================
 *
 * Purpose
 * -------
 * Read-only MITRE ATT&CK security knowledge and SentinelSIEM intelligence
 * workspace.
 *
 * Authoritative Backend Sources
 * -----------------------------
 * GET /api/v1/mitre/statistics
 *     -> MITRE dataset statistics
 *
 * GET /api/v1/mitre/tactics
 *     -> ATT&CK tactics
 *
 * GET /api/v1/mitre/platforms
 *     -> ATT&CK platforms
 *
 * GET /api/v1/mitre/techniques
 *     -> server-side filtered/paginated technique inventory
 *
 * GET /api/v1/mitre/techniques/{id}/detail
 *     -> lazy-loaded technique intelligence
 *
 * Architecture
 * ------------
 * - MITRE knowledge is strictly read-only.
 * - No MITRE knowledge CRUD exists here.
 * - Backend is authoritative.
 * - Statistics come directly from /statistics.
 * - Technique filtering is server-side.
 * - Technique pagination is server-side.
 * - Technique details are lazy-loaded.
 * - No frontend MITRE statistics calculation.
 * - No frontend MITRE coverage calculation.
 * - No fabricated coverage objects.
 * - Detection-to-MITRE mappings remain operational SentinelSIEM data.
 *
 * Canonical Technique Filters
 * ---------------------------
 * - search
 * - tactic
 * - platform
 * - type
 * - coverage
 *
 * IMPORTANT
 * ---------
 * - There is NO tactic_id.
 * - Filter changes reset the technique page to 1.
 * - The table never locally filters paginated results.
 * - MITRE statistics are never calculated in the browser.
 * - MITRE coverage summary is intentionally not rendered on this page.
 *
 * ============================================================================
 */

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import "../Mitre.css";

import MitreStatsCards from "../components/MitreStatsCards";
import TechniqueDetails from "../components/TechniqueDetails";
import TechniqueTable from "../components/TechniqueTable";

import { mitreApi } from "../api";

import type {
  MitrePlatform,
  MitreStatistics,
  MitreTactic,
  MitreTechnique,
  MitreTechniqueDetail,
  MitreTechniqueFilters,
  MitreTechniqueQuery,
} from "../types";

/* ============================================================================
 * Constants
 * ========================================================================== */

const DEFAULT_PAGE = 1;
const DEFAULT_PAGE_SIZE = 30;

/* ============================================================================
 * Error Helpers
 * ========================================================================== */

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    const message = error.message.trim();

    if (message) {
      return message;
    }
  }

  if (typeof error === "string") {
    const message = error.trim();

    if (message) {
      return message;
    }
  }

  return "Unable to load MITRE ATT&CK data.";
}

/* ============================================================================
 * Collection Normalizers
 * ========================================================================== */

function normalizeTechniques(value: unknown): MitreTechnique[] {
  if (Array.isArray(value)) {
    return value.filter(
      (item): item is MitreTechnique =>
        Boolean(item && typeof item === "object"),
    );
  }

  if (value && typeof value === "object") {
    const candidate = value as {
      items?: unknown;
    };

    if (Array.isArray(candidate.items)) {
      return candidate.items.filter(
        (item): item is MitreTechnique =>
          Boolean(item && typeof item === "object"),
      );
    }
  }

  return [];
}

function normalizeTactics(value: unknown): MitreTactic[] {
  if (Array.isArray(value)) {
    return value.filter(
      (item): item is MitreTactic =>
        Boolean(item && typeof item === "object"),
    );
  }

  if (value && typeof value === "object") {
    const candidate = value as {
      items?: unknown;
    };

    if (Array.isArray(candidate.items)) {
      return candidate.items.filter(
        (item): item is MitreTactic =>
          Boolean(item && typeof item === "object"),
      );
    }
  }

  return [];
}

function normalizePlatforms(value: unknown): MitrePlatform[] {
  if (Array.isArray(value)) {
    return value.filter(
      (item): item is MitrePlatform =>
        Boolean(item && typeof item === "object"),
    );
  }

  if (value && typeof value === "object") {
    const candidate = value as {
      items?: unknown;
    };

    if (Array.isArray(candidate.items)) {
      return candidate.items.filter(
        (item): item is MitrePlatform =>
          Boolean(item && typeof item === "object"),
      );
    }
  }

  return [];
}

/* ============================================================================
 * Filter Helpers
 * ========================================================================== */

function normalizeFilters(
  filters: MitreTechniqueFilters,
): MitreTechniqueFilters {
  const normalized: MitreTechniqueFilters = {};

  const search =
    typeof filters.search === "string"
      ? filters.search.trim()
      : "";

  if (search) {
    normalized.search = search;
  }

  const tactic =
    typeof filters.tactic === "string"
      ? filters.tactic.trim()
      : "";

  if (tactic) {
    normalized.tactic = tactic;
  }

  const platform =
    typeof filters.platform === "string"
      ? filters.platform.trim()
      : "";

  if (platform) {
    normalized.platform = platform;
  }

  if (
    filters.type === "TECHNIQUE" ||
    filters.type === "SUB_TECHNIQUE"
  ) {
    normalized.type = filters.type;
  }

  if (
    filters.coverage === "full" ||
    filters.coverage === "partial" ||
    filters.coverage === "unmapped"
  ) {
    normalized.coverage = filters.coverage;
  }

  return normalized;
}

function getFilterKey(
  filters: MitreTechniqueFilters,
): string {
  return JSON.stringify(normalizeFilters(filters));
}

/* ============================================================================
 * Pagination Helpers
 * ========================================================================== */

function normalizePositiveInteger(
  value: unknown,
  fallback: number,
): number {
  const numeric = Number(value);

  if (!Number.isFinite(numeric)) {
    return fallback;
  }

  return Math.max(1, Math.floor(numeric));
}

function normalizeNonNegativeInteger(
  value: unknown,
): number {
  const numeric = Number(value);

  if (!Number.isFinite(numeric)) {
    return 0;
  }

  return Math.max(0, Math.floor(numeric));
}

function getPageStart(
  page: number,
  pageSize: number,
  total: number,
): number {
  if (total <= 0) {
    return 0;
  }

  return (page - 1) * pageSize + 1;
}

function getPageEnd(
  page: number,
  pageSize: number,
  total: number,
): number {
  if (total <= 0) {
    return 0;
  }

  return Math.min(page * pageSize, total);
}

/* ============================================================================
 * Component
 * ========================================================================== */

export function MitrePage() {
  /* ==========================================================================
   * Authoritative Statistics
   * ======================================================================== */

  const [statistics, setStatistics] =
    useState<MitreStatistics | null>(null);

  /* ==========================================================================
   * Reference Data
   * ======================================================================== */

  const [tactics, setTactics] =
    useState<MitreTactic[]>([]);

  const [platforms, setPlatforms] =
    useState<MitrePlatform[]>([]);

  /* ==========================================================================
   * Technique Data
   * ======================================================================== */

  const [techniques, setTechniques] =
    useState<MitreTechnique[]>([]);

  /* ==========================================================================
   * Pagination
   * ======================================================================== */

  const [techniquePage, setTechniquePage] =
    useState(DEFAULT_PAGE);

  const [techniquePageSize, setTechniquePageSize] =
    useState(DEFAULT_PAGE_SIZE);

  const [techniqueTotal, setTechniqueTotal] =
    useState(0);

  const [techniqueTotalPages, setTechniqueTotalPages] =
    useState(0);

  /* ==========================================================================
   * Loading
   * ======================================================================== */

  const [workspaceLoading, setWorkspaceLoading] =
    useState(true);

  const [techniquesLoading, setTechniquesLoading] =
    useState(false);

  const [detailLoading, setDetailLoading] =
    useState(false);

  /* ==========================================================================
   * Errors
   * ======================================================================== */

  const [workspaceError, setWorkspaceError] =
    useState<string | null>(null);

  const [techniquesError, setTechniquesError] =
    useState<string | null>(null);

  const [detailError, setDetailError] =
    useState<string | null>(null);

  /* ==========================================================================
   * Filters
   * ======================================================================== */

  const [filters, setFilters] =
    useState<MitreTechniqueFilters>({});

  /* ==========================================================================
   * Detail Drawer
   * ======================================================================== */

  const [selectedTechniqueId, setSelectedTechniqueId] =
    useState<string | null>(null);

  const [selectedTechnique, setSelectedTechnique] =
    useState<MitreTechniqueDetail | null>(null);

  /* ==========================================================================
   * Request Sequencing
   * ======================================================================== */

  const detailRequestSequence =
    useRef(0);

  const techniqueRequestSequence =
    useRef(0);

  const workspaceRequestSequence =
    useRef(0);

  /* ==========================================================================
   * Load Workspace
   *
   * IMPORTANT:
   * Statistics are loaded directly from /statistics.
   *
   * The page does not use:
   * - legacy overview
   * - frontend calculations
   * - CoverageCard
   * - matrix-derived statistics
   * ======================================================================== */

  const loadWorkspace = useCallback(async () => {
    const requestId =
      ++workspaceRequestSequence.current;

    setWorkspaceLoading(true);
    setWorkspaceError(null);

    try {
      const [
        statisticsResponse,
        tacticsResponse,
        platformsResponse,
      ] = await Promise.all([
        mitreApi.getStatistics(),
        mitreApi.listTactics(),
        mitreApi.listPlatforms(),
      ]);

      if (
        requestId !==
        workspaceRequestSequence.current
      ) {
        return;
      }

      setStatistics(statisticsResponse);

      setTactics(
        normalizeTactics(tacticsResponse),
      );

      setPlatforms(
        normalizePlatforms(platformsResponse),
      );
    } catch (requestError) {
      if (
        requestId !==
        workspaceRequestSequence.current
      ) {
        return;
      }

      setWorkspaceError(
        getErrorMessage(requestError),
      );
    } finally {
      if (
        requestId ===
        workspaceRequestSequence.current
      ) {
        setWorkspaceLoading(false);
      }
    }
  }, []);

  /* ==========================================================================
   * Load Techniques
   * ======================================================================== */

  const loadTechniques = useCallback(
    async (
      requestedFilters: MitreTechniqueFilters,
      page: number,
      pageSize: number,
    ) => {
      const requestId =
        ++techniqueRequestSequence.current;

      setTechniquesLoading(true);
      setTechniquesError(null);

      const normalizedFilters =
        normalizeFilters(requestedFilters);

      const normalizedPage =
        normalizePositiveInteger(
          page,
          DEFAULT_PAGE,
        );

      const normalizedPageSize =
        normalizePositiveInteger(
          pageSize,
          DEFAULT_PAGE_SIZE,
        );

      const query: MitreTechniqueQuery = {
        ...normalizedFilters,
        page: normalizedPage,
        page_size: normalizedPageSize,
      };

      try {
        const response =
          await mitreApi.listTechniques(query);

        if (
          requestId !==
          techniqueRequestSequence.current
        ) {
          return;
        }

        const responsePage =
          normalizePositiveInteger(
            response.pagination?.page,
            normalizedPage,
          );

        const responsePageSize =
          normalizePositiveInteger(
            response.pagination?.page_size,
            normalizedPageSize,
          );

        const responseTotal =
          normalizeNonNegativeInteger(
            response.pagination?.total,
          );

        const responseTotalPages =
          normalizeNonNegativeInteger(
            response.pagination?.total_pages,
          );

        setTechniques(
          normalizeTechniques(response.items),
        );

        setTechniquePage(responsePage);
        setTechniquePageSize(responsePageSize);
        setTechniqueTotal(responseTotal);
        setTechniqueTotalPages(
          responseTotalPages,
        );
      } catch (requestError) {
        if (
          requestId !==
          techniqueRequestSequence.current
        ) {
          return;
        }

        setTechniques([]);
        setTechniqueTotal(0);
        setTechniqueTotalPages(0);

        setTechniquesError(
          getErrorMessage(requestError),
        );
      } finally {
        if (
          requestId ===
          techniqueRequestSequence.current
        ) {
          setTechniquesLoading(false);
        }
      }
    },
    [],
  );

  /* ==========================================================================
   * Initial Workspace
   * ======================================================================== */

  useEffect(() => {
    void loadWorkspace();
  }, [loadWorkspace]);

  /* ==========================================================================
   * Stable Filters
   * ======================================================================== */

  const filterKey = useMemo(
    () => getFilterKey(filters),
    [filters],
  );

  const normalizedFilters = useMemo(
    () => normalizeFilters(filters),
    [filterKey],
  );

  /* ==========================================================================
   * Technique Request
   * ======================================================================== */

  useEffect(() => {
    void loadTechniques(
      normalizedFilters,
      techniquePage,
      techniquePageSize,
    );
  }, [
    filterKey,
    normalizedFilters,
    techniquePage,
    techniquePageSize,
    loadTechniques,
  ]);

  /* ==========================================================================
   * Technique Selection
   * ======================================================================== */

  const handleTechniqueSelect =
    useCallback(
      async (technique: MitreTechnique) => {
        const techniqueId =
          typeof technique.external_id === "string" &&
          technique.external_id.trim()
            ? technique.external_id.trim()
            : technique.id.trim();

        if (!techniqueId) {
          return;
        }

        const requestId =
          ++detailRequestSequence.current;

        setSelectedTechniqueId(
          techniqueId,
        );

        setSelectedTechnique(null);
        setDetailError(null);
        setDetailLoading(true);

        try {
          const detail =
            await mitreApi.getTechniqueDetail(
              techniqueId,
            );

          if (
            requestId !==
            detailRequestSequence.current
          ) {
            return;
          }

          setSelectedTechnique(detail);
        } catch (requestError) {
          if (
            requestId !==
            detailRequestSequence.current
          ) {
            return;
          }

          setDetailError(
            getErrorMessage(requestError),
          );
        } finally {
          if (
            requestId ===
            detailRequestSequence.current
          ) {
            setDetailLoading(false);
          }
        }
      },
      [],
    );

  /* ==========================================================================
   * Close Drawer
   * ======================================================================== */

  const handleCloseDrawer = useCallback(() => {
    detailRequestSequence.current += 1;

    setSelectedTechniqueId(null);
    setSelectedTechnique(null);
    setDetailError(null);
    setDetailLoading(false);
  }, []);

  /* ==========================================================================
   * Escape Key
   * ======================================================================== */

  useEffect(() => {
    if (!selectedTechniqueId) {
      return;
    }

    const handleKeyDown = (
      event: KeyboardEvent,
    ) => {
      if (event.key === "Escape") {
        handleCloseDrawer();
      }
    };

    window.addEventListener(
      "keydown",
      handleKeyDown,
    );

    return () => {
      window.removeEventListener(
        "keydown",
        handleKeyDown,
      );
    };
  }, [
    selectedTechniqueId,
    handleCloseDrawer,
  ]);

  /* ==========================================================================
   * Body Scroll Lock
   * ======================================================================== */

  useEffect(() => {
    if (!selectedTechniqueId) {
      return;
    }

    const originalOverflow =
      document.body.style.overflow;

    document.body.style.overflow = "hidden";

    return () => {
      document.body.style.overflow =
        originalOverflow;
    };
  }, [selectedTechniqueId]);

  /* ==========================================================================
   * Filter Changes
   * ======================================================================== */

  const handleFiltersChange =
    useCallback(
      (
        nextFilters: MitreTechniqueFilters,
      ) => {
        const normalized =
          normalizeFilters(nextFilters);

        setFilters(normalized);
        setTechniquePage(DEFAULT_PAGE);
      },
      [],
    );

  /* ==========================================================================
   * Pagination
   * ======================================================================== */

  const handlePreviousPage =
    useCallback(() => {
      if (techniquePage <= DEFAULT_PAGE) {
        return;
      }

      setTechniquePage(
        (currentPage) =>
          Math.max(
            DEFAULT_PAGE,
            currentPage - 1,
          ),
      );
    }, [techniquePage]);

  const handleNextPage =
    useCallback(() => {
      if (techniqueTotalPages <= 0) {
        return;
      }

      setTechniquePage(
        (currentPage) =>
          Math.min(
            techniqueTotalPages,
            currentPage + 1,
          ),
      );
    }, [techniqueTotalPages]);

  /* ==========================================================================
   * Refresh
   * ======================================================================== */

  const handleRefresh = useCallback(
    async () => {
      await Promise.all([
        loadWorkspace(),
        loadTechniques(
          normalizedFilters,
          techniquePage,
          techniquePageSize,
        ),
      ]);
    },
    [
      loadWorkspace,
      loadTechniques,
      normalizedFilters,
      techniquePage,
      techniquePageSize,
    ],
  );

  /* ==========================================================================
   * Pagination Display
   * ======================================================================== */

  const pageStart = getPageStart(
    techniquePage,
    techniquePageSize,
    techniqueTotal,
  );

  const pageEnd = getPageEnd(
    techniquePage,
    techniquePageSize,
    techniqueTotal,
  );

  const canGoPrevious =
    techniquePage > DEFAULT_PAGE;

  const canGoNext =
    techniqueTotalPages > 0 &&
    techniquePage < techniqueTotalPages;

  /* ==========================================================================
   * Statistics State
   * ======================================================================== */

  const statisticsLoading =
    workspaceLoading &&
    statistics === null;

  const statisticsError =
    statistics === null
      ? workspaceError
      : null;

  /* ==========================================================================
   * Render
   * ======================================================================== */

  return (
    <main
      className="page mitre-page"
      aria-labelledby="mitre-page-title"
    >
      {/* =====================================================================
       * Header
       * =================================================================== */}

      <header className="page__header mitre-page__header">
        <div className="mitre-page__header-content">
          <h1 id="mitre-page-title">
            MITRE ATT&amp;CK
          </h1>

          <p className="page__description">
            Threat intelligence and ATT&amp;CK
            technique knowledge.
          </p>
        </div>

        <button
          type="button"
          className="mitre-page__refresh"
          onClick={() => {
            void handleRefresh();
          }}
          disabled={
            workspaceLoading ||
            techniquesLoading
          }
          aria-label="Refresh MITRE ATT&CK data"
        >
          {workspaceLoading ||
          techniquesLoading
            ? "Refreshing..."
            : "Refresh"}
        </button>
      </header>

      {/* =====================================================================
       * Workspace Error
       * =================================================================== */}

      {workspaceError && (
        <div
          className="mitre-page__error"
          role="alert"
        >
          {workspaceError}
        </div>
      )}

      {/* =====================================================================
       * Authoritative Statistics
       *
       * IMPORTANT:
       * This is the ONLY summary card section on this page.
       *
       * Values come directly from:
       *
       *     GET /api/v1/mitre/statistics
       *
       * No frontend calculation is performed.
       * =================================================================== */}

      <section
        className="mitre-page__statistics"
        aria-label="MITRE ATT&CK statistics"
      >
        <MitreStatsCards
          statistics={statistics}
          loading={statisticsLoading}
          error={statisticsError}
        />
      </section>

      {/* =====================================================================
       * Technique Workspace
       * =================================================================== */}

      <section
        className="mitre-page__techniques"
        aria-label="MITRE ATT&CK technique inventory"
      >
        <TechniqueTable
          items={techniques}
          tactics={tactics}
          platforms={platforms}
          loading={techniquesLoading}
          error={techniquesError}
          filters={filters}
          onFiltersChange={
            handleFiltersChange
          }
          onTechniqueSelect={
            handleTechniqueSelect
          }
        />

        {/* ================================================================
         * Pagination
         * ============================================================== */}

        {!techniquesLoading &&
          !techniquesError &&
          techniqueTotal > 0 && (
            <nav
              className="mitre-technique-pagination"
              aria-label="MITRE ATT&CK technique pagination"
            >
              <div className="mitre-technique-pagination__summary">
                <span>
                  {pageStart}–
                  {pageEnd} Techniques
                </span>

                <span>
                  {" "}
                  / {techniqueTotal}
                </span>
              </div>

              <div className="mitre-technique-pagination__controls">
                <span aria-live="polite">
                  Page {techniquePage} of{" "}
                  {techniqueTotalPages}
                </span>

                <button
                  type="button"
                  className="mitre-technique-pagination__button"
                  onClick={
                    handlePreviousPage
                  }
                  disabled={
                    !canGoPrevious ||
                    techniquesLoading
                  }
                >
                  Previous
                </button>

                <button
                  type="button"
                  className="mitre-technique-pagination__button"
                  onClick={
                    handleNextPage
                  }
                  disabled={
                    !canGoNext ||
                    techniquesLoading
                  }
                >
                  Next
                </button>
              </div>
            </nav>
          )}

        {/* ================================================================
         * Empty State
         * ============================================================== */}

        {!techniquesLoading &&
          !techniquesError &&
          techniqueTotal === 0 && (
            <div
              className="mitre-technique-pagination__empty"
              role="status"
            >
              No MITRE ATT&amp;CK techniques
              match the current filters.
            </div>
          )}
      </section>

      {/* =====================================================================
       * Technique Detail Drawer
       * =================================================================== */}

      {selectedTechniqueId && (
        <>
          <button
            type="button"
            className="mitre-technique-drawer__backdrop"
            aria-label="Close technique details"
            onClick={
              handleCloseDrawer
            }
          />

          <aside
            className="mitre-technique-drawer"
            aria-label="MITRE ATT&CK technique details"
            aria-modal="true"
            role="dialog"
          >
            <header className="mitre-technique-drawer__header">
              <div>
                <span className="mitre-technique-drawer__eyebrow">
                  MITRE ATT&amp;CK
                </span>

                <h2 className="mitre-technique-drawer__title">
                  Technique Details
                </h2>
              </div>

              <button
                type="button"
                className="mitre-technique-drawer__close"
                onClick={
                  handleCloseDrawer
                }
                aria-label="Close technique details"
                title="Close"
              >
                ×
              </button>
            </header>

            <div className="mitre-technique-drawer__body">
              <TechniqueDetails
                technique={selectedTechnique}
                loading={detailLoading}
                error={detailError}
                onBack={
                  handleCloseDrawer
                }
              />
            </div>
          </aside>
        </>
      )}
    </main>
  );
}

export default MitrePage;