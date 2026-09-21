/**
 * ============================================================================
 * SentinelSIEM — Threat Intelligence
 * ============================================================================
 *
 * Professional SOC Threat Intelligence workspace.
 *
 * Final workflow:
 *
 *   IOC Inventory
 *        ↓
 *   Search / Filter
 *        ↓
 *   View / Edit / Enable / Disable
 *        ↓
 *   Backend Validation
 *        ↓
 *   Audit
 *        ↓
 *   Refresh Inventory
 *
 * Product contract:
 *   - Backend is the source of truth.
 *   - KPI values come from the backend summary endpoint.
 *   - Filter catalogue values come from backend summary catalogue maps.
 *   - No frontend KPI calculation.
 *   - No frontend total-pages calculation.
 *   - No Delete IOC workflow.
 *   - Create/Edit never sends status.
 *   - Enable/Disable uses dedicated backend lifecycle operations.
 *   - Manage controls are gated by iocs:manage.
 * ============================================================================
 */

import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type Dispatch,
  type FormEvent,
  type SetStateAction,
} from "react";

import "../ThreatIntelligence.css";

import { Panel } from "../../../components/ui/Panel";

import { useAuthStore } from "../../../store/auth";

import { IOCTable } from "../components/IOCTable";

import { threatIntelligenceApi } from "../api";

import {
  THREAT_INTELLIGENCE_MANAGE,
} from "../permissions";

import type {
  IOC,
  IOCDetail,
  IOCFilterOptions,
  IOCListFilters,
  IOCSeverity,
  IOCType,
  IOCCreateRequest,
  IOCReputation,
  IOCSummary,
} from "../types";

/* ============================================================================
 * Constants
 * ========================================================================== */

const DEFAULT_PAGE = 1;
const DEFAULT_PAGE_SIZE = 30;

/* ============================================================================
 * Filter State
 * ========================================================================== */

interface FilterState {
  query: string;
  type: string;
  severity: string;
  status: string;
  source: string;
  reputation: string;
}

const EMPTY_FILTERS: FilterState = {
  query: "",
  type: "",
  severity: "",
  status: "",
  source: "",
  reputation: "",
};

/* ============================================================================
 * Add / Edit Forms
 * ========================================================================== */

interface IOCFormState {
  value: string;
  type: string;
  severity: string;
  reputation: string;
  source: string;
  description: string;
  tags: string;
  expiration: string;
}

const EMPTY_FORM: IOCFormState = {
  value: "",
  type: "",
  severity: "",
  reputation: "",
  source: "",
  description: "",
  tags: "",
  expiration: "",
};

/* ============================================================================
 * Threat Intelligence Page
 * ========================================================================== */

export default function ThreatIntelligence() {
  /* --------------------------------------------------------------------------
   * Authorization
   * ------------------------------------------------------------------------ */

  const hasPermission = useAuthStore(
    (state) => state.hasPermission,
  );

  const canManage = hasPermission(
    THREAT_INTELLIGENCE_MANAGE,
  );

  /* --------------------------------------------------------------------------
   * Inventory
   * ------------------------------------------------------------------------ */

  const [iocs, setIOCs] = useState<IOC[]>([]);
  const [total, setTotal] = useState(0);

  const [page, setPage] = useState(
    DEFAULT_PAGE,
  );

  const [pageSize] = useState(
    DEFAULT_PAGE_SIZE,
  );

  /*
   * The backend owns total_pages.
   *
   * Current shared Pagination may not expose total_pages yet, so the value is
   * read defensively without calculating it in the browser.
   */
  const [totalPages, setTotalPages] =
    useState(0);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState<string | null>(null);

  /* --------------------------------------------------------------------------
   * Backend Summary / KPI
   * ------------------------------------------------------------------------ */

  const [summary, setSummary] =
    useState<IOCSummary | null>(null);

  const [summaryLoading, setSummaryLoading] =
    useState(true);

  /* --------------------------------------------------------------------------
   * Filters
   * ------------------------------------------------------------------------ */

  const [filters, setFilters] =
    useState<FilterState>(
      EMPTY_FILTERS,
    );

  /* --------------------------------------------------------------------------
   * View Drawer
   * ------------------------------------------------------------------------ */

  const [selectedIOC, setSelectedIOC] =
    useState<IOCDetail | null>(null);

  const [detailsLoading, setDetailsLoading] =
    useState(false);

  const [detailsError, setDetailsError] =
    useState<string | null>(null);

  /* --------------------------------------------------------------------------
   * Add Drawer
   * ------------------------------------------------------------------------ */

  const [addDrawerOpen, setAddDrawerOpen] =
    useState(false);

  const [addLoading, setAddLoading] =
    useState(false);

  const [addError, setAddError] =
    useState<string | null>(null);

  const [addForm, setAddForm] =
    useState<IOCFormState>(
      EMPTY_FORM,
    );

  /* --------------------------------------------------------------------------
   * Edit Drawer
   * ------------------------------------------------------------------------ */

  const [editDrawerOpen, setEditDrawerOpen] =
    useState(false);

  const [editingIOC, setEditingIOC] =
    useState<IOC | null>(null);

  const [editLoading, setEditLoading] =
    useState(false);

  const [editError, setEditError] =
    useState<string | null>(null);

  const [editForm, setEditForm] =
    useState<IOCFormState>(
      EMPTY_FORM,
    );

  /* --------------------------------------------------------------------------
   * Enable / Disable Confirmation
   * ------------------------------------------------------------------------ */

  const [statusActionIOC, setStatusActionIOC] =
    useState<IOC | null>(null);

  const [statusActionLoading, setStatusActionLoading] =
    useState(false);

  const [statusActionError, setStatusActionError] =
    useState<string | null>(null);

  /* ==========================================================================
   * Backend Filter Catalogue
   *
   * IMPORTANT:
   *   Create/Edit/filter dropdowns must not derive their options from the
   *   currently visible IOC records or summary count maps.
   *
   *   The dedicated backend /filter-options endpoint is authoritative and
   *   returns the complete IOC catalogue, including options that currently
   *   have zero records.
   * ======================================================================== */

  const [filterOptions, setFilterOptions] =
    useState<IOCFilterOptions | null>(null);

  const [filterOptionsLoading, setFilterOptionsLoading] =
    useState(true);

  const availableTypes =
    filterOptions?.types ?? [];

  const availableSeverities =
    filterOptions?.severities ?? [];

  const availableStatuses =
    filterOptions?.statuses ?? [];

  const availableSources =
    filterOptions?.sources ?? [];

  const availableReputations =
    filterOptions?.reputations ?? [];

  /* ==========================================================================
   * API Loading
   * ======================================================================== */

  const loadIOCs = useCallback(
    async (
      nextPage: number,
      nextFilters: FilterState,
    ): Promise<void> => {
      try {
        setLoading(true);
        setError(null);

        const params: IOCListFilters = {
          query:
            nextFilters.query.trim() ||
            undefined,

          type:
            nextFilters.type
              ? (nextFilters.type as IOCType) : undefined,

          severity:
            nextFilters.severity
              ? (nextFilters.severity as IOCSeverity) : undefined,

          status:
            nextFilters.status || undefined,

          source:
            nextFilters.source.trim() ||
            undefined,

          reputation:
            nextFilters.reputation
              ? (nextFilters.reputation as IOCReputation) : undefined,

          page: nextPage,
          page_size: pageSize,
        };

        const response =
          await threatIntelligenceApi.listWithFilters(
            params,
          );

        setIOCs(
          response.items ?? [],
        );

        setTotal(
          response.pagination?.total ?? 0,
        );

        const backendPage =
          response.pagination?.page ??
          nextPage;

        setPage(backendPage);

        /*
         * Do not calculate total_pages.
         *
         * The current shared pagination type exposes page/page_size/total.
         * The runtime backend may expose total_pages as an additional field.
         * If it does, use it directly.
         */
        const pagination =
          response.pagination as unknown as {
            total_pages?: unknown;
          };

        const backendTotalPages =


          pagination.total_pages;



        const normalizedTotalPages =


          typeof backendTotalPages === "number"


            ? backendTotalPages


            : typeof backendTotalPages === "string"


              ? Number(backendTotalPages)


              : 0;



        setTotalPages(


          Number.isFinite(


            normalizedTotalPages,


          ) &&


            normalizedTotalPages > 0


            ? normalizedTotalPages


            : 0,


        );
      } catch (err: unknown) {
        setIOCs([]);
        setTotal(0);
        setTotalPages(0);

        setError(
          err instanceof Error
            ? err.message
            : "Failed to load threat intelligence.",
        );
      } finally {
        setLoading(false);
      }
    },
    [pageSize],
  );

  const loadSummary = useCallback(
    async (): Promise<void> => {
      try {
        setSummaryLoading(true);

        const result =
          await threatIntelligenceApi.summary();

        setSummary(result);
      } catch (err: unknown) {
        setSummary(null);

        if (
          err instanceof Error &&
          err.message
        ) {
          setError(
            (current) =>
              current ??
              `Failed to load IOC summary: ${err.message}`,
          );
        }
      } finally {
        setSummaryLoading(false);
      }
    },
    [],
  );

  /* ==========================================================================
   * Backend Filter Catalogue Loading
   * ======================================================================== */

  const loadFilterOptions =
    useCallback(
      async (): Promise<void> => {
        try {
          setFilterOptionsLoading(true);

          const result =
            await threatIntelligenceApi.filterOptions();

          setFilterOptions(result);
        } catch (err: unknown) {
          /*
           * Keep the catalogue empty on failure. The page must never invent
           * fallback IOC options in the browser.
           */
          setFilterOptions(null);

          setError(
            (current) =>
              current ??
              (
                err instanceof Error
                  ? `Failed to load IOC filter options: ${err.message}`
                  : "Failed to load IOC filter options."
              ),
          );
        } finally {
          setFilterOptionsLoading(false);
        }
      },
      [],
    );

  /* ==========================================================================
   * Initial Load
   * ======================================================================== */

  useEffect(() => {
    void loadIOCs(
      DEFAULT_PAGE,
      EMPTY_FILTERS,
    );

    void loadSummary();
    void loadFilterOptions();
  }, [
    loadFilterOptions,
    loadIOCs,
    loadSummary,
  ]);

  /* ==========================================================================
   * Refresh
   * ======================================================================== */

  const handleRefresh = useCallback(
    async (): Promise<void> => {
      await Promise.all([
        loadIOCs(
          page,
          filters,
        ),
        loadSummary(),
        loadFilterOptions(),
      ]);
    },
    [
      filters,
      loadFilterOptions,
      loadIOCs,
      loadSummary,
      page,
    ],
  );

  /* ==========================================================================
   * Filters
   * ======================================================================== */

  const handleFilterChange = useCallback(
    (
      key: keyof FilterState,
      value: string,
    ): void => {
      const nextFilters: FilterState = {
        ...filters,
        [key]: value,
      };

      setFilters(nextFilters);
      setPage(DEFAULT_PAGE);

      void loadIOCs(
        DEFAULT_PAGE,
        nextFilters,
      );
    },
    [
      filters,
      loadIOCs,
    ],
  );

  const handleSearchChange =
    useCallback(
      (value: string): void => {
        setFilters(
          (current) => ({
            ...current,
            query: value,
          }),
        );
      },
      [],
    );

  const handleSearchApply =
    useCallback((): void => {
      const nextFilters: FilterState = {
        ...filters,
        query: filters.query.trim(),
      };

      setFilters(nextFilters);
      setPage(DEFAULT_PAGE);

      void loadIOCs(
        DEFAULT_PAGE,
        nextFilters,
      );
    }, [
      filters,
      loadIOCs,
    ]);

  const handleResetFilters =
    useCallback((): void => {
      setFilters(
        EMPTY_FILTERS,
      );

      setPage(
        DEFAULT_PAGE,
      );

      void loadIOCs(
        DEFAULT_PAGE,
        EMPTY_FILTERS,
      );
    }, [loadIOCs]);

  /* ==========================================================================
   * Pagination
   * ======================================================================== */

  const handlePreviousPage =
    useCallback((): void => {
      if (
        loading ||
        page <= DEFAULT_PAGE
      ) {
        return;
      }

      const nextPage =
        page - 1;

      void loadIOCs(
        nextPage,
        filters,
      );
    }, [
      filters,
      loadIOCs,
      loading,
      page,
    ]);

  const handleNextPage =
    useCallback((): void => {
      /*
       * If the backend has not supplied total_pages, do not invent it.
       */
      if (
        loading ||
        totalPages <= 0 ||
        page >= totalPages
      ) {
        return;
      }

      const nextPage =
        page + 1;

      void loadIOCs(
        nextPage,
        filters,
      );
    }, [
      filters,
      loadIOCs,
      loading,
      page,
      totalPages,
    ]);

  /* ==========================================================================
   * View IOC
   * ======================================================================== */

  const handleOpenIOC =
    useCallback(
      async (
        ioc: IOC,
      ): Promise<void> => {
        try {
          setSelectedIOC(null);
          setDetailsError(null);
          setDetailsLoading(true);

          const detail =
            await threatIntelligenceApi.getDetail(
              ioc.id,
            );

          setSelectedIOC(detail);
        } catch (err: unknown) {
          setSelectedIOC(null);

          setDetailsError(
            err instanceof Error
              ? err.message
              : "Failed to load IOC details.",
          );
        } finally {
          setDetailsLoading(false);
        }
      },
      [],
    );

  const handleCloseDetails =
    useCallback((): void => {
      setSelectedIOC(null);
      setDetailsError(null);
    }, []);

  /* ==========================================================================
   * Add IOC
   * ======================================================================== */

  const handleOpenAdd =
    useCallback((): void => {
      if (!canManage) {
        return;
      }

      setAddError(null);

      setAddForm({
        ...EMPTY_FORM,

        type:
          availableTypes[0] ?? "",

        severity:
          availableSeverities[0] ?? "",

        reputation:
          availableReputations[0] ?? "",
      });

      setAddDrawerOpen(true);
    }, [
      availableReputations,
      availableSeverities,
      availableTypes,
      canManage,
    ]);

  const handleCloseAdd =
    useCallback((): void => {
      if (addLoading) {
        return;
      }

      setAddDrawerOpen(false);
      setAddError(null);
    }, [addLoading]);

  const handleCreateIOC =
    useCallback(
      async (
        event: FormEvent<HTMLFormElement>,
      ): Promise<void> => {
        event.preventDefault();

        if (!canManage || filterOptionsLoading) {
          return;
        }

        const value =
          addForm.value.trim();

        if (!value) {
          setAddError(
            "IOC value is required.",
          );
          return;
        }

        if (!addForm.type) {
          setAddError(
            "IOC type is required.",
          );
          return;
        }

        if (!addForm.severity) {
          setAddError(
            "Severity is required.",
          );
          return;
        }

        const payload: IOCCreateRequest = {
          value,

          type:
            addForm.type as IOCType,

          severity:
            addForm.severity as IOCSeverity,

          reputation:
            addForm.reputation
              ? (addForm.reputation as IOCReputation) : undefined,

          source:
            addForm.source.trim() ||
            undefined,

          description:
            addForm.description.trim() ||
            undefined,

          tags:
            addForm.tags
              .split(",")
              .map(
                (tag) => tag.trim(),
              )
              .filter(Boolean),

          expiration:
            addForm.expiration.trim() ||
            undefined,
        };

        try {
          setAddLoading(true);
          setAddError(null);

          await threatIntelligenceApi.create(
            payload,
          );

          setAddDrawerOpen(false);
          setAddForm(EMPTY_FORM);

          await Promise.all([
            loadIOCs(
              DEFAULT_PAGE,
              filters,
            ),
            loadSummary(),
          ]);

          setPage(
            DEFAULT_PAGE,
          );
        } catch (err: unknown) {
          setAddError(
            err instanceof Error
              ? err.message
              : "Failed to create IOC.",
          );
        } finally {
          setAddLoading(false);
        }
      },
      [
        addForm,
        canManage,
        filters,
        loadIOCs,
        loadSummary,
      ],
    );

  /* ==========================================================================
   * Edit IOC
   * ======================================================================== */

  const handleOpenEdit =
    useCallback(
      (ioc: IOC): void => {
        if (!canManage) {
          return;
        }

        setEditingIOC(ioc);
        setEditError(null);

        setEditForm({
          value:
            ioc.value ??
            ioc.indicator ??
            "",

          type:
            ioc.type ?? "",

          severity:
            ioc.severity ?? "",

          reputation:
            ioc.reputation ?? "",

          source:
            ioc.source ?? "",

          description:
            ioc.description ?? "",

          tags:
            Array.isArray(ioc.tags)
              ? ioc.tags.join(", ")
              : "",

          expiration:
            ioc.expiration ?? "",
        });

        setEditDrawerOpen(true);
      },
      [canManage],
    );

  const handleCloseEdit =
    useCallback((): void => {
      if (editLoading) {
        return;
      }

      setEditDrawerOpen(false);
      setEditingIOC(null);
      setEditError(null);
    }, [editLoading]);

  const handleUpdateIOC =
    useCallback(
      async (
        event: FormEvent<HTMLFormElement>,
      ): Promise<void> => {
        event.preventDefault();

        if (
          !canManage ||
          !editingIOC ||
          filterOptionsLoading
        ) {
          return;
        }

        const value =
          editForm.value.trim();

        if (!value) {
          setEditError(
            "IOC value is required.",
          );
          return;
        }

        if (!editForm.type) {
          setEditError(
            "IOC type is required.",
          );
          return;
        }

        if (!editForm.severity) {
          setEditError(
            "Severity is required.",
          );
          return;
        }

        try {
          setEditLoading(true);
          setEditError(null);

          await threatIntelligenceApi.update(
            editingIOC.id,
            {
              value,

              type:
                editForm.type as IOCType,

              severity:
                editForm.severity as IOCSeverity,

              reputation:
                editForm.reputation
                  ? (editForm.reputation as IOCReputation) : undefined,

              source:
                editForm.source.trim() ||
                undefined,

              description:
                editForm.description.trim() ||
                undefined,

              tags:
                editForm.tags
                  .split(",")
                  .map(
                    (tag) =>
                      tag.trim(),
                  )
                  .filter(Boolean),

              expiration:
                editForm.expiration.trim() ||
                undefined,
            },
          );

          setEditDrawerOpen(false);
          setEditingIOC(null);

          await Promise.all([
            loadIOCs(
              page,
              filters,
            ),
            loadSummary(),
          ]);
        } catch (err: unknown) {
          setEditError(
            err instanceof Error
              ? err.message
              : "Failed to update IOC.",
          );
        } finally {
          setEditLoading(false);
        }
      },
      [
        canManage,
        editForm,
        editingIOC,
        filters,
        loadIOCs,
        loadSummary,
        page,
      ],
    );

  /* ==========================================================================
   * Enable / Disable
   * ======================================================================== */

  const handleToggleStatus =
    useCallback(
      (ioc: IOC): void => {
        if (!canManage) {
          return;
        }

        setStatusActionIOC(ioc);
        setStatusActionError(null);
      },
      [canManage],
    );

  const handleCloseStatusAction =
    useCallback((): void => {
      if (statusActionLoading) {
        return;
      }

      setStatusActionIOC(null);
      setStatusActionError(null);
    }, [statusActionLoading]);

  const handleConfirmStatusAction =
    useCallback(
      async (): Promise<void> => {
        if (
          !canManage ||
          !statusActionIOC
        ) {
          return;
        }

        try {
          setStatusActionLoading(true);
          setStatusActionError(null);

          if (
            isActiveStatus(
              statusActionIOC.status,
            )
          ) {
            await threatIntelligenceApi.revoke(
              statusActionIOC.id,
            );
          } else {
            await threatIntelligenceApi.activate(
              statusActionIOC.id,
            );
          }

          setStatusActionIOC(null);

          await Promise.all([
            loadIOCs(
              page,
              filters,
            ),
            loadSummary(),
          ]);
        } catch (err: unknown) {
          setStatusActionError(
            err instanceof Error
              ? err.message
              : "Failed to change IOC status.",
          );
        } finally {
          setStatusActionLoading(false);
        }
      },
      [
        canManage,
        filters,
        loadIOCs,
        loadSummary,
        page,
        statusActionIOC,
      ],
    );

  /* ==========================================================================
   * Backend KPI Values
   * ======================================================================== */

  const totalIOCs =
    summary?.total ?? 0;

  const activeIOCs =
    summary?.active ?? 0;

  const highRiskIOCs =
    summary?.high_risk ?? 0;

  const expiredIOCs =
    summary?.expired ?? 0;

  /* ==========================================================================
   * Pagination Display
   *
   * The backend owns total_pages.
   * The range below is a display position based on the current backend page
   * and page size; it does not calculate total_pages.
   * ======================================================================== */

  const rangeStart =
    total === 0
      ? 0
      : (page - 1) * pageSize + 1;

  const rangeEnd =
    total === 0
      ? 0
      : Math.min(
          page * pageSize,
          total,
        );

  const paginationLabel =
    useMemo(
      () => {
        if (total === 0) {
          return "0 Threats / Total 0";
        }

        return `${rangeStart}–${rangeEnd} Threats / Total ${total.toLocaleString()}`;
      },
      [
        rangeEnd,
        rangeStart,
        total,
      ],
    );

  /* ==========================================================================
   * Render
   * ======================================================================== */

  return (
    <div className="threat-intelligence">
      {/* ======================================================================
       * Header
       * ==================================================================== */}

      <div className="page-heading">
        <div>
          <h2>
            THREAT INTELLIGENCE
          </h2>

          <p>
            Monitor, investigate, and manage
            threat indicators
          </p>
        </div>

        <div className="threat-intelligence-actions">
          {canManage && (
            <button
              type="button"
              className="primary-action"
              onClick={handleOpenAdd}
              disabled={
                addLoading ||
                editLoading ||
                statusActionLoading
              }
            >
              + Add IOC
            </button>
          )}

          <button
            type="button"
            onClick={() => {
              void handleRefresh();
            }}
            disabled={
              loading ||
              summaryLoading
            }
          >
            {loading || summaryLoading
              ? "Refreshing..."
              : "↻ Refresh"}
          </button>
        </div>
      </div>

      {/* ======================================================================
       * KPI
       * ==================================================================== */}

      <div className="threat-intelligence-kpis">
        <KPICard
          label="Total IOCs"
          value={totalIOCs}
          loading={summaryLoading}
        />

        <KPICard
          label="Active IOCs"
          value={activeIOCs}
          loading={summaryLoading}
          tone="accent"
        />

        <KPICard
          label="High Risk"
          value={highRiskIOCs}
          loading={summaryLoading}
          tone="warning"
        />

        <KPICard
          label="Expired"
          value={expiredIOCs}
          loading={summaryLoading}
          tone="danger"
        />
      </div>

      {/* ======================================================================
       * IOC Inventory
       * ==================================================================== */}

      <Panel
        title="IOC Inventory"
        subtitle={
          error
            ? "Threat intelligence data is currently unavailable"
            : `${total.toLocaleString()} ${
                total === 1
                  ? "indicator"
                  : "indicators"
              } available`
        }
      >
        {/* --------------------------------------------------------------------
         * Filters
         * ------------------------------------------------------------------ */}

        <div className="threat-intelligence-filters">
          <div className="threat-intelligence-search">
            <input
              type="search"
              placeholder="Search indicators..."
              value={filters.query}
              onChange={(event) => {
                handleSearchChange(
                  event.target.value,
                );
              }}
              onKeyDown={(event) => {
                if (
                  event.key === "Enter"
                ) {
                  handleSearchApply();
                }
              }}
              onBlur={
                handleSearchApply
              }
              aria-label="Search indicators"
            />
          </div>

          <select
            value={filters.type}
            onChange={(event) => {
              handleFilterChange(
                "type",
                event.target.value,
              );
            }}
            aria-label="IOC Type"
          >
            <option value="">
              Type
            </option>

            {availableTypes.map(
              (type) => (
                <option
                  key={type}
                  value={type}
                >
                  {formatLabel(type)}
                </option>
              ),
            )}
          </select>

          <select
            value={filters.severity}
            onChange={(event) => {
              handleFilterChange(
                "severity",
                event.target.value,
              );
            }}
            aria-label="IOC Severity"
          >
            <option value="">
              Severity
            </option>

            {availableSeverities.map(
              (severity) => (
                <option
                  key={severity}
                  value={severity}
                >
                  {formatLabel(
                    severity,
                  )}
                </option>
              ),
            )}
          </select>

          <select
            value={filters.status}
            onChange={(event) => {
              handleFilterChange(
                "status",
                event.target.value,
              );
            }}
            aria-label="IOC Status"
          >
            <option value="">
              Status
            </option>

            {availableStatuses.map(
              (status) => (
                <option
                  key={status}
                  value={status}
                >
                  {formatLabel(status)}
                </option>
              ),
            )}
          </select>

          <select
            value={filters.source}
            onChange={(event) => {
              handleFilterChange(
                "source",
                event.target.value,
              );
            }}
            aria-label="IOC Source"
          >
            <option value="">
              Source
            </option>

            {availableSources.map(
              (source) => (
                <option
                  key={source}
                  value={source}
                >
                  {source}
                </option>
              ),
            )}
          </select>

          <select
            value={filters.reputation}
            onChange={(event) => {
              handleFilterChange(
                "reputation",
                event.target.value,
              );
            }}
            aria-label="IOC Reputation"
          >
            <option value="">
              Reputation
            </option>

            {availableReputations.map(
              (reputation) => (
                <option
                  key={reputation}
                  value={reputation}
                >
                  {formatLabel(
                    reputation,
                  )}
                </option>
              ),
            )}
          </select>

        </div>

        <div className="threat-intelligence-filter-actions">
          <button
            type="button"
            className="threat-intelligence-filter-reset"
            onClick={
              handleResetFilters
            }
            disabled={
              loading ||
              isFiltersEmpty(filters)
            }
          >
            Reset Filters
          </button>
        </div>

        {filterOptionsLoading && (
          <div className="empty-state">
            <p>
              Loading IOC filter and form options...
            </p>
          </div>
        )}

        {/* --------------------------------------------------------------------
         * Loading
         * ------------------------------------------------------------------ */}

        {loading && (
          <div className="empty-state">
            <p>
              Loading threat intelligence...
            </p>
          </div>
        )}

        {/* --------------------------------------------------------------------
         * Error
         * ------------------------------------------------------------------ */}

        {!loading && error && (
          <div className="empty-state">
            <p>{error}</p>

            <button
              type="button"
              onClick={() => {
                void handleRefresh();
              }}
              style={{
                marginTop: "0.75rem",
              }}
            >
              Retry
            </button>
          </div>
        )}

        {/* --------------------------------------------------------------------
         * Empty
         * ------------------------------------------------------------------ */}

        {!loading &&
          !error &&
          iocs.length === 0 && (
            <div className="empty-state">
              <p>
                No indicators match the
                current filters.
              </p>
            </div>
          )}

        {/* --------------------------------------------------------------------
         * IOC Table
         * ------------------------------------------------------------------ */}

        {!loading &&
          !error &&
          iocs.length > 0 && (
            <IOCTable
              iocs={iocs}
              canManage={canManage}
              onView={(ioc) => {
                void handleOpenIOC(ioc);
              }}
              onEdit={
                handleOpenEdit
              }
              onToggleStatus={
                handleToggleStatus
              }
            />
          )}

        {/* --------------------------------------------------------------------
         * Pagination
         * ------------------------------------------------------------------ */}

        {!loading &&
          !error && (
            <div className="ioc-pagination">
              <div className="ioc-pagination-content">
                <div className="ioc-pagination-info">
                  {paginationLabel}
                </div>

                <div className="ioc-pagination-controls">
                  <span>
                    {totalPages > 0
                      ? `Page ${page} of ${totalPages}`
                      : `Page ${page}`}
                  </span>

                  <button
                    type="button"
                    className="ioc-pagination-button"
                    onClick={
                      handlePreviousPage
                    }
                    disabled={
                      loading ||
                      page <= DEFAULT_PAGE
                    }
                  >
                    Previous
                  </button>

                  <button
                    type="button"
                    className="ioc-pagination-button"
                    onClick={
                      handleNextPage
                    }
                    disabled={
                      loading ||
                      totalPages <= 0 ||
                      page >= totalPages
                    }
                  >
                    Next
                  </button>
                </div>
              </div>
            </div>
          )}
      </Panel>

      {/* ======================================================================
       * View IOC Drawer
       * ==================================================================== */}

      {(selectedIOC ||
        detailsLoading ||
        detailsError) && (
        <div
          className="ioc-drawer-backdrop"
          onClick={
            handleCloseDetails
          }
        >
          <aside
            className="ioc-details-drawer"
            onClick={(event) => {
              event.stopPropagation();
            }}
          >
            <DrawerHeader
              title="IOC DETAILS"
              onClose={
                handleCloseDetails
              }
            />

            {detailsLoading && (
              <div className="empty-state">
                <p>
                  Loading IOC details...
                </p>
              </div>
            )}

            {!detailsLoading &&
              detailsError && (
                <div className="empty-state">
                  <p>
                    {detailsError}
                  </p>
                </div>
              )}

            {!detailsLoading &&
              !detailsError &&
              selectedIOC && (
                <IOCDetailsContent
                  ioc={selectedIOC}
                />
              )}
          </aside>
        </div>
      )}

      {/* ======================================================================
       * Add IOC Drawer
       * ==================================================================== */}

      {addDrawerOpen && canManage && (
        <div
          className="ioc-drawer-backdrop"
          onClick={
            handleCloseAdd
          }
        >
          <aside
            className="ioc-details-drawer"
            onClick={(event) => {
              event.stopPropagation();
            }}
          >
            <DrawerHeader
              title="ADD IOC"
              onClose={
                handleCloseAdd
              }
              disabled={addLoading}
            />

            <IOCForm
              mode="create"
              form={addForm}
              setForm={setAddForm}
              error={addError}
              loading={addLoading}
              availableTypes={
                availableTypes
              }
              availableSeverities={
                availableSeverities
              }
              availableReputations={
                availableReputations
              }
              availableSources={
                availableSources
              }
              catalogueLoading={filterOptionsLoading}
onSubmit={
                handleCreateIOC
              }
              onCancel={
                handleCloseAdd
              }
            />
          </aside>
        </div>
      )}

      {/* ======================================================================
       * Edit IOC Drawer
       * ==================================================================== */}

      {editDrawerOpen &&
        editingIOC &&
        canManage && (
          <div
            className="ioc-drawer-backdrop"
            onClick={
              handleCloseEdit
            }
          >
            <aside
              className="ioc-details-drawer"
              onClick={(event) => {
                event.stopPropagation();
              }}
            >
              <DrawerHeader
                title="EDIT IOC"
                onClose={
                  handleCloseEdit
                }
                disabled={editLoading}
              />

              <IOCForm
                mode="edit"
                form={editForm}
                setForm={setEditForm}
                error={editError}
                loading={editLoading}
                availableTypes={
                  availableTypes
                }
                availableSeverities={
                  availableSeverities
                }
                availableReputations={
                  availableReputations
                }
                availableSources={
                  availableSources
                }
                catalogueLoading={filterOptionsLoading}
onSubmit={
                  handleUpdateIOC
                }
                onCancel={
                  handleCloseEdit
                }
              />
            </aside>
          </div>
        )}

      {/* ======================================================================
       * Enable / Disable Confirmation
       * ==================================================================== */}

      {statusActionIOC &&
        canManage && (
          <div
            className="ioc-modal-backdrop"
            onClick={
              handleCloseStatusAction
            }
          >
            <div
              className="ioc-modal"
              onClick={(event) => {
                event.stopPropagation();
              }}
            >
              <div className="ioc-modal-header">
                <div>
                  <span>
                    THREAT INTELLIGENCE
                  </span>

                  <h3>
                    {isActiveStatus(
                      statusActionIOC.status,
                    )
                      ? "Disable IOC?"
                      : "Enable IOC?"}
                  </h3>
                </div>

                <button
                  type="button"
                  onClick={
                    handleCloseStatusAction
                  }
                  disabled={
                    statusActionLoading
                  }
                  aria-label="Close confirmation"
                >
                  ×
                </button>
              </div>

              <div className="ioc-confirmation-content">
                <code>
                  {statusActionIOC.indicator ||
                    statusActionIOC.value ||
                    "IOC"}
                </code>

                <p>
                  {isActiveStatus(
                    statusActionIOC.status,
                  )
                    ? "This indicator will no longer be treated as active."
                    : "This indicator will become active again."}
                </p>

                {statusActionError && (
                  <div className="ioc-form-error">
                    {statusActionError}
                  </div>
                )}
              </div>

              <div className="ioc-modal-actions">
                <button
                  type="button"
                  onClick={
                    handleCloseStatusAction
                  }
                  disabled={
                    statusActionLoading
                  }
                >
                  Cancel
                </button>

                <button
                  type="button"
                  className="primary-action"
                  onClick={
                    handleConfirmStatusAction
                  }
                  disabled={
                    statusActionLoading
                  }
                >
                  {statusActionLoading
                    ? "Processing..."
                    : isActiveStatus(
                        statusActionIOC.status,
                      )
                      ? "Disable IOC"
                      : "Enable IOC"}
                </button>
              </div>
            </div>
          </div>
        )}
    </div>
  );
}

/* ============================================================================
 * Drawer Header
 * ========================================================================== */

interface DrawerHeaderProps {
  title: string;
  onClose: () => void;
  disabled?: boolean;
}

function DrawerHeader({
  title,
  onClose,
  disabled = false,
}: DrawerHeaderProps) {
  return (
    <div className="ioc-drawer-header">
      <div>
        <span>
          THREAT INTELLIGENCE
        </span>

        <h3>{title}</h3>
      </div>

      <button
        type="button"
        onClick={onClose}
        disabled={disabled}
        aria-label={`Close ${title}`}
      >
        ×
      </button>
    </div>
  );
}

/* ============================================================================
 * KPI Card
 * ========================================================================== */

interface KPICardProps {
  label: string;
  value: number;
  loading?: boolean;
  tone?:
    | "default"
    | "danger"
    | "warning"
    | "accent";
}

function KPICard({
  label,
  value,
  loading = false,
  tone = "default",
}: KPICardProps) {
  return (
    <div
      className={`threat-kpi-card threat-kpi-${tone}`}
    >
      <span className="threat-kpi-label">
        {label}
      </span>

      <strong className="threat-kpi-value">
        {loading
          ? "—"
          : value.toLocaleString()}
      </strong>
    </div>
  );
}

/* ============================================================================
 * IOC Form
 * ========================================================================== */

interface IOCFormProps {
  mode: "create" | "edit";
  form: IOCFormState;
  setForm: Dispatch<
    SetStateAction<IOCFormState>
  >;
  error: string | null;
  loading: boolean;
  availableTypes: string[];
  availableSeverities: string[];
  availableReputations: string[];
  availableSources: string[];
  catalogueLoading: boolean;
  onSubmit: (
    event: FormEvent<HTMLFormElement>,
  ) => Promise<void>;
  onCancel: () => void;
}

function IOCForm({
  mode,
  form,
  setForm,
  error,
  loading,
  availableTypes,
  availableSeverities,
  availableReputations,
  availableSources,
  catalogueLoading,
  onSubmit,
  onCancel,
}: IOCFormProps) {
  const isCreate =
    mode === "create";

  const updateField = (
    key: keyof IOCFormState,
    value: string,
  ): void => {
    setForm(
      (current) => ({
        ...current,
        [key]: value,
      }),
    );
  };

  return (
    <form
      className="ioc-drawer-form"
      onSubmit={onSubmit}
    >
      <div className="ioc-form-grid">
        <label>
          <span>
            IOC Value *
          </span>

          <input
            type="text"
            value={form.value}
            onChange={(event) => {
              updateField(
                "value",
                event.target.value,
              );
            }}
            placeholder="185.10.20.30"
            required
          />
        </label>

        <label>
          <span>
            IOC Type *
          </span>

          <select
            value={form.type}
            disabled={loading || catalogueLoading}
            onChange={(event) => {
              updateField(
                "type",
                event.target.value,
              );
            }}
            required
          >
            <option value="">
              Select Type
            </option>

            {availableTypes.map(
              (type) => (
                <option
                  key={type}
                  value={type}
                >
                  {formatLabel(type)}
                </option>
              ),
            )}
          </select>
        </label>

        <label>
          <span>
            Severity *
          </span>

          <select
            value={form.severity}
            disabled={loading || catalogueLoading}
            onChange={(event) => {
              updateField(
                "severity",
                event.target.value,
              );
            }}
            required
          >
            <option value="">
              Select Severity
            </option>

            {availableSeverities.map(
              (severity) => (
                <option
                  key={severity}
                  value={severity}
                >
                  {formatLabel(
                    severity,
                  )}
                </option>
              ),
            )}
          </select>
        </label>

        <label>
          <span>
            Reputation
          </span>

          <select
            value={form.reputation}
            disabled={loading || catalogueLoading}
            onChange={(event) => {
              updateField(
                "reputation",
                event.target.value,
              );
            }}
          >
            <option value="">
              Select Reputation
            </option>

            {availableReputations.map(
              (reputation) => (
                <option
                  key={reputation}
                  value={reputation}
                >
                  {formatLabel(
                    reputation,
                  )}
                </option>
              ),
            )}
          </select>
        </label>

        <label>
          <span>
            Source
          </span>

          <select
            value={form.source}
            disabled={loading || catalogueLoading}
            onChange={(event) => {
              updateField(
                "source",
                event.target.value,
              );
            }}
          >
            <option value="">
              Select Source
            </option>

            {availableSources.map(
              (source) => (
                <option
                  key={source}
                  value={source}
                >
                  {source}
                </option>
              ),
            )}
          </select>
        </label>

        <label className="full-width">
          <span>
            Description
          </span>

          <textarea
            value={form.description}
            onChange={(event) => {
              updateField(
                "description",
                event.target.value,
              );
            }}
            rows={4}
            placeholder="Describe the threat indicator..."
          />
        </label>

        <label className="full-width">
          <span>
            Tags
          </span>

          <input
            type="text"
            value={form.tags}
            onChange={(event) => {
              updateField(
                "tags",
                event.target.value,
              );
            }}
            placeholder="malware, botnet, c2"
          />
        </label>

        <label className="full-width">
          <span>
            Expires At
          </span>

          <input
            type="datetime-local"
            value={form.expiration}
            onChange={(event) => {
              updateField(
                "expiration",
                event.target.value,
              );
            }}
          />
        </label>
      </div>

      {catalogueLoading && (
        <div className="ioc-form-error">
          Loading IOC options from backend...
        </div>
      )}

      {error && (
        <div className="ioc-form-error">
          {error}
        </div>
      )}

      <div className="ioc-modal-actions">
        <button
          type="button"
          onClick={onCancel}
          disabled={
            loading ||
            catalogueLoading
          }
        >
          Cancel
        </button>

        <button
          type="submit"
          className="primary-action"
          disabled={loading}
        >
          {loading
            ? isCreate
              ? "Creating..."
              : "Saving..."
            : isCreate
              ? "Create IOC"
              : "Save Changes"}
        </button>
      </div>
    </form>
  );
}

/* ============================================================================
 * IOC Details
 * ========================================================================== */

interface IOCDetailsContentProps {
  ioc: IOCDetail;
}

function IOCDetailsContent({
  ioc,
}: IOCDetailsContentProps) {
  const relationships =
    ioc.relationships;

  return (
    <div className="ioc-drawer-content">
      <section className="ioc-detail-section">
        <div className="ioc-section-title">
          IOC
        </div>

        <code className="ioc-detail-value">
          {ioc.indicator ||
            ioc.value ||
            "—"}
        </code>
      </section>

      <section className="ioc-detail-section">
        <div className="ioc-section-title">
          Overview
        </div>

        <div className="ioc-overview-grid">
          <DetailField
            label="Type"
            value={formatLabel(
              ioc.type,
            )}
          />

          <DetailField
            label="Severity"
            value={formatLabel(
              ioc.severity,
            )}
          />

          <DetailField
            label="Status"
            value={formatLabel(
              ioc.status,
            )}
          />

          <DetailField
            label="Reputation"
            value={formatLabel(
              ioc.reputation,
            )}
          />

          <DetailField
            label="Source"
            value={
              ioc.source || "—"
            }
          />

          <DetailField
            label="First Seen"
            value={formatDateTime(
              ioc.first_seen,
            )}
          />

          <DetailField
            label="Last Seen"
            value={formatDateTime(
              ioc.last_seen,
            )}
          />

          <DetailField
            label="Expires"
            value={formatDateTime(
              ioc.expiration,
            )}
          />

          <DetailField
            label="Created"
            value={formatDateTime(
              ioc.created_at,
            )}
          />

          <DetailField
            label="Updated"
            value={formatDateTime(
              ioc.updated_at,
            )}
          />
        </div>
      </section>

      <section className="ioc-detail-section">
        <div className="ioc-section-title">
          Description
        </div>

        <p className="ioc-description">
          {ioc.description ||
            "No description available."}
        </p>
      </section>

      <section className="ioc-detail-section">
        <div className="ioc-section-title">
          Tags
        </div>

        {ioc.tags?.length ? (
          <div className="ioc-tags">
            {ioc.tags.map(
              (tag) => (
                <span
                  key={tag}
                  className="health-pill"
                >
                  {tag}
                </span>
              ),
            )}
          </div>
        ) : (
          <div className="ioc-no-relationships">
            No tags available.
          </div>
        )}
      </section>

      <RelationshipSection
        title="Related Events"
        count={
          relationships.event_count
        }
        ids={
          relationships.event_ids
        }
      />

      <RelationshipSection
        title="Related Alerts"
        count={
          relationships.alert_count
        }
        ids={
          relationships.alert_ids
        }
      />

      <RelationshipSection
        title="Related Incidents"
        count={
          relationships.incident_count
        }
        ids={
          relationships.incident_ids
        }
      />

      <RelationshipSection
        title="Related Assets"
        count={
          relationships.asset_count
        }
        ids={
          relationships.asset_ids
        }
      />

      <RelationshipSection
        title="MITRE Techniques"
        count={
          relationships.mitre_technique_count
        }
        ids={
          relationships.mitre_technique_ids
        }
      />
    </div>
  );
}

/* ============================================================================
 * Detail Field
 * ========================================================================== */

interface DetailFieldProps {
  label: string;
  value: string;
}

function DetailField({
  label,
  value,
}: DetailFieldProps) {
  return (
    <div className="ioc-detail-field">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

/* ============================================================================
 * Relationship Section
 * ========================================================================== */

interface RelationshipSectionProps {
  title: string;
  count: number;
  ids: string[];
}

function RelationshipSection({
  title,
  count,
  ids,
}: RelationshipSectionProps) {
  return (
    <section className="ioc-detail-section">
      <div className="ioc-section-heading">
        <div>
          <div className="ioc-section-title">
            {title}
          </div>

          <span className="ioc-relationship-count">
            {count}
            {count === 1
              ? " item"
              : " items"}
          </span>
        </div>
      </div>

      {ids.length > 0 ? (
        <div className="ioc-relationship-list">
          {ids
            .slice(0, 5)
            .map((id) => (
              <code key={id}>
                {id}
              </code>
            ))}

          {ids.length > 5 && (
            <span>
              +{ids.length - 5} more
            </span>
          )}
        </div>
      ) : (
        <div className="ioc-no-relationships">
          No related objects found.
        </div>
      )}
    </section>
  );
}

/* ============================================================================
 * Helpers
 * ========================================================================== */

function isFiltersEmpty(
  filters: FilterState,
): boolean {
  return (
    !filters.query.trim() &&
    !filters.type &&
    !filters.severity &&
    !filters.status &&
    !filters.source &&
    !filters.reputation
  );
}

function isActiveStatus(
  status: string,
): boolean {
  return (
    status.trim().toLowerCase() ===
    "active"
  );
}

function formatLabel(
  value: string,
): string {
  const normalized =
    value.trim().toLowerCase();

  if (!normalized) {
    return "Unknown";
  }

  switch (normalized) {
    case "ipv4":
      return "IPv4";

    case "ipv6":
      return "IPv6";

    case "url":
      return "URL";

    case "hash":
      return "Hash";

    case "email":
      return "Email";

    case "domain":
      return "Domain";

    case "hostname":
      return "Hostname";

    case "info":
    case "informational":
      return "Informational";

    default:
      return normalized
        .replace(
          /[_-]+/g,
          " ",
        )
        .replace(
          /\b\w/g,
          (character) =>
            character.toUpperCase(),
        );
  }
}

function formatDateTime(
  value:
    | string
    | null
    | undefined,
): string {
  if (
    !value ||
    !value.trim()
  ) {
    return "—";
  }

  const date =
    new Date(value);

  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    return value;
  }

  return date.toLocaleString();
}
