/*
 * ============================================================================
 * Assets Page
 * SentinelSIEM SOC Dashboard
 * ============================================================================
 */

import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

import "../Assets.css";

import {
  ApiError,
  api,
} from "../../../services/api";

import type {
  Asset,
  AssetCreateRequest,
  AssetListParams,
  AssetListResponse,
  AssetStatisticsResponse,
  AssetStatusUpdateRequest,
  AssetUpdateRequest,
} from "../types";

import AssetDetails from "./AssetDetails";

import AssetFilters from "../components/AssetFilters";
import AssetForm from "../components/AssetForm";
import AssetStatistics from "../components/AssetStatistics";
import AssetTable from "../components/AssetTable";

/*
 * ============================================================================
 * Constants
 * ============================================================================
 */

const DEFAULT_PAGE = 1;
const PAGE_SIZE = 30;

const EMPTY_STATISTICS: AssetStatisticsResponse = {
  total: 0,
  enabled: 0,
  disabled: 0,
  critical: 0,
  by_type: {},
  by_risk: {},
  by_lifecycle_status: {},
  by_operational_status: {},
};

/*
 * ============================================================================
 * Helpers
 * ============================================================================
 */

function getErrorMessage(
  caught: unknown,
  fallback: string,
): string {
  if (caught instanceof ApiError) {
    return caught.detail;
  }

  if (caught instanceof Error) {
    return caught.message;
  }

  return fallback;
}

/*
 * ============================================================================
 * Component
 * ============================================================================
 */

export default function Assets() {
  /*
   * ==========================================================================
   * Data State
   * ==========================================================================
   */

  const [assets, setAssets] =
    useState<Asset[]>([]);

  const [total, setTotal] =
    useState(0);

  const [statistics, setStatistics] =
    useState<AssetStatisticsResponse>(
      EMPTY_STATISTICS,
    );

  /*
   * ==========================================================================
   * Filter / Pagination State
   * ==========================================================================
   */

  const [filters, setFilters] =
    useState<AssetListParams>({
      page: DEFAULT_PAGE,
      page_size: PAGE_SIZE,
    });

  /*
   * ==========================================================================
   * UI State
   * ==========================================================================
   */

  const [loading, setLoading] =
    useState(false);

  const [
    statisticsLoading,
    setStatisticsLoading,
  ] = useState(false);

  const [
    formLoading,
    setFormLoading,
  ] = useState(false);

  const [error, setError] =
    useState<string | null>(null);

  const [
    statisticsError,
    setStatisticsError,
  ] = useState<string | null>(null);

  const [formError, setFormError] =
    useState<string | null>(null);

  /*
   * selectedAsset is shared by:
   *
   * - Details drawer
   * - Edit drawer
   *
   * Only one drawer is open at a time.
   */

  const [
    selectedAsset,
    setSelectedAsset,
  ] = useState<Asset | null>(null);

  const [showForm, setShowForm] =
    useState(false);

  const [
    showDetails,
    setShowDetails,
  ] = useState(false);

  /*
   * ==========================================================================
   * Pagination
   * ==========================================================================
   */

  const currentPage =
    filters.page ?? DEFAULT_PAGE;

  const pageSize =
    filters.page_size ?? PAGE_SIZE;

  const totalPages =
    total > 0
      ? Math.ceil(total / pageSize)
      : 1;

  const canGoPrevious =
    currentPage > 1;

  const canGoNext =
    currentPage < totalPages;

  /*
   * ==========================================================================
   * Display Range
   * ==========================================================================
   */

  const displayRange = useMemo(() => {
    if (total === 0) {
      return {
        start: 0,
        end: 0,
      };
    }

    const start =
      (currentPage - 1) *
        pageSize +
      1;

    const end = Math.min(
      start + assets.length - 1,
      total,
    );

    return {
      start,
      end,
    };
  }, [
    assets.length,
    currentPage,
    pageSize,
    total,
  ]);

  /*
   * ==========================================================================
   * Load Assets
   * ==========================================================================
   */

  const loadAssets =
    useCallback(async () => {
      setLoading(true);
      setError(null);

      try {
        const response: AssetListResponse =
          await api.listAssets({
            ...filters,
            page: currentPage,
            page_size: PAGE_SIZE,
          });

        setAssets(
          response.items ?? [],
        );

        setTotal(
          response.total ?? 0,
        );
      } catch (caught) {
        setError(
          getErrorMessage(
            caught,
            "Unable to load assets.",
          ),
        );

        setAssets([]);
        setTotal(0);
      } finally {
        setLoading(false);
      }
    }, [
      filters,
      currentPage,
    ]);

  /*
   * ==========================================================================
   * Load Statistics
   * ==========================================================================
   */

  const loadStatistics =
    useCallback(async () => {
      setStatisticsLoading(true);
      setStatisticsError(null);

      try {
        const response =
          await api.getAssetStatistics();

        setStatistics(response);
      } catch (caught) {
        setStatisticsError(
          getErrorMessage(
            caught,
            "Unable to load asset statistics.",
          ),
        );
      } finally {
        setStatisticsLoading(false);
      }
    }, []);

  /*
   * ==========================================================================
   * Initial / Filtered Load
   * ==========================================================================
   */

  useEffect(() => {
    void loadAssets();
  }, [loadAssets]);

  useEffect(() => {
    void loadStatistics();
  }, [loadStatistics]);

  /*
   * ==========================================================================
   * Refresh
   * ==========================================================================
   *
   * Refresh preserves current search, filters and page.
   * ==========================================================================
   */

  const refreshAssets =
    useCallback(async () => {
      await Promise.all([
        loadAssets(),
        loadStatistics(),
      ]);
    }, [
      loadAssets,
      loadStatistics,
    ]);

  /*
   * ==========================================================================
   * Create Asset
   * ==========================================================================
   */

  const handleCreateAsset =
    useCallback(
      async (
        payload: AssetCreateRequest,
      ): Promise<void> => {
        setFormLoading(true);
        setFormError(null);

        try {
          await api.createAsset(
            payload,
          );

          setShowForm(false);
          setShowDetails(false);
          setSelectedAsset(null);
          setFormError(null);

          setFilters((current) => ({
            ...current,
            page: DEFAULT_PAGE,
            page_size: PAGE_SIZE,
          }));

          await loadStatistics();
        } catch (caught) {
          setFormError(
            getErrorMessage(
              caught,
              "Unable to create asset.",
            ),
          );
        } finally {
          setFormLoading(false);
        }
      },
      [loadStatistics],
    );

  /*
   * ==========================================================================
   * Update Asset
   * ==========================================================================
   */

  const handleUpdateAsset =
    useCallback(
      async (
        payload: AssetUpdateRequest,
      ): Promise<void> => {
        if (!selectedAsset) {
          return;
        }

        setFormLoading(true);
        setFormError(null);

        try {
          await api.updateAsset(
            selectedAsset.asset_id,
            payload,
          );

          setShowForm(false);
          setShowDetails(false);
          setSelectedAsset(null);
          setFormError(null);

          await refreshAssets();
        } catch (caught) {
          setFormError(
            getErrorMessage(
              caught,
              "Unable to update asset.",
            ),
          );
        } finally {
          setFormLoading(false);
        }
      },
      [
        selectedAsset,
        refreshAssets,
      ],
    );

  /*
   * ==========================================================================
   * Form Submit
   * ==========================================================================
   */

  const handleFormSubmit =
    useCallback(
      async (
        payload:
          | AssetCreateRequest
          | AssetUpdateRequest,
      ): Promise<void> => {
        if (selectedAsset) {
          await handleUpdateAsset(
            payload as AssetUpdateRequest,
          );

          return;
        }

        await handleCreateAsset(
          payload as AssetCreateRequest,
        );
      },
      [
        selectedAsset,
        handleCreateAsset,
        handleUpdateAsset,
      ],
    );

  /*
   * ==========================================================================
   * Enable Asset
   * ==========================================================================
   */

  const handleEnableAsset =
    useCallback(
      async (
        asset: Asset,
      ): Promise<void> => {
        setError(null);

        const payload: AssetStatusUpdateRequest =
          {
            lifecycle_status:
              "ENABLED",
          };

        try {
          await api.updateAssetStatus(
            asset.asset_id,
            payload,
          );

          await refreshAssets();
        } catch (caught) {
          setError(
            getErrorMessage(
              caught,
              "Unable to enable asset.",
            ),
          );
        }
      },
      [refreshAssets],
    );

  /*
   * ==========================================================================
   * Disable Asset
   * ==========================================================================
   */

  const handleDisableAsset =
    useCallback(
      async (
        asset: Asset,
      ): Promise<void> => {
        const confirmed =
          window.confirm(
            `Disable asset "${asset.name}"?`,
          );

        if (!confirmed) {
          return;
        }

        setError(null);

        const payload: AssetStatusUpdateRequest =
          {
            lifecycle_status:
              "DISABLED",
          };

        try {
          await api.updateAssetStatus(
            asset.asset_id,
            payload,
          );

          await refreshAssets();
        } catch (caught) {
          setError(
            getErrorMessage(
              caught,
              "Unable to disable asset.",
            ),
          );
        }
      },
      [refreshAssets],
    );

  /*
   * ==========================================================================
   * View Asset
   * ==========================================================================
   *
   * IMPORTANT:
   *
   * View no longer navigates to /assets/:assetId.
   *
   * The inventory remains visible and AssetDetails is rendered
   * inside the right-side drawer.
   * ==========================================================================
   */

  const handleViewAsset =
    useCallback(
      (asset: Asset) => {
        if (showForm) {
          setShowForm(false);
        }

        setFormError(null);
        setSelectedAsset(asset);
        setShowDetails(true);
      },
      [showForm],
    );

  /*
   * ==========================================================================
   * Edit Asset
   * ==========================================================================
   */

  const handleEditAsset =
    useCallback(
      (asset: Asset) => {
        if (showDetails) {
          setShowDetails(false);
        }

        setSelectedAsset(asset);
        setFormError(null);
        setShowForm(true);
      },
      [showDetails],
    );

  /*
   * ==========================================================================
   * Open Create Form
   * ==========================================================================
   */

  const handleOpenCreate =
    useCallback(() => {
      setShowDetails(false);
      setSelectedAsset(null);
      setFormError(null);
      setShowForm(true);
    }, []);

  /*
   * ==========================================================================
   * Close Form
   * ==========================================================================
   */

  const handleCloseForm =
    useCallback(() => {
      if (formLoading) {
        return;
      }

      setShowForm(false);
      setSelectedAsset(null);
      setFormError(null);
    }, [formLoading]);

  /*
   * ==========================================================================
   * Close Details
   * ==========================================================================
   */

  const handleCloseDetails =
    useCallback(() => {
      if (formLoading) {
        return;
      }

      setShowDetails(false);
      setSelectedAsset(null);
      setFormError(null);
    }, [formLoading]);

  /*
   * ==========================================================================
   * Escape Key
   * ==========================================================================
   *
   * Drawer components also receive Escape through this page-level handler.
   * ==========================================================================
   */

  useEffect(() => {
    if (
      !showForm &&
      !showDetails
    ) {
      return;
    }

    const handleKeyDown = (
      event: KeyboardEvent,
    ) => {
      if (
        event.key !==
        "Escape"
      ) {
        return;
      }

      if (formLoading) {
        return;
      }

      if (showForm) {
        handleCloseForm();
        return;
      }

      if (showDetails) {
        handleCloseDetails();
      }
    };

    document.addEventListener(
      "keydown",
      handleKeyDown,
    );

    return () => {
      document.removeEventListener(
        "keydown",
        handleKeyDown,
      );
    };
  }, [
    showForm,
    showDetails,
    formLoading,
    handleCloseForm,
    handleCloseDetails,
  ]);

  /*
   * ==========================================================================
   * Body Scroll Lock
   * ==========================================================================
   */

  useEffect(() => {
    const drawerOpen =
      showForm ||
      showDetails;

    if (!drawerOpen) {
      return;
    }

    const previousOverflow =
      document.body.style.overflow;

    document.body.style.overflow =
      "hidden";

    return () => {
      document.body.style.overflow =
        previousOverflow;
    };
  }, [
    showForm,
    showDetails,
  ]);

  /*
   * ==========================================================================
   * Filters
   * ==========================================================================
   *
   * Every filter change immediately applies and resets pagination to page 1.
   * ==========================================================================
   */

  const handleFiltersChange =
    useCallback(
      (
        nextFilters: AssetListParams,
      ) => {
        setFilters({
          ...nextFilters,
          page: DEFAULT_PAGE,
          page_size: PAGE_SIZE,
        });
      },
      [],
    );

  /*
   * ==========================================================================
   * Reset Filters
   * ==========================================================================
   */

  const handleResetFilters =
    useCallback(() => {
      setFilters({
        page: DEFAULT_PAGE,
        page_size: PAGE_SIZE,
      });
    }, []);

  /*
   * ==========================================================================
   * Previous Page
   * ==========================================================================
   */

  const handlePreviousPage =
    useCallback(() => {
      if (
        !canGoPrevious ||
        loading
      ) {
        return;
      }

      setFilters((current) => ({
        ...current,
        page: Math.max(
          DEFAULT_PAGE,
          (current.page ??
            DEFAULT_PAGE) - 1,
        ),
        page_size: PAGE_SIZE,
      }));
    }, [
      canGoPrevious,
      loading,
    ]);

  /*
   * ==========================================================================
   * Next Page
   * ==========================================================================
   */

  const handleNextPage =
    useCallback(() => {
      if (
        !canGoNext ||
        loading
      ) {
        return;
      }

      setFilters((current) => ({
        ...current,
        page:
          (current.page ??
            DEFAULT_PAGE) + 1,
        page_size: PAGE_SIZE,
      }));
    }, [
      canGoNext,
      loading,
    ]);

  /*
   * ==========================================================================
   * Render
   * ==========================================================================
   */

  return (
    <main className="assets-page">
      <div className="mx-auto w-full max-w-[1600px] space-y-6">

        {/* ==================================================================
            Page Header
            ================================================================== */}

        <section className="flex w-full flex-row items-center justify-between gap-4 rounded-xl border border-slate-800/80 bg-slate-950/40 p-5 shadow-sm sm:p-6">
          <div className="min-w-0 flex-1">
            <div className="flex min-w-0 flex-1 items-center gap-3">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-cyan-500/20 bg-cyan-500/10">
                <span
                  aria-hidden="true"
                  className="text-lg text-cyan-400"
                >
                  ◈
                </span>
              </div>

              <div className="min-w-0 flex-1">
                <h1 className="whitespace-nowrap text-2xl font-semibold tracking-tight text-slate-100 sm:text-3xl">
                  Assets
                </h1>

                <p className="mt-1 whitespace-nowrap text-sm text-slate-400">
                  Manage and monitor all infrastructure assets.
                </p>
              </div>
            </div>
          </div>

          <div className="flex shrink-0 items-center gap-2">
            <button
              type="button"
              onClick={() => {
                void refreshAssets();
              }}
              disabled={
                loading ||
                statisticsLoading
              }
              aria-label="Refresh assets"
              className="inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-slate-700 bg-slate-900/60 px-4 text-sm font-medium text-slate-300 shadow-sm transition hover:border-slate-600 hover:bg-slate-800 hover:text-white focus:outline-none focus:ring-2 focus:ring-slate-500/20 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <span
                aria-hidden="true"
                className={
                  loading ||
                  statisticsLoading
                    ? "animate-spin"
                    : ""
                }
              >
                ⟳
              </span>

              Refresh
            </button>

            <button
              type="button"
              onClick={
                handleOpenCreate
              }
              disabled={formLoading}
              className="inline-flex h-10 shrink-0 items-center justify-center gap-2 rounded-lg border border-cyan-400/30 bg-cyan-500/10 px-5 text-sm font-semibold text-cyan-300 shadow-sm transition hover:border-cyan-400/50 hover:bg-cyan-500/20 hover:text-cyan-200 focus:outline-none focus:ring-2 focus:ring-cyan-500/30 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <span
                aria-hidden="true"
                className="text-base"
              >
                +
              </span>

              Add Asset
            </button>
          </div>
        </section>

        {/* ==================================================================
            Statistics
            ================================================================== */}

        <section className="w-full">
          <AssetStatistics
            statistics={statistics}
            loading={
              statisticsLoading
            }
            error={
              statisticsError
            }
          />
        </section>

        {/* ==================================================================
            Filters
            ================================================================== */}

        <section className="w-full overflow-hidden rounded-xl border border-slate-800/80 bg-slate-950/40 shadow-sm">
          <div className="border-b border-slate-800/80 px-5 py-4 sm:px-6">
            <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h2 className="text-sm font-semibold text-slate-200">
                  Asset Filters
                </h2>

                <p className="mt-0.5 text-xs text-slate-500">
                  Search and filter managed
                  infrastructure assets.
                </p>
              </div>

              <span className="text-xs text-slate-600">
                {total.toLocaleString()}{" "}
                matching
              </span>
            </div>
          </div>

          <div className="p-5 sm:p-6">
            <AssetFilters
              value={filters}
              loading={loading}
              onChange={
                handleFiltersChange
              }
              onReset={
                handleResetFilters
              }
            />
          </div>
        </section>

        {/* ==================================================================
            General Error
            ================================================================== */}

        {error && (
          <div
            role="alert"
            className="flex flex-col gap-3 rounded-xl border border-red-500/20 bg-red-500/5 px-4 py-3 text-sm text-red-300 sm:flex-row sm:items-center sm:justify-between"
          >
            <div className="flex items-start gap-3">
              <span
                aria-hidden="true"
                className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-red-500/10 text-xs font-bold text-red-400"
              >
                !
              </span>

              <span>{error}</span>
            </div>

            <button
              type="button"
              onClick={() => {
                void refreshAssets();
              }}
              className="shrink-0 font-medium text-red-300 underline underline-offset-2 transition hover:text-red-200"
            >
              Retry
            </button>
          </div>
        )}

        {/* ==================================================================
            Asset Table
            ================================================================== */}

        <section className="w-full overflow-hidden rounded-xl border border-slate-800/80 bg-slate-950/40 shadow-sm">
          <div className="flex flex-col gap-2 border-b border-slate-800/80 px-5 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-6">
            <div>
              <h2 className="text-sm font-semibold text-slate-200">
                SentinelSIEM Managed Assets
              </h2>

              <p className="mt-0.5 text-xs text-slate-500">
                Registered infrastructure and
                managed endpoints.
              </p>
            </div>

            <div className="text-xs text-slate-500">
              {total.toLocaleString()}{" "}
              asset
              {total === 1
                ? ""
                : "s"}
            </div>
          </div>

          <div className="w-full">
            <AssetTable
              assets={assets}
              loading={loading}
              error={error}
              onView={
                handleViewAsset
              }
              onEdit={
                handleEditAsset
              }
              onEnable={
                handleEnableAsset
              }
              onDisable={
                handleDisableAsset
              }
            />
          </div>
        </section>

        {/* ==================================================================
            Pagination
            ================================================================== */}

        <section className="flex flex-col gap-4 rounded-xl border border-slate-800/80 bg-slate-950/30 px-5 py-4 sm:px-6 lg:flex-row lg:items-center lg:justify-between">
          <div className="text-sm text-slate-500">
            {total === 0 ? (
              "No assets found."
            ) : (
              <>
                <span className="font-medium text-slate-300">
                  {displayRange.start.toLocaleString()}
                </span>

                {"–"}

                <span className="font-medium text-slate-300">
                  {displayRange.end.toLocaleString()}
                </span>

                {" Assets / Total "}

                <span className="font-medium text-slate-300">
                  {total.toLocaleString()}
                </span>
              </>
            )}
          </div>

          <div className="flex items-center justify-between gap-3 sm:justify-end">
            <span className="text-xs text-slate-600">
              Page{" "}
              <span className="font-medium text-slate-400">
                {currentPage}
              </span>

              {" of "}

              <span className="font-medium text-slate-400">
                {totalPages}
              </span>
            </span>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={
                  handlePreviousPage
                }
                disabled={
                  !canGoPrevious ||
                  loading
                }
                className="inline-flex h-9 items-center justify-center rounded-lg border border-slate-700 bg-slate-900/60 px-4 text-sm font-medium text-slate-300 transition hover:border-slate-600 hover:bg-slate-800 hover:text-white focus:outline-none focus:ring-2 focus:ring-slate-500/20 disabled:cursor-not-allowed disabled:opacity-40"
              >
                Previous
              </button>

              <button
                type="button"
                onClick={
                  handleNextPage
                }
                disabled={
                  !canGoNext ||
                  loading
                }
                className="inline-flex h-9 items-center justify-center rounded-lg border border-slate-700 bg-slate-900/60 px-4 text-sm font-medium text-slate-300 transition hover:border-slate-600 hover:bg-slate-800 hover:text-white focus:outline-none focus:ring-2 focus:ring-slate-500/20 disabled:cursor-not-allowed disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </div>
        </section>
      </div>

      {/* ====================================================================
          CREATE / EDIT RIGHT-SIDE DRAWER
          ==================================================================== */}

      {showForm && (
        <div
          className="asset-drawer-overlay"
          role="dialog"
          aria-modal="true"
          aria-label={
            selectedAsset
              ? `Edit asset ${selectedAsset.name}`
              : "Create asset"
          }
          onMouseDown={(event) => {
            if (
              event.target ===
                event.currentTarget &&
              !formLoading
            ) {
              handleCloseForm();
            }
          }}
        >
          <aside
            className="asset-drawer asset-drawer-form"
            onMouseDown={(event) => {
              event.stopPropagation();
            }}
          >
            <div className="asset-drawer__header">
              <div className="min-w-0">
                <p className="asset-drawer__eyebrow">
                  Asset Management
                </p>

                <h2 className="asset-drawer__title">
                  {selectedAsset
                    ? "Edit Asset"
                    : "Create Asset"}
                </h2>
              </div>

              <button
                type="button"
                className="asset-drawer__close"
                aria-label="Close asset form"
                onClick={
                  handleCloseForm
                }
                disabled={formLoading}
              >
                ×
              </button>
            </div>

            <div className="asset-drawer__body">
              <AssetForm
                asset={selectedAsset}
                loading={formLoading}
                error={formError}
                onSubmit={
                  handleFormSubmit
                }
                onCancel={
                  handleCloseForm
                }
              />
            </div>
          </aside>
        </div>
      )}

      {/* ====================================================================
          DETAILS RIGHT-SIDE DRAWER
          ==================================================================== */}

      {showDetails &&
        selectedAsset && (
          <div
            className="asset-drawer-overlay"
            role="dialog"
            aria-modal="true"
            aria-label={`Asset details for ${selectedAsset.name}`}
            onMouseDown={(event) => {
              if (
                event.target ===
                event.currentTarget
              ) {
                handleCloseDetails();
              }
            }}
          >
            <aside
              className="asset-drawer asset-drawer-details"
              onMouseDown={(event) => {
                event.stopPropagation();
              }}
            >
              <div className="asset-drawer__header">
                <div className="min-w-0">
                  <p className="asset-drawer__eyebrow">
                    Asset Details
                  </p>

                  <h2 className="asset-drawer__title">
                    {selectedAsset.name}
                  </h2>
                </div>

                <button
                  type="button"
                  className="asset-drawer__close"
                  aria-label="Close asset details"
                  onClick={
                    handleCloseDetails
                  }
                  disabled={formLoading}
                >
                  ×
                </button>
              </div>

              <div className="asset-drawer__body">
                <AssetDetails
                  assetId={
                    selectedAsset.asset_id
                  }
                  onClose={
                    handleCloseDetails
                  }
                  onEdit={() => {
                    handleEditAsset(
                      selectedAsset,
                    );
                  }}
                />
              </div>
            </aside>
          </div>
        )}
    </main>
  );
}