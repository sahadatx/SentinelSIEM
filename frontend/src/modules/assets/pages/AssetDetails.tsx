/* ==========================================================================
 * Asset Details Page
 * SentinelSIEM SOC Dashboard
 * ========================================================================== */

import {
  type ReactNode,
  useCallback,
  useEffect,
  useState,
} from "react";

import "../Assets.css";

import { Link } from "react-router-dom";

import {
  api,
  ApiError,
} from "../../../services/api";

import type {
  Asset,
  AssetStatusUpdateRequest,
  AssetUpdateRequest,
} from "../types";

import AssetForm from "../components/AssetForm";
import AssetStatusBadge from "../components/AssetStatusBadge";

/* ==========================================================================
 * Props
 * ========================================================================== */

export interface AssetDetailsProps {
  /**
   * Asset details are identified by assetId.
   *
   * userId is kept optional for compatibility with existing page contracts.
   */
  userId?: string;

  assetId?: string;

  /**
   * When provided, AssetDetails behaves as drawer content.
   *
   * When omitted, the component keeps standalone-page behavior for:
   * /assets/:assetId
   */
  onClose?: () => void;

  /**
   * When provided, the parent controls the Edit workflow.
   *
   * This is used by the Assets inventory right-side drawer.
   */
  onEdit?: (asset: Asset) => void;
}

/* ==========================================================================
 * Types
 * ========================================================================== */

type AssetDetailsTab =
  | "overview"
  | "events"
  | "vulnerabilities"
  | "network"
  | "software"
  | "activity";

/* ==========================================================================
 * Helpers
 * ========================================================================== */

function formatDate(
  value: string | null | undefined,
): string {
  if (!value) {
    return "—";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString();
}

function formatValue(
  value: string | null | undefined,
): string {
  return value?.trim() || "—";
}

function formatTags(
  tags: string[] | null | undefined,
): string {
  if (!tags || tags.length === 0) {
    return "—";
  }

  return tags.join(", ");
}

function formatEnumLabel(
  value: string | null | undefined,
): string {
  if (!value?.trim()) {
    return "—";
  }

  return value
    .trim()
    .toLowerCase()
    .split("_")
    .filter(Boolean)
    .map(
      (part) =>
        part.charAt(0).toUpperCase() +
        part.slice(1),
    )
    .join(" ");
}

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

/* ==========================================================================
 * Component
 * ========================================================================== */

export default function AssetDetails({
  assetId,
  onClose,
  onEdit,
}: AssetDetailsProps) {
  /*
   * ==========================================================================
   * Mode
   * ==========================================================================
   *
   * onClose means the component is being rendered inside the inventory
   * right-side drawer.
   *
   * Without onClose, it behaves as the traditional standalone details page.
   */

  const isDrawer =
    typeof onClose === "function";

  const isParentControlledEdit =
    typeof onEdit === "function";

  /* ==========================================================================
   * State
   * ======================================================================== */

  const [asset, setAsset] =
    useState<Asset | null>(null);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState<string | null>(null);

  /*
   * Local edit state is retained only for standalone-page compatibility.
   *
   * Inventory drawer editing is controlled by Assets.tsx.
   */

  const [
    showEditForm,
    setShowEditForm,
  ] = useState(false);

  const [
    formLoading,
    setFormLoading,
  ] = useState(false);

  const [
    formError,
    setFormError,
  ] = useState<string | null>(null);

  const [
    statusLoading,
    setStatusLoading,
  ] = useState(false);

  const [
    activeTab,
    setActiveTab,
  ] =
    useState<AssetDetailsTab>(
      "overview",
    );

  /* ==========================================================================
   * Load Asset
   * ======================================================================== */

  const loadAsset = useCallback(
    async () => {
      if (!assetId) {
        setAsset(null);
        setError(
          "Asset ID is required.",
        );
        setLoading(false);
        return;
      }

      setLoading(true);
      setError(null);

      try {
        const response =
          await api.getAsset(
            assetId,
          );

        setAsset(response);
      } catch (caught) {
        setError(
          getErrorMessage(
            caught,
            "Unable to load asset.",
          ),
        );

        setAsset(null);
      } finally {
        setLoading(false);
      }
    },
    [assetId],
  );

  /* ==========================================================================
   * Initial Load
   * ======================================================================== */

  useEffect(() => {
    void loadAsset();
  }, [loadAsset]);

  /* ==========================================================================
   * Update Asset
   * ======================================================================== */

  const handleUpdate = useCallback(
    async (
      payload: AssetUpdateRequest,
    ): Promise<void> => {
      if (!asset) {
        return;
      }

      setFormLoading(true);
      setFormError(null);

      try {
        const updated =
          await api.updateAsset(
            asset.asset_id,
            payload,
          );

        setAsset(updated);
        setShowEditForm(false);
        setFormError(null);
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
    [asset],
  );

  /* ==========================================================================
   * Update Lifecycle Status
   * ======================================================================== */

  const updateLifecycleStatus =
    useCallback(
      async (
        lifecycleStatus:
          | "ENABLED"
          | "DISABLED",
      ): Promise<void> => {
        if (
          !asset ||
          statusLoading
        ) {
          return;
        }

        const payload: AssetStatusUpdateRequest =
          {
            lifecycle_status:
              lifecycleStatus,
          };

        setStatusLoading(true);
        setError(null);

        try {
          const updated =
            await api.updateAssetStatus(
              asset.asset_id,
              payload,
            );

          setAsset(updated);
        } catch (caught) {
          setError(
            getErrorMessage(
              caught,
              lifecycleStatus ===
                "ENABLED"
                ? "Unable to enable asset."
                : "Unable to disable asset.",
            ),
          );
        } finally {
          setStatusLoading(false);
        }
      },
      [
        asset,
        statusLoading,
      ],
    );

  /* ==========================================================================
   * Enable Asset
   * ======================================================================== */

  const handleEnable =
    useCallback(async () => {
      if (
        !asset ||
        statusLoading
      ) {
        return;
      }

      await updateLifecycleStatus(
        "ENABLED",
      );
    }, [
      asset,
      statusLoading,
      updateLifecycleStatus,
    ]);

  /* ==========================================================================
   * Disable Asset
   * ======================================================================== */

  const handleDisable =
    useCallback(async () => {
      if (
        !asset ||
        statusLoading
      ) {
        return;
      }

      const confirmed =
        window.confirm(
          `Disable asset "${asset.name}"?`,
        );

      if (!confirmed) {
        return;
      }

      await updateLifecycleStatus(
        "DISABLED",
      );
    }, [
      asset,
      statusLoading,
      updateLifecycleStatus,
    ]);

  /* ==========================================================================
   * Edit
   * ======================================================================== */

  const handleOpenEdit =
    useCallback(() => {
      if (!asset) {
        return;
      }

      /*
       * Inventory drawer:
       *
       * Delegate editing to Assets.tsx.
       */

      if (
        isParentControlledEdit &&
        onEdit
      ) {
        onEdit(asset);
        return;
      }

      /*
       * Standalone page:
       *
       * Keep the local edit form for backward compatibility.
       */

      setFormError(null);
      setShowEditForm(true);
    }, [
      asset,
      isParentControlledEdit,
      onEdit,
    ]);

  /* ==========================================================================
   * Close Local Edit
   * ======================================================================== */

  const handleCloseEdit =
    useCallback(() => {
      if (formLoading) {
        return;
      }

      setShowEditForm(false);
      setFormError(null);
    }, [formLoading]);

  /* ==========================================================================
   * Close Drawer
   * ======================================================================== */

  const handleCloseDrawer =
    useCallback(() => {
      if (
        formLoading ||
        statusLoading
      ) {
        return;
      }

      if (onClose) {
        onClose();
      }
    }, [
      formLoading,
      statusLoading,
      onClose,
    ]);

  /* ==========================================================================
   * Escape Key
   * ======================================================================== */

  useEffect(() => {
    if (!isDrawer) {
      return;
    }

    const handleKeyDown = (
      event: KeyboardEvent,
    ) => {
      if (
        event.key !== "Escape"
      ) {
        return;
      }

      handleCloseDrawer();
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
    isDrawer,
    handleCloseDrawer,
  ]);

  /* ==========================================================================
   * Loading State
   * ======================================================================== */

  if (loading) {
    return (
      <DetailsShell isDrawer={isDrawer}>
        <div
          aria-busy="true"
          aria-label="Loading asset details"
          className="space-y-6"
        >
          <div className="space-y-3">
            <div className="h-4 w-32 animate-pulse rounded bg-slate-800" />

            <div className="h-8 w-56 animate-pulse rounded bg-slate-800" />

            <div className="h-3 w-72 animate-pulse rounded bg-slate-800" />
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
            <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
              {Array.from({
                length: 12,
              }).map((_, index) => (
                <div
                  key={index}
                  className="space-y-2"
                >
                  <div className="h-3 w-20 animate-pulse rounded bg-slate-800" />

                  <div className="h-4 w-32 animate-pulse rounded bg-slate-800" />
                </div>
              ))}
            </div>
          </div>
        </div>
      </DetailsShell>
    );
  }

  /* ==========================================================================
   * Error State
   * ======================================================================== */

  if (error && !asset) {
    return (
      <DetailsShell isDrawer={isDrawer}>
        <div className="space-y-6">

          {!isDrawer && (
            <Link
              to="/assets"
              className="inline-flex items-center text-sm text-slate-400 transition hover:text-slate-200"
            >
              ← Back to Assets
            </Link>
          )}

          <div
            role="alert"
            className="rounded-xl border border-red-500/20 bg-red-500/5 p-6"
          >
            <div className="flex items-start gap-3">
              <span
                aria-hidden="true"
                className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-red-500/10 text-sm font-bold text-red-400"
              >
                !
              </span>

              <div className="min-w-0">
                <h1 className="text-lg font-semibold text-red-300">
                  Unable to load asset
                </h1>

                <p className="mt-2 break-words text-sm leading-6 text-red-400">
                  {error}
                </p>
              </div>
            </div>

            <button
              type="button"
              onClick={() => {
                void loadAsset();
              }}
              className="mt-5 inline-flex h-9 items-center justify-center rounded-lg border border-slate-700 bg-slate-900 px-4 text-sm font-medium text-slate-300 transition hover:border-slate-600 hover:bg-slate-800 hover:text-white focus:outline-none focus:ring-2 focus:ring-slate-500/20"
            >
              Retry
            </button>
          </div>
        </div>
      </DetailsShell>
    );
  }

  if (!asset) {
    return null;
  }

  /* ==========================================================================
   * Tabs
   * ======================================================================== */

  const tabs: Array<{
    id: AssetDetailsTab;
    label: string;
  }> = [
    {
      id: "overview",
      label: "Overview",
    },
    {
      id: "events",
      label: "Events",
    },
    {
      id: "vulnerabilities",
      label: "Vulnerabilities",
    },
    {
      id: "network",
      label: "Network",
    },
    {
      id: "software",
      label: "Software",
    },
    {
      id: "activity",
      label: "Activity",
    },
  ];

  /* ==========================================================================
   * Main Content
   * ======================================================================== */

  const content = (
    <div className="space-y-6">

      {/* ======================================================================
          Standalone Back Link
          ==================================================================== */}

      {!isDrawer && (
        <Link
          to="/assets"
          className="inline-flex items-center text-sm text-slate-400 transition hover:text-slate-200"
        >
          ← Back to Assets
        </Link>
      )}

      {/* ======================================================================
          Header
          ==================================================================== */}

      <header className="flex flex-col gap-5">
        <div className="min-w-0">

          <div className="flex flex-wrap items-center gap-3">
            <h1 className="break-words text-2xl font-semibold tracking-tight text-slate-100 sm:text-3xl">
              {asset.name}
            </h1>

            <AssetStatusBadge
              status={
                asset.lifecycle_status
              }
            />
          </div>

          <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-slate-500">
            <span className="font-mono text-xs text-slate-500">
              {formatValue(
                asset.ip_address,
              )}
            </span>

            <span
              aria-hidden="true"
              className="text-slate-700"
            >
              •
            </span>

            <span>
              {formatEnumLabel(
                asset.operating_system,
              )}
            </span>

            <span
              aria-hidden="true"
              className="text-slate-700"
            >
              •
            </span>

            <span>
              {formatEnumLabel(
                asset.asset_type,
              )}
            </span>
          </div>

          <p className="mt-2 break-all font-mono text-[11px] text-slate-700">
            {asset.asset_id}
          </p>
        </div>

        {/* ====================================================================
            Actions
            ================================================================== */}

        <div className="flex w-full flex-wrap items-center gap-2">

          {/* Refresh */}

          <button
            type="button"
            onClick={() => {
              void loadAsset();
            }}
            disabled={
              loading ||
              statusLoading ||
              formLoading
            }
            className="inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-4 text-sm font-medium text-slate-300 transition hover:border-slate-600 hover:bg-slate-800 hover:text-white focus:outline-none focus:ring-2 focus:ring-slate-500/20 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <span
              aria-hidden="true"
              className={
                loading
                  ? "animate-spin"
                  : ""
              }
            >
              ⟳
            </span>

            Refresh
          </button>

          {/* Edit */}

          <button
            type="button"
            onClick={
              handleOpenEdit
            }
            disabled={
              statusLoading ||
              formLoading
            }
            className="inline-flex h-10 items-center justify-center rounded-lg border border-slate-700 bg-slate-900 px-4 text-sm font-medium text-slate-300 transition hover:border-slate-600 hover:bg-slate-800 hover:text-white focus:outline-none focus:ring-2 focus:ring-slate-500/20 disabled:cursor-not-allowed disabled:opacity-50"
          >
            Edit
          </button>

          {/* Lifecycle */}

          {asset.lifecycle_status ===
          "ENABLED" ? (
            <button
              type="button"
              onClick={() => {
                void handleDisable();
              }}
              disabled={
                statusLoading ||
                formLoading
              }
              className="inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 px-4 text-sm font-medium text-amber-300 transition hover:border-amber-500/50 hover:bg-amber-500/10 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {statusLoading
                ? "Disabling..."
                : "Disable"}
            </button>
          ) : (
            <button
              type="button"
              onClick={() => {
                void handleEnable();
              }}
              disabled={
                statusLoading ||
                formLoading
              }
              className="inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/5 px-4 text-sm font-medium text-emerald-300 transition hover:border-emerald-500/50 hover:bg-emerald-500/10 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {statusLoading
                ? "Enabling..."
                : "Enable"}
            </button>
          )}
        </div>
      </header>

      {/* ======================================================================
          General Error
          ==================================================================== */}

      {error && (
        <div
          role="alert"
          className="flex flex-col gap-3 rounded-lg border border-red-500/20 bg-red-500/5 px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
        >
          <span className="break-words text-sm text-red-400">
            {error}
          </span>

          <button
            type="button"
            onClick={() => {
              void loadAsset();
            }}
            className="self-start text-sm font-medium text-red-300 underline underline-offset-2 transition hover:text-red-200 sm:self-auto"
          >
            Retry
          </button>
        </div>
      )}

      {/* ======================================================================
          Tabs
          ==================================================================== */}

      <section className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900">
        <nav
          aria-label="Asset details"
          className="flex overflow-x-auto border-b border-slate-800"
        >
          {tabs.map((tab) => {
            const active =
              activeTab === tab.id;

            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => {
                  setActiveTab(tab.id);
                }}
                className={[
                  "relative whitespace-nowrap px-4 py-3 text-sm font-medium transition sm:px-5",
                  active
                    ? "text-cyan-300"
                    : "text-slate-500 hover:text-slate-300",
                ].join(" ")}
                aria-current={
                  active
                    ? "page"
                    : undefined
                }
              >
                {tab.label}

                {active && (
                  <span className="absolute inset-x-0 bottom-0 h-0.5 bg-cyan-400" />
                )}
              </button>
            );
          })}
        </nav>

        {/* ====================================================================
            Tab Content
            ================================================================== */}

        <div className="p-5 sm:p-6">

          {/* ==================================================================
              Overview
              ================================================================== */}

          {activeTab ===
            "overview" && (
            <div className="space-y-8">

              <div>
                <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
                  Asset Overview
                </h2>

                <p className="mt-1 text-xs text-slate-600">
                  Core identity, lifecycle, operational state, risk, and ownership information.
                </p>
              </div>

              <dl className="grid gap-x-8 gap-y-7 sm:grid-cols-2 lg:grid-cols-3">

                <DetailField
                  label="Asset Name"
                  value={asset.name}
                />

                <DetailField
                  label="Hostname"
                  value={
                    asset.hostname
                  }
                />

                <DetailField
                  label="IP Address"
                  value={
                    asset.ip_address
                  }
                  mono
                />

                <DetailField
                  label="MAC Address"
                  value={
                    asset.mac_address
                  }
                  mono
                />

                <DetailField
                  label="Asset Type"
                  value={formatEnumLabel(
                    asset.asset_type,
                  )}
                />

                <DetailField
                  label="Operating System"
                  value={formatEnumLabel(
                    asset.operating_system,
                  )}
                />

                <DetailField
                  label="Environment"
                  value={formatEnumLabel(
                    asset.environment,
                  )}
                />

                <DetailField
                  label="Owner"
                  value={
                    asset.owner
                  }
                />

                <DetailField
                  label="Location"
                  value={
                    asset.location
                  }
                />

                <DetailField
                  label="Lifecycle Status"
                  value={formatEnumLabel(
                    asset.lifecycle_status,
                  )}
                  badge
                />

                <DetailField
                  label="Operational Status"
                  value={formatEnumLabel(
                    asset.operational_status,
                  )}
                />

                <DetailField
                  label="Risk"
                  value={formatEnumLabel(
                    asset.risk,
                  )}
                  risk
                />

                <DetailField
                  label="First Seen"
                  value={formatDate(
                    asset.first_seen,
                  )}
                />

                <DetailField
                  label="Last Seen"
                  value={formatDate(
                    asset.last_seen,
                  )}
                />

                <DetailField
                  label="Created"
                  value={formatDate(
                    asset.created_at,
                  )}
                />

                <DetailField
                  label="Last Updated"
                  value={formatDate(
                    asset.updated_at,
                  )}
                />

                <DetailField
                  label="Tags"
                  value={formatTags(
                    asset.tags,
                  )}
                />
              </dl>

              {/* Description */}

              <div className="border-t border-slate-800 pt-6">
                <h3 className="text-xs font-medium uppercase tracking-wider text-slate-500">
                  Description
                </h3>

                <p className="mt-2 whitespace-pre-wrap break-words text-sm leading-6 text-slate-400">
                  {formatValue(
                    asset.description,
                  )}
                </p>
              </div>

              {/* Metadata */}

              <div className="border-t border-slate-800 pt-6">
                <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <h3 className="text-xs font-medium uppercase tracking-wider text-slate-500">
                      Metadata
                    </h3>

                    <p className="mt-1 text-xs text-slate-600">
                      Additional structured information associated with this asset.
                    </p>
                  </div>

                  <span className="text-[10px] uppercase tracking-wider text-slate-700">
                    JSON Object
                  </span>
                </div>

                <div className="mt-3">
                  {asset.metadata &&
                  Object.keys(
                    asset.metadata,
                  ).length > 0 ? (
                    <pre className="max-h-[500px] overflow-auto rounded-lg border border-slate-800 bg-slate-950 p-4 font-mono text-xs leading-6 text-slate-400">
                      {JSON.stringify(
                        asset.metadata,
                        null,
                        2,
                      )}
                    </pre>
                  ) : (
                    <p className="text-sm text-slate-500">
                      No metadata available.
                    </p>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* ==================================================================
              Events
              ================================================================== */}

          {activeTab ===
            "events" && (
            <EmptyTabState
              title="Asset Events"
              description="Asset-related security events will appear here."
              icon="◉"
            />
          )}

          {/* ==================================================================
              Vulnerabilities
              ================================================================== */}

          {activeTab ===
            "vulnerabilities" && (
            <EmptyTabState
              title="Asset Vulnerabilities"
              description="Detected vulnerabilities associated with this asset will appear here."
              icon="△"
            />
          )}

          {/* ==================================================================
              Network
              ================================================================== */}

          {activeTab ===
            "network" && (
            <div className="space-y-6">
              <div>
                <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
                  Network
                </h2>

                <p className="mt-1 text-xs text-slate-600">
                  Network identity currently available for this asset.
                </p>
              </div>

              <dl className="grid gap-x-8 gap-y-7 sm:grid-cols-2 lg:grid-cols-3">
                <DetailField
                  label="IP Address"
                  value={
                    asset.ip_address
                  }
                  mono
                />

                <DetailField
                  label="MAC Address"
                  value={
                    asset.mac_address
                  }
                  mono
                />

                <DetailField
                  label="Hostname"
                  value={
                    asset.hostname
                  }
                />

                <DetailField
                  label="Location"
                  value={
                    asset.location
                  }
                />

                <DetailField
                  label="Environment"
                  value={formatEnumLabel(
                    asset.environment,
                  )}
                />

                <DetailField
                  label="Operational Status"
                  value={formatEnumLabel(
                    asset.operational_status,
                  )}
                />
              </dl>

              <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-4">
                <p className="text-xs leading-5 text-slate-600">
                  Network interfaces, segments, open ports, and protocols require corresponding backend asset-network data sources.
                </p>
              </div>
            </div>
          )}

          {/* ==================================================================
              Software
              ================================================================== */}

          {activeTab ===
            "software" && (
            <EmptyTabState
              title="Installed Software"
              description="Software inventory associated with this asset will appear here."
              icon="▣"
            />
          )}

          {/* ==================================================================
              Activity
              ================================================================== */}

          {activeTab ===
            "activity" && (
            <div className="space-y-6">
              <div>
                <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
                  Asset Activity
                </h2>

                <p className="mt-1 text-xs text-slate-600">
                  Lifecycle and management activity for this asset.
                </p>
              </div>

              <div className="space-y-3">
                <ActivityItem
                  label="Asset Created"
                  timestamp={
                    asset.created_at
                  }
                />

                <ActivityItem
                  label="Last Updated"
                  timestamp={
                    asset.updated_at
                  }
                />

                {asset.first_seen && (
                  <ActivityItem
                    label="First Seen"
                    timestamp={
                      asset.first_seen
                    }
                  />
                )}

                {asset.last_seen && (
                  <ActivityItem
                    label="Last Seen"
                    timestamp={
                      asset.last_seen
                    }
                  />
                )}
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-4">
                <p className="text-xs leading-5 text-slate-600">
                  Complete create, update, enable, and disable audit history is provided by the SentinelSIEM audit system.
                </p>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* ======================================================================
          Standalone Edit Form
          ==================================================================== */}

      {!isParentControlledEdit &&
        showEditForm && (
          <div
            className="fixed inset-0 z-50 flex items-center justify-center overflow-y-auto bg-black/70 p-4 backdrop-blur-[2px]"
            role="dialog"
            aria-modal="true"
            aria-label={`Edit asset ${asset.name}`}
            onMouseDown={(
              event,
            ) => {
              if (
                event.target ===
                  event.currentTarget &&
                !formLoading
              ) {
                handleCloseEdit();
              }
            }}
          >
            <div
              className="w-full max-w-3xl"
              onMouseDown={(
                event,
              ) => {
                event.stopPropagation();
              }}
            >
              <AssetForm
                asset={asset}
                loading={
                  formLoading
                }
                error={
                  formError
                }
                onSubmit={
                  handleUpdate
                }
                onCancel={
                  handleCloseEdit
                }
              />
            </div>
          </div>
        )}
    </div>
  );

  /* ==========================================================================
   * Drawer / Standalone Shell
   * ======================================================================== */

  return (
    <DetailsShell isDrawer={isDrawer}>
      {content}
    </DetailsShell>
  );
}

/* ==========================================================================
 * Details Shell
 * ========================================================================== */

interface DetailsShellProps {
  children: ReactNode;

  isDrawer: boolean;
}

function DetailsShell({
  children,
  isDrawer,
}: DetailsShellProps) {
  /*
   * Standalone route:
   *
   * Return the content without any drawer wrapper.
   */

  if (!isDrawer) {
    return (
      <div className="space-y-6">
        {children}
      </div>
    );
  }

  /*
   * Inventory:
   *
   * Assets.tsx owns the outer right-side drawer,
   * including the header and close button.
   */

  return (
    <div className="asset-details-drawer-content">
      {children}
    </div>
  );
}

/* ==========================================================================
 * Detail Field
 * ========================================================================== */

interface DetailFieldProps {
  label: string;

  value:
    | string
    | null
    | undefined;

  mono?: boolean;

  badge?: boolean;

  risk?: boolean;
}

function DetailField({
  label,
  value,
  mono = false,
  badge = false,
  risk = false,
}: DetailFieldProps) {
  const normalizedValue =
    value?.trim() || "—";

  return (
    <div className="min-w-0">
      <dt className="text-xs font-medium uppercase tracking-wider text-slate-500">
        {label}
      </dt>

      <dd
        className={[
          "mt-1 break-words text-sm",
          badge
            ? "inline-flex rounded-md border border-slate-700 bg-slate-950 px-2 py-1 text-slate-300"
            : risk
              ? "font-medium text-slate-200"
              : "text-slate-200",
          mono
            ? "font-mono"
            : "",
        ]
          .filter(Boolean)
          .join(" ")}
      >
        {normalizedValue}
      </dd>
    </div>
  );
}

/* ==========================================================================
 * Empty Tab State
 * ========================================================================== */

interface EmptyTabStateProps {
  title: string;

  description: string;

  icon: string;
}

function EmptyTabState({
  title,
  description,
  icon,
}: EmptyTabStateProps) {
  return (
    <div className="flex min-h-[260px] flex-col items-center justify-center text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-slate-800 bg-slate-950 text-xl text-slate-600">
        <span aria-hidden="true">
          {icon}
        </span>
      </div>

      <h2 className="mt-4 text-sm font-semibold text-slate-300">
        {title}
      </h2>

      <p className="mt-2 max-w-md text-xs leading-5 text-slate-600">
        {description}
      </p>
    </div>
  );
}

/* ==========================================================================
 * Activity Item
 * ========================================================================== */

interface ActivityItemProps {
  label: string;

  timestamp:
    | string
    | null
    | undefined;
}

function ActivityItem({
  label,
  timestamp,
}: ActivityItemProps) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-3">
      <div className="flex items-center gap-3">
        <span
          aria-hidden="true"
          className="h-2 w-2 rounded-full bg-cyan-400"
        />

        <span className="text-sm text-slate-300">
          {label}
        </span>
      </div>

      <span className="shrink-0 text-xs text-slate-600">
        {formatDate(timestamp)}
      </span>
    </div>
  );
}