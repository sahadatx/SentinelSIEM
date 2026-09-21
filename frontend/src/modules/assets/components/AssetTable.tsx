/* ==========================================================================
 * Asset Table
 * SentinelSIEM SOC Dashboard
 * ========================================================================== */

import {
  CheckCircle2,
  Eye,
  MoreVertical,
  Pencil,
  PauseCircle,
  PlayCircle,
} from "lucide-react";

import {
  createPortal,
} from "react-dom";

import {
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import type {
  Asset,
} from "../types";

import AssetStatusBadge from "./AssetStatusBadge";

/* ==========================================================================
 * Props
 * ========================================================================== */

export interface AssetTableProps {
  assets: Asset[];

  loading?: boolean;

  error?: string | null;

  onView?: (
    asset: Asset,
  ) => void;

  onEdit?: (
    asset: Asset,
  ) => void;

  onEnable?: (
    asset: Asset,
  ) => void;

  onDisable?: (
    asset: Asset,
  ) => void;
}

/* ==========================================================================
 * Helpers
 * ========================================================================== */

function displayValue(
  value: string | null | undefined,
): string {
  return value?.trim() || "—";
}

/**
 * Convert machine-readable values into human-readable labels.
 *
 * Examples:
 *   WEB_SERVER       -> Web Server
 *   WINDOWS_SERVER   -> Windows Server
 *   DISASTER_RECOVERY -> Disaster Recovery
 */
function formatLabel(
  value: string | null | undefined,
): string {
  if (!value?.trim()) {
    return "—";
  }

  return value
    .trim()
    .toLowerCase()
    .split(/[\s_-]+/)
    .filter(Boolean)
    .map(
      (part) =>
        part.charAt(0).toUpperCase() +
        part.slice(1),
    )
    .join(" ");
}

/**
 * Return the lifecycle action available for the asset.
 *
 * IMPORTANT:
 * Lifecycle status and operational status are separate concepts.
 *
 * ENABLED  -> Disable action
 * DISABLED -> Enable action
 */
function getLifecycleAction(
  asset: Asset,
): "enable" | "disable" | null {
  switch (
    asset.lifecycle_status
      ?.trim()
      .toUpperCase()
  ) {
    case "ENABLED":
      return "disable";

    case "DISABLED":
      return "enable";

    default:
      return null;
  }
}

/* ==========================================================================
 * Loading Rows
 * ========================================================================== */

function LoadingRows() {
  return (
    <>
      {Array.from({
        length: 6,
      }).map((_, rowIndex) => (
        <tr
          key={`asset-loading-row-${rowIndex}`}
          className="asset-table-loading-row"
        >
          {Array.from({
            length: 8,
          }).map((_, cellIndex) => (
            <td
              key={`asset-loading-cell-${rowIndex}-${cellIndex}`}
              className="asset-table-loading-cell"
            >
              <div
                aria-hidden="true"
                className="asset-table-skeleton"
              />
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}

/* ==========================================================================
 * Empty State
 * ========================================================================== */

function EmptyState() {
  return (
    <tr>
      <td
        colSpan={8}
        className="asset-table-empty-cell"
      >
        <div className="asset-table-empty">
          <div
            className="asset-table-empty-icon"
            aria-hidden="true"
          >
            <CheckCircle2
              size={20}
              strokeWidth={1.6}
            />
          </div>

          <p className="asset-table-empty-title">
            No assets found
          </p>

          <p className="asset-table-empty-description">
            Try changing the filters or create
            a new asset.
          </p>
        </div>
      </td>
    </tr>
  );
}

/* ==========================================================================
 * Error State
 * ========================================================================== */

function ErrorState({
  error,
}: {
  error: string;
}) {
  return (
    <div
      role="alert"
      className="asset-table-error"
    >
      <span className="asset-table-error-title">
        Unable to load assets
      </span>

      <span className="asset-table-error-message">
        {error}
      </span>
    </div>
  );
}

/* ==========================================================================
 * Action Menu
 * ========================================================================== */

interface AssetActionsProps {
  asset: Asset;

  onView?: (
    asset: Asset,
  ) => void;

  onEdit?: (
    asset: Asset,
  ) => void;

  onEnable?: (
    asset: Asset,
  ) => void;

  onDisable?: (
    asset: Asset,
  ) => void;
}

interface MenuPosition {
  top: number;
  left: number;
}

const ACTION_MENU_WIDTH = 190;
const ACTION_MENU_ESTIMATED_HEIGHT = 180;
const VIEWPORT_GAP = 8;
const MENU_GAP = 6;

/* ==========================================================================
 * Asset Actions
 * ========================================================================== */

function AssetActions({
  asset,
  onView,
  onEdit,
  onEnable,
  onDisable,
}: AssetActionsProps) {
  const [
    open,
    setOpen,
  ] = useState(false);

  const [
    menuPosition,
    setMenuPosition,
  ] = useState<MenuPosition | null>(
    null,
  );

  const triggerRef =
    useRef<HTMLButtonElement>(null);

  const menuRef =
    useRef<HTMLDivElement>(null);

  const lifecycleAction =
    getLifecycleAction(asset);

  const hasActions = Boolean(
    onView ||
      onEdit ||
      (lifecycleAction === "enable" &&
        onEnable) ||
      (lifecycleAction === "disable" &&
        onDisable),
  );

  /* ------------------------------------------------------------------------
   * Calculate menu position
   * ---------------------------------------------------------------------- */

  const updateMenuPosition =
    useCallback(() => {
      const trigger =
        triggerRef.current;

      if (!trigger) {
        return;
      }

      const rect =
        trigger.getBoundingClientRect();

      let left =
        rect.right -
        ACTION_MENU_WIDTH;

      let top =
        rect.bottom +
        MENU_GAP;

      /* --------------------------------------------------------------------
       * Horizontal viewport protection
       * ------------------------------------------------------------------ */

      if (
        left <
        VIEWPORT_GAP
      ) {
        left =
          VIEWPORT_GAP;
      }

      if (
        left +
          ACTION_MENU_WIDTH >
        window.innerWidth -
          VIEWPORT_GAP
      ) {
        left =
          window.innerWidth -
          ACTION_MENU_WIDTH -
          VIEWPORT_GAP;
      }

      /* --------------------------------------------------------------------
       * Vertical viewport protection
       *
       * Prefer opening below the trigger.
       * If there is not enough space, open above.
       * ------------------------------------------------------------------ */

      const spaceBelow =
        window.innerHeight -
        rect.bottom;

      const spaceAbove =
        rect.top;

      if (
        spaceBelow <
          ACTION_MENU_ESTIMATED_HEIGHT +
            MENU_GAP &&
        spaceAbove >
          ACTION_MENU_ESTIMATED_HEIGHT +
            MENU_GAP
      ) {
        top =
          rect.top -
          ACTION_MENU_ESTIMATED_HEIGHT -
          MENU_GAP;
      }

      if (
        top <
        VIEWPORT_GAP
      ) {
        top =
          VIEWPORT_GAP;
      }

      setMenuPosition({
        top,
        left,
      });
    }, []);

  /* ------------------------------------------------------------------------
   * Open / close menu
   * ---------------------------------------------------------------------- */

  function handleToggle() {
    if (open) {
      setOpen(false);
      return;
    }

    updateMenuPosition();
    setOpen(true);
  }

  /* ------------------------------------------------------------------------
   * Reposition while open
   * ---------------------------------------------------------------------- */

  useEffect(() => {
    if (!open) {
      return;
    }

    updateMenuPosition();

    function handleViewportChange() {
      updateMenuPosition();
    }

    window.addEventListener(
      "resize",
      handleViewportChange,
    );

    window.addEventListener(
      "scroll",
      handleViewportChange,
      true,
    );

    return () => {
      window.removeEventListener(
        "resize",
        handleViewportChange,
      );

      window.removeEventListener(
        "scroll",
        handleViewportChange,
        true,
      );
    };
  }, [
    open,
    updateMenuPosition,
  ]);

  /* ------------------------------------------------------------------------
   * Outside click
   * ---------------------------------------------------------------------- */

  useEffect(() => {
    if (!open) {
      return;
    }

    function handlePointerDown(
      event: MouseEvent,
    ) {
      const target =
        event.target as Node;

      const clickedTrigger =
        triggerRef.current?.contains(
          target,
        );

      const clickedMenu =
        menuRef.current?.contains(
          target,
        );

      if (
        !clickedTrigger &&
        !clickedMenu
      ) {
        setOpen(false);
      }
    }

    document.addEventListener(
      "mousedown",
      handlePointerDown,
    );

    return () => {
      document.removeEventListener(
        "mousedown",
        handlePointerDown,
      );
    };
  }, [open]);

  /* ------------------------------------------------------------------------
   * Escape
   * ---------------------------------------------------------------------- */

  useEffect(() => {
    if (!open) {
      return;
    }

    function handleKeyDown(
      event: KeyboardEvent,
    ) {
      if (event.key === "Escape") {
        setOpen(false);

        requestAnimationFrame(() => {
          triggerRef.current?.focus();
        });
      }
    }

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
  }, [open]);

  /* ------------------------------------------------------------------------
   * No actions
   * ---------------------------------------------------------------------- */

  if (!hasActions) {
    return (
      <span className="asset-table-no-action">
        —
      </span>
    );
  }

  /* ------------------------------------------------------------------------
   * Action handlers
   * ---------------------------------------------------------------------- */

  function handleView() {
    setOpen(false);
    onView?.(asset);
  }

  function handleEdit() {
    setOpen(false);
    onEdit?.(asset);
  }

  function handleEnable() {
    setOpen(false);
    onEnable?.(asset);
  }

  function handleDisable() {
    setOpen(false);
    onDisable?.(asset);
  }

  /* ------------------------------------------------------------------------
   * Dropdown
   * ---------------------------------------------------------------------- */

  const dropdown =
    open &&
    menuPosition &&
    typeof document !==
      "undefined"
      ? createPortal(
          <div
            ref={menuRef}
            role="menu"
            aria-label={`Actions for ${asset.name}`}
            className="asset-action-dropdown"
            style={{
              position: "fixed",
              top: menuPosition.top,
              left: menuPosition.left,
            }}
          >
            {/* ==============================================================
             * View
             * ============================================================ */}

            {onView && (
              <button
                type="button"
                role="menuitem"
                onClick={handleView}
                className="asset-action-item"
              >
                <Eye
                  size={15}
                  strokeWidth={1.8}
                  aria-hidden="true"
                />

                <span>
                  View
                </span>
              </button>
            )}

            {/* ==============================================================
             * Edit
             * ============================================================ */}

            {onEdit && (
              <button
                type="button"
                role="menuitem"
                onClick={handleEdit}
                className="asset-action-item"
              >
                <Pencil
                  size={15}
                  strokeWidth={1.8}
                  aria-hidden="true"
                />

                <span>
                  Edit
                </span>
              </button>
            )}

            {/* ==============================================================
             * Enable
             * ============================================================ */}

            {lifecycleAction ===
              "enable" &&
              onEnable && (
                <button
                  type="button"
                  role="menuitem"
                  onClick={
                    handleEnable
                  }
                  className="asset-action-item"
                >
                  <PlayCircle
                    size={15}
                    strokeWidth={1.8}
                    aria-hidden="true"
                  />

                  <span>
                    Enable
                  </span>
                </button>
              )}

            {/* ==============================================================
             * Disable
             * ============================================================ */}

            {lifecycleAction ===
              "disable" &&
              onDisable && (
                <>
                  <div
                    className="asset-action-divider"
                    aria-hidden="true"
                  />

                  <button
                    type="button"
                    role="menuitem"
                    onClick={
                      handleDisable
                    }
                    className="asset-action-item asset-action-disable"
                  >
                    <PauseCircle
                      size={15}
                      strokeWidth={1.8}
                      aria-hidden="true"
                    />

                    <span>
                      Disable
                    </span>
                  </button>
                </>
              )}
          </div>,
          document.body,
        )
      : null;

  /* ------------------------------------------------------------------------
   * Render
   * ---------------------------------------------------------------------- */

  return (
    <>
      <div className="asset-action-menu">
        <button
          ref={triggerRef}
          type="button"
          title="Asset actions"
          aria-label={`Actions for ${asset.name}`}
          aria-haspopup="menu"
          aria-expanded={open}
          onClick={handleToggle}
          className="asset-action-trigger"
        >
          <MoreVertical
            size={17}
            strokeWidth={1.9}
            aria-hidden="true"
          />
        </button>
      </div>

      {dropdown}
    </>
  );
}

/* ==========================================================================
 * Component
 * ========================================================================== */

export default function AssetTable({
  assets,
  loading = false,
  error = null,
  onView,
  onEdit,
  onEnable,
  onDisable,
}: AssetTableProps) {
  /* ==========================================================================
   * Error State
   * ======================================================================== */

  if (
    error &&
    !loading
  ) {
    return (
      <ErrorState
        error={error}
      />
    );
  }

  /* ==========================================================================
   * Render
   * ======================================================================== */

  return (
    <section
      aria-label="Asset table"
      className="asset-table-panel"
    >
      {/* ====================================================================
       * Table
       * ================================================================== */}

      <div className="asset-table-scroll">
        <table className="asset-table">
          <caption className="sr-only">
            SentinelSIEM managed assets
          </caption>

          {/* ================================================================
           * Header
           * ============================================================ */}

          <thead>
            <tr>
              <th
                scope="col"
                className="asset-col-asset"
              >
                Asset
              </th>

              <th
                scope="col"
                className="asset-col-type"
              >
                Type
              </th>

              <th
                scope="col"
                className="asset-col-ip"
              >
                IP Address
              </th>

              <th
                scope="col"
                className="asset-col-os"
              >
                Operating System
              </th>

              <th
                scope="col"
                className="asset-col-status"
              >
                Status
              </th>

              <th
                scope="col"
                className="asset-col-risk"
              >
                Risk
              </th>

              <th
                scope="col"
                className="asset-col-last-seen"
              >
                Last Seen
              </th>

              <th
                scope="col"
                className="asset-col-actions"
              >
                Actions
              </th>
            </tr>
          </thead>

          {/* ================================================================
           * Body
           * ============================================================ */}

          <tbody>
            {loading ? (
              <LoadingRows />
            ) : assets.length ===
              0 ? (
              <EmptyState />
            ) : (
              assets.map(
                (asset) => (
                  <tr
                    key={
                      asset.asset_id
                    }
                    className="asset-table-row"
                  >
                    {/* ======================================================
                     * Asset
                     * ==================================================== */}

                    <td className="asset-table-cell asset-cell-primary">
                      <div className="asset-identity">
                        <div className="asset-name-row">
                          <span
                            className="asset-name-marker"
                            aria-hidden="true"
                          />

                          {onView ? (
                            <button
                              type="button"
                              onClick={() =>
                                onView(
                                  asset,
                                )
                              }
                              className="asset-name-button"
                              title={`View ${asset.name}`}
                            >
                              {displayValue(
                                asset.name,
                              )}
                            </button>
                          ) : (
                            <span className="asset-name">
                              {displayValue(
                                asset.name,
                              )}
                            </span>
                          )}
                        </div>

                        <p
                          className="asset-hostname"
                          title={
                            asset.hostname ||
                            undefined
                          }
                        >
                          {displayValue(
                            asset.hostname,
                          )}
                        </p>
                      </div>
                    </td>

                    {/* ======================================================
                     * Type
                     * ==================================================== */}

                    <td className="asset-table-cell">
                      <span className="asset-type">
                        {formatLabel(
                          asset.asset_type,
                        )}
                      </span>
                    </td>

                    {/* ======================================================
                     * IP Address
                     * ==================================================== */}

                    <td className="asset-table-cell">
                      <span
                        className="asset-ip-address"
                        title={
                          asset.ip_address ||
                          undefined
                        }
                      >
                        {displayValue(
                          asset.ip_address,
                        )}
                      </span>
                    </td>

                    {/* ======================================================
                     * Operating System
                     * ==================================================== */}

                    <td className="asset-table-cell">
                      <span
                        className="asset-operating-system"
                        title={
                          asset.operating_system ||
                          undefined
                        }
                      >
                        {formatLabel(
                          asset.operating_system,
                        )}
                      </span>
                    </td>

                    {/* ======================================================
                     * Lifecycle Status
                     *
                     * IMPORTANT:
                     * Do not use operational_status here.
                     *
                     * The table status represents whether the asset is
                     * enabled or disabled in the asset inventory.
                     * ==================================================== */}

                    <td className="asset-table-cell">
                      <AssetStatusBadge
                        status={
                          asset.lifecycle_status
                        }
                      />
                    </td>

                    {/* ======================================================
                     * Risk
                     * ==================================================== */}

                    <td className="asset-table-cell">
                      <span
                        className={[
                          "asset-risk-badge",
                          `asset-risk-${asset.risk
                            .trim()
                            .toLowerCase()}`,
                        ].join(" ")}
                      >
                        {formatLabel(
                          asset.risk,
                        )}
                      </span>
                    </td>

                    {/* ======================================================
                     * Last Seen
                     * ==================================================== */}

                    <td className="asset-table-cell">
                      <span
                        className="asset-last-seen"
                        title={
                          asset.last_seen ||
                          undefined
                        }
                      >
                        {displayValue(
                          asset.last_seen,
                        )}
                      </span>
                    </td>

                    {/* ======================================================
                     * Actions
                     * ==================================================== */}

                    <td className="asset-table-cell asset-actions-cell">
                      <AssetActions
                        asset={asset}
                        onView={onView}
                        onEdit={onEdit}
                        onEnable={
                          onEnable
                        }
                        onDisable={
                          onDisable
                        }
                      />
                    </td>
                  </tr>
                ),
              )
            )}
          </tbody>
        </table>
      </div>

      {/* ====================================================================
       * Footer
       * ================================================================== */}

      {!loading &&
        assets.length >
          0 && (
          <div className="asset-table-footer">
            <span className="asset-table-footer-label">
              Showing
            </span>

            <span className="asset-table-footer-count">
              {assets.length}
            </span>

            <span className="asset-table-footer-label">
              asset
              {assets.length ===
              1
                ? ""
                : "s"}
            </span>
          </div>
        )}
    </section>
  );
}