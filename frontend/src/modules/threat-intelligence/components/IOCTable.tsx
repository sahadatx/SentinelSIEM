import {
  useEffect,
  useState,
} from "react";

import type { IOC } from "../types";

/* ============================================================================
 * IOC Table
 * ========================================================================== */

interface IOCTableProps {
  iocs: IOC[];
  canManage: boolean;
  onView: (ioc: IOC) => void;
  onEdit: (ioc: IOC) => void;
  onToggleStatus: (ioc: IOC) => void;
}

/**
 * Threat Intelligence IOC inventory table.
 *
 * Final columns:
 *
 *   IOC | Type | Severity | Status | Source | Reputation | Last Seen | Actions
 *
 * Responsibilities:
 *   - Render backend-provided IOC records.
 *   - Display human-readable IOC metadata.
 *   - Expose View / Edit / Enable / Disable actions.
 *
 * This component intentionally does NOT:
 *   - calculate KPI values;
 *   - calculate pagination;
 *   - filter IOC records;
 *   - calculate total pages;
 *   - create or modify IOC state directly.
 *
 * Parent page + backend remain the source of truth.
 */
export function IOCTable({
  iocs,
  canManage,
  onView,
  onEdit,
  onToggleStatus,
}: IOCTableProps) {
  const [openMenuId, setOpenMenuId] =
    useState<string | null>(null);

  useEffect(() => {
    if (!openMenuId) {
      return;
    }

    const handleDocumentClick = () => {
      setOpenMenuId(null);
    };

    const handleEscape = (
      event: KeyboardEvent,
    ) => {
      if (event.key === "Escape") {
        setOpenMenuId(null);
      }
    };

    document.addEventListener(
      "click",
      handleDocumentClick,
    );

    document.addEventListener(
      "keydown",
      handleEscape,
    );

    return () => {
      document.removeEventListener(
        "click",
        handleDocumentClick,
      );

      document.removeEventListener(
        "keydown",
        handleEscape,
      );
    };
  }, [openMenuId]);

  const handleMenuToggle = (
    event: React.MouseEvent<HTMLButtonElement>,
    iocId: string,
  ) => {
    event.stopPropagation();

    setOpenMenuId((current) =>
      current === iocId
        ? null
        : iocId,
    );
  };

  const handleViewIOC = (ioc: IOC) => {
    setOpenMenuId(null);
    onView(ioc);
  };

  const handleEditIOC = (ioc: IOC) => {
    setOpenMenuId(null);
    onEdit(ioc);
  };

  const handleToggleIOCStatus = (ioc: IOC) => {
    setOpenMenuId(null);
    onToggleStatus(ioc);
  };

  if (iocs.length === 0) {
    return (
      <div className="empty-state">
        <p>No indicators available.</p>
      </div>
    );
  }

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {/* IOC */}
            <th>IOC</th>

            {/* Type */}
            <th>Type</th>

            {/* Severity */}
            <th>Severity</th>

            {/* Status */}
            <th>Status</th>

            {/* Source */}
            <th>Source</th>

            {/* Reputation */}
            <th>Reputation</th>

            {/* Last Seen */}
            <th>Last Seen</th>

            {/* Actions */}
            <th>Actions</th>
          </tr>
        </thead>

        <tbody>
          {iocs.map((ioc) => (
            <tr key={ioc.id}>
              {/* ==================================================================
               * IOC
               * ================================================================== */}

              <td>
                <button
                  type="button"
                  className="ioc-value-button"
                  onClick={() => onView(ioc)}
                  title="View IOC"
                >
                  <code>
                    {ioc.indicator || ioc.value || "—"}
                  </code>
                </button>
              </td>

              {/* ==================================================================
               * Type
               * ================================================================== */}

              <td>
                <span className="health-pill">
                  {formatType(ioc.type)}
                </span>
              </td>

              {/* ==================================================================
               * Severity
               * ================================================================== */}

              <td>
                <span
                  className={`health-pill ${getSeverityClass(
                    ioc.severity,
                  )}`}
                >
                  {formatSeverity(ioc.severity)}
                </span>
              </td>

              {/* ==================================================================
               * Status
               * ================================================================== */}

              <td>
                <span
                  className={`health-pill ${getStatusClass(
                    ioc.status,
                  )}`}
                >
                  {formatStatus(ioc.status)}
                </span>
              </td>

              {/* ==================================================================
               * Source
               * ================================================================== */}

              <td>
                {ioc.source || "—"}
              </td>

              {/* ==================================================================
               * Reputation
               * ================================================================== */}

              <td>
                <span
                  className={`health-pill ${getReputationClass(
                    ioc.reputation,
                  )}`}
                >
                  {formatReputation(ioc.reputation)}
                </span>
              </td>

              {/* ==================================================================
               * Last Seen
               * ================================================================== */}

              <td>
                <span
                  className="ioc-last-seen"
                  title={formatFullDate(ioc.last_seen)}
                >
                  {formatRelativeTime(ioc.last_seen)}
                </span>
              </td>

              {/* ==================================================================
               * Actions
               * ================================================================== */}

              <td>
                <div
                  className="ioc-actions"
                  onClick={(event) => {
                    event.stopPropagation();
                  }}
                >
                  <button
                    type="button"
                    className={`ioc-action-button ${
                      openMenuId === ioc.id
                        ? "is-open"
                        : ""
                    }`}
                    onClick={(event) =>
                      handleMenuToggle(
                        event,
                        ioc.id,
                      )
                    }
                    aria-label={`IOC actions ${
                      ioc.indicator ||
                      ioc.value ||
                      ""
                    }`}
                    aria-expanded={
                      openMenuId === ioc.id
                    }
                    aria-haspopup="menu"
                    title="IOC actions"
                  >
                    ⋮
                  </button>

                  {openMenuId === ioc.id && (
                    <div
                      className="ioc-action-menu"
                      role="menu"
                      onClick={(event) => {
                        event.stopPropagation();
                      }}
                    >
                      <button
                        type="button"
                        role="menuitem"
                        onClick={() =>
                          handleViewIOC(ioc)
                        }
                      >
                        <span aria-hidden="true">
                          👁
                        </span>

                        <span>
                          View IOC
                        </span>
                      </button>

                      {canManage && (
                        <>
                          <button
                            type="button"
                            role="menuitem"
                            onClick={() =>
                              handleEditIOC(ioc)
                            }
                          >
                            <span aria-hidden="true">
                              ✏️
                            </span>

                            <span>
                              Edit IOC
                            </span>
                          </button>

                          <button
                            type="button"
                            role="menuitem"
                            onClick={() =>
                              handleToggleIOCStatus(
                                ioc,
                              )
                            }
                          >
                            <span aria-hidden="true">
                              ●
                            </span>

                            <span>
                              {isActiveStatus(
                                ioc.status,
                              )
                                ? "Disable IOC"
                                : "Enable IOC"}
                            </span>
                          </button>
                        </>
                      )}
                    </div>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ============================================================================
 * Type Formatting
 * ========================================================================== */

/**
 * Convert backend IOC type into a compact human-readable label.
 *
 * Examples:
 *   ipv4      → IPv4
 *   ipv6      → IPv6
 *   domain    → Domain
 *   url       → URL
 *   hash      → Hash
 *   email     → Email
 *   hostname  → Hostname
 */
function formatType(type: string): string {
  const normalized = type.trim().toLowerCase();

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

    default:
      if (!normalized) {
        return "Unknown";
      }

      return normalized
        .replace(/[\_-]+/g, " ")
        .replace(
          /\b\w/g,
          (character) => character.toUpperCase(),
        );
  }
}

/* ============================================================================
 * Severity
 * ========================================================================== */

function formatSeverity(severity: string): string {
  const normalized = severity.trim().toLowerCase();

  switch (normalized) {
    case "critical":
      return "Critical";

    case "high":
      return "High";

    case "medium":
      return "Medium";

    case "low":
      return "Low";

    case "info":
    case "informational":
      return "Informational";

    default:
      return severity || "Unknown";
  }
}

function getSeverityClass(severity: string): string {
  const normalized = severity.trim().toLowerCase();

  switch (normalized) {
    case "critical":
      return "offline";

    case "high":
      return "degraded";

    case "medium":
      return "warning";

    case "low":
      return "healthy";

    case "info":
    case "informational":
      return "";

    default:
      return "";
  }
}

/* ============================================================================
 * Status
 * ========================================================================== */

function formatStatus(status: string): string {
  const normalized = status.trim().toLowerCase();

  switch (normalized) {
    case "active":
      return "Active";

    case "expired":
      return "Expired";

    case "revoked":
      return "Revoked";

    default:
      if (!normalized) {
        return "Unknown";
      }

      return normalized
        .replace(/[\_-]+/g, " ")
        .replace(
          /\b\w/g,
          (character) => character.toUpperCase(),
        );
  }
}

function getStatusClass(status: string): string {
  const normalized = status.trim().toLowerCase();

  switch (normalized) {
    case "active":
      return "healthy";

    case "expired":
      return "degraded";

    case "revoked":
      return "offline";

    default:
      return "";
  }
}

function isActiveStatus(status: string): boolean {
  return status.trim().toLowerCase() === "active";
}

/* ============================================================================
 * Reputation
 * ========================================================================== */

/**
 * Normalize reputation values for display.
 *
 * Backend catalogue:
 *   unknown
 *   benign
 *   suspicious
 *   malicious
 */
function formatReputation(reputation: string): string {
  const normalized = reputation.trim().toLowerCase();

  switch (normalized) {
    case "malicious":
      return "Malicious";

    case "suspicious":
      return "Suspicious";

    case "benign":
      return "Benign";

    case "unknown":
      return "Unknown";

    default:
      return reputation || "Unknown";
  }
}

/**
 * Map reputation to existing SentinelSIEM health-pill classes.
 */
function getReputationClass(reputation: string): string {
  const normalized = reputation.trim().toLowerCase();

  switch (normalized) {
    case "malicious":
      return "offline";

    case "suspicious":
      return "degraded";

    case "benign":
      return "healthy";

    case "unknown":
      return "";

    default:
      return "";
  }
}

/* ============================================================================
 * Date / Time
 * ========================================================================== */

/**
 * Render Last Seen as a relative time.
 *
 * Examples:
 *   2 min ago
 *   15 min ago
 *   1 hour ago
 *   2 days ago
 *
 * The timestamp itself comes from the backend.
 * This helper only controls presentation.
 */
function formatRelativeTime(value?: string | null): string {
  if (!value) {
    return "—";
  }

  const timestamp = new Date(value).getTime();

  if (!Number.isFinite(timestamp)) {
    return "—";
  }

  const difference = Date.now() - timestamp;

  if (difference < 0) {
    return "Just now";
  }

  const seconds = Math.floor(difference / 1000);

  if (seconds < 60) {
    return "Just now";
  }

  const minutes = Math.floor(seconds / 60);

  if (minutes < 60) {
    return `${minutes} min ago`;
  }

  const hours = Math.floor(minutes / 60);

  if (hours < 24) {
    return `${hours} hour${hours === 1 ? "" : "s"} ago`;
  }

  const days = Math.floor(hours / 24);

  if (days < 30) {
    return `${days} day${days === 1 ? "" : "s"} ago`;
  }

  const months = Math.floor(days / 30);

  if (months < 12) {
    return `${months} month${months === 1 ? "" : "s"} ago`;
  }

  const years = Math.floor(months / 12);

  return `${years} year${years === 1 ? "" : "s"} ago`;
}

/**
 * Full timestamp used as a tooltip for Last Seen.
 */
function formatFullDate(value?: string | null): string {
  if (!value) {
    return "No timestamp available";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "Invalid timestamp";
  }

  return date.toLocaleString();
}

/* ============================================================================
 * Default Export
 * ========================================================================== */

export default IOCTable;