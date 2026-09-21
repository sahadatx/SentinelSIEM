/* ==========================================================================
 * Asset Status Badge
 * SentinelSIEM SOC Dashboard
 * ========================================================================== */

import type {
  AssetLifecycleStatus,
  AssetOperationalStatus,
  AssetStatus,
} from "../types";

/* ==========================================================================
 * Props
 * ========================================================================== */

interface AssetStatusBadgeProps {
  status: AssetStatus | string;
  className?: string;
}

/* ==========================================================================
 * Status Helpers
 * ========================================================================== */

/**
 * Normalize a status value for consistent comparison and display.
 */
function normalizeStatus(status: string): string {
  return status.trim().toUpperCase();
}

/**
 * Return Tailwind classes for the supplied asset status.
 *
 * Supported lifecycle statuses:
 *   - ENABLED
 *   - DISABLED
 *
 * Supported operational statuses:
 *   - ONLINE
 *   - OFFLINE
 *   - UNKNOWN
 *   - MAINTENANCE
 *
 * Unknown values intentionally fall back to a neutral style.
 */
function getStatusClasses(status: string): string {
  switch (normalizeStatus(status)) {
    /* ----------------------------------------------------------------------
     * Lifecycle
     * ---------------------------------------------------------------------- */

    case "ENABLED":
      return [
        "border-emerald-500/20",
        "bg-emerald-500/10",
        "text-emerald-400",
      ].join(" ");

    case "DISABLED":
      return [
        "border-slate-500/20",
        "bg-slate-500/10",
        "text-slate-400",
      ].join(" ");

    /* ----------------------------------------------------------------------
     * Operational
     * ---------------------------------------------------------------------- */

    case "ONLINE":
      return [
        "border-emerald-500/20",
        "bg-emerald-500/10",
        "text-emerald-400",
      ].join(" ");

    case "OFFLINE":
      return [
        "border-red-500/20",
        "bg-red-500/10",
        "text-red-400",
      ].join(" ");

    case "MAINTENANCE":
      return [
        "border-amber-500/20",
        "bg-amber-500/10",
        "text-amber-400",
      ].join(" ");

    case "UNKNOWN":
      return [
        "border-slate-500/20",
        "bg-slate-500/10",
        "text-slate-300",
      ].join(" ");

    default:
      return [
        "border-slate-500/20",
        "bg-slate-500/10",
        "text-slate-300",
      ].join(" ");
  }
}

/**
 * Convert a machine-readable status into a human-readable label.
 *
 * Examples:
 *   ENABLED     -> Enabled
 *   DISABLED    -> Disabled
 *   ONLINE      -> Online
 *   OFFLINE     -> Offline
 *   UNKNOWN     -> Unknown
 *   MAINTENANCE -> Maintenance
 */
function getStatusLabel(status: string): string {
  const normalized = normalizeStatus(status);

  if (!normalized) {
    return "Unknown";
  }

  return normalized
    .split(/[\s_-]+/)
    .filter(Boolean)
    .map(
      (part) =>
        part.charAt(0).toUpperCase() + part.slice(1).toLowerCase(),
    )
    .join(" ");
}

/* ==========================================================================
 * Type Guards
 * ========================================================================== */

/**
 * Check whether a value is a valid lifecycle status.
 */
export function isAssetLifecycleStatus(
  status: string,
): status is AssetLifecycleStatus {
  const normalized = normalizeStatus(status);

  return (
    normalized === "ENABLED" ||
    normalized === "DISABLED"
  );
}

/**
 * Check whether a value is a valid operational status.
 */
export function isAssetOperationalStatus(
  status: string,
): status is AssetOperationalStatus {
  const normalized = normalizeStatus(status);

  return (
    normalized === "ONLINE" ||
    normalized === "OFFLINE" ||
    normalized === "UNKNOWN" ||
    normalized === "MAINTENANCE"
  );
}

/* ==========================================================================
 * Component
 * ========================================================================== */

export default function AssetStatusBadge({
  status,
  className = "",
}: AssetStatusBadgeProps) {
  const label = getStatusLabel(status);

  const classes = [
    "inline-flex",
    "items-center",
    "whitespace-nowrap",
    "rounded-full",
    "border",
    "px-2.5",
    "py-1",
    "text-xs",
    "font-medium",
    "leading-none",
    getStatusClasses(status),
    className,
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <span
      className={classes}
      aria-label={`Asset status: ${label}`}
    >
      <span
        className="mr-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-current"
        aria-hidden="true"
      />

      {label}
    </span>
  );
}