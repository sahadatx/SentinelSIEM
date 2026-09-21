/*
 * ============================================================================
 * Asset Filters
 * SentinelSIEM SOC Dashboard
 * ============================================================================
 */

import {
  useCallback,
  useEffect,
  useState,
} from "react";

import type {
  ChangeEvent,
} from "react";

import type {
  AssetListParams,
  AssetOperatingSystem,
  AssetEnvironment,
  AssetRisk,
  AssetStatus,
  AssetType,
} from "../types";

/*
 * ============================================================================
 * Props
 * ============================================================================
 */

export interface AssetFiltersProps {
  value: AssetListParams;

  onChange: (
    filters: AssetListParams,
  ) => void;

  onReset?: () => void;

  loading?: boolean;
}

/*
 * ============================================================================
 * Constants
 * ============================================================================
 */

const PAGE_SIZE = 30;

/**
 * Exact Asset Type filter options.
 */
const ASSET_TYPE_OPTIONS: readonly AssetType[] = [
  "SERVER",
  "WORKSTATION",
  "LAPTOP",
  "DESKTOP",
  "NETWORK_DEVICE",
  "ROUTER",
  "SWITCH",
  "FIREWALL",
  "LOAD_BALANCER",
  "DATABASE",
  "WEB_SERVER",
  "APPLICATION_SERVER",
  "MAIL_SERVER",
  "DNS_SERVER",
  "PROXY_SERVER",
  "VIRTUAL_MACHINE",
  "CONTAINER",
  "CLOUD_RESOURCE",
  "STORAGE",
  "IOT_DEVICE",
  "SECURITY_APPLIANCE",
  "OTHER",
];

/**
 * Lifecycle + operational status filter options.
 *
 * Backend accepts both lifecycle and operational status values
 * through the `status` query parameter.
 */
const STATUS_OPTIONS: readonly AssetStatus[] = [
  "ENABLED",
  "DISABLED",
  "ONLINE",
  "OFFLINE",
  "UNKNOWN",
  "MAINTENANCE",
];

/**
 * Exact Risk filter options.
 */
const RISK_OPTIONS: readonly AssetRisk[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFORMATIONAL",
];

/**
 * Exact Operating System filter options.
 */
const OS_OPTIONS: readonly AssetOperatingSystem[] = [
  "WINDOWS",
  "WINDOWS_SERVER",
  "LINUX",
  "UBUNTU",
  "DEBIAN",
  "CENTOS",
  "RHEL",
  "FEDORA",
  "ROCKY_LINUX",
  "ALMALINUX",
  "KALI_LINUX",
  "MACOS",
  "FREEBSD",
  "ANDROID",
  "IOS",
  "NETWORK_OS",
  "OTHER",
];

/**
 * Exact Environment filter options.
 */
const ENVIRONMENT_OPTIONS: readonly AssetEnvironment[] = [
  "PRODUCTION",
  "STAGING",
  "DEVELOPMENT",
  "TESTING",
  "QA",
  "UAT",
  "DISASTER_RECOVERY",
  "OTHER",
];

/*
 * ============================================================================
 * Helpers
 * ============================================================================
 */

/**
 * Convert machine-readable values into human-readable labels.
 *
 * Examples:
 *   WEB_SERVER       -> Web Server
 *   WINDOWS_SERVER   -> Windows Server
 *   DISASTER_RECOVERY -> Disaster Recovery
 */
function formatOptionLabel(
  value: string,
): string {
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

/*
 * ============================================================================
 * Component
 * ============================================================================
 */

export default function AssetFilters({
  value,
  onChange,
  onReset,
  loading = false,
}: AssetFiltersProps) {
  /*
   * ==========================================================================
   * Local State
   * ==========================================================================
   *
   * Local state is used for the search input so typing does not immediately
   * trigger an API request on every keystroke.
   *
   * Dropdown selections are applied immediately.
   */

  const [search, setSearch] = useState(
    value.search ?? "",
  );

  const [searchTimer, setSearchTimer] =
    useState<ReturnType<typeof setTimeout> | null>(
      null,
    );

  /*
   * ==========================================================================
   * Synchronize Search With Parent
   * ==========================================================================
   */

  useEffect(() => {
    setSearch(value.search ?? "");
  }, [value.search]);

  /*
   * ==========================================================================
   * Cleanup Search Timer
   * ==========================================================================
   */

  useEffect(() => {
    return () => {
      if (searchTimer) {
        clearTimeout(searchTimer);
      }
    };
  }, [searchTimer]);

  /*
   * ==========================================================================
   * Apply Search
   * ==========================================================================
   */

  const applySearch = useCallback(
    (nextSearch: string) => {
      const nextFilters: AssetListParams =
        {
          ...value,
          page: 1,
          page_size: PAGE_SIZE,
        };

      const normalizedSearch =
        nextSearch.trim();

      if (normalizedSearch) {
        nextFilters.search =
          normalizedSearch;
      } else {
        delete nextFilters.search;
      }

      onChange(nextFilters);
    },
    [onChange, value],
  );

  /*
   * ==========================================================================
   * Search Change
   * ==========================================================================
   */

  const handleSearchChange = useCallback(
    (
      event: ChangeEvent<HTMLInputElement>,
    ) => {
      const nextSearch =
        event.target.value;

      setSearch(nextSearch);

      if (searchTimer) {
        clearTimeout(searchTimer);
      }

      const timer = setTimeout(() => {
        applySearch(nextSearch);
      }, 300);

      setSearchTimer(timer);
    },
    [
      applySearch,
      searchTimer,
    ],
  );

  /*
   * ==========================================================================
   * Dropdown Filter Change
   * ==========================================================================
   */

  const handleFilterChange = useCallback(
    (
      key:
        | "asset_type"
        | "status"
        | "risk"
        | "os"
        | "environment",
      event: ChangeEvent<HTMLSelectElement>,
    ) => {
      const nextValue =
        event.target.value;

      const nextFilters: AssetListParams =
        {
          ...value,
          page: 1,
          page_size: PAGE_SIZE,
        };

      if (nextValue) {
        nextFilters[key] =
          nextValue as never;
      } else {
        delete nextFilters[key];
      }

      onChange(nextFilters);
    },
    [onChange, value],
  );

  /*
   * ==========================================================================
   * Reset Filters
   * ==========================================================================
   */

  const handleReset = useCallback(() => {
    if (searchTimer) {
      clearTimeout(searchTimer);
      setSearchTimer(null);
    }

    setSearch("");

    if (onReset) {
      onReset();
      return;
    }

    onChange({
      page: 1,
      page_size: PAGE_SIZE,
    });
  }, [
    onChange,
    onReset,
    searchTimer,
  ]);

  /*
   * ==========================================================================
   * Render
   * ==========================================================================
   */

  return (
    <div
      className="w-full"
      aria-label="Asset filters"
    >
      <div className="grid w-full grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-6">
        {/* ====================================================================
            Search
            ==================================================================== */}

        <div className="min-w-0 xl:col-span-2">
          <label
            htmlFor="asset-filter-search"
            className="sr-only"
          >
            Search assets
          </label>

          <div className="relative">
            <span
              aria-hidden="true"
              className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-sm text-slate-500"
            >
              🔍
            </span>

            <input
              id="asset-filter-search"
              type="search"
              value={search}
              onChange={handleSearchChange}
              placeholder="Search assets..."
              disabled={loading}
              autoComplete="off"
              className="h-10 w-full rounded-lg border border-slate-700/80 bg-slate-950/80 pl-9 pr-3 text-sm text-slate-100 outline-none transition placeholder:text-slate-600 hover:border-slate-600 focus:border-cyan-500/60 focus:ring-2 focus:ring-cyan-500/10 disabled:cursor-not-allowed disabled:opacity-50"
            />
          </div>
        </div>

        {/* ====================================================================
            Asset Type
            ==================================================================== */}

        <div className="min-w-0">
          <label
            htmlFor="asset-filter-type"
            className="sr-only"
          >
            Asset Type
          </label>

          <div className="relative">
            <select
              id="asset-filter-type"
              value={value.asset_type ?? ""}
              onChange={(event) =>
                handleFilterChange(
                  "asset_type",
                  event,
                )
              }
              disabled={loading}
              className="h-10 w-full appearance-none rounded-lg border border-slate-700/80 bg-slate-950/80 px-3 pr-8 text-sm text-slate-100 outline-none transition hover:border-slate-600 focus:border-cyan-500/60 focus:ring-2 focus:ring-cyan-500/10 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <option value="">
                Asset Type
              </option>

              {ASSET_TYPE_OPTIONS.map(
                (option) => (
                  <option
                    key={option}
                    value={option}
                  >
                    {formatOptionLabel(
                      option,
                    )}
                  </option>
                ),
              )}
            </select>

            <span
              aria-hidden="true"
              className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-500"
            >
              ▼
            </span>
          </div>
        </div>

        {/* ====================================================================
            Status
            ==================================================================== */}

        <div className="min-w-0">
          <label
            htmlFor="asset-filter-status"
            className="sr-only"
          >
            Status
          </label>

          <div className="relative">
            <select
              id="asset-filter-status"
              value={value.status ?? ""}
              onChange={(event) =>
                handleFilterChange(
                  "status",
                  event,
                )
              }
              disabled={loading}
              className="h-10 w-full appearance-none rounded-lg border border-slate-700/80 bg-slate-950/80 px-3 pr-8 text-sm text-slate-100 outline-none transition hover:border-slate-600 focus:border-cyan-500/60 focus:ring-2 focus:ring-cyan-500/10 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <option value="">
                Status
              </option>

              {STATUS_OPTIONS.map(
                (option) => (
                  <option
                    key={option}
                    value={option}
                  >
                    {formatOptionLabel(
                      option,
                    )}
                  </option>
                ),
              )}
            </select>

            <span
              aria-hidden="true"
              className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-500"
            >
              ▼
            </span>
          </div>
        </div>

        {/* ====================================================================
            Risk
            ==================================================================== */}

        <div className="min-w-0">
          <label
            htmlFor="asset-filter-risk"
            className="sr-only"
          >
            Risk
          </label>

          <div className="relative">
            <select
              id="asset-filter-risk"
              value={value.risk ?? ""}
              onChange={(event) =>
                handleFilterChange(
                  "risk",
                  event,
                )
              }
              disabled={loading}
              className="h-10 w-full appearance-none rounded-lg border border-slate-700/80 bg-slate-950/80 px-3 pr-8 text-sm text-slate-100 outline-none transition hover:border-slate-600 focus:border-cyan-500/60 focus:ring-2 focus:ring-cyan-500/10 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <option value="">
                Risk
              </option>

              {RISK_OPTIONS.map(
                (option) => (
                  <option
                    key={option}
                    value={option}
                  >
                    {formatOptionLabel(
                      option,
                    )}
                  </option>
                ),
              )}
            </select>

            <span
              aria-hidden="true"
              className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-500"
            >
              ▼
            </span>
          </div>
        </div>

        {/* ====================================================================
            Operating System
            ==================================================================== */}

        <div className="min-w-0">
          <label
            htmlFor="asset-filter-os"
            className="sr-only"
          >
            Operating System
          </label>

          <div className="relative">
            <select
              id="asset-filter-os"
              value={value.os ?? ""}
              onChange={(event) =>
                handleFilterChange(
                  "os",
                  event,
                )
              }
              disabled={loading}
              className="h-10 w-full appearance-none rounded-lg border border-slate-700/80 bg-slate-950/80 px-3 pr-8 text-sm text-slate-100 outline-none transition hover:border-slate-600 focus:border-cyan-500/60 focus:ring-2 focus:ring-cyan-500/10 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <option value="">
                OS
              </option>

              {OS_OPTIONS.map(
                (option) => (
                  <option
                    key={option}
                    value={option}
                  >
                    {formatOptionLabel(
                      option,
                    )}
                  </option>
                ),
              )}
            </select>

            <span
              aria-hidden="true"
              className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-500"
            >
              ▼
            </span>
          </div>
        </div>

        {/* ====================================================================
            Environment
            ==================================================================== */}

        <div className="min-w-0">
          <label
            htmlFor="asset-filter-environment"
            className="sr-only"
          >
            Environment
          </label>

          <div className="relative">
            <select
              id="asset-filter-environment"
              value={
                value.environment ?? ""
              }
              onChange={(event) =>
                handleFilterChange(
                  "environment",
                  event,
                )
              }
              disabled={loading}
              className="h-10 w-full appearance-none rounded-lg border border-slate-700/80 bg-slate-950/80 px-3 pr-8 text-sm text-slate-100 outline-none transition hover:border-slate-600 focus:border-cyan-500/60 focus:ring-2 focus:ring-cyan-500/10 disabled:cursor-not-allowed disabled:opacity-50"
            >
              <option value="">
                Environment
              </option>

              {ENVIRONMENT_OPTIONS.map(
                (option) => (
                  <option
                    key={option}
                    value={option}
                  >
                    {formatOptionLabel(
                      option,
                    )}
                  </option>
                ),
              )}
            </select>

            <span
              aria-hidden="true"
              className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-500"
            >
              ▼
            </span>
          </div>
        </div>
      </div>

      {/* ======================================================================
          Reset
          ====================================================================== */}

      <div className="mt-3 flex justify-end">
        <button
          type="button"
          onClick={handleReset}
          disabled={
            loading ||
            (
              !value.search &&
              !value.asset_type &&
              !value.status &&
              !value.risk &&
              !value.os &&
              !value.environment
            )
          }
          className="inline-flex h-9 items-center justify-center rounded-lg border border-slate-700/80 bg-slate-900/60 px-4 text-sm font-medium text-slate-300 transition hover:border-slate-600 hover:bg-slate-800 hover:text-white focus:outline-none focus:ring-2 focus:ring-slate-500/20 disabled:cursor-not-allowed disabled:opacity-40"
        >
          Reset
        </button>
      </div>
    </div>
  );
}