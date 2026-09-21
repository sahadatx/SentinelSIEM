import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";

import type { ReactNode } from "react";

import {
  Activity,
  ChevronLeft,
  ChevronRight,
  CircleAlert,
  Eye,
  Filter,
  Info,
  RefreshCw,
  RotateCcw,
  Search,
  Shield,
  ShieldAlert,
  TriangleAlert,
  X,
} from "lucide-react";

import { useNavigate } from "react-router-dom";

import { Panel } from "../../../components/ui/Panel";
import { ApiError } from "../../../services/api";

import { eventsApi } from "../api";

import type {
  Event,
  EventFilterOptions,
  EventFilterState,
  EventStatisticsResponse,
} from "../types";

import "../Events.css";

/* ==========================================================================
 * Constants
 * ========================================================================== */

const PAGE_SIZE = 30;

const EMPTY_FILTERS: EventFilterState = {
  query: "",
  source: "",
  source_ip: "",
  destination_ip: "",
  username: "",
  action: "",
  outcome: "",
  severity: "",
  category: "",
  start_time: "",
  end_time: "",
};

const EMPTY_STATISTICS: EventStatisticsResponse = {
  total: 0,
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
};

/* ==========================================================================
 * Helpers
 * ========================================================================== */

function formatDate(value?: string | null): string {
  if (!value) {
    return "—";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "—";
  }

  return date.toLocaleString();
}

function formatSeverity(value?: string | null): string {
  if (!value) {
    return "Unknown";
  }

  return value
    .replace(/[-_]+/g, " ")
    .replace(/\b\w/g, (character) =>
      character.toUpperCase(),
    );
}

function formatOptionLabel(value: string): string {
  return value
    .replace(/[-_]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (character) =>
      character.toUpperCase(),
    );
}

function getSeverityClass(
  severity?: string | null,
): string {
  switch (severity?.toLowerCase()) {
    case "critical":
      return "events-severity events-severity-critical";

    case "high":
      return "events-severity events-severity-high";

    case "medium":
      return "events-severity events-severity-medium";

    case "low":
      return "events-severity events-severity-low";

    case "info":
      return "events-severity events-severity-info";

    default:
      return "events-severity events-severity-unknown";
  }
}

function getApiErrorMessage(
  error: unknown,
): string {
  if (error instanceof ApiError) {
    return error.detail;
  }

  if (error instanceof Error) {
    return error.message;
  }

  return "Unable to load security events.";
}

function normalizeDateForApi(
  value: string,
  endOfDay = false,
): string | undefined {
  if (!value) {
    return undefined;
  }

  const date = new Date(
    `${value}T${
      endOfDay
        ? "23:59:59.999"
        : "00:00:00.000"
    }`,
  );

  if (Number.isNaN(date.getTime())) {
    return undefined;
  }

  return date.toISOString();
}

/* ==========================================================================
 * Active Filter Count
 * ========================================================================== */

function countActiveFilters(
  filters: EventFilterState,
): number {
  return [
    filters.query,
    filters.source,
    filters.source_ip,
    filters.destination_ip,
    filters.username,
    filters.action,
    filters.outcome,
    filters.severity,
    filters.category,
    filters.start_time,
    filters.end_time,
  ].filter((value) => {
    if (
      value === undefined ||
      value === null
    ) {
      return false;
    }

    return (
      String(value).trim().length > 0
    );
  }).length;
}

/* ==========================================================================
 * Events Page
 * ========================================================================== */

export default function Events() {
  const navigate = useNavigate();

  /* ------------------------------------------------------------------------
   * Event data
   * ------------------------------------------------------------------------ */

  const [events, setEvents] =
    useState<Event[]>([]);

  const [total, setTotal] =
    useState(0);

  const [page, setPage] =
    useState(1);

  /* ------------------------------------------------------------------------
   * Backend aggregate statistics
   * ------------------------------------------------------------------------ */

  const [statistics, setStatistics] =
    useState<EventStatisticsResponse>(
      EMPTY_STATISTICS,
    );

  /* ------------------------------------------------------------------------
   * Active filters
   * ------------------------------------------------------------------------ */

  const [appliedFilters, setAppliedFilters] =
    useState<EventFilterState>({
      ...EMPTY_FILTERS,
    });

  /* ------------------------------------------------------------------------
   * Dynamic filter options
   * ------------------------------------------------------------------------ */

  const [filterOptions, setFilterOptions] =
    useState<EventFilterOptions>({
      sources: [],
      users: [],
      actions: [],
      outcomes: [],
      severities: [],
      categories: [],
    });

  const [
    filterOptionsLoading,
    setFilterOptionsLoading,
  ] = useState(true);

  const [
    filterOptionsError,
    setFilterOptionsError,
  ] = useState<string | null>(null);

  /* ------------------------------------------------------------------------
   * Request state
   * ------------------------------------------------------------------------ */

  const [loading, setLoading] =
    useState(true);

  const [refreshing, setRefreshing] =
    useState(false);

  const [error, setError] =
    useState<string | null>(null);

  /* ==========================================================================
   * Filter Options
   * ========================================================================== */

  const loadFilterOptions =
    useCallback(async () => {
      setFilterOptionsLoading(true);
      setFilterOptionsError(null);

      try {
        const response =
          await eventsApi.getFilterOptions();

        setFilterOptions(response);
      } catch (requestError) {
        setFilterOptionsError(
          getApiErrorMessage(
            requestError,
          ),
        );
      } finally {
        setFilterOptionsLoading(false);
      }
    }, []);

  useEffect(() => {
    void loadFilterOptions();
  }, [loadFilterOptions]);

  /* ==========================================================================
   * API Filters
   * ========================================================================== */

  const appliedApiFilters =
    useMemo(
      () => ({
        query:
          appliedFilters.query.trim() ||
          undefined,

        source:
          appliedFilters.source.trim() ||
          undefined,

        source_ip:
          appliedFilters.source_ip.trim() ||
          undefined,

        destination_ip:
          appliedFilters.destination_ip.trim() ||
          undefined,

        username:
          appliedFilters.username.trim() ||
          undefined,

        action:
          appliedFilters.action.trim() ||
          undefined,

        outcome:
          appliedFilters.outcome.trim() ||
          undefined,

        severity:
          appliedFilters.severity.trim() ||
          undefined,

        category:
          appliedFilters.category.trim() ||
          undefined,

        start_time:
          normalizeDateForApi(
            appliedFilters.start_time,
          ),

        end_time:
          normalizeDateForApi(
            appliedFilters.end_time,
            true,
          ),
      }),
      [appliedFilters],
    );

  /* ==========================================================================
   * Active Filter Count
   * ========================================================================== */

  const activeFilterCount =
    useMemo(
      () =>
        countActiveFilters(
          appliedFilters,
        ),
      [appliedFilters],
    );

  const hasAppliedFilters =
    activeFilterCount > 0;

  /* ==========================================================================
   * Load Events + Statistics
   * ========================================================================== */

  const loadEvents = useCallback(
    async (
      showRefreshState = false,
    ) => {
      if (showRefreshState) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      setError(null);

      try {
        const [
          eventsResponse,
          statisticsResponse,
        ] = await Promise.all([
          eventsApi.list({
            ...appliedApiFilters,
            page,
            page_size: PAGE_SIZE,
          }),

          eventsApi.getStatistics(
            appliedApiFilters,
          ),
        ]);

        setEvents(
          eventsResponse.items,
        );

        setTotal(
          eventsResponse.pagination.total,
        );

        setStatistics(
          statisticsResponse,
        );
      } catch (requestError) {
        setEvents([]);
        setTotal(0);

        setStatistics({
          ...EMPTY_STATISTICS,
        });

        setError(
          getApiErrorMessage(
            requestError,
          ),
        );
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [
      appliedApiFilters,
      page,
    ],
  );

  /* ==========================================================================
   * Automatic Loading
   * ========================================================================== */

  useEffect(() => {
    void loadEvents();
  }, [loadEvents]);

  /* ==========================================================================
   * Immediate Filter Update
   * ========================================================================== */

  function updateFilter<
    Key extends keyof EventFilterState,
  >(
    key: Key,
    value: EventFilterState[Key],
  ): void {
    setPage(1);

    setAppliedFilters(
      (current) => ({
        ...current,
        [key]: value,
      }),
    );
  }

  /* ==========================================================================
   * Reset Filters
   * ========================================================================== */

  function handleResetFilters(): void {
    if (!hasAppliedFilters) {
      return;
    }

    setPage(1);

    setAppliedFilters({
      ...EMPTY_FILTERS,
    });
  }

  /* ==========================================================================
   * Clear Search
   * ========================================================================== */

  function handleClearSearch(): void {
    updateFilter(
      "query",
      "",
    );
  }

  /* ==========================================================================
   * Refresh
   * ========================================================================== */

  async function handleRefresh(): Promise<void> {
    await Promise.all([
      loadEvents(true),
      loadFilterOptions(),
    ]);
  }

  /* ==========================================================================
   * Open Event Details
   * ========================================================================== */

  function handleViewEvent(
    eventId: string,
  ): void {
    navigate(
      `/events/${encodeURIComponent(eventId)}`,
    );
  }

  /* ==========================================================================
   * Pagination
   * ========================================================================== */

  const totalPages =
    Math.max(
      1,
      Math.ceil(
        total / PAGE_SIZE,
      ),
    );

  const hasPreviousPage =
    page > 1;

  const hasNextPage =
    page < totalPages;

  function handlePreviousPage(): void {
    if (
      loading ||
      refreshing ||
      !hasPreviousPage
    ) {
      return;
    }

    setPage(
      (current) =>
        Math.max(
          1,
          current - 1,
        ),
    );
  }

  function handleNextPage(): void {
    if (
      loading ||
      refreshing ||
      !hasNextPage
    ) {
      return;
    }

    setPage(
      (current) =>
        Math.min(
          totalPages,
          current + 1,
        ),
    );
  }

  /* ==========================================================================
   * Display Range
   * ========================================================================== */

  const firstItem =
    total === 0
      ? 0
      : (page - 1) *
          PAGE_SIZE +
        1;

  const lastItem =
    total === 0
      ? 0
      : Math.min(
          page * PAGE_SIZE,
          total,
        );

  /* ==========================================================================
   * Render
   * ========================================================================== */

  return (
    <main
      className="events-page"
      aria-label="Security events"
    >
      {/* =====================================================================
       * Page Header
       * ===================================================================== */}

      <header className="events-page-header">
        <div className="events-page-heading">
          <span className="events-page-eyebrow">
            SECURITY OPERATIONS CENTER
          </span>

          <h1 className="events-page-title">
            Security Events
          </h1>

          <p className="events-page-description">
            Search and investigate normalized
            security events received by
            SentinelSIEM.
          </p>
        </div>

        <div className="events-page-actions">
          <button
            type="button"
            className="events-refresh-button"
            onClick={handleRefresh}
            disabled={
              loading ||
              refreshing
            }
            title="Refresh security events"
          >
            <RefreshCw
              size={15}
              aria-hidden="true"
              className={
                refreshing
                  ? "events-refresh-icon is-spinning"
                  : "events-refresh-icon"
              }
            />

            <span>
              {refreshing
                ? "Refreshing..."
                : "Refresh"}
            </span>
          </button>
        </div>
      </header>

      {/* =====================================================================
       * Error Banner
       * ===================================================================== */}

      {error && (
        <section
          className="events-error-banner"
          role="alert"
          aria-live="assertive"
        >
          <div className="events-error-icon">
            <ShieldAlert
              size={17}
              aria-hidden="true"
            />
          </div>

          <div className="events-error-content">
            <strong>
              Unable to load security events
            </strong>

            <span>
              {error}
            </span>
          </div>
        </section>
      )}

      {/* =====================================================================
       * Metrics
       * ===================================================================== */}

      <section
        className="events-metrics"
        aria-label="Event severity statistics"
      >
        <EventMetric
          label="Total Events"
          value={statistics.total}
          detail="all filtered events"
          icon={
            <Activity
              size={18}
              aria-hidden="true"
            />
          }
        />

        <EventMetric
          label="Critical"
          value={statistics.critical}
          detail="all filtered events"
          icon={
            <ShieldAlert
              size={18}
              aria-hidden="true"
            />
          }
          tone="critical"
        />

        <EventMetric
          label="High"
          value={statistics.high}
          detail="all filtered events"
          icon={
            <TriangleAlert
              size={18}
              aria-hidden="true"
            />
          }
          tone="high"
        />

        <EventMetric
          label="Medium"
          value={statistics.medium}
          detail="all filtered events"
          icon={
            <Shield
              size={18}
              aria-hidden="true"
            />
          }
          tone="medium"
        />

        <EventMetric
          label="Low"
          value={statistics.low}
          detail="all filtered events"
          icon={
            <CircleAlert
              size={18}
              aria-hidden="true"
            />
          }
          tone="low"
        />

        <EventMetric
          label="Info"
          value={statistics.info}
          detail="all filtered events"
          icon={
            <Info
              size={18}
              aria-hidden="true"
            />
          }
          tone="info"
        />
      </section>

      {/* =====================================================================
       * Event Directory
       * ===================================================================== */}

      <section
        className="events-directory"
        aria-label="Event directory"
      >
        <Panel
          title="Event Directory"
          subtitle={
            loading
              ? "Loading security events..."
              : total === 0
                ? "No events found"
                : `${firstItem}–${lastItem} of ${statistics.total} events`
          }
        >
          {/* -----------------------------------------------------------------
           * Filter Toolbar
           * ----------------------------------------------------------------- */}

          <div className="events-filter-toolbar">
            <div className="events-filter-heading">
              <div className="events-filter-title">
                <Filter
                  size={15}
                  aria-hidden="true"
                />

                <span>
                  Event Filters
                </span>
              </div>

              {hasAppliedFilters && (
                <span className="events-filter-active">
                  Filters active
                </span>
              )}
            </div>

            {/* ---------------------------------------------------------------
             * Search
             * --------------------------------------------------------------- */}

            <label className="events-filter-field events-filter-search">
              <span className="events-filter-label">
                Search
              </span>

              <div className="events-input-wrap">
                <Search
                  size={15}
                  aria-hidden="true"
                />

                <input
                  type="search"
                  value={
                    appliedFilters.query
                  }
                  onChange={(event) =>
                    updateFilter(
                      "query",
                      event.target.value,
                    )
                  }
                  placeholder="Search events..."
                  aria-label="Search events"
                  autoComplete="off"
                />

                {appliedFilters.query && (
                  <button
                    type="button"
                    className="events-input-clear"
                    onClick={
                      handleClearSearch
                    }
                    aria-label="Clear event search"
                  >
                    <X
                      size={13}
                      aria-hidden="true"
                    />
                  </button>
                )}
              </div>
            </label>

            {/* ---------------------------------------------------------------
             * Structured Filters
             * --------------------------------------------------------------- */}

            <div className="events-filter-grid">
              <label className="events-filter-field">
                <span className="events-filter-label">
                  Source
                </span>

                <select
                  value={
                    appliedFilters.source
                  }
                  onChange={(event) =>
                    updateFilter(
                      "source",
                      event.target.value,
                    )
                  }
                  disabled={
                    filterOptionsLoading
                  }
                  aria-label="Filter by source"
                >
                  <option value="">
                    All sources
                  </option>

                  {filterOptions.sources.map(
                    (value) => (
                      <option
                        key={value}
                        value={value}
                      >
                        {formatOptionLabel(
                          value,
                        )}
                      </option>
                    ),
                  )}
                </select>
              </label>

              <label className="events-filter-field">
                <span className="events-filter-label">
                  Source IP
                </span>

                <input
                  type="text"
                  value={
                    appliedFilters.source_ip
                  }
                  onChange={(event) =>
                    updateFilter(
                      "source_ip",
                      event.target.value,
                    )
                  }
                  placeholder="e.g. 10.0.0.1"
                  aria-label="Filter by source IP"
                  autoComplete="off"
                />
              </label>

              <label className="events-filter-field">
                <span className="events-filter-label">
                  Destination IP
                </span>

                <input
                  type="text"
                  value={
                    appliedFilters.destination_ip
                  }
                  onChange={(event) =>
                    updateFilter(
                      "destination_ip",
                      event.target.value,
                    )
                  }
                  placeholder="e.g. 10.0.0.2"
                  aria-label="Filter by destination IP"
                  autoComplete="off"
                />
              </label>

              <label className="events-filter-field">
                <span className="events-filter-label">
                  User
                </span>

                <select
                  value={
                    appliedFilters.username
                  }
                  onChange={(event) =>
                    updateFilter(
                      "username",
                      event.target.value,
                    )
                  }
                  disabled={
                    filterOptionsLoading
                  }
                  aria-label="Filter by user"
                >
                  <option value="">
                    All users
                  </option>

                  {filterOptions.users.map(
                    (value) => (
                      <option
                        key={value}
                        value={value}
                      >
                        {value}
                      </option>
                    ),
                  )}
                </select>
              </label>

              <label className="events-filter-field">
                <span className="events-filter-label">
                  Action
                </span>

                <select
                  value={
                    appliedFilters.action
                  }
                  onChange={(event) =>
                    updateFilter(
                      "action",
                      event.target.value,
                    )
                  }
                  disabled={
                    filterOptionsLoading
                  }
                  aria-label="Filter by action"
                >
                  <option value="">
                    All actions
                  </option>

                  {filterOptions.actions.map(
                    (value) => (
                      <option
                        key={value}
                        value={value}
                      >
                        {formatOptionLabel(
                          value,
                        )}
                      </option>
                    ),
                  )}
                </select>
              </label>

              <label className="events-filter-field">
                <span className="events-filter-label">
                  Outcome
                </span>

                <select
                  value={
                    appliedFilters.outcome
                  }
                  onChange={(event) =>
                    updateFilter(
                      "outcome",
                      event.target.value,
                    )
                  }
                  disabled={
                    filterOptionsLoading
                  }
                  aria-label="Filter by outcome"
                >
                  <option value="">
                    All outcomes
                  </option>

                  {filterOptions.outcomes.map(
                    (value) => (
                      <option
                        key={value}
                        value={value}
                      >
                        {formatOptionLabel(
                          value,
                        )}
                      </option>
                    ),
                  )}
                </select>
              </label>

              <label className="events-filter-field">
                <span className="events-filter-label">
                  Severity
                </span>

                <select
                  value={
                    appliedFilters.severity
                  }
                  onChange={(event) =>
                    updateFilter(
                      "severity",
                      event.target.value,
                    )
                  }
                  disabled={
                    filterOptionsLoading
                  }
                  aria-label="Filter by severity"
                >
                  <option value="">
                    All severities
                  </option>

                  {filterOptions.severities.map(
                    (value) => (
                      <option
                        key={value}
                        value={value}
                      >
                        {formatSeverity(
                          value,
                        )}
                      </option>
                    ),
                  )}
                </select>
              </label>

              <label className="events-filter-field">
                <span className="events-filter-label">
                  Category
                </span>

                <select
                  value={
                    appliedFilters.category
                  }
                  onChange={(event) =>
                    updateFilter(
                      "category",
                      event.target.value,
                    )
                  }
                  disabled={
                    filterOptionsLoading
                  }
                  aria-label="Filter by category"
                >
                  <option value="">
                    All categories
                  </option>

                  {filterOptions.categories.map(
                    (value) => (
                      <option
                        key={value}
                        value={value}
                      >
                        {formatOptionLabel(
                          value,
                        )}
                      </option>
                    ),
                  )}
                </select>
              </label>

              <label className="events-filter-field">
                <span className="events-filter-label">
                  From
                </span>

                <input
                  className="events-date-input"
                  type="date"
                  value={
                    appliedFilters.start_time
                  }
                  max={
                    appliedFilters.end_time ||
                    undefined
                  }
                  onChange={(event) =>
                    updateFilter(
                      "start_time",
                      event.target.value,
                    )
                  }
                  aria-label="Filter events from date"
                />
              </label>

              <label className="events-filter-field">
                <span className="events-filter-label">
                  To
                </span>

                <input
                  className="events-date-input"
                  type="date"
                  value={
                    appliedFilters.end_time
                  }
                  min={
                    appliedFilters.start_time ||
                    undefined
                  }
                  onChange={(event) =>
                    updateFilter(
                      "end_time",
                      event.target.value,
                    )
                  }
                  aria-label="Filter events to date"
                />
              </label>
            </div>

            {/* ---------------------------------------------------------------
             * Filter Options Error
             * --------------------------------------------------------------- */}

            {filterOptionsError && (
              <div
                className="events-filter-option-error"
                role="status"
              >
                <span>
                  Filter options could not
                  be loaded.
                </span>

                <button
                  type="button"
                  onClick={() =>
                    void loadFilterOptions()
                  }
                >
                  Retry
                </button>
              </div>
            )}

            {/* ---------------------------------------------------------------
             * Filter Footer
             * --------------------------------------------------------------- */}

            <div className="events-filter-footer">
              <div className="events-filter-status">
                {hasAppliedFilters ? (
                  <span className="events-filter-applied-text">
                    Filters applied
                    <strong className="events-filter-count">
                      {activeFilterCount}
                    </strong>
                  </span>
                ) : (
                  <span>
                    Showing all Events
                  </span>
                )}
              </div>

              <div className="events-filter-actions">
                <button
                  type="button"
                  className="events-clear-filters"
                  onClick={
                    handleResetFilters
                  }
                  disabled={
                    loading ||
                    refreshing ||
                    !hasAppliedFilters
                  }
                  title={
                    hasAppliedFilters
                      ? "Reset all event filters"
                      : "No active filters"
                  }
                >
                  <RotateCcw
                    size={14}
                    aria-hidden="true"
                  />

                  <span>
                    Reset Filters
                  </span>
                </button>
              </div>
            </div>
          </div>

          {/* -----------------------------------------------------------------
           * Event Table
           *
           * View column added to match Audit Logs.
           * ----------------------------------------------------------------- */}

          <div className="events-table-container events-table-container-full">
            <div className="events-table-scroll">
              <table className="events-table events-table-compact">
                <thead>
                  <tr>
                    <th className="events-col-timestamp">
                      Timestamp
                    </th>

                    <th className="events-col-source">
                      Source
                    </th>

                    <th className="events-col-source-ip">
                      Source IP
                    </th>

                    <th className="events-col-destination">
                      Destination
                    </th>

                    <th className="events-col-user">
                      User
                    </th>

                    <th className="events-col-action">
                      Action
                    </th>

                    <th className="events-col-outcome">
                      Outcome
                    </th>

                    <th className="events-col-severity">
                      Severity
                    </th>

                    <th className="events-col-category">
                      Category
                    </th>

                    <th className="events-col-view">
                      View
                    </th>
                  </tr>
                </thead>

                <tbody>
                  {events.map(
                    (event) => (
                      <tr
                        key={
                          event.event_id
                        }
                      >
                        <td className="events-cell-timestamp">
                          <strong>
                            {formatDate(
                              event.timestamp,
                            )}
                          </strong>
                        </td>

                        <td className="events-cell-source">
                          <strong
                            className="events-cell-truncate"
                            title={
                              event.source ||
                              "—"
                            }
                          >
                            {event.source ||
                              "—"}
                          </strong>

                          <small
                            className="events-cell-truncate"
                            title={
                              event.source_type ||
                              "Unknown source"
                            }
                          >
                            {event.source_type ||
                              "Unknown source"}
                          </small>
                        </td>

                        <td className="events-cell-mono">
                          {event.source_ip ||
                            "—"}
                        </td>

                        <td className="events-cell-mono">
                          {event.destination_ip ||
                            "—"}
                        </td>

                        <td>
                          <span
                            className="events-cell-truncate"
                            title={
                              event.username ||
                              "—"
                            }
                          >
                            {event.username ||
                              "—"}
                          </span>
                        </td>

                        <td>
                          <span
                            className="events-cell-truncate"
                            title={
                              event.action ||
                              "—"
                            }
                          >
                            {event.action ||
                              "—"}
                          </span>
                        </td>

                        <td>
                          <span className="events-outcome">
                            {event.outcome ||
                              "—"}
                          </span>
                        </td>

                        <td>
                          <span
                            className={getSeverityClass(
                              event.severity,
                            )}
                          >
                            <span className="events-severity-dot" />

                            {formatSeverity(
                              event.severity,
                            )}
                          </span>
                        </td>

                        <td>
                          <span
                            className="events-category events-cell-truncate"
                            title={
                              event.category ||
                              "—"
                            }
                          >
                            {event.category ||
                              "—"}
                          </span>
                        </td>

                        {/* -------------------------------------------------
                         * View
                         * ------------------------------------------------- */}

                        <td className="events-cell-view">
                          <button
                            type="button"
                            className="events-view-button"
                            onClick={() =>
                              handleViewEvent(
                                event.event_id,
                              )
                            }
                            title="View event details"
                            aria-label={`View event ${event.event_id}`}
                          >
                            <Eye
                              size={15}
                              aria-hidden="true"
                            />

                            <span>
                              View
                            </span>
                          </button>
                        </td>
                      </tr>
                    ),
                  )}

                  {!loading &&
                    events.length ===
                      0 && (
                      <EmptyState
                        cols={10}
                        message={
                          error
                            ? "Unable to load events."
                            : hasAppliedFilters
                              ? "No events match the current filters."
                              : "No security events available."
                        }
                      />
                    )}

                  {loading && (
                    <tr className="events-loading-row">
                      <td colSpan={10}>
                        <div className="events-loading-state">
                          <RefreshCw
                            size={18}
                            className="is-spinning"
                            aria-hidden="true"
                          />

                          <span>
                            Loading security events...
                          </span>
                        </div>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* -----------------------------------------------------------------
           * Pagination
           * ----------------------------------------------------------------- */}

          <footer className="events-pagination">
            <div className="events-pagination-summary">
              <strong>
                {total === 0
                  ? "0"
                  : `${firstItem}–${lastItem}`}
              </strong>

              <span>
                of {total} events
              </span>
            </div>

            <div className="events-pagination-page">
              Page{" "}
              <strong>
                {page}
              </strong>{" "}
              of{" "}
              <strong>
                {totalPages}
              </strong>
            </div>

            <div className="events-pagination-actions">
              <button
                type="button"
                className="events-pagination-button"
                onClick={
                  handlePreviousPage
                }
                disabled={
                  loading ||
                  refreshing ||
                  !hasPreviousPage
                }
                aria-label="Previous page"
              >
                <ChevronLeft
                  size={15}
                  aria-hidden="true"
                />

                <span>
                  Previous
                </span>
              </button>

              <button
                type="button"
                className="events-pagination-button"
                onClick={
                  handleNextPage
                }
                disabled={
                  loading ||
                  refreshing ||
                  !hasNextPage
                }
                aria-label="Next page"
              >
                <span>
                  Next
                </span>

                <ChevronRight
                  size={15}
                  aria-hidden="true"
                />
              </button>
            </div>
          </footer>
        </Panel>
      </section>
    </main>
  );
}

/* ==========================================================================
 * Event Metric
 * ========================================================================== */

function EventMetric({
  label,
  value,
  detail,
  icon,
  tone = "default",
}: {
  label: string;
  value: string | number;
  detail: string;
  icon: ReactNode;
  tone?:
    | "default"
    | "critical"
    | "high"
    | "medium"
    | "low"
    | "info";
}) {
  return (
    <article
      className={`events-metric-card events-metric-card-${tone}`}
    >
      <div className="events-metric-icon">
        {icon}
      </div>

      <div className="events-metric-content">
        <span className="events-metric-label">
          {label}
        </span>

        <strong className="events-metric-value">
          {value}
        </strong>

        <small className="events-metric-detail">
          {detail}
        </small>
      </div>
    </article>
  );
}

/* ==========================================================================
 * Empty State
 * ========================================================================== */

function EmptyState({
  cols,
  message,
}: {
  cols: number;
  message: string;
}) {
  return (
    <tr className="events-empty-row">
      <td colSpan={cols}>
        <div className="events-empty-state">
          <div className="events-empty-icon">
            <Activity
              size={22}
              aria-hidden="true"
            />
          </div>

          <strong>
            {message}
          </strong>

          <span>
            Try adjusting the search
            criteria or filters.
          </span>
        </div>
      </td>
    </tr>
  );
}