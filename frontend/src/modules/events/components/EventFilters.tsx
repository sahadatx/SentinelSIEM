import {
  RotateCcw,
  Search,
  X,
} from "lucide-react";

import type {
  EventFilterOptions,
  EventListParams,
} from "../types";

/* ==========================================================================
 * Props
 * ========================================================================== */

export interface EventFiltersProps {
  filters: EventListParams;
  options: EventFilterOptions;
  onChange: (filters: EventListParams) => void;
  onApply: () => void;
  onReset: () => void;
  disabled?: boolean;
  loadingOptions?: boolean;
}

/* ==========================================================================
 * Helpers
 * ========================================================================== */

function formatOption(value: string): string {
  return value
    .replace(/[-_]+/g, " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

/* ==========================================================================
 * Component
 * ========================================================================== */

export default function EventFilters({
  filters,
  options,
  onChange,
  onApply,
  onReset,
  disabled = false,
  loadingOptions = false,
}: EventFiltersProps) {
  /* ------------------------------------------------------------------------
   * Update Filter
   * ------------------------------------------------------------------------ */

  function updateFilter(
    key: keyof EventListParams,
    value: string,
  ): void {
    const normalizedValue = value.trim();

    onChange({
      ...filters,
      [key]: normalizedValue || undefined,
      page: 1,
    });
  }

  /* ------------------------------------------------------------------------
   * Clear Search
   * ------------------------------------------------------------------------ */

  function clearSearch(): void {
    onChange({
      ...filters,
      query: undefined,
      page: 1,
    });
  }

  /* ------------------------------------------------------------------------
   * Active Filter State
   * ------------------------------------------------------------------------ */

  const hasFilters =
    Boolean(filters.query?.trim()) ||
    Boolean(filters.source?.trim()) ||
    Boolean(filters.source_ip?.trim()) ||
    Boolean(filters.destination_ip?.trim()) ||
    Boolean(filters.username?.trim()) ||
    Boolean(filters.action?.trim()) ||
    Boolean(filters.outcome?.trim()) ||
    Boolean(filters.severity?.trim()) ||
    Boolean(filters.category?.trim()) ||
    Boolean(filters.start_time) ||
    Boolean(filters.end_time);

  /* ------------------------------------------------------------------------
   * Render
   * ------------------------------------------------------------------------ */

  return (
    <section
      className="events-filter-toolbar"
      aria-label="Event filters"
    >
      {/* ==================================================================
       * Search
       * ================================================================== */}

      <div className="events-filter-search-row">
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
              value={filters.query ?? ""}
              onChange={(event) =>
                updateFilter(
                  "query",
                  event.target.value,
                )
              }
              placeholder="Search events..."
              aria-label="Search events"
              disabled={disabled}
              autoComplete="off"
            />

            {filters.query && (
              <button
                type="button"
                className="events-input-clear"
                onClick={clearSearch}
                disabled={disabled}
                aria-label="Clear event search"
                title="Clear search"
              >
                <X
                  size={13}
                  aria-hidden="true"
                />
              </button>
            )}
          </div>
        </label>
      </div>

      {/* ==================================================================
       * Filter Grid
       * ================================================================== */}

      <div className="events-filter-grid">
        {/* ----------------------------------------------------------------
         * Source
         * ---------------------------------------------------------------- */}

        <label className="events-filter-field">
          <span className="events-filter-label">
            Source
          </span>

          <select
            value={filters.source ?? ""}
            onChange={(event) =>
              updateFilter(
                "source",
                event.target.value,
              )
            }
            aria-label="Filter by source"
            disabled={disabled || loadingOptions}
          >
            <option value="">
              All Sources
            </option>

            {options.sources.map((source) => (
              <option
                key={source}
                value={source}
              >
                {source}
              </option>
            ))}
          </select>
        </label>

        {/* ----------------------------------------------------------------
         * Source IP
         * ---------------------------------------------------------------- */}

        <label className="events-filter-field">
          <span className="events-filter-label">
            Source IP
          </span>

          <input
            type="text"
            value={filters.source_ip ?? ""}
            onChange={(event) =>
              updateFilter(
                "source_ip",
                event.target.value,
              )
            }
            placeholder="e.g. 10.0.0.1"
            aria-label="Filter by source IP"
            disabled={disabled}
            inputMode="decimal"
            autoComplete="off"
          />
        </label>

        {/* ----------------------------------------------------------------
         * Destination IP
         * ---------------------------------------------------------------- */}

        <label className="events-filter-field">
          <span className="events-filter-label">
            Destination IP
          </span>

          <input
            type="text"
            value={filters.destination_ip ?? ""}
            onChange={(event) =>
              updateFilter(
                "destination_ip",
                event.target.value,
              )
            }
            placeholder="e.g. 192.168.1.10"
            aria-label="Filter by destination IP"
            disabled={disabled}
            inputMode="decimal"
            autoComplete="off"
          />
        </label>

        {/* ----------------------------------------------------------------
         * User
         * ---------------------------------------------------------------- */}

        <label className="events-filter-field">
          <span className="events-filter-label">
            User
          </span>

          <select
            value={filters.username ?? ""}
            onChange={(event) =>
              updateFilter(
                "username",
                event.target.value,
              )
            }
            aria-label="Filter by user"
            disabled={disabled || loadingOptions}
          >
            <option value="">
              All Users
            </option>

            {options.users.map((username) => (
              <option
                key={username}
                value={username}
              >
                {username}
              </option>
            ))}
          </select>
        </label>

        {/* ----------------------------------------------------------------
         * Action
         * ---------------------------------------------------------------- */}

        <label className="events-filter-field">
          <span className="events-filter-label">
            Action
          </span>

          <select
            value={filters.action ?? ""}
            onChange={(event) =>
              updateFilter(
                "action",
                event.target.value,
              )
            }
            aria-label="Filter by action"
            disabled={disabled || loadingOptions}
          >
            <option value="">
              All Actions
            </option>

            {options.actions.map((action) => (
              <option
                key={action}
                value={action}
              >
                {formatOption(action)}
              </option>
            ))}
          </select>
        </label>

        {/* ----------------------------------------------------------------
         * Outcome
         * ---------------------------------------------------------------- */}

        <label className="events-filter-field">
          <span className="events-filter-label">
            Outcome
          </span>

          <select
            value={filters.outcome ?? ""}
            onChange={(event) =>
              updateFilter(
                "outcome",
                event.target.value,
              )
            }
            aria-label="Filter by outcome"
            disabled={disabled || loadingOptions}
          >
            <option value="">
              All Outcomes
            </option>

            {options.outcomes.map((outcome) => (
              <option
                key={outcome}
                value={outcome}
              >
                {formatOption(outcome)}
              </option>
            ))}
          </select>
        </label>

        {/* ----------------------------------------------------------------
         * Severity
         * ---------------------------------------------------------------- */}

        <label className="events-filter-field">
          <span className="events-filter-label">
            Severity
          </span>

          <select
            value={filters.severity ?? ""}
            onChange={(event) =>
              updateFilter(
                "severity",
                event.target.value,
              )
            }
            aria-label="Filter by severity"
            disabled={disabled || loadingOptions}
          >
            <option value="">
              All Severities
            </option>

            {options.severities.map((severity) => (
              <option
                key={severity}
                value={severity}
              >
                {formatOption(severity)}
              </option>
            ))}
          </select>
        </label>

        {/* ----------------------------------------------------------------
         * Category
         * ---------------------------------------------------------------- */}

        <label className="events-filter-field">
          <span className="events-filter-label">
            Category
          </span>

          <select
            value={filters.category ?? ""}
            onChange={(event) =>
              updateFilter(
                "category",
                event.target.value,
              )
            }
            aria-label="Filter by category"
            disabled={disabled || loadingOptions}
          >
            <option value="">
              All Categories
            </option>

            {options.categories.map((category) => (
              <option
                key={category}
                value={category}
              >
                {formatOption(category)}
              </option>
            ))}
          </select>
        </label>

        {/* ----------------------------------------------------------------
         * From
         * ---------------------------------------------------------------- */}

        <label className="events-filter-field">
          <span className="events-filter-label">
            From
          </span>

          <input
            type="datetime-local"
            value={filters.start_time ?? ""}
            onChange={(event) =>
              updateFilter(
                "start_time",
                event.target.value,
              )
            }
            aria-label="Filter events from date and time"
            disabled={disabled}
          />
        </label>

        {/* ----------------------------------------------------------------
         * To
         * ---------------------------------------------------------------- */}

        <label className="events-filter-field">
          <span className="events-filter-label">
            To
          </span>

          <input
            type="datetime-local"
            value={filters.end_time ?? ""}
            onChange={(event) =>
              updateFilter(
                "end_time",
                event.target.value,
              )
            }
            aria-label="Filter events to date and time"
            disabled={disabled}
          />
        </label>
      </div>

      {/* ==================================================================
       * Filter Footer
       * ================================================================== */}

      <div className="events-filter-footer">
        <div className="events-filter-status">
          {hasFilters
            ? "Filters are ready to apply."
            : "No event filters applied."}
        </div>

        <div className="events-filter-actions">
          <button
            type="button"
            className="events-clear-filters"
            onClick={onReset}
            disabled={disabled}
            title="Reset event filters"
          >
            <RotateCcw
              size={14}
              aria-hidden="true"
            />

            <span>
              Reset
            </span>
          </button>

          <button
            type="button"
            className="events-apply-filters"
            onClick={onApply}
            disabled={disabled}
            title="Apply event filters"
          >
            <Search
              size={14}
              aria-hidden="true"
            />

            <span>
              Apply Filters
            </span>
          </button>
        </div>
      </div>
    </section>
  );
}