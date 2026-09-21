/**
 * ============================================================================
 * SentinelSIEM — User Filters
 * ============================================================================
 *
 * Professional presentation component for User Management filters.
 *
 * Responsibilities:
 * - Search users by username or email
 * - Filter by account state
 * - Filter by lock state
 * - Filter by role
 * - Display active-filter state
 * - Display active-filter count
 * - Reset all filters
 *
 * Filtering state is owned by the parent User Management container.
 * ============================================================================
 */

import type {
  ChangeEvent,
} from "react";

import {
  ChevronDown,
  RotateCcw,
  Search,
  X,
} from "lucide-react";


/* ============================================================================
 * Filter Types
 * ========================================================================== */

export type ActiveFilter =
  | ""
  | "active"
  | "disabled";


export type LockedFilter =
  | ""
  | "locked"
  | "unlocked";


export type RoleFilter =
  | ""
  | "ADMIN"
  | "SECURITY_ANALYST"
  | "SOC_ANALYST"
  | "INVESTIGATOR"
  | "VIEWER";


/* ============================================================================
 * Props
 * ========================================================================== */

export interface UserFiltersProps {
  search: string;

  activeFilter: ActiveFilter;

  lockedFilter: LockedFilter;

  roleFilter: RoleFilter;

  loading: boolean;

  hasFilters: boolean;

  onSearchChange: (
    value: string,
  ) => void;

  onActiveFilterChange: (
    value: ActiveFilter,
  ) => void;

  onLockedFilterChange: (
    value: LockedFilter,
  ) => void;

  onRoleFilterChange: (
    value: RoleFilter,
  ) => void;

  onClear: () => void;
}


/* ============================================================================
 * Filter Options
 * ========================================================================== */

interface FilterOption {
  value: string;
  label: string;
}


const ACTIVE_FILTER_OPTIONS: FilterOption[] = [
  {
    value: "",
    label: "All account states",
  },
  {
    value: "active",
    label: "Active",
  },
  {
    value: "disabled",
    label: "Disabled",
  },
];


const LOCKED_FILTER_OPTIONS: FilterOption[] = [
  {
    value: "",
    label: "All lock states",
  },
  {
    value: "locked",
    label: "Locked",
  },
  {
    value: "unlocked",
    label: "Unlocked",
  },
];


const ROLE_FILTER_OPTIONS: FilterOption[] = [
  {
    value: "",
    label: "All roles",
  },
  {
    value: "ADMIN",
    label: "Admin",
  },
  {
    value: "SECURITY_ANALYST",
    label: "Security Analyst",
  },
  {
    value: "SOC_ANALYST",
    label: "SOC Analyst",
  },
  {
    value: "INVESTIGATOR",
    label: "Investigator",
  },
  {
    value: "VIEWER",
    label: "Viewer",
  },
];


/* ============================================================================
 * User Filters
 * ========================================================================== */

export default function UserFilters({
  search,
  activeFilter,
  lockedFilter,
  roleFilter,
  loading,
  hasFilters,
  onSearchChange,
  onActiveFilterChange,
  onLockedFilterChange,
  onRoleFilterChange,
  onClear,
}: UserFiltersProps) {


  /* ==========================================================================
   * Active Filter Count
   * ======================================================================== */

  const activeFilterCount =
    countActiveFilters({
      search,
      activeFilter,
      lockedFilter,
      roleFilter,
    });


  /*
   * Parent state remains authoritative.
   *
   * hasFilters is preserved for compatibility with
   * the existing User Management container.
   */
  const filtersAreActive =
    hasFilters ||
    activeFilterCount > 0;


  /* ==========================================================================
   * Search
   * ======================================================================== */

  function handleSearchChange(
    event: ChangeEvent<HTMLInputElement>,
  ): void {

    onSearchChange(
      event.target.value,
    );
  }


  function handleClearSearch(): void {

    if (loading) {
      return;
    }

    onSearchChange("");
  }


  /* ==========================================================================
   * Account State
   * ======================================================================== */

  function handleActiveFilterChange(
    value: string,
  ): void {

    if (isActiveFilter(value)) {
      onActiveFilterChange(
        value,
      );
    }
  }


  /* ==========================================================================
   * Lock State
   * ======================================================================== */

  function handleLockedFilterChange(
    value: string,
  ): void {

    if (isLockedFilter(value)) {
      onLockedFilterChange(
        value,
      );
    }
  }


  /* ==========================================================================
   * Role
   * ======================================================================== */

  function handleRoleFilterChange(
    value: string,
  ): void {

    if (isRoleFilter(value)) {
      onRoleFilterChange(
        value,
      );
    }
  }


  /* ==========================================================================
   * Reset
   * ======================================================================== */

  function handleReset(): void {

    if (
      loading ||
      !filtersAreActive
    ) {
      return;
    }

    onClear();
  }


  /* ==========================================================================
   * Render
   * ======================================================================== */

  return (
    <section
      className="users-filter-panel"
      aria-label="User directory filters"
    >


      {/* ====================================================================
          Filter Header
          ==================================================================== */}

      <div className="users-filter-header">

        <div className="users-filter-header-copy">

          <div className="users-filter-heading-row">

            <span className="users-filter-eyebrow">
              DIRECTORY FILTERS
            </span>


            <span
              className={
                `users-filter-status${
                  filtersAreActive
                    ? " is-active"
                    : ""
                }`
              }
            >

              <span
                className="users-filter-status-dot"
                aria-hidden="true"
              />

              {filtersAreActive
                ? "Filtered view"
                : "All users"}

            </span>

          </div>


          <h3 className="users-filter-title">
            Find users
          </h3>


          <p className="users-filter-description">
            Search and filter the user directory
            by account state, lock state, or role.
          </p>

        </div>

      </div>


      {/* ====================================================================
          Filter Controls
          ==================================================================== */}

      <div className="users-filter-controls">


        {/* ------------------------------------------------------------------
            Search
            ------------------------------------------------------------------ */}

        <label
          className={
            "users-filter-field " +
            "users-filter-search-field"
          }
        >

          <span className="users-filter-field-label">
            Search
          </span>


          <span className="users-filter-search-control">

            <Search
              className="users-filter-search-icon"
              size={15}
              aria-hidden="true"
            />


            <input
              type="search"
              value={search}
              onChange={
                handleSearchChange
              }
              placeholder="Username or email..."
              aria-label="Search users"
              disabled={loading}
              autoComplete="off"
              spellCheck={false}
            />


            {search.length > 0 &&
              !loading && (

                <button
                  type="button"
                  className="users-filter-clear-search"
                  onClick={
                    handleClearSearch
                  }
                  aria-label="Clear search"
                  title="Clear search"
                >

                  <X
                    size={13}
                    aria-hidden="true"
                  />

                </button>

              )}

          </span>

        </label>


        {/* ------------------------------------------------------------------
            Account State
            ------------------------------------------------------------------ */}

        <FilterSelect
          label="Account State"
          value={activeFilter}
          disabled={loading}
          options={
            ACTIVE_FILTER_OPTIONS
          }
          onChange={
            handleActiveFilterChange
          }
        />


        {/* ------------------------------------------------------------------
            Lock State
            ------------------------------------------------------------------ */}

        <FilterSelect
          label="Lock State"
          value={lockedFilter}
          disabled={loading}
          options={
            LOCKED_FILTER_OPTIONS
          }
          onChange={
            handleLockedFilterChange
          }
        />


        {/* ------------------------------------------------------------------
            Role
            ------------------------------------------------------------------ */}

        <FilterSelect
          label="Role"
          value={roleFilter}
          disabled={loading}
          options={
            ROLE_FILTER_OPTIONS
          }
          onChange={
            handleRoleFilterChange
          }
        />

      </div>


      {/* ====================================================================
          Filter Actions
          ==================================================================== */}

      <div className="users-filter-actions">


        {/* ------------------------------------------------------------------
            Left Status
            ------------------------------------------------------------------ */}

        <div
          className="users-filter-actions-meta"
          role="status"
          aria-live="polite"
        >

          {filtersAreActive ? (

            <>

              <span
                className="users-filter-active-indicator"
                aria-hidden="true"
              />

              <span>
                Filters applied
              </span>


              <span
                className="users-filter-count"
                aria-label={
                  `${activeFilterCount} active filters`
                }
              >
                {activeFilterCount}
              </span>

            </>

          ) : (

            <span>
              Showing all users
            </span>

          )}

        </div>


        {/* ------------------------------------------------------------------
            Reset
            ------------------------------------------------------------------ */}

        <button
          type="button"
          className="users-filter-reset-button"
          onClick={
            handleReset
          }
          disabled={
            loading ||
            !filtersAreActive
          }
          title={
            filtersAreActive
              ? "Reset all filters"
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

    </section>
  );
}


/* ============================================================================
 * Filter Select
 * ========================================================================== */

interface FilterSelectProps {
  label: string;

  value: string;

  disabled: boolean;

  options: FilterOption[];

  onChange: (
    value: string,
  ) => void;
}


function FilterSelect({
  label,
  value,
  disabled,
  options,
  onChange,
}: FilterSelectProps) {

  const hasValue =
    value !== "";


  return (
    <label
      className={
        `users-filter-field ` +
        `users-filter-select-field${
          hasValue
            ? " is-selected"
            : ""
        }`
      }
    >

      <span className="users-filter-field-label">
        {label}
      </span>


      <span className="users-filter-select-control">

        <select
          value={value}
          onChange={(event) => {
            onChange(
              event.target.value,
            );
          }}
          disabled={disabled}
          aria-label={label}
        >

          {options.map(
            (option) => (

              <option
                key={option.value}
                value={option.value}
              >
                {option.label}
              </option>

            ),
          )}

        </select>


        <ChevronDown
          className="users-filter-select-chevron"
          size={14}
          aria-hidden="true"
        />

      </span>

    </label>
  );
}


/* ============================================================================
 * Active Filter Counter
 * ========================================================================== */

interface UserFilterState {
  search: string;

  activeFilter: ActiveFilter;

  lockedFilter: LockedFilter;

  roleFilter: RoleFilter;
}


function countActiveFilters(
  filters: UserFilterState,
): number {

  let count = 0;


  /*
   * Search
   */
  if (
    filters.search.trim().length > 0
  ) {
    count += 1;
  }


  /*
   * Account State
   */
  if (
    filters.activeFilter !== ""
  ) {
    count += 1;
  }


  /*
   * Lock State
   */
  if (
    filters.lockedFilter !== ""
  ) {
    count += 1;
  }


  /*
   * Role
   */
  if (
    filters.roleFilter !== ""
  ) {
    count += 1;
  }


  return count;
}


/* ============================================================================
 * Type Guards
 * ========================================================================== */

function isActiveFilter(
  value: string,
): value is ActiveFilter {

  return (
    value === "" ||
    value === "active" ||
    value === "disabled"
  );
}


function isLockedFilter(
  value: string,
): value is LockedFilter {

  return (
    value === "" ||
    value === "locked" ||
    value === "unlocked"
  );
}


function isRoleFilter(
  value: string,
): value is RoleFilter {

  return (
    value === "" ||
    value === "ADMIN" ||
    value === "SECURITY_ANALYST" ||
    value === "SOC_ANALYST" ||
    value === "INVESTIGATOR" ||
    value === "VIEWER"
  );
}


/* ============================================================================
 * End of File
 * ============================================================================
 */