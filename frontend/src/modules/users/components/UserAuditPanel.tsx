/**
 * ============================================================================
 * SentinelSIEM — Individual User Audit Panel
 * ============================================================================
 *
 * Scoped audit history for:
 *
 *   Users
 *      ↓
 *   User Details
 *      ↓
 *   Audit History
 *
 * Responsibilities
 * ----------------
 *
 *   - Load audit events for the selected user
 *   - Load User Management directory for target resolution
 *   - Apply filters immediately
 *   - Maintain 30-event pagination
 *   - Use backend-authoritative pagination metadata
 *   - Use backend-authoritative total
 *   - Display backend-authoritative statistics when available
 *   - Open selected event details
 *   - Protect against stale async responses
 *
 * Pagination contract
 * -------------------
 *
 * UI / feature layer:
 *
 *   page
 *   page_size
 *
 * Examples:
 *
 *   Page 1 → page=1, page_size=30
 *   Page 2 → page=2, page_size=30
 *   Page 3 → page=3, page_size=30
 *
 * The feature API boundary is responsible for translating this into the
 * shared transport representation when required.
 *
 * This panel therefore does NOT manually construct limit/offset requests.
 *
 * Filter contract
 * ---------------
 *
 *   Action
 *   Outcome
 *   Target
 *   Source IP
 *   From
 *   To
 *
 * Intentionally excluded
 * ----------------------
 *
 *   Actor
 *   Category
 *   Search
 *
 * Backend remains authoritative for:
 *
 *   - audit activities
 *   - total
 *   - statistics
 *   - filtering
 *   - authorization
 *   - pagination semantics
 *
 * ============================================================================
 */

import {
  AlertCircle,
  CheckCircle2,
  FileSearch,
  RefreshCw,
  Shield,
  XCircle,
} from "lucide-react";

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import type { ReactNode } from "react";

import { usersApi } from "../api";

import type {
  User,
  UserAuditEvent,
  UserAuditListParams,
  UserAuditListResponse,
} from "../types";

import UserAuditEventDetails from "./UserAuditEventDetails";
import UserAuditFilters from "./UserAuditFilters";

import UserAuditTable, {
  type UserAuditTargetUser,
} from "./UserAuditTable";


/* ============================================================================
 * Constants
 * ========================================================================== */

const AUDIT_PAGE_SIZE = 30;

const FIRST_PAGE = 1;

const USER_DIRECTORY_PAGE_SIZE = 200;


/* ============================================================================
 * Types
 * ========================================================================== */

interface UserAuditStatisticsState {
  total: number;
  success: number;
  failure: number;
  denied: number;
}


/**
 * Optional statistics exposed by some backend response versions.
 *
 * The core list response remains authoritative for:
 *
 *   activities
 *   total
 *   limit
 *   offset
 */
type UserAuditResponseWithOptionalStatistics =
  UserAuditListResponse & {
    statistics?: {
      total?: number;
      success?: number;
      failure?: number;
      denied?: number;
    } | null;
  };


/* ============================================================================
 * Props
 * ========================================================================== */

export interface UserAuditPanelProps {
  /**
   * Selected User Management user ID.
   */
  userId: string;

  /**
   * Optional external refresh trigger.
   */
  refreshKey?: number;
}


/* ============================================================================
 * Defaults
 * ========================================================================== */

const EMPTY_STATISTICS:
  UserAuditStatisticsState = {
  total: 0,
  success: 0,
  failure: 0,
  denied: 0,
};


/* ============================================================================
 * Component
 * ========================================================================== */

export default function UserAuditPanel({
  userId,
  refreshKey = 0,
}: UserAuditPanelProps) {
  /* ==========================================================================
   * Identity
   * ======================================================================== */

  const normalizedUserId =
    useMemo(
      () => userId.trim(),
      [userId],
    );


  /* ==========================================================================
   * Audit State
   * ======================================================================== */

  const [activities, setActivities] =
    useState<UserAuditEvent[]>([]);

  const [total, setTotal] =
    useState(0);

  const [page, setPage] =
    useState(FIRST_PAGE);

  const [pageSize, setPageSize] =
    useState(AUDIT_PAGE_SIZE);

  const [statistics, setStatistics] =
    useState<UserAuditStatisticsState>(
      EMPTY_STATISTICS,
    );


  /* ==========================================================================
   * Filters
   * ======================================================================== */

  const [filters, setFilters] =
    useState<UserAuditListParams>({});


  /* ==========================================================================
   * Target User Directory
   * ======================================================================== */

  const [targetUsers, setTargetUsers] =
    useState<User[]>([]);

  const [usersLoading, setUsersLoading] =
    useState(true);

  const [usersError, setUsersError] =
    useState<string | null>(null);


  /* ==========================================================================
   * Loading State
   * ======================================================================== */

  const [loading, setLoading] =
    useState(true);

  const [refreshing, setRefreshing] =
    useState(false);


  /* ==========================================================================
   * Error State
   * ======================================================================== */

  const [error, setError] =
    useState<string | null>(null);


  /* ==========================================================================
   * Selected Event
   * ======================================================================== */

  const [selectedEvent, setSelectedEvent] =
    useState<UserAuditEvent | null>(null);


  /* ==========================================================================
   * Async Request Coordination
   * ======================================================================== */

  const auditRequestSequence =
    useRef(0);

  const usersRequestSequence =
    useRef(0);


  /* ==========================================================================
   * Pagination
   * ======================================================================== */

  const totalPages =
    useMemo(() => {
      if (
        total <= 0 ||
        pageSize <= 0
      ) {
        return 0;
      }

      return Math.ceil(
        total / pageSize,
      );
    }, [
      pageSize,
      total,
    ]);


  const hasPreviousPage =
    page > FIRST_PAGE;


  const hasNextPage =
    totalPages > 0 &&
    page < totalPages;


  const visibleFirst =
    total > 0
      ? (
          (
            page - FIRST_PAGE
          ) *
          pageSize
        ) + 1
      : 0;


  const visibleLast =
    total > 0
      ? Math.min(
          (
            (
              page - FIRST_PAGE
            ) *
            pageSize
          ) +
            activities.length,
          total,
        )
      : 0;


  /* ==========================================================================
   * Load Target User Directory
   * ======================================================================== */

  const loadTargetUsers =
    useCallback(async () => {
      const requestId =
        ++usersRequestSequence.current;

      setUsersLoading(true);
      setUsersError(null);

      try {
        const firstResponse =
          await usersApi.list({
            limit:
              USER_DIRECTORY_PAGE_SIZE,
            offset: 0,
          });

        if (
          requestId !==
          usersRequestSequence.current
        ) {
          return;
        }

        const firstUsers =
          Array.isArray(
            firstResponse.users,
          )
            ? firstResponse.users
            : [];

        const allUsers =
          [...firstUsers];


        /* ----------------------------------------------------------------------
         * Determine remaining directory pages
         * -------------------------------------------------------------------- */

        const reportedTotalPages =
          Number.isFinite(
            firstResponse.total_pages,
          )
            ? Math.max(
                FIRST_PAGE,
                Number(
                  firstResponse.total_pages,
                ),
              )
            : inferTotalPages(
                firstResponse.total,
                USER_DIRECTORY_PAGE_SIZE,
              );


        /* ----------------------------------------------------------------------
         * Load remaining pages
         * -------------------------------------------------------------------- */

        for (
          let currentPage =
            FIRST_PAGE + 1;

          currentPage <=
            reportedTotalPages;

          currentPage += 1
        ) {
          const response =
            await usersApi.list({
              limit:
                USER_DIRECTORY_PAGE_SIZE,

              offset:
                (
                  currentPage -
                  FIRST_PAGE
                ) *
                USER_DIRECTORY_PAGE_SIZE,
            });

          if (
            requestId !==
            usersRequestSequence.current
          ) {
            return;
          }

          if (
            Array.isArray(
              response.users,
            )
          ) {
            allUsers.push(
              ...response.users,
            );
          }
        }


        /* ----------------------------------------------------------------------
         * Normalize directory
         * -------------------------------------------------------------------- */

        const uniqueUsers =
          deduplicateUsers(
            allUsers,
          );

        uniqueUsers.sort(
          compareUsers,
        );


        /* ----------------------------------------------------------------------
         * Commit
         * -------------------------------------------------------------------- */

        setTargetUsers(
          uniqueUsers,
        );
      } catch (requestError) {
        if (
          requestId !==
          usersRequestSequence.current
        ) {
          return;
        }

        setTargetUsers([]);

        setUsersError(
          getErrorMessage(
            requestError,
            "Unable to load users for the Target filter.",
          ),
        );
      } finally {
        if (
          requestId !==
          usersRequestSequence.current
        ) {
          return;
        }

        setUsersLoading(false);
      }
    }, []);


  /* ==========================================================================
   * Load Audit Events
   * ======================================================================== */

  const loadAudit =
    useCallback(
      async (
        requestedPage: number,
        requestedFilters: UserAuditListParams,
        showRefreshState = false,
      ) => {
        const requestId =
          ++auditRequestSequence.current;


        /* ----------------------------------------------------------------------
         * Validate selected user
         * -------------------------------------------------------------------- */

        if (!normalizedUserId) {
          setActivities([]);
          setTotal(0);
          setPage(FIRST_PAGE);
          setPageSize(
            AUDIT_PAGE_SIZE,
          );
          setStatistics(
            EMPTY_STATISTICS,
          );
          setSelectedEvent(null);
          setError(
            "A valid user ID is required.",
          );
          setLoading(false);
          setRefreshing(false);

          return;
        }


        /* ----------------------------------------------------------------------
         * Normalize requested page
         * -------------------------------------------------------------------- */

        const safePage =
          Number.isFinite(
            requestedPage,
          )
            ? Math.max(
                FIRST_PAGE,
                Math.floor(
                  requestedPage,
                ),
              )
            : FIRST_PAGE;


        /* ----------------------------------------------------------------------
         * Loading state
         * -------------------------------------------------------------------- */

        if (showRefreshState) {
          setRefreshing(true);
        } else {
          setLoading(true);
        }

        setError(null);


        /* ----------------------------------------------------------------------
         * Sanitize filters
         * -------------------------------------------------------------------- */

        const cleanFilters =
          sanitizeFilters(
            requestedFilters,
          );


        /* ----------------------------------------------------------------------
         * Build feature-level request
         *
         * IMPORTANT
         * ---------
         *
         * This panel now sends page/page_size.
         *
         * The feature API boundary handles any required conversion to
         * limit/offset for the shared HTTP transport.
         *
         * Therefore pagination logic exists in ONE place:
         *
         *   page
         *   page_size
         *
         * -------------------------------------------------------------------- */

        const requestParams =
          {
            ...cleanFilters,

            page:
              safePage,

            page_size:
              AUDIT_PAGE_SIZE,
          };


        try {
          const response =
            await usersApi.audit(
              normalizedUserId,
              requestParams,
            );


          /* --------------------------------------------------------------------
           * Ignore stale response
           * ------------------------------------------------------------------ */

          if (
            requestId !==
            auditRequestSequence.current
          ) {
            return;
          }


          const responseWithStatistics =
            response as UserAuditResponseWithOptionalStatistics;


          /* --------------------------------------------------------------------
           * Activities
           * ------------------------------------------------------------------ */

          const nextActivities =
            Array.isArray(
              response.activities,
            )
              ? response.activities
              : [];


          /* --------------------------------------------------------------------
           * Backend total
           * ------------------------------------------------------------------ */

          const nextTotal =
            Number.isFinite(
              response.total,
            )
              ? Math.max(
                  0,
                  Number(
                    response.total,
                  ),
                )
              : 0;


          /* --------------------------------------------------------------------
           * Backend page size
           * ------------------------------------------------------------------ */

          const nextPageSize =
            Number.isFinite(
              response.limit,
            ) &&
            Number(
              response.limit,
            ) > 0
              ? Number(
                  response.limit,
                )
              : AUDIT_PAGE_SIZE;


          /* --------------------------------------------------------------------
           * Backend offset
           *
           * Backend remains authoritative.
           *
           * The feature API request is page-based, while the response may
           * still expose offset metadata.
           * ------------------------------------------------------------------ */

          const backendOffset =
            Number.isFinite(
              response.offset,
            )
              ? Math.max(
                  0,
                  Number(
                    response.offset,
                  ),
                )
              : (
                  safePage -
                  FIRST_PAGE
                ) *
                nextPageSize;


          /* --------------------------------------------------------------------
           * Resolve actual page
           *
           * Example:
           *
           *   offset 0  / limit 30 → page 1
           *   offset 30 / limit 30 → page 2
           *   offset 60 / limit 30 → page 3
           * ------------------------------------------------------------------ */

          const resolvedPage =
            Math.max(
              FIRST_PAGE,
              Math.floor(
                backendOffset /
                  nextPageSize,
              ) + FIRST_PAGE,
            );


          /* --------------------------------------------------------------------
           * Backend statistics
           *
           * Statistics are for the complete filtered dataset when supplied.
           *
           * They are NOT calculated from the current 30-event page.
           * ------------------------------------------------------------------ */

          const backendStatistics =
            responseWithStatistics.statistics;


          const nextStatistics:
            UserAuditStatisticsState = {
            total:
              Number.isFinite(
                backendStatistics?.total,
              )
                ? Math.max(
                    0,
                    Number(
                      backendStatistics.total,
                    ),
                  )
                : nextTotal,

            success:
              Number.isFinite(
                backendStatistics?.success,
              )
                ? Math.max(
                    0,
                    Number(
                      backendStatistics.success,
                    ),
                  )
                : 0,

            failure:
              Number.isFinite(
                backendStatistics?.failure,
              )
                ? Math.max(
                    0,
                    Number(
                      backendStatistics.failure,
                    ),
                  )
                : 0,

            denied:
              Number.isFinite(
                backendStatistics?.denied,
              )
                ? Math.max(
                    0,
                    Number(
                      backendStatistics.denied,
                    ),
                  )
                : 0,
          };


          /* --------------------------------------------------------------------
           * Commit response
           * ------------------------------------------------------------------ */

          setActivities(
            nextActivities,
          );

          setTotal(
            nextTotal,
          );

          setPageSize(
            nextPageSize,
          );

          setStatistics(
            nextStatistics,
          );

          setPage(
            resolvedPage,
          );

          setSelectedEvent(
            null,
          );
        } catch (requestError) {
          if (
            requestId !==
            auditRequestSequence.current
          ) {
            return;
          }

          setActivities([]);
          setTotal(0);
          setPage(FIRST_PAGE);
          setPageSize(
            AUDIT_PAGE_SIZE,
          );
          setStatistics(
            EMPTY_STATISTICS,
          );
          setSelectedEvent(null);

          setError(
            getErrorMessage(
              requestError,
              "Unable to retrieve user audit history.",
            ),
          );
        } finally {
          if (
            requestId !==
            auditRequestSequence.current
          ) {
            return;
          }

          setLoading(false);
          setRefreshing(false);
        }
      },
      [
        normalizedUserId,
      ],
    );


  /* ==========================================================================
   * Initial Load / User Change / External Refresh
   * ======================================================================== */

  useEffect(() => {
    setFilters({});
    setActivities([]);
    setTotal(0);
    setPage(FIRST_PAGE);
    setPageSize(
      AUDIT_PAGE_SIZE,
    );
    setStatistics(
      EMPTY_STATISTICS,
    );
    setSelectedEvent(null);
    setError(null);

    void loadTargetUsers();

    void loadAudit(
      FIRST_PAGE,
      {},
      false,
    );
  }, [
    loadAudit,
    loadTargetUsers,
    normalizedUserId,
    refreshKey,
  ]);


  /* ==========================================================================
   * Cleanup
   * ======================================================================== */

  useEffect(() => {
    return () => {
      auditRequestSequence.current += 1;
      usersRequestSequence.current += 1;
    };
  }, []);


  /* ==========================================================================
   * Refresh
   * ======================================================================== */

  const handleRefresh =
    useCallback(async () => {
      if (
        loading ||
        refreshing
      ) {
        return;
      }

      await Promise.all([
        loadTargetUsers(),

        loadAudit(
          page,
          filters,
          true,
        ),
      ]);
    }, [
      filters,
      loadAudit,
      loadTargetUsers,
      loading,
      page,
      refreshing,
    ]);


  /* ==========================================================================
   * Filter Change
   * ======================================================================== */

  const handleFilterChange =
    useCallback(
      (
        nextFilters:
          UserAuditListParams,
      ) => {
        const normalizedFilters =
          sanitizeFilters(
            nextFilters,
          );

        setFilters(
          normalizedFilters,
        );

        setPage(
          FIRST_PAGE,
        );

        setSelectedEvent(
          null,
        );

        void loadAudit(
          FIRST_PAGE,
          normalizedFilters,
          false,
        );
      },
      [
        loadAudit,
      ]);


  /* ==========================================================================
   * Reset Filters
   * ======================================================================== */

  const handleResetFilters =
    useCallback(() => {
      if (
        loading ||
        refreshing
      ) {
        return;
      }

      setFilters({});

      setPage(
        FIRST_PAGE,
      );

      setSelectedEvent(
        null,
      );

      void loadAudit(
        FIRST_PAGE,
        {},
        false,
      );
    }, [
      loadAudit,
      loading,
      refreshing,
    ]);


  /* ==========================================================================
   * Previous Page
   * ======================================================================== */

  const handlePreviousPage =
    useCallback(() => {
      if (
        !hasPreviousPage ||
        loading ||
        refreshing
      ) {
        return;
      }

      const nextPage =
        Math.max(
          FIRST_PAGE,
          page - 1,
        );

      setPage(
        nextPage,
      );

      void loadAudit(
        nextPage,
        filters,
        false,
      );
    }, [
      filters,
      hasPreviousPage,
      loadAudit,
      loading,
      page,
      refreshing,
    ]);


  /* ==========================================================================
   * Next Page
   * ======================================================================== */

  const handleNextPage =
    useCallback(() => {
      if (
        !hasNextPage ||
        loading ||
        refreshing
      ) {
        return;
      }

      const nextPage =
        Math.min(
          totalPages,
          page + 1,
        );

      setPage(
        nextPage,
      );

      void loadAudit(
        nextPage,
        filters,
        false,
      );
    }, [
      filters,
      hasNextPage,
      loadAudit,
      loading,
      page,
      refreshing,
      totalPages,
    ]);


  /* ==========================================================================
   * Event Selection
   * ======================================================================== */

  const handleSelectEvent =
    useCallback(
      (
        event: UserAuditEvent,
      ) => {
        setSelectedEvent(
          event,
        );
      },
      [],
    );


  const handleCloseEventDetails =
    useCallback(() => {
      setSelectedEvent(
        null,
      );
    }, []);


  /* ==========================================================================
   * Render
   * ======================================================================== */

  return (
    <section
      className="user-audit-panel"
      aria-labelledby="user-audit-panel-title"
    >

      {/* ======================================================================
       * Panel Header
       * ==================================================================== */}

      <header className="user-audit-panel-header">

        <div className="user-audit-panel-heading">

          <div className="user-audit-panel-heading-icon">
            <FileSearch
              size={18}
              aria-hidden="true"
            />
          </div>

          <div>

            <span className="user-audit-panel-eyebrow">
              AUDIT HISTORY
            </span>

            <h3 id="user-audit-panel-title">
              Account Activity
            </h3>

            <p>
              Security and account-management events recorded for this user.
            </p>

          </div>

        </div>


        <button
          type="button"
          className="user-audit-refresh-button"
          onClick={handleRefresh}
          disabled={
            loading ||
            refreshing
          }
          aria-label="Refresh audit history"
          title="Refresh audit history"
        >
          <RefreshCw
            size={14}
            className={
              refreshing
                ? "spin"
                : undefined
            }
            aria-hidden="true"
          />

          <span>
            {refreshing
              ? "Refreshing..."
              : "Refresh"}
          </span>
        </button>

      </header>


      {/* ======================================================================
       * Target User Directory Warning
       * ==================================================================== */}

      {usersError && (
        <div
          className="user-audit-alert user-audit-alert-warning"
          role="status"
        >
          <AlertCircle
            size={16}
            aria-hidden="true"
          />

          <div>
            <strong>
              Target filter unavailable
            </strong>

            <span>
              {usersError}
            </span>
          </div>
        </div>
      )}


      {/* ======================================================================
       * Audit Error
       * ==================================================================== */}

      {error && (
        <div
          className="user-audit-alert user-audit-alert-error"
          role="alert"
        >
          <AlertCircle
            size={16}
            aria-hidden="true"
          />

          <div>
            <strong>
              Unable to load audit history
            </strong>

            <span>
              {error}
            </span>
          </div>
        </div>
      )}


      {/* ======================================================================
       * Statistics
       * ==================================================================== */}

      {!error && (
        <section
          className="user-audit-metrics"
          aria-label="Audit activity statistics"
        >
          <Metric
            label="Events"
            value={statistics.total}
            icon={
              <Shield
                size={17}
                aria-hidden="true"
              />
            }
          />

          <Metric
            label="Successful"
            value={statistics.success}
            icon={
              <CheckCircle2
                size={17}
                aria-hidden="true"
              />
            }
          />

          <Metric
            label="Failed"
            value={statistics.failure}
            icon={
              <XCircle
                size={17}
                aria-hidden="true"
              />
            }
          />

          <Metric
            label="Denied"
            value={statistics.denied}
            icon={
              <AlertCircle
                size={17}
                aria-hidden="true"
              />
            }
          />
        </section>
      )}


      {/* ======================================================================
       * Filters
       * ==================================================================== */}

      {!error && (
        <section
          className="user-audit-filters-wrapper"
          aria-label="Audit filters"
        >
          <UserAuditFilters
            filters={filters}
            onChange={handleFilterChange}
            onReset={handleResetFilters}
            targetUsers={targetUsers}
            targetUsersLoading={
              usersLoading
            }
            disabled={
              refreshing
            }
          />
        </section>
      )}


      {/* ======================================================================
       * Loading
       * ==================================================================== */}

      {loading && (
        <div
          className="user-audit-state user-audit-loading-state"
          role="status"
          aria-busy="true"
        >
          <RefreshCw
            size={17}
            className="spin"
            aria-hidden="true"
          />

          <span>
            Loading audit history...
          </span>
        </div>
      )}


      {/* ======================================================================
       * Audit Table
       * ==================================================================== */}

      {!error &&
        (
          loading ||
          activities.length > 0
        ) && (
          <UserAuditTable
            activities={activities}
            targetUsers={
              targetUsers as UserAuditTargetUser[]
            }
            loading={loading}
            onSelect={
              handleSelectEvent
            }
          />
        )}


      {/* ======================================================================
       * Empty State
       * ==================================================================== */}

      {!loading &&
        !error &&
        activities.length === 0 && (
          <div
            className="user-audit-state user-audit-empty-state"
            role="status"
          >
            <Shield
              size={18}
              aria-hidden="true"
            />

            <div>
              <strong>
                No audit activity
              </strong>

              <span>
                No matching audit events are currently available for this user.
              </span>
            </div>
          </div>
        )}


      {/* ======================================================================
       * Pagination
       *
       * EXACT STRUCTURE:
       *
       *   [ 1–30 Events / Total 250 • Page 1 of 9 ] [ Previous Next ]
       *
       * The inner content wrapper is intentionally centered.
       *
       * There is NO:
       *
       *   justify-content: space-between
       *
       * relationship between the summary and controls.
       *
       * This keeps Previous / Next beside the pagination information,
       * matching the Global Audit pagination pattern.
       * ==================================================================== */}

      {!loading &&
        !error &&
        total > 0 && (
          <footer
            className="user-audit-pagination"
            aria-label="User audit pagination"
          >
            <div className="user-audit-pagination-content">

              <div className="user-audit-pagination-summary">

                <strong>
                  {visibleFirst}
                  {"–"}
                  {visibleLast}
                </strong>

                <span className="user-audit-pagination-label">
                  {total === 1
                    ? "Event"
                    : "Events"}
                </span>

                <span
                  className="user-audit-pagination-separator"
                  aria-hidden="true"
                >
                  /
                </span>

                <span className="user-audit-pagination-total">
                  Total {total}
                </span>

                <span
                  className="user-audit-pagination-separator"
                  aria-hidden="true"
                >
                  •
                </span>

                <span className="user-audit-pagination-page">
                  Page {page}
                  {" "}
                  of{" "}
                  {totalPages}
                </span>

              </div>


              <div className="user-audit-pagination-controls">

                <button
                  type="button"
                  className="user-audit-pagination-button"
                  onClick={
                    handlePreviousPage
                  }
                  disabled={
                    !hasPreviousPage ||
                    loading ||
                    refreshing
                  }
                  aria-label="Previous audit page"
                >
                  Previous
                </button>


                <button
                  type="button"
                  className="user-audit-pagination-button"
                  onClick={
                    handleNextPage
                  }
                  disabled={
                    !hasNextPage ||
                    loading ||
                    refreshing
                  }
                  aria-label="Next audit page"
                >
                  Next
                </button>

              </div>

            </div>
          </footer>
        )}


      {/* ======================================================================
       * Selected Event Details
       * ==================================================================== */}

      {selectedEvent && (
        <UserAuditEventDetails
          event={
            selectedEvent
          }
          targetUsers={
            targetUsers as UserAuditTargetUser[]
          }
          onClose={
            handleCloseEventDetails
          }
        />
      )}

    </section>
  );
}


/* ============================================================================
 * Metric
 * ========================================================================== */

function Metric({
  label,
  value,
  icon,
}: {
  label: string;
  value: number;
  icon: ReactNode;
}) {
  return (
    <div
      className="metric-card user-audit-metric-card"
      aria-label={`${label}: ${value}`}
    >
      <div
        className="metric-icon"
        aria-hidden="true"
      >
        {icon}
      </div>

      <div className="user-audit-metric-content">
        <span>
          {label}
        </span>

        <strong>
          {value}
        </strong>
      </div>
    </div>
  );
}


/* ============================================================================
 * Filter Sanitization
 * ========================================================================== */

function sanitizeFilters(
  value: UserAuditListParams,
): UserAuditListParams {
  const next:
    UserAuditListParams = {};


  if (
    typeof value.action === "string" &&
    value.action.trim()
  ) {
    next.action =
      value.action.trim();
  }


  if (
    typeof value.outcome === "string" &&
    value.outcome.trim()
  ) {
    next.outcome =
      value.outcome.trim();
  }


  if (
    typeof value.target_user_id === "string" &&
    value.target_user_id.trim()
  ) {
    next.target_user_id =
      value.target_user_id.trim();
  }


  if (
    typeof value.source_ip === "string" &&
    value.source_ip.trim()
  ) {
    next.source_ip =
      value.source_ip.trim();
  }


  if (
    typeof value.date_from === "string" &&
    value.date_from.trim()
  ) {
    next.date_from =
      value.date_from.trim();
  }


  if (
    typeof value.date_to === "string" &&
    value.date_to.trim()
  ) {
    next.date_to =
      value.date_to.trim();
  }


  return next;
}


/* ============================================================================
 * User Directory Helpers
 * ========================================================================== */

function deduplicateUsers(
  users: User[],
): User[] {
  const byId =
    new Map<string, User>();

  for (
    const user of users
  ) {
    if (
      !user ||
      typeof user.user_id !== "string"
    ) {
      continue;
    }

    const normalizedId =
      user.user_id.trim();

    if (!normalizedId) {
      continue;
    }

    if (
      !byId.has(
        normalizedId,
      )
    ) {
      byId.set(
        normalizedId,
        user,
      );
    }
  }

  return Array.from(
    byId.values(),
  );
}


function compareUsers(
  first: User,
  second: User,
): number {
  const firstLabel =
    (
      first.display_name ??
      first.username ??
      first.email ??
      ""
    )
      .trim()
      .toLocaleLowerCase();

  const secondLabel =
    (
      second.display_name ??
      second.username ??
      second.email ??
      ""
    )
      .trim()
      .toLocaleLowerCase();

  return firstLabel.localeCompare(
    secondLabel,
  );
}


/**
 * Infer directory page count when the backend does not expose total_pages.
 */
function inferTotalPages(
  totalValue: unknown,
  pageSize: number,
): number {
  const total =
    Number.isFinite(
      totalValue,
    )
      ? Math.max(
          0,
          Number(
            totalValue,
          ),
        )
      : 0;

  if (
    total <= 0 ||
    pageSize <= 0
  ) {
    return FIRST_PAGE;
  }

  return Math.max(
    FIRST_PAGE,
    Math.ceil(
      total / pageSize,
    ),
  );
}


/* ============================================================================
 * Error Handling
 * ========================================================================== */

function getErrorMessage(
  error: unknown,
  fallback: string,
): string {
  if (
    error &&
    typeof error === "object" &&
    "detail" in error &&
    typeof error.detail === "string"
  ) {
    return error.detail;
  }

  if (
    error instanceof Error &&
    error.message.trim()
  ) {
    return error.message;
  }

  return fallback;
}