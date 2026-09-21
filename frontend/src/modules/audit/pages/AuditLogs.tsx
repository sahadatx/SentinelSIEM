/**
 * ============================================================================
 * SentinelSIEM — Global Audit Logs Page
 * ============================================================================
 *
 * Route:
 *
 *     /audit
 *
 * Backend:
 *
 *     /api/v1/audit
 *
 * Locked permission:
 *
 *     users:read
 *
 * ============================================================================
 * Responsibilities
 * ============================================================================
 *
 * - Load global audit events
 * - Load audit statistics
 * - Load the authoritative User Management directory
 * - Provide real users to Actor / Target filters
 * - Provide the same user directory to the audit table
 * - Resolve actor / target UUIDs into human-readable identities
 * - Apply audit filters
 * - Handle backend-authoritative pagination
 * - Refresh audit data
 * - Switch between table and timeline views
 * - Open immutable event details
 * - Handle permission boundaries
 * - Prevent stale requests from overwriting current state
 *
 * ============================================================================
 * Architecture
 * ============================================================================
 *
 * Global Audit
 *
 *     AuditLogs
 *        |
 *        +---- auditApi.list()
 *        |
 *        +---- auditApi.statistics()
 *        |
 *        +---- usersApi.list()
 *                 |
 *                 +---- Actor dropdown
 *                 +---- Target dropdown
 *                 +---- AuditTable identity resolution
 *
 * The Users API remains the authoritative source for user identities.
 *
 * ============================================================================
 * IMPORTANT
 * ============================================================================
 *
 * This page does NOT:
 *
 * - authenticate
 * - authorize
 * - access the database
 * - create audit records
 * - modify audit records
 * - delete audit records
 *
 * Backend/API layers remain authoritative.
 * ============================================================================
 */

import {
  AlertCircle,
  FileSearch,
  List,
  RefreshCw,
  ShieldAlert,
  Table2,
  X,
} from "lucide-react";

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import { useAuthStore } from "../../../store/auth";

import { usersApi } from "../../users/api";

import type {
  User,
} from "../../users/types";

import { auditApi } from "../api";

import {
  DEFAULT_AUDIT_PAGE,
  DEFAULT_AUDIT_PAGE_SIZE,
} from "../types";

import type {
  AuditEvent,
  AuditListParams,
  AuditStatistics,
} from "../types";

import { AUDIT_READ } from "../permissions";

import AuditEventDetails
  from "../components/AuditEventDetails";

import AuditFilters
  from "../components/AuditFilters";

import AuditStats
  from "../components/AuditStats";

import AuditTable
  from "../components/AuditTable";

import AuditTimeline
  from "../components/AuditTimeline";

import type {
  AuditUserOption,
} from "../components/AuditFilters";

import type {
  AuditIdentityUser,
} from "../components/AuditTable";

import "../Audit.css";


/* ============================================================================
 * Constants
 * ========================================================================== */

const AUDIT_PERMISSION =
  AUDIT_READ;

const PERMISSION_DENIED_MESSAGE =
  "You do not have permission to view global audit logs.";

const DEFAULT_LOAD_ERROR_MESSAGE =
  "Unable to load global audit logs. Please try again.";

const DEFAULT_STATISTICS_ERROR_MESSAGE =
  "Unable to load audit statistics.";

const DEFAULT_USERS_ERROR_MESSAGE =
  "Unable to load audit identity options.";

/*
 * User Management API currently permits a maximum
 * page size of 200.
 *
 * We intentionally use the maximum value and continue
 * page-by-page until the complete authoritative directory
 * has been loaded.
 */
const USER_DIRECTORY_PAGE_SIZE =
  200;


/* ============================================================================
 * View
 * ========================================================================== */

type AuditView =
  | "table"
  | "timeline";


/* ============================================================================
 * Page
 * ========================================================================== */

export default function AuditLogs() {

  /* ==========================================================================
   * Permission
   * ======================================================================== */

  const hasPermission =
    useAuthStore(
      (state) =>
        state.hasPermission,
    );

  const canReadAudit =
    hasPermission(
      AUDIT_PERMISSION,
    );


  /* ==========================================================================
   * Audit Pagination
   * ======================================================================== */

  const [page, setPage] =
    useState<number>(
      DEFAULT_AUDIT_PAGE,
    );

  const pageSize =
    DEFAULT_AUDIT_PAGE_SIZE;

  const [total, setTotal] =
    useState<number>(0);


  /* ==========================================================================
   * Audit Events
   * ======================================================================== */

  const [events, setEvents] =
    useState<AuditEvent[]>([]);


  /* ==========================================================================
   * Audit Filters
   * ======================================================================== */

  const [filters, setFilters] =
    useState<AuditListParams>({});


  /* ==========================================================================
   * Audit Statistics
   * ======================================================================== */

  const [
    statistics,
    setStatistics,
  ] = useState<AuditStatistics | null>(
    null,
  );


  /* ==========================================================================
   * Selected Event
   * ======================================================================== */

  const [
    selectedEvent,
    setSelectedEvent,
  ] = useState<AuditEvent | null>(
    null,
  );


  /* ==========================================================================
   * View
   * ======================================================================== */

  const [view, setView] =
    useState<AuditView>(
      "table",
    );


  /* ==========================================================================
   * Audit Loading
   * ======================================================================== */

  const [loading, setLoading] =
    useState<boolean>(true);

  const [refreshing, setRefreshing] =
    useState<boolean>(false);

  const [
    statisticsLoading,
    setStatisticsLoading,
  ] = useState<boolean>(true);


  /* ==========================================================================
   * User Directory
   * ======================================================================== */

  const [
    auditUsers,
    setAuditUsers,
  ] = useState<User[]>([]);

  const [
    usersLoading,
    setUsersLoading,
  ] = useState<boolean>(true);

  const [
    usersError,
    setUsersError,
  ] = useState<string | null>(null);


  /* ==========================================================================
   * Errors
   * ======================================================================== */

  const [error, setError] =
    useState<string | null>(null);

  const [
    statisticsError,
    setStatisticsError,
  ] = useState<string | null>(
    null,
  );


  /* ==========================================================================
   * Request Guards
   * ======================================================================== */

  /*
   * Every asynchronous loader gets its own monotonically
   * increasing request ID.
   *
   * This prevents a slow previous request from overwriting
   * state produced by a newer request.
   */
  const listRequestId =
    useRef<number>(0);

  const statisticsRequestId =
    useRef<number>(0);

  const usersRequestId =
    useRef<number>(0);


  /* ==========================================================================
   * Normalized Filters
   * ======================================================================== */

  const normalizedFilters =
    useMemo(
      () =>
        sanitizeFilters(
          filters,
        ),
      [
        filters,
      ],
    );


  /* ==========================================================================
   * Audit List Parameters
   * ======================================================================== */

  const listParams =
    useMemo<AuditListParams>(
      () => ({
        ...normalizedFilters,

        page,

        page_size:
          pageSize,
      }),
      [
        normalizedFilters,
        page,
        pageSize,
      ],
    );


  /* ==========================================================================
   * Statistics Parameters
   * ======================================================================== */

  const statisticsParams =
    useMemo<AuditListParams>(
      () =>
        buildStatisticsParams(
          normalizedFilters,
        ),
      [
        normalizedFilters,
      ],
    );


  /* ==========================================================================
   * User Options
   * ======================================================================== */

  /*
   * Actor and Target filters use the same authoritative
   * User Management directory.
   */
  const actorOptions =
    useMemo<AuditUserOption[]>(
      () =>
        auditUsers.map(
          (
            user,
          ) => ({
            user_id:
              user.user_id,

            display_name:
              normalizeNullableText(
                user.display_name,
              ),

            username:
              normalizeUsername(
                user.username,
              ),

            role:
              formatUserRole(
                user,
              ),
          }),
        ),
      [
        auditUsers,
      ],
    );


  const targetOptions =
    actorOptions;


  /* ============================================================================
   * Audit Table Identity Users
   * ========================================================================== */

  /*
   * AuditTable receives exactly the same user directory
   * used by Actor / Target filters.
   *
   * This is important:
   *
   *     Users API
   *          |
   *          +---- filters
   *          |
   *          +---- table identity resolution
   *
   * There is no second identity source.
   */
  const identityUsers =
    useMemo<AuditIdentityUser[]>(
      () =>
        auditUsers.map(
          (
            user,
          ) => ({
            user_id:
              user.user_id,

            display_name:
              normalizeNullableText(
                user.display_name,
              ),

            username:
              normalizeUsername(
                user.username,
              ),

            role:
              formatUserRole(
                user,
              ),
          }),
        ),
      [
        auditUsers,
      ],
    );


  /* ==========================================================================
   * Load Audit Users
   * ======================================================================== */

  const loadAuditUsers =
    useCallback(
      async () => {

        const requestId =
          ++usersRequestId.current;


        /*
         * Permission boundary.
         */
        if (!canReadAudit) {

          setAuditUsers([]);

          setUsersLoading(false);

          setUsersError(null);

          return;
        }


        setUsersLoading(true);

        setUsersError(null);


        try {

          /*
           * ------------------------------------------------------------------
           * First User Directory Page
           * ------------------------------------------------------------------
           */

          const firstResponse =
            await usersApi.list({
              limit:
                USER_DIRECTORY_PAGE_SIZE,

              offset:
                0,
            });


          /*
           * Ignore stale request.
           */
          if (
            requestId !==
            usersRequestId.current
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
            [
              ...firstUsers,
            ];


          /*
           * Backend total is authoritative.
           */
          const totalUsers =
            normalizeCount(
              firstResponse.total,
            );


          /*
           * Prefer backend total_pages.
           *
           * Fallback is only used when the backend does not
           * provide a valid value.
           */
          const totalPages =
            normalizePositiveInteger(
              firstResponse.total_pages,
            ) ??
            calculateUserTotalPages(
              totalUsers,
              USER_DIRECTORY_PAGE_SIZE,
            );


          /*
           * ------------------------------------------------------------------
           * Remaining User Directory Pages
           * ------------------------------------------------------------------
           */

          for (
            let currentPage = 2;
            currentPage <= totalPages;
            currentPage += 1
          ) {

            /*
             * Abort state updates when a newer request has
             * started.
             */
            if (
              requestId !==
              usersRequestId.current
            ) {
              return;
            }


            const offset =
              (
                currentPage -
                1
              ) *
              USER_DIRECTORY_PAGE_SIZE;


            const response =
              await usersApi.list({
                limit:
                  USER_DIRECTORY_PAGE_SIZE,

                offset,
              });


            if (
              requestId !==
              usersRequestId.current
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


          /*
           * ------------------------------------------------------------------
           * Directory Normalization
           * ------------------------------------------------------------------
           *
           * A user should appear only once in the identity
           * directory even if an overlapping backend page
           * accidentally returns the same record twice.
           */

          const uniqueUsers =
            deduplicateUsers(
              allUsers,
            );


          const sortedUsers =
            sortUsers(
              uniqueUsers,
            );


          /*
           * Final stale-request guard before committing
           * the complete directory.
           */
          if (
            requestId !==
            usersRequestId.current
          ) {
            return;
          }


          setAuditUsers(
            sortedUsers,
          );

        } catch (
          requestError
        ) {

          if (
            requestId !==
            usersRequestId.current
          ) {
            return;
          }


          setAuditUsers([]);

          setUsersError(
            getErrorMessage(
              requestError,
              DEFAULT_USERS_ERROR_MESSAGE,
            ),
          );

        } finally {

          if (
            requestId ===
            usersRequestId.current
          ) {

            setUsersLoading(false);

          }

        }

      },
      [
        canReadAudit,
      ],
    );


  /* ==========================================================================
   * Load Audit Events
   * ======================================================================== */

  const loadAudit =
    useCallback(
      async (
        showRefreshing = false,
      ) => {

        const requestId =
          ++listRequestId.current;


        /*
         * Permission boundary.
         */
        if (!canReadAudit) {

          setEvents([]);

          setTotal(0);

          setSelectedEvent(null);

          setError(
            PERMISSION_DENIED_MESSAGE,
          );

          setLoading(false);

          setRefreshing(false);

          return;
        }


        if (showRefreshing) {

          setRefreshing(true);

        } else {

          setLoading(true);

        }


        setError(null);


        try {

          const response =
            await auditApi.list(
              listParams,
            );


          /*
           * Ignore stale request.
           */
          if (
            requestId !==
            listRequestId.current
          ) {
            return;
          }


          const nextEvents =
            Array.isArray(
              response.items,
            )
              ? response.items
              : [];


          setEvents(
            nextEvents,
          );


          setTotal(
            normalizeCount(
              response.total,
            ),
          );


          /*
           * Backend is authoritative about the actual
           * page returned by the API.
           */
          const responsePage =
            normalizePositiveInteger(
              response.page,
            );


          if (
            responsePage !== null &&
            responsePage !== page
          ) {

            setPage(
              responsePage,
            );

          }


          /*
           * A newly loaded page invalidates the currently
           * selected event.
           */
          setSelectedEvent(null);

        } catch (
          requestError
        ) {

          if (
            requestId !==
            listRequestId.current
          ) {
            return;
          }


          setEvents([]);

          setTotal(0);

          setSelectedEvent(null);

          setError(
            getErrorMessage(
              requestError,
              DEFAULT_LOAD_ERROR_MESSAGE,
            ),
          );

        } finally {

          if (
            requestId ===
            listRequestId.current
          ) {

            setLoading(false);

            setRefreshing(false);

          }

        }

      },
      [
        canReadAudit,
        listParams,
        page,
      ],
    );


  /* ==========================================================================
   * Load Statistics
   * ======================================================================== */

  const loadStatistics =
    useCallback(
      async () => {

        const requestId =
          ++statisticsRequestId.current;


        /*
         * Permission boundary.
         */
        if (!canReadAudit) {

          setStatistics(null);

          setStatisticsLoading(false);

          setStatisticsError(null);

          return;
        }


        setStatisticsLoading(true);

        setStatisticsError(null);


        try {

          const response =
            await auditApi.statistics(
              statisticsParams,
            );


          if (
            requestId !==
            statisticsRequestId.current
          ) {
            return;
          }


          setStatistics(
            normalizeStatistics(
              response,
            ),
          );

        } catch (
          requestError
        ) {

          if (
            requestId !==
            statisticsRequestId.current
          ) {
            return;
          }


          setStatistics(null);

          setStatisticsError(
            getErrorMessage(
              requestError,
              DEFAULT_STATISTICS_ERROR_MESSAGE,
            ),
          );

        } finally {

          if (
            requestId ===
            statisticsRequestId.current
          ) {

            setStatisticsLoading(false);

          }

        }

      },
      [
        canReadAudit,
        statisticsParams,
      ],
    );


  /* ==========================================================================
   * Initial / Filtered Audit Load
   * ======================================================================== */

  useEffect(() => {

    void loadAudit();

  }, [
    loadAudit,
  ]);


  /* ==========================================================================
   * Statistics Load
   * ======================================================================== */

  useEffect(() => {

    void loadStatistics();

  }, [
    loadStatistics,
  ]);


  /* ==========================================================================
   * User Directory Load
   * ======================================================================== */

  useEffect(() => {

    void loadAuditUsers();

  }, [
    loadAuditUsers,
  ]);


  /* ==========================================================================
   * Refresh
   * ======================================================================== */

  const handleRefresh =
    useCallback(
      async () => {

        if (
          loading ||
          refreshing
        ) {
          return;
        }


        await Promise.all([
          loadAudit(true),
          loadStatistics(),
          loadAuditUsers(),
        ]);

      },
      [
        loading,
        refreshing,
        loadAudit,
        loadStatistics,
        loadAuditUsers,
      ],
    );


  /* ==========================================================================
   * Filter Change
   * ======================================================================== */

  const handleFiltersChange =
    useCallback(
      (
        nextFilters: AuditListParams,
      ) => {

        /*
         * A filter change invalidates the selected event
         * and always returns to the first audit page.
         */
        setSelectedEvent(null);

        setPage(
          DEFAULT_AUDIT_PAGE,
        );

        setFilters(
          sanitizeFilters(
            nextFilters,
          ),
        );

      },
      [],
    );


  /* ==========================================================================
   * Filter Reset
   * ======================================================================== */

  const handleFiltersReset =
    useCallback(
      () => {

        setSelectedEvent(null);

        setPage(
          DEFAULT_AUDIT_PAGE,
        );

        setFilters({});

      },
      [],
    );


  /* ==========================================================================
   * Audit Pagination
   * ======================================================================== */

  const totalPages =
    useMemo(
      () =>
        calculateTotalPages(
          total,
          pageSize,
        ),
      [
        total,
        pageSize,
      ],
    );


  const canGoPrevious =
    page > 1;


  const canGoNext =
    page < totalPages;


  const handlePreviousPage =
    useCallback(
      () => {

        if (
          loading ||
          refreshing ||
          !canGoPrevious
        ) {
          return;
        }


        setSelectedEvent(null);

        setPage(
          (
            currentPage,
          ) =>
            Math.max(
              DEFAULT_AUDIT_PAGE,
              currentPage - 1,
            ),
        );

      },
      [
        loading,
        refreshing,
        canGoPrevious,
      ],
    );


  const handleNextPage =
    useCallback(
      () => {

        if (
          loading ||
          refreshing ||
          !canGoNext
        ) {
          return;
        }


        setSelectedEvent(null);

        setPage(
          (
            currentPage,
          ) =>
            Math.min(
              totalPages,
              currentPage + 1,
            ),
        );

      },
      [
        loading,
        refreshing,
        canGoNext,
        totalPages,
      ],
    );


  /* ==========================================================================
   * Event Selection
   * ======================================================================== */

  const handleSelectEvent =
    useCallback(
      (
        event: AuditEvent,
      ) => {

        setSelectedEvent(
          event,
        );

      },
      [],
    );


  /* ==========================================================================
   * Close Details
   * ======================================================================== */

  const handleCloseDetails =
    useCallback(
      () => {

        setSelectedEvent(null);

      },
      [],
    );


  /* ==========================================================================
   * Escape Key
   * ======================================================================== */

  useEffect(() => {

    if (!selectedEvent) {
      return;
    }


    const handleKeyDown =
      (
        keyboardEvent: KeyboardEvent,
      ) => {

        if (
          keyboardEvent.key ===
          "Escape"
        ) {

          setSelectedEvent(null);

        }

      };


    window.addEventListener(
      "keydown",
      handleKeyDown,
    );


    return () => {

      window.removeEventListener(
        "keydown",
        handleKeyDown,
      );

    };

  }, [
    selectedEvent,
  ]);


  /* ==========================================================================
   * Permission Boundary
   * ======================================================================== */

  if (!canReadAudit) {

    return (
      <section
        className="audit-page"
        aria-labelledby="audit-permission-title"
      >

        <header className="page-heading">

          <div>

            <span className="audit-section-kicker">
              SECURITY AUDIT
            </span>

            <h2 id="audit-permission-title">
              Audit Logs
            </h2>

            <p>
              Review security and
              account activity
              across SentinelSIEM.
            </p>

          </div>

          <ShieldAlert
            size={22}
            aria-hidden="true"
          />

        </header>


        <div
          className="notice warning"
          role="alert"
        >

          <ShieldAlert
            size={17}
            aria-hidden="true"
          />

          <span>

            {PERMISSION_DENIED_MESSAGE}

            {" "}

            Required permission:

            {" "}

            <code>
              {AUDIT_PERMISSION}
            </code>

          </span>

        </div>

      </section>
    );
  }


  /* ==========================================================================
   * Main Render
   * ======================================================================== */

  return (
    <section
      className="audit-page"
      aria-labelledby="audit-page-title"
    >

      {/* ======================================================================
          Header
          ==================================================================== */}

      <header className="page-heading">

        <div>

          <span className="audit-section-kicker">
            SECURITY AUDIT
          </span>

          <h2 id="audit-page-title">
            Audit Logs
          </h2>

          <p>
            Review security events,
            account changes,
            authorization activity,
            and system actions
            across SentinelSIEM.
          </p>

        </div>


        <div className="audit-page-header-actions">

          <button
            type="button"
            className="secondary-button"
            onClick={
              handleRefresh
            }
            disabled={
              loading ||
              refreshing
            }
            title="Refresh audit logs"
            aria-label="Refresh audit logs"
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

        </div>

      </header>


      {/* ======================================================================
          Context Notice
          ==================================================================== */}

      <div
        className="notice"
        role="note"
      >

        <FileSearch
          size={16}
          aria-hidden="true"
        />

        <span>
          Global audit activity
          across SentinelSIEM.
          Audit records are
          read-only and generated
          by the backend security
          boundary.
        </span>

      </div>


      {/* ======================================================================
          Main Error
          ==================================================================== */}

      {error && (

        <div
          className="notice warning"
          role="alert"
        >

          <AlertCircle
            size={16}
            aria-hidden="true"
          />

          <span>
            {error}
          </span>

        </div>

      )}


      {/* ======================================================================
          Statistics Error
          ==================================================================== */}

      {statisticsError && (

        <div
          className="notice warning"
          role="alert"
        >

          <AlertCircle
            size={16}
            aria-hidden="true"
          />

          <span>
            {statisticsError}
          </span>

        </div>

      )}


      {/* ======================================================================
          User Directory Error
          ==================================================================== */}

      {usersError && (

        <div
          className="notice warning"
          role="alert"
        >

          <AlertCircle
            size={16}
            aria-hidden="true"
          />

          <span>
            {usersError}
          </span>

        </div>

      )}


      {/* ======================================================================
          Statistics
          ==================================================================== */}

      <AuditStats
        statistics={
          statistics
        }
        loading={
          statisticsLoading
        }
      />


      {/* ======================================================================
          Filters
          ==================================================================== */}

      <AuditFilters
        filters={
          filters
        }
        onChange={
          handleFiltersChange
        }
        onReset={
          handleFiltersReset
        }
        actors={
          actorOptions
        }
        targets={
          targetOptions
        }
        disabled={
          loading ||
          refreshing ||
          usersLoading
        }
      />


      {/* ======================================================================
          Toolbar
          ==================================================================== */}

      <div className="audit-toolbar">

        <div className="audit-toolbar-info">

          <span className="audit-toolbar-label">
            AUDIT EVENTS
          </span>


          {!loading && (

            <span className="audit-toolbar-count">

              {formatNumber(
                total,
              )}

              {" "}

              {total === 1
                ? "event"
                : "events"}

            </span>

          )}

        </div>


        <div
          className="audit-view-toggle"
          role="group"
          aria-label="Audit event view"
        >

          <button
            type="button"
            className={
              view === "table"
                ? "audit-view-button active"
                : "audit-view-button"
            }
            onClick={() =>
              setView("table")
            }
            aria-pressed={
              view === "table"
            }
          >

            <Table2
              size={14}
              aria-hidden="true"
            />

            <span>
              Table
            </span>

          </button>


          <button
            type="button"
            className={
              view === "timeline"
                ? "audit-view-button active"
                : "audit-view-button"
            }
            onClick={() =>
              setView("timeline")
            }
            aria-pressed={
              view === "timeline"
            }
          >

            <List
              size={14}
              aria-hidden="true"
            />

            <span>
              Timeline
            </span>

          </button>

        </div>

      </div>


      {/* ======================================================================
          Loading
          ==================================================================== */}

      {loading && (

        <div
          className="empty"
          role="status"
          aria-live="polite"
          aria-busy="true"
        >
          Loading audit logs...
        </div>

      )}


      {/* ======================================================================
          Empty
          ==================================================================== */}

      {!loading &&
        !error &&
        events.length === 0 && (

          <div
            className="empty"
            role="status"
          >
            No audit events match
            the current filters.
          </div>

        )}


      {/* ======================================================================
          Table
          ==================================================================== */}

      {!loading &&
        !error &&
        events.length > 0 &&
        view === "table" && (

          <AuditTable
            events={
              events
            }
            loading={false}
            onSelect={
              handleSelectEvent
            }
            identityUsers={
              identityUsers
            }
          />

        )}


      {/* ======================================================================
          Timeline
          ==================================================================== */}

      {!loading &&
        !error &&
        events.length > 0 &&
        view === "timeline" && (

          <AuditTimeline
            events={
              events
            }
            loading={false}
            onSelect={
              handleSelectEvent
            }
          />

        )}


      {/* ======================================================================
          Pagination
          ==================================================================== */}

      {!loading &&
        total > 0 &&
        (() => {

          const startItem =
            (page - 1) *
              pageSize +
            1;

          const endItem =
            Math.min(
              page * pageSize,
              total,
            );


          return (
            <div
              className="audit-pagination"
              aria-label="Audit pagination"
            >

              <div className="audit-pagination-content">

                {/* ----------------------------------------------------------------
                    Pagination Information
                    ---------------------------------------------------------------- */}

                <div
                  className="audit-pagination-info"
                  aria-live="polite"
                >

                  <strong>
                    {formatNumber(
                      startItem,
                    )}
                    {"–"}
                    {formatNumber(
                      endItem,
                    )}
                  </strong>

                  <span className="audit-pagination-label">
                    Events
                  </span>

                  <span className="audit-pagination-separator">
                    /
                  </span>

                  <span className="audit-pagination-total">
                    Total{" "}
                    {formatNumber(
                      total,
                    )}
                  </span>

                  <span className="audit-pagination-divider">
                    •
                  </span>

                  <span className="audit-pagination-page">
                    Page{" "}
                    <strong>
                      {page}
                    </strong>
                    {" "}
                    of{" "}
                    <strong>
                      {totalPages}
                    </strong>
                  </span>

                </div>


                {/* ----------------------------------------------------------------
                    Pagination Controls
                    ---------------------------------------------------------------- */}

                <div className="audit-pagination-controls">

                  <button
                    type="button"
                    className="audit-pagination-button"
                    onClick={
                      handlePreviousPage
                    }
                    disabled={
                      loading ||
                      refreshing ||
                      !canGoPrevious
                    }
                    aria-label="Previous page"
                    title="Previous page"
                  >
                    Previous
                  </button>


                  <button
                    type="button"
                    className="audit-pagination-button"
                    onClick={
                      handleNextPage
                    }
                    disabled={
                      loading ||
                      refreshing ||
                      !canGoNext
                    }
                    aria-label="Next page"
                    title="Next page"
                  >
                    Next
                  </button>

                </div>

              </div>

            </div>
          );

        })()}


      {/* ======================================================================
          Event Details
          ==================================================================== */}

      {selectedEvent && (

        <div
          className="audit-detail-overlay"
          role="presentation"
          onMouseDown={(
            mouseEvent,
          ) => {

            if (
              mouseEvent.target ===
              mouseEvent.currentTarget
            ) {

              handleCloseDetails();

            }

          }}
        >

          <div
            className="audit-detail-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="audit-detail-title"
          >

            <div className="audit-detail-modal-header">

              <div>

                <span className="audit-section-kicker">
                  AUDIT EVENT
                </span>

                <h3 id="audit-detail-title">
                  Event Details
                </h3>

              </div>


              <button
                type="button"
                className="audit-detail-close"
                onClick={
                  handleCloseDetails
                }
                title="Close event details"
                aria-label="Close event details"
              >

                <X
                  size={18}
                  aria-hidden="true"
                />

              </button>

            </div>


            <div className="audit-detail-modal-body">

              <AuditEventDetails
                event={
                  selectedEvent
                }
                onClose={
                  handleCloseDetails
                }
              />

            </div>

          </div>

        </div>

      )}

    </section>
  );
}


/* ============================================================================
 * Statistics Parameters
 * ========================================================================== */

function buildStatisticsParams(
  filters: AuditListParams,
): AuditListParams {

  const params:
    AuditListParams = {};


  copyFilter(
    filters,
    params,
    "action",
  );


  copyFilter(
    filters,
    params,
    "category",
  );


  /*
   * Backend statistics currently accepts the canonical
   * result-style parameter. Prefer result when present,
   * otherwise use outcome.
   */
  if (
    hasText(
      filters.result,
    )
  ) {

    params.result =
      filters.result.trim();

  } else if (
    hasText(
      filters.outcome,
    )
  ) {

    params.result =
      filters.outcome.trim();

  }


  /*
   * Actor filter:
   *
   *     actor
   *       ↓
   *     actor_user_id
   *
   * Backend/API transport remains authoritative.
   */
  if (
    hasText(
      filters.actor,
    )
  ) {

    params.actor =
      filters.actor.trim();

  } else if (
    hasText(
      filters.actor_user_id,
    )
  ) {

    params.actor =
      filters.actor_user_id.trim();

  }


  /*
   * Target filter.
   */
  if (
    hasText(
      filters.target,
    )
  ) {

    params.target =
      filters.target.trim();

  } else if (
    hasText(
      filters.target_user_id,
    )
  ) {

    params.target =
      filters.target_user_id.trim();

  }


  /*
   * Source filter.
   */
  if (
    hasText(
      filters.source,
    )
  ) {

    params.source =
      filters.source.trim();

  } else if (
    hasText(
      filters.source_ip,
    )
  ) {

    params.source =
      filters.source_ip.trim();

  }


  copyFilter(
    filters,
    params,
    "date_from",
  );


  copyFilter(
    filters,
    params,
    "date_to",
  );


  return params;
}


/* ============================================================================
 * Filter Sanitization
 * ========================================================================== */

function sanitizeFilters(
  filters: AuditListParams,
): AuditListParams {

  const sanitized:
    AuditListParams = {};


  copyFilter(
    filters,
    sanitized,
    "action",
  );


  copyFilter(
    filters,
    sanitized,
    "category",
  );


  copyFilter(
    filters,
    sanitized,
    "result",
  );


  copyFilter(
    filters,
    sanitized,
    "outcome",
  );


  copyFilter(
    filters,
    sanitized,
    "actor",
  );


  copyFilter(
    filters,
    sanitized,
    "actor_user_id",
  );


  copyFilter(
    filters,
    sanitized,
    "target",
  );


  copyFilter(
    filters,
    sanitized,
    "target_user_id",
  );


  copyFilter(
    filters,
    sanitized,
    "source",
  );


  copyFilter(
    filters,
    sanitized,
    "source_ip",
  );


  copyFilter(
    filters,
    sanitized,
    "date_from",
  );


  copyFilter(
    filters,
    sanitized,
    "date_to",
  );


  return sanitized;
}


/* ============================================================================
 * Filter Copy
 * ========================================================================== */

function copyFilter(
  source: AuditListParams,
  target: AuditListParams,
  key:
    | "action"
    | "category"
    | "result"
    | "outcome"
    | "actor"
    | "actor_user_id"
    | "target"
    | "target_user_id"
    | "source"
    | "source_ip"
    | "date_from"
    | "date_to",
): void {

  const value =
    source[key];


  if (
    hasText(value)
  ) {

    target[key] =
      value.trim();

  }
}


/* ============================================================================
 * Statistics Normalization
 * ========================================================================== */

function normalizeStatistics(
  value: AuditStatistics,
): AuditStatistics {

  return {

    total:
      normalizeCount(
        value?.total,
      ),

    success:
      normalizeCount(
        value?.success,
      ),

    failure:
      normalizeCount(
        value?.failure,
      ),

    denied:
      normalizeCount(
        value?.denied,
      ),

    unique_actors:
      normalizeCount(
        value?.unique_actors,
      ),

    unique_targets:
      normalizeCount(
        value?.unique_targets,
      ),

  };
}


/* ============================================================================
 * User Sorting
 * ========================================================================== */

function sortUsers(
  users: User[],
): User[] {

  return [...users].sort(
    (
      left,
      right,
    ) => {

      const leftLabel =
        (
          normalizeNullableText(
            left.display_name,
          ) ||
          normalizeUsername(
            left.username,
          ) ||
          "Unknown User"
        ).toLowerCase();


      const rightLabel =
        (
          normalizeNullableText(
            right.display_name,
          ) ||
          normalizeUsername(
            right.username,
          ) ||
          "Unknown User"
        ).toLowerCase();


      return leftLabel.localeCompare(
        rightLabel,
      );

    },
  );
}


/* ============================================================================
 * User Deduplication
 * ========================================================================== */

function deduplicateUsers(
  users: User[],
): User[] {

  const seen =
    new Set<string>();

  const unique:
    User[] = [];


  for (
    const user of users
  ) {

    const userId =
      normalizeNullableText(
        user.user_id,
      );


    if (!userId) {
      continue;
    }


    if (
      seen.has(userId)
    ) {
      continue;
    }


    seen.add(userId);

    unique.push(user);

  }


  return unique;
}


/* ============================================================================
 * User Pagination
 * ========================================================================== */

function calculateUserTotalPages(
  total: number,
  pageSize: number,
): number {

  const safeTotal =
    normalizeCount(
      total,
    );

  const safePageSize =
    Math.max(
      1,
      normalizeCount(
        pageSize,
      ),
    );


  if (
    safeTotal === 0
  ) {
    return 0;
  }


  return Math.ceil(
    safeTotal /
    safePageSize,
  );
}


/* ============================================================================
 * User Role
 * ========================================================================== */

/**
 * Convert the authoritative User Management role data
 * into a clean display string.
 *
 * Important:
 *
 * User.roles may contain either primitive role values or
 * structured role objects depending on the backend contract.
 *
 * We deliberately inspect unknown values instead of blindly
 * calling String(role), which could produce:
 *
 *     [object Object]
 *
 * in the UI.
 */
function formatUserRole(
  user: User,
): string | null {

  if (
    !Array.isArray(
      user.roles,
    ) ||
    user.roles.length === 0
  ) {
    return null;
  }


  const roles =
    user.roles
      .map(
        (
          role,
        ) =>
          extractRoleLabel(
            role,
          ),
      )
      .filter(
        (
          value,
        ): value is string =>
          Boolean(value),
      );


  if (
    roles.length === 0
  ) {
    return null;
  }


  /*
   * Remove duplicate role labels while preserving
   * the original ordering.
   */
  const uniqueRoles =
    [
      ...new Set(
        roles,
      ),
    ];


  return uniqueRoles.join(
    ", ",
  );
}


/* ============================================================================
 * Role Label Extraction
 * ========================================================================== */

function extractRoleLabel(
  value: unknown,
): string | null {

  /*
   * Primitive role representation.
   */
  if (
    typeof value === "string"
  ) {

    const normalized =
      value.trim();


    return normalized
      ? formatRole(
          normalized,
        )
      : null;
  }


  /*
   * Numeric role representation is not normally expected,
   * but converting it safely is preferable to rendering
   * [object Object].
   */
  if (
    typeof value === "number" &&
    Number.isFinite(value)
  ) {

    return formatRole(
      String(value),
    );

  }


  /*
   * Structured role representation.
   */
  if (
    value &&
    typeof value === "object"
  ) {

    const roleObject =
      value as Record<
        string,
        unknown
      >;


    const candidates = [
      roleObject.name,
      roleObject.display_name,
      roleObject.label,
      roleObject.code,
      roleObject.key,
      roleObject.slug,
      roleObject.role,
    ];


    for (
      const candidate of candidates
    ) {

      if (
        typeof candidate !==
        "string"
      ) {
        continue;
      }


      const normalized =
        candidate.trim();


      if (!normalized) {
        continue;
      }


      return formatRole(
        normalized,
      );

    }

  }


  return null;
}


/* ============================================================================
 * Role Formatting
 * ========================================================================== */

function formatRole(
  value: string,
): string {

  const normalized =
    value
      .trim()
      .replace(
        /[-_]+/g,
        " ",
      )
      .replace(
        /\s+/g,
        " ",
      );


  if (!normalized) {
    return "User";
  }


  return normalized.replace(
    /\b\w/g,
    (
      character,
    ) =>
      character.toUpperCase(),
  );
}


/* ============================================================================
 * Username Normalization
 * ========================================================================== */

function normalizeUsername(
  value:
    | string
    | null
    | undefined,
): string {

  if (
    typeof value !==
    "string"
  ) {
    return "";
  }


  return value.trim();
}


/* ============================================================================
 * Nullable Text
 * ========================================================================== */

function normalizeNullableText(
  value:
    | string
    | null
    | undefined,
): string | null {

  if (
    typeof value !==
    "string"
  ) {
    return null;
  }


  const normalized =
    value.trim();


  return normalized
    ? normalized
    : null;
}


/* ============================================================================
 * Number Helpers
 * ========================================================================== */

function normalizeCount(
  value:
    | number
    | null
    | undefined,
): number {

  if (
    typeof value !== "number" ||
    !Number.isFinite(value)
  ) {
    return 0;
  }


  return Math.max(
    0,
    Math.floor(value),
  );
}


function normalizePositiveInteger(
  value:
    | number
    | null
    | undefined,
): number | null {

  if (
    typeof value !== "number" ||
    !Number.isFinite(value)
  ) {
    return null;
  }


  const normalized =
    Math.floor(value);


  return normalized >= 1
    ? normalized
    : null;
}


/* ============================================================================
 * Audit Pagination
 * ========================================================================== */

function calculateTotalPages(
  total: number,
  pageSize: number,
): number {

  const safeTotal =
    normalizeCount(
      total,
    );


  const safePageSize =
    Math.max(
      1,
      normalizeCount(
        pageSize,
      ),
    );


  /*
   * Keep one logical page for the empty state.
   */
  return Math.max(
    1,
    Math.ceil(
      safeTotal /
      safePageSize,
    ),
  );
}


/* ============================================================================
 * Number Formatting
 * ========================================================================== */

function formatNumber(
  value: number,
): string {

  return new Intl.NumberFormat(
    "en-US",
    {
      maximumFractionDigits: 0,
    },
  ).format(
    normalizeCount(
      value,
    ),
  );
}


/* ============================================================================
 * Text Helpers
 * ========================================================================== */

function hasText(
  value:
    | string
    | undefined
    | null,
): value is string {

  return (
    typeof value === "string" &&
    value.trim().length > 0
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
    error instanceof Error &&
    error.message.trim()
  ) {

    return error.message;
  }


  if (
    error &&
    typeof error === "object"
  ) {

    const candidate =
      error as Record<
        string,
        unknown
      >;


    if (
      typeof candidate.detail ===
        "string" &&
      candidate.detail.trim()
    ) {

      return candidate.detail;
    }


    if (
      typeof candidate.message ===
        "string" &&
      candidate.message.trim()
    ) {

      return candidate.message;
    }


    const response =
      candidate.response;


    if (
      response &&
      typeof response === "object"
    ) {

      const responseObject =
        response as Record<
          string,
          unknown
        >;


      const data =
        responseObject.data;


      if (
        data &&
        typeof data === "object"
      ) {

        const dataObject =
          data as Record<
            string,
            unknown
          >;


        if (
          typeof dataObject.detail ===
            "string" &&
          dataObject.detail.trim()
        ) {

          return dataObject.detail;
        }


        if (
          typeof dataObject.message ===
            "string" &&
          dataObject.message.trim()
        ) {

          return dataObject.message;
        }

      }

    }

  }


  return fallback;
}


/* ============================================================================
 * End of File
 * ============================================================================
 */