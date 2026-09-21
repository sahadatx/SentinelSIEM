/**
 * ============================================================================
 * SentinelSIEM — Incidents Page
 * ============================================================================
 *
 * Final Incident / SOC Investigation workflow.
 *
 * IMPORTANT
 * ---------
 * Backend is authoritative for:
 *   - KPI statistics
 *   - filter catalogues
 *   - user directory
 *   - roles
 *   - assignee validation
 *   - lifecycle validation
 *   - audit
 *   - pagination
 *
 * This page deliberately does NOT:
 *   - calculate KPI values
 *   - calculate total pages
 *   - hardcode users
 *   - hardcode dynamic filter options
 *   - expose Priority
 *   - expose Ownership Group
 *   - expose Delete / Archive
 *   - expose an Apply Filters button
 *
 * Final RBAC
 * ---------
 * ADMIN
 * SECURITY_ANALYST
 * SOC_ANALYST
 * INVESTIGATOR
 *   -> View + Manage
 *
 * VIEWER
 *   -> View only
 *
 * ========================================================================== */

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import "../Incidents.css";

import { Panel } from "../../../components/ui/Panel";
import { useAuthStore } from "../../../store/auth";

import { usersApi } from "../../users/api";
import type { User } from "../../users/types";

import { incidentsApi } from "../api";
import { IncidentTable } from "../components/IncidentTable";
import {
  INCIDENTS_MANAGE,
} from "../permissions";

import type {
  Incident,
  IncidentAssignee,
  IncidentCreateRequest,
  IncidentDetail,
  IncidentFilterOptions,
  IncidentRelatedAlert,
  IncidentSeverity,
  IncidentStatus,
  IncidentUpdateRequest,
} from "../types";

/* ============================================================================
 * Constants
 * ========================================================================== */

const INITIAL_PAGE = 1;
const PAGE_SIZE = 30;
const SEARCH_DEBOUNCE_MS = 350;

/* ============================================================================
 * Filter State
 * ========================================================================== */

interface FilterState {
  search: string;
  severity: "" | IncidentSeverity;
  status: "" | IncidentStatus;
  assignee: string;
}

const DEFAULT_FILTERS: FilterState = {
  search: "",
  severity: "",
  status: "",
  assignee: "",
};

/* ============================================================================
 * Empty Backend State
 * ========================================================================== */

const EMPTY_FILTER_OPTIONS: IncidentFilterOptions = {
  statuses: [],
  severities: [],
  assignees: [],
};

/* ============================================================================
 * Create Form
 * ========================================================================== */

interface CreateFormState {
  title: string;
  description: string;
  severity: "" | IncidentSeverity;
  assigned_to: string;
}

/* ============================================================================
 * Edit Form
 * ========================================================================== */

interface EditFormState {
  title: string;
  description: string;
  severity: "" | IncidentSeverity;
  status: "" | IncidentStatus;
  assigned_to: string;
}

/* ============================================================================
 * Helpers
 * ========================================================================== */

function formatLabel(
  value: string | null | undefined,
): string {
  if (!value) {
    return "";
  }

  return value
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (character) =>
      character.toUpperCase(),
    );
}

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

function getErrorMessage(
  error: unknown,
  fallback: string,
): string {
  if (error instanceof Error && error.message.trim()) {
    return error.message;
  }

  if (
    typeof error === "object" &&
    error !== null
  ) {
    const candidate =
      error as Record<string, unknown>;

    if (
      typeof candidate.message === "string" &&
      candidate.message.trim()
    ) {
      return candidate.message;
    }

    if (
      typeof candidate.detail === "string" &&
      candidate.detail.trim()
    ) {
      return candidate.detail;
    }
  }

  return fallback;
}

/* ============================================================================
 * User → IncidentAssignee
 * ========================================================================== */

function userToAssignee(
  user: User,
): IncidentAssignee | null {
  const userId =
    typeof user.user_id === "string"
      ? user.user_id.trim()
      : "";

  if (!userId) {
    return null;
  }

  const displayName =
    typeof user.display_name === "string"
      ? user.display_name.trim()
      : "";

  const username =
    typeof user.username === "string"
      ? user.username.trim()
      : "";

  const roles = Array.isArray(user.roles)
    ? user.roles
    : [];

  return {
    user_id: userId,
    display_name:
      displayName ||
      username ||
      userId,
    username:
      username || undefined,
    roles,
    is_active:
      typeof user.is_active === "boolean"
        ? user.is_active
        : undefined,
    is_locked:
      typeof user.is_locked === "boolean"
        ? user.is_locked
        : undefined,
  };
}

function normalizeIncidentAssignee(
  value: unknown,
): IncidentAssignee | null {
  if (
    !value ||
    typeof value !== "object"
  ) {
    return null;
  }

  const candidate =
    value as Record<string, unknown>;

  const userId =
    typeof candidate.user_id === "string"
      ? candidate.user_id.trim()
      : "";

  if (!userId) {
    return null;
  }

  const displayName =
    typeof candidate.display_name === "string"
      ? candidate.display_name.trim()
      : "";

  const username =
    typeof candidate.username === "string"
      ? candidate.username.trim()
      : "";

  const roles = Array.isArray(candidate.roles)
    ? candidate.roles
        .filter(
          (role) =>
            typeof role === "string" &&
            role.trim().length > 0,
        )
        .map(
          (role) =>
            role as User["roles"][number],
        )
    : [];

  return {
    user_id: userId,
    display_name:
      displayName ||
      username ||
      userId,
    username:
      username || undefined,
    roles,
    is_active:
      typeof candidate.is_active === "boolean"
        ? candidate.is_active
        : undefined,
    is_locked:
      typeof candidate.is_locked === "boolean"
        ? candidate.is_locked
        : undefined,
  };
}

function getAssigneeName(
  assignee:
    | IncidentAssignee
    | null
    | undefined,
): string {
  if (!assignee) {
    return "Unassigned";
  }

  return (
    assignee.display_name ||
    assignee.username ||
    assignee.user_id
  );
}

function getAssigneeRole(
  assignee:
    | IncidentAssignee
    | null
    | undefined,
): string {
  return assignee?.roles?.[0] ?? "";
}

/* ============================================================================
 * Component
 * ========================================================================== */

export default function Incidents() {
  /* ==========================================================================
   * RBAC
   * ======================================================================== */

  const hasPermission = useAuthStore(
    (state) => state.hasPermission,
  );

  const canManage = hasPermission(
    INCIDENTS_MANAGE,
  );

  /* ==========================================================================
   * List
   * ======================================================================== */

  const [incidents, setIncidents] =
    useState<Incident[]>([]);

  const [page, setPage] =
    useState(INITIAL_PAGE);

  const [pageSize] =
    useState(PAGE_SIZE);

  const [total, setTotal] =
    useState(0);

  const [totalPages, setTotalPages] =
    useState(0);

  const [loading, setLoading] =
    useState(true);

  const [refreshing, setRefreshing] =
    useState(false);

  const [error, setError] =
    useState<string | null>(null);

  /* ==========================================================================
   * Backend Statistics
   * ======================================================================== */

  const [statistics, setStatistics] =
    useState({
      total: 0,
      open: 0,
      investigating: 0,
      critical: 0,
      high: 0,
      resolved: 0,
    });

  /* ==========================================================================
   * Backend Filter Options
   * ======================================================================== */

  const [filterOptions, setFilterOptions] =
    useState<IncidentFilterOptions>(
      EMPTY_FILTER_OPTIONS,
    );

  const [
    filterOptionsLoading,
    setFilterOptionsLoading,
  ] = useState(true);

  const [
    filterOptionsError,
    setFilterOptionsError,
  ] = useState<string | null>(null);

  /* ==========================================================================
   * Backend User Directory
   * ======================================================================== */

  const [directoryUsers, setDirectoryUsers] =
    useState<IncidentAssignee[]>([]);

  const [directoryLoading, setDirectoryLoading] =
    useState(false);

  const [directoryError, setDirectoryError] =
    useState<string | null>(null);

  /* ==========================================================================
   * Filters
   * ======================================================================== */

  const [filters, setFilters] =
    useState<FilterState>(
      DEFAULT_FILTERS,
    );

  /* ==========================================================================
   * View Drawer
   * ======================================================================== */

  const [
    selectedIncidentId,
    setSelectedIncidentId,
  ] = useState<string | null>(null);

  const [
    selectedIncident,
    setSelectedIncident,
  ] = useState<IncidentDetail | null>(
    null,
  );

  const [
    detailsLoading,
    setDetailsLoading,
  ] = useState(false);

  const [
    detailsError,
    setDetailsError,
  ] = useState<string | null>(null);

  /* ==========================================================================
   * Related Alerts Drawer
   * ======================================================================== */

  const [
    relatedAlertsOpen,
    setRelatedAlertsOpen,
  ] = useState(false);

  const [
    relatedAlertsIncident,
    setRelatedAlertsIncident,
  ] = useState<Incident | null>(null);

  const [
    relatedAlerts,
    setRelatedAlerts,
  ] = useState<IncidentRelatedAlert[]>(
    [],
  );

  const [
    relatedAlertsLoading,
    setRelatedAlertsLoading,
  ] = useState(false);

  const [
    relatedAlertsError,
    setRelatedAlertsError,
  ] = useState<string | null>(null);

  /* ==========================================================================
   * Create Drawer
   * ======================================================================== */

  const [showCreate, setShowCreate] =
    useState(false);

  const [creating, setCreating] =
    useState(false);

  const [createError, setCreateError] =
    useState<string | null>(null);

  const [createRole, setCreateRole] =
    useState("");

  const [createForm, setCreateForm] =
    useState<CreateFormState>({
      title: "",
      description: "",
      severity: "",
      assigned_to: "",
    });

  /* ==========================================================================
   * Edit Drawer
   * ======================================================================== */

  const [showEdit, setShowEdit] =
    useState(false);

  const [editing, setEditing] =
    useState(false);

  const [editError, setEditError] =
    useState<string | null>(null);

  const [editRole, setEditRole] =
    useState("");

  const [editForm, setEditForm] =
    useState<EditFormState>({
      title: "",
      description: "",
      severity: "",
      status: "",
      assigned_to: "",
    });

  /* ==========================================================================
   * Request Lifecycle
   * ======================================================================== */

  const mountedRef =
    useRef(true);

  const searchDebounceRef =
    useRef<ReturnType<typeof setTimeout> | null>(
      null,
    );

  const requestIdRef =
    useRef(0);

  const firstFilterRenderRef =
    useRef(true);

  useEffect(() => {
    mountedRef.current = true;

    return () => {
      mountedRef.current = false;

      if (
        searchDebounceRef.current !== null
      ) {
        clearTimeout(
          searchDebounceRef.current,
        );

        searchDebounceRef.current = null;
      }
    };
  }, []);

  /* ==========================================================================
   * Load Statistics
   * ======================================================================== */

  const loadStatistics =
    useCallback(
      async (): Promise<void> => {
        try {
          const response =
            await incidentsApi.statistics();

          if (!mountedRef.current) {
            return;
          }

          setStatistics({
            total: response.total,
            open: response.open,
            investigating:
              response.investigating,
            critical:
              response.critical,
            high:
              response.high,
            resolved:
              response.resolved,
          });
        } catch {
          /*
           * Statistics failure must not
           * prevent the incident queue from
           * rendering.
           */
        }
      },
      [],
    );

  /* ==========================================================================
   * Load Filter Options
   * ======================================================================== */

  const loadFilterOptions =
    useCallback(
      async (): Promise<void> => {
        setFilterOptionsLoading(true);
        setFilterOptionsError(null);

        try {
          const response =
            await incidentsApi.filterOptions();

          if (!mountedRef.current) {
            return;
          }

          const statuses =
            Array.isArray(response.statuses)
              ? response.statuses
              : [];

          const severities =
            Array.isArray(response.severities)
              ? response.severities
              : [];

          /*
           * Backend filter-options may return assignee UUID strings,
           * while the frontend state expects hydrated IncidentAssignee
           * objects.
           *
           * Preserve UUIDs here as lightweight assignee records.
           * The User Management directory is the authoritative source
           * for display_name / roles / active / locked state.
           */
          const assignees: IncidentAssignee[] =
            Array.isArray(response.assignees)
              ? response.assignees
                  .map((value) => {
                    const raw = value as unknown;

                    if (typeof raw === "string") {
                      const userId = raw.trim();

                      if (!userId) {
                        return null;
                      }

                      return {
                        user_id: userId,
                        display_name: userId,
                        username: undefined,
                        roles: [],
                        is_active: true,
                        is_locked: false,
                      } satisfies IncidentAssignee;
                    }

                    return normalizeIncidentAssignee(
                      raw,
                    );
                  })
                  .filter(
                    (
                      item,
                    ): item is IncidentAssignee =>
                      item !== null,
                  )
              : [];

          setFilterOptions({
            statuses,
            severities,
            assignees,
          });
        } catch (
          errorValue: unknown
        ) {
          if (!mountedRef.current) {
            return;
          }

          setFilterOptions(
            EMPTY_FILTER_OPTIONS,
          );

          setFilterOptionsError(
            getErrorMessage(
              errorValue,
              "Failed to load incident filter options.",
            ),
          );
        } finally {
          if (mountedRef.current) {
            setFilterOptionsLoading(false);
          }
        }
      },
      [],
    );

  /* ==========================================================================
   * Load User Directory
   *
   * IMPORTANT
   * ---------
   * This uses the feature-level User Management
   * API. No named usersApi is imported from services/api.
   * ======================================================================== */

  const loadDirectory =
    useCallback(
      async (): Promise<void> => {
        if (!canManage) {
          setDirectoryUsers([]);
          setDirectoryError(null);
          return;
        }

        setDirectoryLoading(true);
        setDirectoryError(null);

        try {
          /*
           * User Management is the authoritative source.
           *
           * Fetch the complete paginated directory.
           */
          const pageSize = 200;

          const firstResponse =
            await usersApi.list({
              limit: pageSize,
              offset: 0,
            });

          if (!mountedRef.current) {
            return;
          }

          const firstUsers =
            Array.isArray(firstResponse.users)
              ? firstResponse.users
              : [];

          const total =
            typeof firstResponse.total === "number"
              ? firstResponse.total
              : firstUsers.length;

          const totalPages =
            typeof firstResponse.total_pages === "number" &&
            firstResponse.total_pages > 0
              ? firstResponse.total_pages
              : Math.max(
                  1,
                  Math.ceil(total / pageSize),
                );

          const allUsers: User[] = [
            ...firstUsers,
          ];

          let offset = firstUsers.length;

          for (
            let page = 2;
            page <= totalPages;
            page += 1
          ) {
            const response =
              await usersApi.list({
                limit: pageSize,
                offset,
              });

            if (!mountedRef.current) {
              return;
            }

            const users =
              Array.isArray(response.users)
                ? response.users
                : [];

            if (users.length === 0) {
              break;
            }

            allUsers.push(...users);
            offset += users.length;
          }

          /*
           * Deduplicate by canonical User Management UUID.
           */
          const uniqueUsers =
            Array.from(
              new Map(
                allUsers
                  .filter(
                    (user) =>
                      Boolean(user?.user_id),
                  )
                  .map((user) => [
                    String(user.user_id),
                    user,
                  ]),
              ).values(),
            );

          /*
           * Convert every User Management record first.
           * Do not silently lose users because of role handling here.
           */
          const convertedUsers =
            uniqueUsers
              .map(userToAssignee)
              .filter(
                (
                  item,
                ): item is IncidentAssignee =>
                  item !== null,
              );

          /*
           * Only Active + Unlocked users are eligible
           * for Incident assignment.
           */
          const eligibleUsers =
            convertedUsers.filter(
              (user) =>
                user.is_active !== false &&
                user.is_locked !== true,
            );

          if (import.meta.env.DEV) {
            console.debug(
              "[Incidents] User Management directory:",
              {
                totalFromBackend: total,
                totalPages,
                fetchedUsers: allUsers.length,
                uniqueUsers: uniqueUsers.length,
                convertedUsers:
                  convertedUsers.length,
                activeUnlockedUsers:
                  eligibleUsers.length,
              },
            );

            console.debug(
              "[Incidents] Users excluded from assignment:",
              convertedUsers
                .filter(
                  (user) =>
                    user.is_active === false ||
                    user.is_locked === true,
                )
                .map((user) => ({
                  user_id: user.user_id,
                  display_name:
                    user.display_name,
                  roles: user.roles,
                  is_active:
                    user.is_active,
                  is_locked:
                    user.is_locked,
                })),
            );
          }

          if (!mountedRef.current) {
            return;
          }

          setDirectoryUsers(
            eligibleUsers,
          );
          setDirectoryError(null);
        } catch (
          errorValue: unknown
        ) {
          if (!mountedRef.current) {
            return;
          }

          setDirectoryUsers([]);

          setDirectoryError(
            getErrorMessage(
              errorValue,
              "Failed to load user directory.",
            ),
          );
        } finally {
          if (mountedRef.current) {
            setDirectoryLoading(false);
          }
        }
      },
      [canManage],
    );


  const assignedUserIds = useMemo(() => {
    const ids = new Set<string>();

    for (const value of filterOptions.assignees) {
      if (typeof value === "string") {
        const userId = String(value).trim();

        if (userId) {
          ids.add(userId);
        }

        continue;
      }

      const normalized = normalizeIncidentAssignee(value);

      if (normalized?.user_id) {
        ids.add(normalized.user_id);
      }
    }

    return ids;
  }, [filterOptions.assignees]);

  /*
   * Assignee FILTER:
   * Only users actually assigned to incidents.
   * Name/role comes from User Management.
   */
  const allAssignees = useMemo(() => {
    const map = new Map<string, IncidentAssignee>();

    for (const user of directoryUsers) {
      if (!user.user_id) {
        continue;
      }

      if (
        user.is_active === false ||
        user.is_locked === true
      ) {
        continue;
      }

      if (
        user.roles.some(
          (role) =>
            String(role).trim().toUpperCase() === "VIEWER",
        )
      ) {
        continue;
      }

      if (assignedUserIds.has(user.user_id)) {
        map.set(user.user_id, user);
      }
    }

    /*
     * Compatibility fallback for hydrated backend assignees.
     */
    for (const value of filterOptions.assignees) {
      const normalized = normalizeIncidentAssignee(value);

      if (
        normalized?.user_id &&
        !map.has(normalized.user_id) &&
        !normalized.roles.some(
          (role) =>
            String(role).trim().toUpperCase() === "VIEWER",
        )
      ) {
        map.set(normalized.user_id, normalized);
      }
    }

    return Array.from(map.values()).sort(
      (first, second) =>
        getAssigneeName(first).localeCompare(
          getAssigneeName(second),
        ),
    );
  }, [
    assignedUserIds,
    directoryUsers,
    filterOptions.assignees,
  ]);

  /* ==========================================================================
   * Backend Roles
   *
   * Create/Edit roles come from User Management.
   * VIEWER is excluded as an assignee role.
   * ======================================================================== */

  const availableRoles = useMemo<string[]>(() => {
    const roles = new Map<string, string>();

    for (const user of directoryUsers) {
      if (
        user.is_active === false ||
        user.is_locked === true
      ) {
        continue;
      }

      for (const role of user.roles) {
        const normalizedRole = String(role).trim();

        if (!normalizedRole) {
          continue;
        }

        if (
          normalizedRole.toUpperCase() === "VIEWER"
        ) {
          continue;
        }

        const key = normalizedRole.toUpperCase();

        if (!roles.has(key)) {
          roles.set(key, normalizedRole);
        }
      }
    }

    return Array.from(roles.values()).sort(
      (first, second) =>
        first.localeCompare(second),
    );
  }, [directoryUsers]);

  /* ==========================================================================
   * Role → User
   * ======================================================================== */

  const createAssigneeOptions = useMemo(() => {
    if (!createRole) {
      return [];
    }

    const selectedRole =
      createRole.trim().toUpperCase();

    return directoryUsers
      .filter(
        (user) =>
          user.is_active !== false &&
          user.is_locked !== true &&
          !user.roles.some(
            (role) =>
              String(role).trim().toUpperCase() === "VIEWER",
          ) &&
          user.roles.some(
            (role) =>
              String(role).trim().toUpperCase() ===
              selectedRole,
          ),
      )
      .sort(
        (first, second) =>
          getAssigneeName(first).localeCompare(
            getAssigneeName(second),
          ),
      );
  }, [
    directoryUsers,
    createRole,
  ]);

  const editAssigneeOptions = useMemo(() => {
    if (!editRole) {
      return [];
    }

    const selectedRole =
      editRole.trim().toUpperCase();

    return directoryUsers
      .filter(
        (user) =>
          user.is_active !== false &&
          user.is_locked !== true &&
          !user.roles.some(
            (role) =>
              String(role).trim().toUpperCase() === "VIEWER",
          ) &&
          user.roles.some(
            (role) =>
              String(role).trim().toUpperCase() ===
              selectedRole,
          ),
      )
      .sort(
        (first, second) =>
          getAssigneeName(first).localeCompare(
            getAssigneeName(second),
          ),
      );
  }, [
    directoryUsers,
    editRole,
  ]);

  /* ==========================================================================
   * Load Incidents
   * ======================================================================== */

  const loadIncidents =
    useCallback(
      async (
        currentFilters: FilterState,
        currentPage: number,
        showSpinner = true,
      ): Promise<void> => {
        const requestId =
          ++requestIdRef.current;

        if (showSpinner) {
          setLoading(true);
        } else {
          setRefreshing(true);
        }

        setError(null);

        try {
          const response =
            await incidentsApi.listWithFilters(
              {
                query:
                  currentFilters.search.trim() ||
                  undefined,

                severity:
                  currentFilters.severity ||
                  undefined,

                status:
                  currentFilters.status ||
                  undefined,

                assigned_to:
                  currentFilters.assignee.trim() ||
                  undefined,

                page: currentPage,

                page_size: pageSize,
              },
            );

          if (
            !mountedRef.current ||
            requestId !==
              requestIdRef.current
          ) {
            return;
          }

          setIncidents(
            Array.isArray(
              response.items,
            )
              ? response.items
              : [],
          );

          setTotal(
            response.pagination?.total ??
              0,
          );

          /*
           * Backend is authoritative.
           * Frontend does not calculate this.
           */
          setPage(
            response.pagination?.page ??
              currentPage,
          );

          setTotalPages(
            response.pagination
              ?.total_pages ?? 0,
          );
        } catch (
          errorValue: unknown
        ) {
          if (
            !mountedRef.current ||
            requestId !==
              requestIdRef.current
          ) {
            return;
          }

          setIncidents([]);
          setTotal(0);
          setTotalPages(0);

          setError(
            getErrorMessage(
              errorValue,
              "Failed to load incidents.",
            ),
          );
        } finally {
          if (
            mountedRef.current &&
            requestId ===
              requestIdRef.current
          ) {
            setLoading(false);
            setRefreshing(false);
          }
        }
      },
      [pageSize],
    );

  /* ==========================================================================
   * Initial Load
   * ======================================================================== */

  useEffect(() => {
    void loadIncidents(
      DEFAULT_FILTERS,
      INITIAL_PAGE,
      true,
    );

    void loadStatistics();
    void loadFilterOptions();
  }, [
    loadIncidents,
    loadStatistics,
    loadFilterOptions,
  ]);

  /* ==========================================================================
   * User Directory Load
   * ======================================================================== */

  useEffect(() => {
    void loadDirectory();
  }, [loadDirectory]);

  /* ==========================================================================
   * Auto Apply Filters
   *
   * Search is debounced.
   * Select fields apply immediately.
   * ======================================================================== */

  useEffect(() => {
    if (
      firstFilterRenderRef.current
    ) {
      firstFilterRenderRef.current =
        false;

      return;
    }

    if (
      searchDebounceRef.current !== null
    ) {
      clearTimeout(
        searchDebounceRef.current,
      );

      searchDebounceRef.current =
        null;
    }

    const currentFilters = {
      ...filters,
    };

    const hasSearch =
      currentFilters.search.trim()
        .length > 0;

    if (hasSearch) {
      searchDebounceRef.current =
        setTimeout(() => {
          void loadIncidents(
            currentFilters,
            INITIAL_PAGE,
            true,
          );
        }, SEARCH_DEBOUNCE_MS);

      return () => {
        if (
          searchDebounceRef.current !== null
        ) {
          clearTimeout(
            searchDebounceRef.current,
          );

          searchDebounceRef.current =
            null;
        }
      };
    }

    void loadIncidents(
      currentFilters,
      INITIAL_PAGE,
      true,
    );

    return undefined;
  }, [
    filters.search,
    filters.severity,
    filters.status,
    filters.assignee,
    loadIncidents,
  ]);

  /* ==========================================================================
   * Refresh
   * ======================================================================== */

  const handleRefresh =
    useCallback(
      async (): Promise<void> => {
        await Promise.all([
          loadIncidents(
            filters,
            page,
            false,
          ),
          loadStatistics(),
          loadFilterOptions(),
          loadDirectory(),
        ]);
      },
      [
        filters,
        page,
        loadIncidents,
        loadStatistics,
        loadFilterOptions,
        loadDirectory,
      ],
    );

  /* ==========================================================================
   * Reset Filters
   * ======================================================================== */

  /*
   * Viewer cannot use the Assignee filter.
   * Clear any stale value if permissions change.
   */
  useEffect(() => {
    if (!canManage && filters.assignee) {
      setFilters((current) => ({
        ...current,
        assignee: "",
      }));
    }
  }, [canManage, filters.assignee]);

  const handleResetFilters =
    useCallback((): void => {
      if (
        searchDebounceRef.current !== null
      ) {
        clearTimeout(
          searchDebounceRef.current,
        );

        searchDebounceRef.current =
          null;
      }

      setPage(INITIAL_PAGE);
      setFilters({
        ...DEFAULT_FILTERS,
      });
    }, []);

  /* ==========================================================================
   * View Incident
   * ======================================================================== */

  const openDetails =
    useCallback(
      async (
        incidentId: string,
      ): Promise<void> => {
        if (!incidentId.trim()) {
          return;
        }

        setSelectedIncidentId(
          incidentId,
        );

        setSelectedIncident(null);
        setDetailsError(null);
        setDetailsLoading(true);

        try {
          const detail =
            await incidentsApi.getDetail(
              incidentId,
            );

          if (!mountedRef.current) {
            return;
          }

          setSelectedIncident(
            detail,
          );
        } catch (
          errorValue: unknown
        ) {
          if (!mountedRef.current) {
            return;
          }

          setDetailsError(
            getErrorMessage(
              errorValue,
              "Failed to load incident details.",
            ),
          );
        } finally {
          if (mountedRef.current) {
            setDetailsLoading(false);
          }
        }
      },
      [],
    );

  const handleView =
    useCallback(
      (incident: Incident): void => {
        void openDetails(
          incident.incident_id,
        );
      },
      [openDetails],
    );

  const closeDetails =
    useCallback((): void => {
      if (showEdit) {
        return;
      }

      setSelectedIncidentId(null);
      setSelectedIncident(null);
      setDetailsError(null);
    }, [showEdit]);

  /* ==========================================================================
   * Related Alerts
   * ======================================================================== */

  const openRelatedAlerts =
    useCallback(
      async (
        incident: Incident,
      ): Promise<void> => {
        if (!incident.incident_id) {
          return;
        }

        setRelatedAlertsIncident(
          incident,
        );

        setRelatedAlertsOpen(true);
        setRelatedAlerts([]);
        setRelatedAlertsError(null);
        setRelatedAlertsLoading(true);

        try {
          const response =
            await incidentsApi.getRelatedAlerts(
              incident.incident_id,
            );

          if (!mountedRef.current) {
            return;
          }

          setRelatedAlerts(
            Array.isArray(response)
              ? response
              : [],
          );
        } catch (
          errorValue: unknown
        ) {
          if (!mountedRef.current) {
            return;
          }

          setRelatedAlertsError(
            getErrorMessage(
              errorValue,
              "Failed to load related alerts.",
            ),
          );
        } finally {
          if (mountedRef.current) {
            setRelatedAlertsLoading(
              false,
            );
          }
        }
      },
      [],
    );

  const handleRelatedAlerts =
    useCallback(
      (incident: Incident): void => {
        void openRelatedAlerts(
          incident,
        );
      },
      [openRelatedAlerts],
    );

  const closeRelatedAlerts =
    useCallback((): void => {
      setRelatedAlertsOpen(false);
      setRelatedAlerts([]);
      setRelatedAlertsError(null);
      setRelatedAlertsIncident(null);
    }, []);

  /* ==========================================================================
   * Create
   * ======================================================================== */

  const openCreate =
    useCallback((): void => {
      if (!canManage) {
        return;
      }

      setCreateError(null);
      setCreateRole("");

      setCreateForm({
        title: "",
        description: "",
        severity: "",
        assigned_to: "",
      });

      setShowCreate(true);
    }, [canManage]);

  const closeCreate =
    useCallback((): void => {
      if (creating) {
        return;
      }

      setShowCreate(false);
      setCreateError(null);
    }, [creating]);

  const handleCreate =
    useCallback(
      async (): Promise<void> => {
        if (!canManage) {
          return;
        }

        const title =
          createForm.title.trim();

        const description =
          createForm.description.trim();

        if (!title) {
          setCreateError(
            "Incident title is required.",
          );
          return;
        }

        if (!description) {
          setCreateError(
            "Incident description is required.",
          );
          return;
        }

        if (!createForm.severity) {
          setCreateError(
            "Incident severity is required.",
          );
          return;
        }

        const assignedTo =
          createForm.assigned_to.trim();

        if (assignedTo) {
          const selectedAssignee =
            createAssigneeOptions.find(
              (user) =>
                user.user_id ===
                assignedTo,
            );

          if (!selectedAssignee) {
            setCreateError(
              "Selected assignee is not available for the selected role.",
            );
            return;
          }
        }

        try {
          setCreating(true);
          setCreateError(null);

          const payload:
            IncidentCreateRequest = {
            title,
            description,
            severity:
              createForm.severity,
            assigned_to:
              assignedTo || null,
          };

          const created =
            await incidentsApi.create(
              payload,
            );

          if (!mountedRef.current) {
            return;
          }

          setShowCreate(false);

          await Promise.all([
            loadIncidents(
              filters,
              page,
              false,
            ),
            loadStatistics(),
            loadFilterOptions(),
            loadDirectory(),
          ]);

          if (created?.incident_id) {
            await openDetails(
              created.incident_id,
            );
          }
        } catch (
          errorValue: unknown
        ) {
          if (!mountedRef.current) {
            return;
          }

          setCreateError(
            getErrorMessage(
              errorValue,
              "Failed to create incident.",
            ),
          );
        } finally {
          if (mountedRef.current) {
            setCreating(false);
          }
        }
      },
      [
        canManage,
        createForm,
        createAssigneeOptions,
        filters,
        page,
        loadIncidents,
        loadStatistics,
        loadFilterOptions,
        loadDirectory,
        openDetails,
      ],
    );

  /* ==========================================================================
   * Edit
   * ======================================================================== */

  const openEdit =
    useCallback(
      (incident: IncidentDetail): void => {
        if (!canManage) {
          return;
        }

        const assignedUser =
          directoryUsers.find(
            (user) =>
              user.user_id ===
              incident.assigned_to,
          );

        const assignedRole =
          assignedUser?.roles?.find(
            (role) =>
              String(role).toUpperCase() !== "VIEWER",
          ) ?? "";

        setEditRole(assignedRole);

        setEditForm({
          title:
            incident.title ?? "",
          description:
            incident.description ?? "",
          severity:
            incident.severity,
          status:
            incident.status,
          assigned_to:
            incident.assigned_to ??
            "",
        });

        setEditError(null);
        setShowEdit(true);
      },
      [
        canManage,
        directoryUsers,
      ],
    );

  const handleEditFromTable =
    useCallback(
      async (
        incident: Incident,
      ): Promise<void> => {
        if (!canManage) {
          return;
        }

        try {
          const detail =
            await incidentsApi.getDetail(
              incident.incident_id,
            );

          if (!mountedRef.current) {
            return;
          }

          setSelectedIncident(
            detail,
          );

          setSelectedIncidentId(
            detail.incident_id,
          );

          openEdit(detail);
        } catch (
          errorValue: unknown
        ) {
          if (!mountedRef.current) {
            return;
          }

          setDetailsError(
            getErrorMessage(
              errorValue,
              "Failed to load incident before editing.",
            ),
          );
        }
      },
      [
        canManage,
        openEdit,
      ],
    );

  const closeEdit =
    useCallback((): void => {
      if (editing) {
        return;
      }

      setShowEdit(false);
      setEditError(null);
    }, [editing]);

  const handleEdit =
    useCallback(
      async (): Promise<void> => {
        if (
          !canManage ||
          !selectedIncident
        ) {
          return;
        }

        const title =
          editForm.title.trim();

        const description =
          editForm.description.trim();

        if (!title) {
          setEditError(
            "Incident title is required.",
          );
          return;
        }

        if (!description) {
          setEditError(
            "Incident description is required.",
          );
          return;
        }

        if (!editForm.severity) {
          setEditError(
            "Incident severity is required.",
          );
          return;
        }

        if (!editForm.status) {
          setEditError(
            "Incident status is required.",
          );
          return;
        }

        const assignedTo =
          editForm.assigned_to.trim();

        if (assignedTo) {
          const selectedAssignee =
            editAssigneeOptions.find(
              (user) =>
                user.user_id ===
                assignedTo,
            );

          if (!selectedAssignee) {
            setEditError(
              "Selected assignee is not available for the selected role.",
            );
            return;
          }
        }

        try {
          setEditing(true);
          setEditError(null);

          const payload:
            IncidentUpdateRequest = {
            title,
            description,
            severity:
              editForm.severity,
            status:
              editForm.status,
            assigned_to:
              assignedTo || null,
          };

          const updated =
            await incidentsApi.update(
              selectedIncident.incident_id,
              payload,
            );

          if (!mountedRef.current) {
            return;
          }

          setShowEdit(false);

          setSelectedIncident(
            updated as IncidentDetail,
          );

          await Promise.all([
            loadIncidents(
              filters,
              page,
              false,
            ),
            loadStatistics(),
            loadFilterOptions(),
            loadDirectory(),
          ]);

          await openDetails(
            selectedIncident.incident_id,
          );
        } catch (
          errorValue: unknown
        ) {
          if (!mountedRef.current) {
            return;
          }

          setEditError(
            getErrorMessage(
              errorValue,
              "Failed to update incident.",
            ),
          );
        } finally {
          if (mountedRef.current) {
            setEditing(false);
          }
        }
      },
      [
        canManage,
        selectedIncident,
        editForm,
        editAssigneeOptions,
        filters,
        page,
        loadIncidents,
        loadStatistics,
        loadFilterOptions,
        loadDirectory,
        openDetails,
      ],
    );

  /* ==========================================================================
   * Pagination
   * ======================================================================== */

  const handlePreviousPage =
    useCallback((): void => {
      if (
        loading ||
        page <= 1
      ) {
        return;
      }

      void loadIncidents(
        filters,
        page - 1,
        true,
      );
    }, [
      loading,
      page,
      filters,
      loadIncidents,
    ]);

  const handleNextPage =
    useCallback((): void => {
      if (
        loading ||
        totalPages <= 0 ||
        page >= totalPages
      ) {
        return;
      }

      void loadIncidents(
        filters,
        page + 1,
        true,
      );
    }, [
      loading,
      totalPages,
      page,
      filters,
      loadIncidents,
    ]);

  /* ==========================================================================
   * KPI
   *
   * Direct backend values only.
   * ======================================================================== */

  const kpis = useMemo(
    () => [
      {
        key: "total",
        label: "Total Incidents",
        value: statistics.total,
      },
      {
        key: "open",
        label: "Open",
        value: statistics.open,
      },
      {
        key: "investigating",
        label: "Investigating",
        value:
          statistics.investigating,
      },
      {
        key: "critical",
        label: "Critical",
        value:
          statistics.critical,
      },
      {
        key: "high",
        label: "High",
        value:
          statistics.high,
      },
      {
        key: "resolved",
        label: "Resolved",
        value:
          statistics.resolved,
      },
    ],
    [statistics],
  );

  /* ==========================================================================
   * Render
   * ======================================================================== */

  return (
    <div className="incidents-page">
      {/* =====================================================================
       * Header
       * =================================================================== */}

      <div className="page-heading">
        <div>
          <h2>INCIDENTS</h2>

          <p>
            Security incidents requiring
            investigation and response
          </p>
        </div>

        <div className="page-heading-actions">
          <button
            type="button"
            className="secondary-button"
            onClick={() => {
              void handleRefresh();
            }}
            disabled={
              loading ||
              refreshing
            }
          >
            {refreshing
              ? "Refreshing..."
              : "Refresh"}
          </button>

          {canManage && (
            <button
              type="button"
              className="primary-button"
              onClick={openCreate}
              disabled={
                filterOptionsLoading ||
                filterOptions.severities
                  .length === 0
              }
            >
              Create Incident
            </button>
          )}
        </div>
      </div>

      {/* =====================================================================
       * KPI
       * =================================================================== */}

      <div className="incident-kpi-grid">
        {kpis.map((kpi) => (
          <div
            key={kpi.key}
            className="incident-kpi-card"
          >
            <span className="incident-kpi-label">
              {kpi.label}
            </span>

            <strong className="incident-kpi-value">
              {kpi.value}
            </strong>
          </div>
        ))}
      </div>

      {/* =====================================================================
       * Filters
       * =================================================================== */}

      <Panel
        title="Incident filters"
        subtitle="Filter the incident queue"
      >
        <div className="incident-filters">
          {/* Search */}

          <div className="incident-filter-search">
            <label htmlFor="incident-search">
              Search
            </label>

            <input
              id="incident-search"
              type="search"
              placeholder="Search incidents..."
              value={filters.search}
              onChange={(event) => {
                setPage(
                  INITIAL_PAGE,
                );

                setFilters(
                  (current) => ({
                    ...current,
                    search:
                      event.target.value,
                  }),
                );
              }}
            />
          </div>


          {/* Severity */}

          <div className="incident-filter-field">
            <label htmlFor="incident-severity">
              Severity
            </label>

            <select
              id="incident-severity"
              value={filters.severity}
              disabled={
                filterOptionsLoading
              }
              onChange={(event) => {
                setPage(
                  INITIAL_PAGE,
                );

                setFilters(
                  (current) => ({
                    ...current,
                    severity:
                      event.target
                        .value as
                        | ""
                        | IncidentSeverity,
                  }),
                );
              }}
            >
              <option value="">
                All Severities
              </option>

              {filterOptions.severities.map(
                (severity) => (
                  <option
                    key={severity}
                    value={severity}
                  >
                    {formatLabel(
                      severity,
                    )}
                  </option>
                ),
              )}
            </select>
          </div>

          {/* Status */}

          <div className="incident-filter-field">
            <label htmlFor="incident-status">
              Status
            </label>

            <select
              id="incident-status"
              value={filters.status}
              disabled={
                filterOptionsLoading
              }
              onChange={(event) => {
                setPage(
                  INITIAL_PAGE,
                );

                setFilters(
                  (current) => ({
                    ...current,
                    status:
                      event.target
                        .value as
                        | ""
                        | IncidentStatus,
                  }),
                );
              }}
            >
              <option value="">
                All Statuses
              </option>

              {filterOptions.statuses.map(
                (status) => (
                  <option
                    key={status}
                    value={status}
                  >
                    {formatLabel(status)}
                  </option>
                ),
              )}
            </select>
          </div>

          {/* Assignee — manage roles only */}

          {canManage && (
            <div className="incident-filter-field">
              <label htmlFor="incident-assignee">
                Assignee
              </label>

              <select
                id="incident-assignee"
                value={filters.assignee}
                disabled={filterOptionsLoading}
                onChange={(event) => {
                  setPage(INITIAL_PAGE);

                  setFilters((current) => ({
                    ...current,
                    assignee: event.target.value,
                  }));
                }}
              >
                <option value="">
                  All Assignees
                </option>

                {allAssignees.map((assignee) => (
                  <option
                    key={assignee.user_id}
                    value={assignee.user_id}
                  >
                    {getAssigneeName(assignee)}
                    {getAssigneeRole(assignee)
                      ? ` — ${getAssigneeRole(assignee)}`
                      : ""}
                  </option>
                ))}
              </select>
            </div>
          )}

        </div>

        {/* Reset Filters */}

        <div className="incident-filter-reset-row">
          <button
            type="button"
            className="secondary-button"
            onClick={
              handleResetFilters
            }
            disabled={
              loading &&
              refreshing
            }
          >
            Reset Filters
          </button>
        </div>

        {filterOptionsError && (
          <div
            className="form-error"
            role="alert"
          >
            {filterOptionsError}
          </div>
        )}

        {canManage &&
          directoryError && (
            <div
              className="form-error"
              role="alert"
            >
              {directoryError}
            </div>
          )}
      </Panel>

      {/* =====================================================================
       * Incident Table
       * =================================================================== */}

      <Panel
        title="Incident queue"
        subtitle={
          error
            ? "Incident data is currently unavailable"
            : "Security incidents"
        }
      >
        {loading && (
          <div
            className="empty-state"
            role="status"
          >
            <p>
              Loading incidents...
            </p>
          </div>
        )}

        {!loading && error && (
          <div
            className="empty-state"
            role="alert"
          >
            <p>{error}</p>

            <button
              type="button"
              className="primary-button"
              onClick={() => {
                void loadIncidents(
                  filters,
                  page,
                  true,
                );

                void loadStatistics();
                void loadFilterOptions();

                if (canManage) {
                  void loadDirectory();
                }
              }}
            >
              Retry
            </button>
          </div>
        )}

        {!loading && !error && (
          <IncidentTable
            incidents={incidents}
            canManage={canManage}
          assignees={directoryUsers}
            onView={handleView}
            onEdit={
              handleEditFromTable
            }
            onRelatedAlerts={
              handleRelatedAlerts
            }
          />
        )}
      </Panel>

      {/* =====================================================================
       * Pagination
       * =================================================================== */}

      {!loading &&
        !error &&
        total > 0 && (
          <div className="incident-pagination">
            <div className="incident-pagination-summary">
              <span>
                {incidents.length > 0
                  ? `${(page - 1) * pageSize + 1}–${Math.min(
                      page * pageSize,
                      total,
                    )}`
                  : "0"}
                {" "}Incidents/Total{" "}
                {total.toLocaleString()}
              </span>

              <span>•</span>

              <span>
                Page {page} of{" "}
                {totalPages}
              </span>
            </div>

            <div className="incident-pagination-actions">
              <button
                type="button"
                className="secondary-button"
                onClick={
                  handlePreviousPage
                }
                disabled={
                  loading ||
                  page <= 1
                }
              >
                Previous
              </button>

              <button
                type="button"
                className="secondary-button"
                onClick={
                  handleNextPage
                }
                disabled={
                  loading ||
                  totalPages <= 0 ||
                  page >= totalPages
                }
              >
                Next
              </button>
            </div>
          </div>
        )}

      {/* =====================================================================
       * Create Incident Drawer
       * =================================================================== */}

      {showCreate &&
        canManage && (
          <div
            className="incident-drawer-overlay"
            role="presentation"
            onMouseDown={(event) => {
              if (
                event.target ===
                event.currentTarget
              ) {
                closeCreate();
              }
            }}
          >
            <aside
              className="incident-details-drawer"
              role="dialog"
              aria-modal="true"
              aria-labelledby="create-incident-title"
            >
              <div className="incident-drawer-header">
                <div>
                  <span className="drawer-eyebrow">
                    INCIDENT
                  </span>

                  <h3 id="create-incident-title">
                    Create Incident
                  </h3>

                  <p>
                    Create a security incident
                    for investigation and
                    response.
                  </p>
                </div>

                <button
                  type="button"
                  className="icon-button"
                  onClick={
                    closeCreate
                  }
                  disabled={creating}
                  aria-label="Close create incident drawer"
                >
                  ×
                </button>
              </div>

              <div className="incident-drawer-body">
                {createError && (
                  <div
                    className="form-error"
                    role="alert"
                  >
                    {createError}
                  </div>
                )}

                <div className="form-field">
                  <label htmlFor="create-title">
                    Title *
                  </label>

                  <input
                    id="create-title"
                    type="text"
                    value={createForm.title}
                    onChange={(event) => {
                      setCreateForm(
                        (current) => ({
                          ...current,
                          title:
                            event.target.value,
                        }),
                      );
                    }}
                    placeholder="Incident title"
                    disabled={creating}
                  />
                </div>

                <div className="form-field">
                  <label htmlFor="create-description">
                    Description *
                  </label>

                  <textarea
                    id="create-description"
                    rows={6}
                    value={
                      createForm.description
                    }
                    onChange={(event) => {
                      setCreateForm(
                        (current) => ({
                          ...current,
                          description:
                            event.target.value,
                        }),
                      );
                    }}
                    placeholder="Describe the incident..."
                    disabled={creating}
                  />
                </div>

                <div className="form-field">
                  <label htmlFor="create-severity">
                    Severity *
                  </label>

                  <select
                    id="create-severity"
                    value={
                      createForm.severity
                    }
                    disabled={
                      creating ||
                      filterOptionsLoading
                    }
                    onChange={(event) => {
                      setCreateForm(
                        (current) => ({
                          ...current,
                          severity:
                            event.target
                              .value as
                              | ""
                              | IncidentSeverity,
                        }),
                      );
                    }}
                  >
                    <option value="">
                      Select Severity
                    </option>

                    {filterOptions.severities.map(
                      (severity) => (
                        <option
                          key={severity}
                          value={severity}
                        >
                          {formatLabel(
                            severity,
                          )}
                        </option>
                      ),
                    )}
                  </select>
                </div>

                <div className="form-field">
                  <label htmlFor="create-assignee-role">
                    Assignee Role
                  </label>

                  <select
                    id="create-assignee-role"
                    value={createRole}
                    disabled={
                      creating ||
                      directoryLoading
                    }
                    onChange={(event) => {
                      setCreateRole(
                        event.target.value,
                      );

                      setCreateForm(
                        (current) => ({
                          ...current,
                          assigned_to: "",
                        }),
                      );
                    }}
                  >
                    <option value="">
                      Select Role
                    </option>

                    {availableRoles.map(
                      (role) => (
                        <option
                          key={role}
                          value={role}
                        >
                          {formatLabel(role)}
                        </option>
                      ),
                    )}
                  </select>
                </div>

                <div className="form-field">
                  <label htmlFor="create-assignee">
                    Assignee
                  </label>

                  <select
                    id="create-assignee"
                    value={
                      createForm.assigned_to
                    }
                    disabled={
                      creating ||
                      directoryLoading ||
                      !createRole
                    }
                    onChange={(event) => {
                      setCreateForm(
                        (current) => ({
                          ...current,
                          assigned_to:
                            event.target.value,
                        }),
                      );
                    }}
                  >
                    <option value="">
                      Unassigned
                    </option>

                    {createAssigneeOptions.map(
                      (assignee) => (
                        <option
                          key={
                            assignee.user_id
                          }
                          value={
                            assignee.user_id
                          }
                        >
                          {getAssigneeName(
                            assignee,
                          )}
                          {getAssigneeRole(
                            assignee,
                          )
                            ? ` — ${getAssigneeRole(
                                assignee,
                              )}`
                            : ""}
                        </option>
                      ),
                    )}
                  </select>
                </div>

                <div className="form-help">
                  Status is assigned by the
                  backend and starts at Open.
                </div>
              </div>

              <div className="incident-modal-footer">
                <button
                  type="button"
                  className="secondary-button"
                  onClick={
                    closeCreate
                  }
                  disabled={creating}
                >
                  Cancel
                </button>

                <button
                  type="button"
                  className="primary-button"
                  onClick={() => {
                    void handleCreate();
                  }}
                  disabled={creating}
                >
                  {creating
                    ? "Creating..."
                    : "Create Incident"}
                </button>
              </div>
            </aside>
          </div>
        )}

      {/* =====================================================================
       * View Incident Drawer
       * =================================================================== */}

      {selectedIncidentId && (
        <div
          className="incident-drawer-overlay"
          role="presentation"
          onMouseDown={(event) => {
            if (
              event.target ===
              event.currentTarget
            ) {
              closeDetails();
            }
          }}
        >
          <aside
            className="incident-details-drawer"
            role="dialog"
            aria-modal="true"
            aria-labelledby="incident-details-title"
          >
            <div className="incident-drawer-header">
              <div>
                <span className="drawer-eyebrow">
                  INCIDENT
                </span>

                <h3 id="incident-details-title">
                  {selectedIncident
                    ?.incident_number ??
                    "Incident Details"}
                </h3>

                {selectedIncident && (
                  <p>
                    {
                      selectedIncident.title
                    }
                  </p>
                )}
              </div>

              <button
                type="button"
                className="icon-button"
                onClick={
                  closeDetails
                }
                aria-label="Close incident details"
              >
                ×
              </button>
            </div>

            <div className="incident-drawer-body">
              {detailsLoading && (
                <div
                  className="empty-state"
                  role="status"
                >
                  <p>
                    Loading incident details...
                  </p>
                </div>
              )}

              {!detailsLoading &&
                detailsError && (
                  <div
                    className="empty-state"
                    role="alert"
                  >
                    <p>
                      {detailsError}
                    </p>

                    <button
                      type="button"
                      className="primary-button"
                      onClick={() => {
                        if (
                          selectedIncidentId
                        ) {
                          void openDetails(
                            selectedIncidentId,
                          );
                        }
                      }}
                    >
                      Retry
                    </button>
                  </div>
                )}

              {!detailsLoading &&
                !detailsError &&
                selectedIncident && (
                  <>
                    <section className="drawer-section">
                      <h4>Overview</h4>

                      <div className="drawer-grid">
                        <div>
                          <span>
                            Incident
                          </span>

                          <strong>
                            {
                              selectedIncident.incident_number
                            }
                          </strong>
                        </div>

                        <div>
                          <span>
                            Title
                          </span>

                          <strong>
                            {
                              selectedIncident.title
                            }
                          </strong>
                        </div>

                        <div>
                          <span>
                            Severity
                          </span>

                          <strong
                            className={`severity-badge severity-${selectedIncident.severity}`}
                          >
                            {formatLabel(
                              selectedIncident.severity,
                            )}
                          </strong>
                        </div>

                        <div>
                          <span>
                            Status
                          </span>

                          <strong
                            className={`status-badge status-${selectedIncident.status}`}
                          >
                            {formatLabel(
                              selectedIncident.status,
                            )}
                          </strong>
                        </div>

                        <div>
                          <span>
                            Assignee
                          </span>

                          {(() => {
                            const user =
                              directoryUsers.find(
                                (item) =>
                                  item.user_id ===
                                  selectedIncident.assigned_to,
                              );

                            return (
                              <>
                                <strong>
                                  {user
                                    ? getAssigneeName(
                                        user,
                                      )
                                    : "Unassigned"}
                                </strong>

                                {user &&
                                  getAssigneeRole(
                                    user,
                                  ) && (
                                    <small>
                                      {getAssigneeRole(
                                        user,
                                      )}
                                    </small>
                                  )}
                              </>
                            );
                          })()}
                        </div>

                        <div>
                          <span>
                            Created By
                          </span>

                          <strong>
                            {
                              selectedIncident.created_by
                            }
                          </strong>
                        </div>

                        <div>
                          <span>
                            Created
                          </span>

                          <strong>
                            {formatDate(
                              selectedIncident.created_at,
                            )}
                          </strong>
                        </div>

                        <div>
                          <span>
                            Updated
                          </span>

                          <strong>
                            {formatDate(
                              selectedIncident.updated_at,
                            )}
                          </strong>
                        </div>
                      </div>
                    </section>

                    <section className="drawer-section">
                      <h4>
                        Description
                      </h4>

                      <p>
                        {selectedIncident.description ||
                          "No description provided."}
                      </p>
                    </section>

                    <section className="drawer-section">
                      <div className="drawer-section-heading">
                        <h4>
                          Related Alerts
                        </h4>

                        <button
                          type="button"
                          className="secondary-button"
                          onClick={() => {
                            void openRelatedAlerts(
                              selectedIncident,
                            );
                          }}
                        >
                          View Alerts
                        </button>
                      </div>

                      <button
                        type="button"
                        className="drawer-related-count"
                        onClick={() => {
                          void openRelatedAlerts(
                            selectedIncident,
                          );
                        }}
                      >
                        {selectedIncident.alert_ids
                          ?.length ?? 0}{" "}
                        related alert
                        {(selectedIncident.alert_ids
                          ?.length ?? 0) ===
                        1
                          ? ""
                          : "s"}
                      </button>
                    </section>

                    <section className="drawer-section">
                      <h4>
                        Timeline
                      </h4>

                      {selectedIncident.timeline
                        ?.length ? (
                        <div className="drawer-timeline">
                          {selectedIncident.timeline.map(
                            (entry) => (
                              <div
                                key={
                                  entry.entry_id
                                }
                                className="timeline-item"
                              >
                                <strong>
                                  {formatLabel(
                                    entry.event_type,
                                  )}
                                </strong>

                                <p>
                                  {
                                    entry.description
                                  }
                                </p>

                                <small>
                                  {entry.actor}
                                  {" · "}
                                  {formatDate(
                                    entry.occurred_at,
                                  )}
                                </small>
                              </div>
                            ),
                          )}
                        </div>
                      ) : (
                        <p>
                          No lifecycle events.
                        </p>
                      )}
                    </section>

                    <section className="drawer-section">
                      <h4>
                        Audit History
                      </h4>

                      {selectedIncident
                        .audit_history
                        ?.length ? (
                        <div className="drawer-list">
                          {selectedIncident.audit_history.map(
                            (entry) => (
                              <div
                                key={
                                  entry.audit_id
                                }
                                className="drawer-list-item"
                              >
                                <strong>
                                  {formatLabel(
                                    entry.action,
                                  )}
                                </strong>

                                <small>
                                  {entry.actor}
                                  {" · "}
                                  {formatDate(
                                    entry.created_at,
                                  )}
                                </small>

                                {entry.field_name && (
                                  <span>
                                    {formatLabel(
                                      entry.field_name,
                                    )}
                                    {": "}
                                    {entry.from_value ??
                                      "—"}
                                    {" → "}
                                    {entry.to_value ??
                                      "—"}
                                  </span>
                                )}
                              </div>
                            ),
                          )}
                        </div>
                      ) : (
                        <p>
                          No audit history.
                        </p>
                      )}
                    </section>

                    {canManage && (
                      <section className="drawer-section">
                        <h4>
                          Actions
                        </h4>

                        <div className="drawer-actions">
                          <button
                            type="button"
                            className="secondary-button"
                            onClick={() => {
                              openEdit(
                                selectedIncident,
                              );
                            }}
                          >
                            Edit Incident
                          </button>
                        </div>
                      </section>
                    )}
                  </>
                )}
            </div>
          </aside>
        </div>
      )}

      {/* =====================================================================
       * Related Alerts Drawer
       * =================================================================== */}

      {relatedAlertsOpen && (
        <div
          className="incident-drawer-overlay"
          role="presentation"
          onMouseDown={(event) => {
            if (
              event.target ===
              event.currentTarget
            ) {
              closeRelatedAlerts();
            }
          }}
        >
          <aside
            className="incident-details-drawer"
            role="dialog"
            aria-modal="true"
            aria-labelledby="related-alerts-title"
          >
            <div className="incident-drawer-header">
              <div>
                <span className="drawer-eyebrow">
                  RELATED ALERTS
                </span>

                <h3 id="related-alerts-title">
                  {relatedAlertsIncident
                    ?.incident_number ??
                    "Incident Alerts"}
                </h3>

                <p>
                  Alerts associated with this
                  incident.
                </p>
              </div>

              <button
                type="button"
                className="icon-button"
                onClick={
                  closeRelatedAlerts
                }
                aria-label="Close related alerts drawer"
              >
                ×
              </button>
            </div>

            <div className="incident-drawer-body">
              {relatedAlertsLoading && (
                <div
                  className="empty-state"
                  role="status"
                >
                  <p>
                    Loading related alerts...
                  </p>
                </div>
              )}

              {!relatedAlertsLoading &&
                relatedAlertsError && (
                  <div
                    className="empty-state"
                    role="alert"
                  >
                    <p>
                      {relatedAlertsError}
                    </p>

                    <button
                      type="button"
                      className="primary-button"
                      onClick={() => {
                        if (
                          relatedAlertsIncident
                        ) {
                          void openRelatedAlerts(
                            relatedAlertsIncident,
                          );
                        }
                      }}
                    >
                      Retry
                    </button>
                  </div>
                )}

              {!relatedAlertsLoading &&
                !relatedAlertsError &&
                relatedAlerts.length ===
                  0 && (
                  <div className="empty-state">
                    <p>
                      No related alerts.
                    </p>
                  </div>
                )}

              {!relatedAlertsLoading &&
                !relatedAlertsError &&
                relatedAlerts.length >
                  0 && (
                  <div className="drawer-list">
                    {relatedAlerts.map(
                      (alert) => (
                        <div
                          key={
                            alert.alert_id
                          }
                          className="drawer-list-item"
                        >
                          <strong>
                            {alert.title}
                          </strong>

                          <span>
                            {formatLabel(
                              alert.severity,
                            )}
                            {" • "}
                            {formatLabel(
                              alert.status,
                            )}
                          </span>

                          {alert.rule_name && (
                            <span>
                              Rule:{" "}
                              {
                                alert.rule_name
                              }
                            </span>
                          )}

                          <small>
                            Last Seen:{" "}
                            {formatDate(
                              alert.last_seen_at,
                            )}
                          </small>
                        </div>
                      ),
                    )}
                  </div>
                )}
            </div>
          </aside>
        </div>
      )}

      {/* =====================================================================
       * Edit Incident Drawer
       * =================================================================== */}

      {showEdit &&
        canManage &&
        selectedIncident && (
          <div
            className="incident-drawer-overlay"
            role="presentation"
            onMouseDown={(event) => {
              if (
                event.target ===
                event.currentTarget
              ) {
                closeEdit();
              }
            }}
          >
            <aside
              className="incident-details-drawer"
              role="dialog"
              aria-modal="true"
              aria-labelledby="edit-incident-title"
            >
              <div className="incident-drawer-header">
                <div>
                  <span className="drawer-eyebrow">
                    INCIDENT
                  </span>

                  <h3 id="edit-incident-title">
                    Edit Incident
                  </h3>

                  <p>
                    {
                      selectedIncident.incident_number
                    }
                  </p>
                </div>

                <button
                  type="button"
                  className="icon-button"
                  onClick={
                    closeEdit
                  }
                  disabled={editing}
                  aria-label="Close edit incident drawer"
                >
                  ×
                </button>
              </div>

              <div className="incident-drawer-body">
                {editError && (
                  <div
                    className="form-error"
                    role="alert"
                  >
                    {editError}
                  </div>
                )}

                <div className="form-field">
                  <label htmlFor="edit-title">
                    Title *
                  </label>

                  <input
                    id="edit-title"
                    type="text"
                    value={editForm.title}
                    onChange={(event) => {
                      setEditForm(
                        (current) => ({
                          ...current,
                          title:
                            event.target.value,
                        }),
                      );
                    }}
                    disabled={editing}
                  />
                </div>

                <div className="form-field">
                  <label htmlFor="edit-description">
                    Description *
                  </label>

                  <textarea
                    id="edit-description"
                    rows={6}
                    value={
                      editForm.description
                    }
                    onChange={(event) => {
                      setEditForm(
                        (current) => ({
                          ...current,
                          description:
                            event.target.value,
                        }),
                      );
                    }}
                    disabled={editing}
                  />
                </div>

                <div className="form-field">
                  <label htmlFor="edit-severity">
                    Severity *
                  </label>

                  <select
                    id="edit-severity"
                    value={
                      editForm.severity
                    }
                    disabled={
                      editing ||
                      filterOptionsLoading
                    }
                    onChange={(event) => {
                      setEditForm(
                        (current) => ({
                          ...current,
                          severity:
                            event.target
                              .value as
                              | ""
                              | IncidentSeverity,
                        }),
                      );
                    }}
                  >
                    <option value="">
                      Select Severity
                    </option>

                    {filterOptions.severities.map(
                      (severity) => (
                        <option
                          key={severity}
                          value={severity}
                        >
                          {formatLabel(
                            severity,
                          )}
                        </option>
                      ),
                    )}
                  </select>
                </div>

                <div className="form-field">
                  <label htmlFor="edit-status">
                    Status *
                  </label>

                  <select
                    id="edit-status"
                    value={
                      editForm.status
                    }
                    disabled={
                      editing ||
                      filterOptionsLoading
                    }
                    onChange={(event) => {
                      setEditForm(
                        (current) => ({
                          ...current,
                          status:
                            event.target
                              .value as
                              | ""
                              | IncidentStatus,
                        }),
                      );
                    }}
                  >
                    <option value="">
                      Select Status
                    </option>

                    {filterOptions.statuses.map(
                      (status) => (
                        <option
                          key={status}
                          value={status}
                        >
                          {formatLabel(
                            status,
                          )}
                        </option>
                      ),
                    )}
                  </select>

                  <div className="form-help">
                    The backend validates
                    lifecycle transitions.
                  </div>
                </div>

                <div className="form-field">
                  <label htmlFor="edit-assignee-role">
                    Assignee Role
                  </label>

                  <select
                    id="edit-assignee-role"
                    value={editRole}
                    disabled={
                      editing ||
                      directoryLoading
                    }
                    onChange={(event) => {
                      setEditRole(
                        event.target.value,
                      );

                      setEditForm(
                        (current) => ({
                          ...current,
                          assigned_to: "",
                        }),
                      );
                    }}
                  >
                    <option value="">
                      Select Role
                    </option>

                    {availableRoles.map(
                      (role) => (
                        <option
                          key={role}
                          value={role}
                        >
                          {formatLabel(role)}
                        </option>
                      ),
                    )}
                  </select>
                </div>

                <div className="form-field">
                  <label htmlFor="edit-assignee">
                    Assignee
                  </label>

                  <select
                    id="edit-assignee"
                    value={
                      editForm.assigned_to
                    }
                    disabled={
                      editing ||
                      directoryLoading ||
                      !editRole
                    }
                    onChange={(event) => {
                      setEditForm(
                        (current) => ({
                          ...current,
                          assigned_to:
                            event.target.value,
                        }),
                      );
                    }}
                  >
                    <option value="">
                      Unassigned
                    </option>

                    {editAssigneeOptions.map(
                      (assignee) => (
                        <option
                          key={
                            assignee.user_id
                          }
                          value={
                            assignee.user_id
                          }
                        >
                          {getAssigneeName(
                            assignee,
                          )}
                          {getAssigneeRole(
                            assignee,
                          )
                            ? ` — ${getAssigneeRole(
                                assignee,
                              )}`
                            : ""}
                        </option>
                      ),
                    )}
                  </select>
                </div>
              </div>

              <div className="incident-modal-footer">
                <button
                  type="button"
                  className="secondary-button"
                  onClick={
                    closeEdit
                  }
                  disabled={editing}
                >
                  Cancel
                </button>

                <button
                  type="button"
                  className="primary-button"
                  onClick={() => {
                    void handleEdit();
                  }}
                  disabled={editing}
                >
                  {editing
                    ? "Saving..."
                    : "Save Changes"}
                </button>
              </div>
            </aside>
          </div>
        )}
    </div>
  );
}
