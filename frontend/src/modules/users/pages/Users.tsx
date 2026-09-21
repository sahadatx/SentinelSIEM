/**
 * ============================================================================
 * SentinelSIEM — Users Page
 * ============================================================================
 *
 * User Management dashboard.
 *
 * Responsibilities
 * ----------------
 * - User list loading
 * - User statistics loading
 * - Search and filtering
 * - Role filtering
 * - Backend-driven pagination
 * - RBAC permission gating
 * - User selection
 * - Create / edit / role / security workflows
 * - User audit workflow
 * - User deletion
 *
 * Delete UX / Security Contract
 * -----------------------------
 * The backend UserManagementService remains the final authority for:
 *
 * - actor validation
 * - active/unlocked ADMIN authorization
 * - self-delete protection
 * - target existence
 * - last active ADMIN protection
 * - session revocation
 * - safe session-revoke failure handling
 * - audit persistence
 * - final deletion authorization
 *
 * The frontend provides contextual UX before the request:
 *
 * - self-delete is blocked immediately with an explanation;
 * - active ADMIN accounts receive an explicit last-ADMIN warning;
 * - normal users receive the standard confirmation;
 * - backend rejection messages are preserved and shown to the operator.
 *
 * No native window.confirm() is used.
 * Delete confirmation is rendered through a portal.
 * Body scrolling is locked while the modal is open.
 */

import {
  useCallback,
  useEffect,
  useState,
} from "react";

import {
  AlertTriangle,
  RefreshCw,
  ShieldAlert,
  Trash2,
  UserPlus,
  UsersRound,
  X,
} from "lucide-react";

import { createPortal } from "react-dom";

import "../Users.css";

import { Panel } from "../../../components/ui/Panel";
import { useAuthStore } from "../../../store/auth";

import {
  USERS_MANAGE,
  USERS_READ,
} from "../permissions";

import { usersApi } from "../api";

import type {
  User,
  UserListParams,
  UserStatistics,
} from "../types";

import CreateUserForm from "../components/CreateUserForm";
import EditUserForm from "../components/EditUserForm";
import UserAuditPanel from "../components/UserAuditPanel";
import UserDetailsPanel from "../components/UserDetailsPanel";
import UserFilters from "../components/UserFilters";

import type {
  ActiveFilter,
  LockedFilter,
  RoleFilter,
} from "../components/UserFilters";

import UserRoleEditor from "../components/UserRoleEditor";
import UserSecurityActions from "../components/UserSecurityActions";
import UserStats from "../components/UserStats";
import UserTable from "../components/UserTable";

/* ============================================================================
 * Constants
 * ========================================================================== */

const DEFAULT_LIMIT = 30;
const SEARCH_DEBOUNCE_MS = 300;

/* ============================================================================
 * Types
 * ========================================================================== */

type UsersView =
  | "details"
  | "edit"
  | "role"
  | "security"
  | "audit"
  | "create";

export type UserSecurityAction =
  | "enable_user"
  | "disable_user"
  | "lock_user"
  | "unlock_user"
  | "reset_password"
  | "force_password_change"
  | "active_sessions"
  | "revoke_sessions";

type DeleteModalMode =
  | "confirmation"
  | "self-delete"
  | "admin-warning";

/* ============================================================================
 * Helpers
 * ========================================================================== */

function getErrorMessage(error: unknown): string {
  if (
    error &&
    typeof error === "object" &&
    "detail" in error &&
    typeof error.detail === "string"
  ) {
    return error.detail;
  }

  if (error instanceof Error) {
    return error.message;
  }

  return "Unable to complete the user management operation.";
}

function buildUserListParams(
  search: string,
  activeFilter: ActiveFilter,
  lockedFilter: LockedFilter,
  roleFilter: RoleFilter,
  limit: number,
  offset: number,
): UserListParams {
  const params: UserListParams = {
    limit,
    offset,
  };

  const normalizedSearch = search.trim();

  if (normalizedSearch) {
    params.search = normalizedSearch;
  }

  if (activeFilter === "active") {
    params.is_active = true;
  }

  if (activeFilter === "disabled") {
    params.is_active = false;
  }

  if (lockedFilter === "locked") {
    params.is_locked = true;
  }

  if (lockedFilter === "unlocked") {
    params.is_locked = false;
  }

  if (roleFilter) {
    params.role = roleFilter;
  }

  return params;
}

function isAdminUser(user: User): boolean {
  if (!Array.isArray(user.roles)) {
    return false;
  }

  return user.roles.some(
    (role) => String(role).toUpperCase() === "ADMIN",
  );
}

/* ============================================================================
 * Users Page
 * ========================================================================== */

export default function Users() {
  /* ==========================================================================
   * RBAC
   * ======================================================================== */

  const hasPermission = useAuthStore(
    (state) => state.hasPermission,
  );

  /*
   * Keep the current authenticated user ID only for contextual UX.
   *
   * IMPORTANT:
   * This is NOT the final security decision.
   * Backend UserManagementService remains authoritative.
   */
  const currentUserId = useAuthStore(
    (state) => state.user?.user_id ?? null,
  );

  const canReadUsers = hasPermission(USERS_READ);
  const canManageUsers = hasPermission(USERS_MANAGE);

  const canUseSecurityActions = canManageUsers;

  /* ==========================================================================
   * User Data
   * ======================================================================== */

  const [users, setUsers] = useState<User[]>([]);

  const [statistics, setStatistics] =
    useState<UserStatistics>({
      total: 0,
      active: 0,
      disabled: 0,
      locked: 0,
    });

  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(0);

  /* ==========================================================================
   * Filters
   * ======================================================================== */

  const [search, setSearch] = useState("");
  const [activeFilter, setActiveFilter] =
    useState<ActiveFilter>("");
  const [lockedFilter, setLockedFilter] =
    useState<LockedFilter>("");
  const [roleFilter, setRoleFilter] =
    useState<RoleFilter>("");

  /* ==========================================================================
   * Pagination
   * ======================================================================== */

  const limit = DEFAULT_LIMIT;
  const [offset, setOffset] = useState(0);

  /* ==========================================================================
   * Request State
   * ======================================================================== */

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [deletingUserId, setDeletingUserId] =
    useState<string | null>(null);

  /* ==========================================================================
   * Delete Modal State
   * ======================================================================== */

  const [
    deleteConfirmationUser,
    setDeleteConfirmationUser,
  ] = useState<User | null>(null);

  const [deleteModalMode, setDeleteModalMode] =
    useState<DeleteModalMode>("confirmation");

  /* ==========================================================================
   * Workflow State
   * ======================================================================== */

  const [selectedUser, setSelectedUser] =
    useState<User | null>(null);

  const [activeView, setActiveView] =
    useState<UsersView | null>(null);

  const [securityAction, setSecurityAction] =
    useState<UserSecurityAction | null>(null);

  const selectedUserId =
    selectedUser?.user_id ?? null;

  /* ==========================================================================
   * Load Users
   * ======================================================================== */

  const loadUsers = useCallback(
    async (showRefreshState = false) => {
      if (showRefreshState) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      setError(null);

      try {
        const params = buildUserListParams(
          search,
          activeFilter,
          lockedFilter,
          roleFilter,
          limit,
          offset,
        );

        const [
          userResponse,
          statisticsResponse,
        ] = await Promise.all([
          usersApi.list(params),
          usersApi.statistics(),
        ]);

        const nextUsers = Array.isArray(
          userResponse.users,
        )
          ? userResponse.users
          : [];

        setUsers(nextUsers);
        setTotal(userResponse.total ?? 0);
        setTotalPages(
          userResponse.total_pages ?? 0,
        );
        setStatistics(statisticsResponse);
      } catch (requestError) {
        setUsers([]);
        setTotal(0);
        setTotalPages(0);

        setError(
          getErrorMessage(requestError),
        );
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [
      activeFilter,
      limit,
      lockedFilter,
      offset,
      roleFilter,
      search,
    ],
  );

  /* ==========================================================================
   * Filter / Load Effect
   * ======================================================================== */

  useEffect(() => {
    const delay = search.trim()
      ? SEARCH_DEBOUNCE_MS
      : 0;

    const timer = window.setTimeout(() => {
      void loadUsers(false);
    }, delay);

    return () => {
      window.clearTimeout(timer);
    };
  }, [loadUsers, search]);

  /* ==========================================================================
   * Derived State
   * ======================================================================== */

  const hasFilters =
    Boolean(search.trim()) ||
    activeFilter !== "" ||
    lockedFilter !== "" ||
    roleFilter !== "";

  const pageNumber =
    Math.floor(offset / limit) + 1;

  const firstItem =
    total === 0
      ? 0
      : offset + 1;

  const lastItem =
    total === 0
      ? 0
      : Math.min(
          offset + users.length,
          total,
        );

  const hasPreviousPage = offset > 0;

  const hasNextPage =
    totalPages > 0 &&
    pageNumber < totalPages;

  /* ==========================================================================
   * Drawer Escape
   * ======================================================================== */

  useEffect(() => {
    const drawerOpen =
      activeView === "create" ||
      Boolean(selectedUser && activeView);

    if (!drawerOpen) {
      return;
    }

    function handleEscape(event: KeyboardEvent) {
      if (event.key !== "Escape") {
        return;
      }

      if (deleteConfirmationUser) {
        return;
      }

      if (deletingUserId) {
        return;
      }

      setSelectedUser(null);
      setActiveView(null);
      setSecurityAction(null);
    }

    document.addEventListener(
      "keydown",
      handleEscape,
    );

    return () => {
      document.removeEventListener(
        "keydown",
        handleEscape,
      );
    };
  }, [
    activeView,
    deleteConfirmationUser,
    deletingUserId,
    selectedUser,
  ]);

  /* ==========================================================================
   * Body Scroll Lock
   * ======================================================================== */

  useEffect(() => {
    const drawerOpen =
      activeView === "create" ||
      Boolean(selectedUser && activeView);

    const deleteModalOpen =
      Boolean(deleteConfirmationUser);

    if (!drawerOpen && !deleteModalOpen) {
      return;
    }

    const previousOverflow =
      document.body.style.overflow;

    const previousPaddingRight =
      document.body.style.paddingRight;

    const scrollbarWidth =
      window.innerWidth -
      document.documentElement.clientWidth;

    document.body.style.overflow = "hidden";

    if (scrollbarWidth > 0) {
      document.body.style.paddingRight =
        `${scrollbarWidth}px`;
    }

    return () => {
      document.body.style.overflow =
        previousOverflow;

      document.body.style.paddingRight =
        previousPaddingRight;
    };
  }, [
    activeView,
    deleteConfirmationUser,
    selectedUser,
  ]);

  /* ==========================================================================
   * Delete Modal Escape
   * ======================================================================== */

  useEffect(() => {
    if (!deleteConfirmationUser) {
      return;
    }

    function handleDeleteModalEscape(
      event: KeyboardEvent,
    ) {
      if (event.key !== "Escape") {
        return;
      }

      if (deletingUserId) {
        return;
      }

      setDeleteConfirmationUser(null);
      setDeleteModalMode("confirmation");
    }

    document.addEventListener(
      "keydown",
      handleDeleteModalEscape,
    );

    return () => {
      document.removeEventListener(
        "keydown",
        handleDeleteModalEscape,
      );
    };
  }, [
    deleteConfirmationUser,
    deletingUserId,
  ]);

  /* ==========================================================================
   * Drawer Helpers
   * ======================================================================== */

  const closeDrawer = useCallback(() => {
    if (
      deletingUserId ||
      deleteConfirmationUser
    ) {
      return;
    }

    setSelectedUser(null);
    setActiveView(null);
    setSecurityAction(null);
  }, [
    deleteConfirmationUser,
    deletingUserId,
  ]);

  const openDrawer = useCallback(
    (
      user: User,
      view: UsersView,
    ) => {
      if (
        deletingUserId ||
        deleteConfirmationUser
      ) {
        return;
      }

      setSelectedUser(user);
      setActiveView(view);

      if (view !== "security") {
        setSecurityAction(null);
      }
    },
    [
      deleteConfirmationUser,
      deletingUserId,
    ],
  );

  /* ==========================================================================
   * Filter Handlers
   * ======================================================================== */

  const handleSearchChange = useCallback(
    (value: string) => {
      setSearch(value);
      setOffset(0);
    },
    [],
  );

  const handleActiveFilterChange =
    useCallback(
      (value: ActiveFilter) => {
        setActiveFilter(value);
        setOffset(0);
      },
      [],
    );

  const handleLockedFilterChange =
    useCallback(
      (value: LockedFilter) => {
        setLockedFilter(value);
        setOffset(0);
      },
      [],
    );

  const handleRoleFilterChange =
    useCallback(
      (value: RoleFilter) => {
        setRoleFilter(value);
        setOffset(0);
      },
      [],
    );

  const handleClearFilters =
    useCallback(() => {
      setSearch("");
      setActiveFilter("");
      setLockedFilter("");
      setRoleFilter("");
      setOffset(0);
    }, []);

  /* ==========================================================================
   * Refresh
   * ======================================================================== */

  const handleRefresh = useCallback(
    async () => {
      if (
        deleteConfirmationUser ||
        deletingUserId
      ) {
        return;
      }

      await loadUsers(true);
    },
    [
      deleteConfirmationUser,
      deletingUserId,
      loadUsers,
    ],
  );

  /* ==========================================================================
   * Pagination
   * ======================================================================== */

  const handlePreviousPage =
    useCallback(() => {
      if (
        loading ||
        refreshing ||
        deletingUserId ||
        deleteConfirmationUser ||
        !hasPreviousPage
      ) {
        return;
      }

      setOffset((currentOffset) =>
        Math.max(
          0,
          currentOffset - limit,
        ),
      );
    }, [
      deleteConfirmationUser,
      deletingUserId,
      hasPreviousPage,
      limit,
      loading,
      refreshing,
    ]);

  const handleNextPage =
    useCallback(() => {
      if (
        loading ||
        refreshing ||
        deletingUserId ||
        deleteConfirmationUser ||
        !hasNextPage
      ) {
        return;
      }

      setOffset(
        (currentOffset) =>
          currentOffset + limit,
      );
    }, [
      deleteConfirmationUser,
      deletingUserId,
      hasNextPage,
      limit,
      loading,
      refreshing,
    ]);

  /* ==========================================================================
   * User Workflows
   * ======================================================================== */

  const handleViewUser = useCallback(
    (user: User) => {
      if (
        deleteConfirmationUser ||
        deletingUserId
      ) {
        return;
      }

      openDrawer(user, "details");
    },
    [
      deleteConfirmationUser,
      deletingUserId,
      openDrawer,
    ],
  );

  const handleCreateUser = useCallback(
    () => {
      if (
        !canManageUsers ||
        deletingUserId ||
        deleteConfirmationUser
      ) {
        return;
      }

      setSelectedUser(null);
      setSecurityAction(null);
      setActiveView("create");
    },
    [
      canManageUsers,
      deleteConfirmationUser,
      deletingUserId,
    ],
  );

  const handleUserCreated = useCallback(
    (user: User) => {
      setSelectedUser(user);
      setActiveView("details");
      setSecurityAction(null);

      void loadUsers(true);
    },
    [loadUsers],
  );

  const handleEditUser = useCallback(
    (user: User) => {
      if (
        !canManageUsers ||
        deletingUserId ||
        deleteConfirmationUser
      ) {
        return;
      }

      openDrawer(user, "edit");
    },
    [
      canManageUsers,
      deleteConfirmationUser,
      deletingUserId,
      openDrawer,
    ],
  );

  const handleUserUpdated = useCallback(
    (updatedUser: User) => {
      setSelectedUser(updatedUser);
      setActiveView("details");
      setSecurityAction(null);

      void loadUsers(true);
    },
    [loadUsers],
  );

  const handleRoleEdit = useCallback(
    (user: User) => {
      if (
        !canManageUsers ||
        deletingUserId ||
        deleteConfirmationUser
      ) {
        return;
      }

      openDrawer(user, "role");
    },
    [
      canManageUsers,
      deleteConfirmationUser,
      deletingUserId,
      openDrawer,
    ],
  );

  const handleAuditHistory = useCallback(
    (user: User) => {
      if (
        !canReadUsers ||
        deletingUserId ||
        deleteConfirmationUser
      ) {
        return;
      }

      openDrawer(user, "audit");
    },
    [
      canReadUsers,
      deleteConfirmationUser,
      deletingUserId,
      openDrawer,
    ],
  );

  const handleSecurity = useCallback(
    (user: User) => {
      if (
        !canUseSecurityActions ||
        deletingUserId ||
        deleteConfirmationUser
      ) {
        return;
      }

      setSelectedUser(user);
      setActiveView("security");
      setSecurityAction(null);
    },
    [
      canUseSecurityActions,
      deleteConfirmationUser,
      deletingUserId,
    ],
  );

  const handleSecurityAction =
    useCallback(
      (
        user: User,
        action: UserSecurityAction,
      ) => {
        if (
          !canUseSecurityActions ||
          deletingUserId ||
          deleteConfirmationUser
        ) {
          return;
        }

        setSelectedUser(user);
        setActiveView("security");
        setSecurityAction(action);
      },
      [
        canUseSecurityActions,
        deleteConfirmationUser,
        deletingUserId,
      ],
    );

  /* ==========================================================================
   * DELETE USER — REQUEST
   * ======================================================================== */

  const handleDeleteRequest =
    useCallback(
      (userId: string) => {
        if (!canManageUsers) {
          return;
        }

        if (
          deletingUserId ||
          deleteConfirmationUser
        ) {
          return;
        }

        const targetUser = users.find(
          (user) =>
            user.user_id === userId,
        );

        if (!targetUser) {
          setError(
            "Unable to locate the selected user.",
          );
          return;
        }

        setError(null);

        /*
         * Close the underlying drawer/workflow first.
         * The delete workflow becomes the only active layer.
         */
        setSelectedUser(null);
        setActiveView(null);
        setSecurityAction(null);

        /*
         * SELF DELETE
         *
         * This is a UX pre-check only.
         * Backend remains authoritative.
         */
        if (
          currentUserId &&
          targetUser.user_id === currentUserId
        ) {
          setDeleteModalMode("self-delete");
          setDeleteConfirmationUser(
            targetUser,
          );
          return;
        }

        /*
         * ACTIVE ADMIN
         *
         * We cannot safely determine from the paginated/filtered
         * frontend dataset whether this is the LAST active ADMIN.
         *
         * Therefore we do NOT claim that it is the last ADMIN.
         *
         * Instead, we show the exact contextual warning that the
         * backend will enforce last-active-ADMIN protection.
         */
        if (
          targetUser.is_active &&
          isAdminUser(targetUser)
        ) {
          setDeleteModalMode("admin-warning");
          setDeleteConfirmationUser(
            targetUser,
          );
          return;
        }

        /*
         * NORMAL DELETE CONFIRMATION
         */
        setDeleteModalMode("confirmation");
        setDeleteConfirmationUser(
          targetUser,
        );
      },
      [
        canManageUsers,
        currentUserId,
        deleteConfirmationUser,
        deletingUserId,
        users,
      ],
    );

  /* ==========================================================================
   * DELETE USER — CONFIRM
   * ======================================================================== */

  const handleConfirmUserDelete =
    useCallback(async () => {
      if (
        !deleteConfirmationUser ||
        !canManageUsers ||
        deletingUserId
      ) {
        return;
      }

      /*
       * Self-delete is already blocked at the UX layer.
       * This is NOT relied upon as a security boundary.
       */
      if (
        deleteModalMode === "self-delete"
      ) {
        return;
      }

      const userId =
        deleteConfirmationUser.user_id;

      setDeleteConfirmationUser(null);
      setDeleteModalMode("confirmation");

      setDeletingUserId(userId);
      setError(null);

      try {
        /*
         * FINAL AUTHORIZATION IS BACKEND-SIDE.
         *
         * UserManagementService performs:
         * - actor validation
         * - ADMIN authorization
         * - self-delete protection
         * - target validation
         * - last active ADMIN protection
         * - session revocation
         * - audit persistence
         * - deletion
         */
        await usersApi.remove(userId);

        if (
          selectedUserId === userId
        ) {
          setSelectedUser(null);
          setActiveView(null);
          setSecurityAction(null);
        }

        await loadUsers(true);
      } catch (deleteError) {
        /*
         * Preserve backend security/error messages.
         */
        setError(
          getErrorMessage(deleteError),
        );
      } finally {
        setDeletingUserId(null);
      }
    }, [
      canManageUsers,
      deleteConfirmationUser,
      deleteModalMode,
      deletingUserId,
      loadUsers,
      selectedUserId,
    ]);

  /* ==========================================================================
   * DELETE USER — CANCEL
   * ======================================================================== */

  const handleCancelDelete =
    useCallback(() => {
      if (deletingUserId) {
        return;
      }

      setDeleteConfirmationUser(null);
      setDeleteModalMode("confirmation");
    }, [deletingUserId]);

  /* ==========================================================================
   * Sessions Revoked
   * ======================================================================== */

  const handleSessionsRevoked =
    useCallback(() => {
      /*
       * UserSecurityActions owns session revocation.
       * No additional action is required here.
       */
    }, []);

  /* ==========================================================================
   * Permission Gate
   * ======================================================================== */

  if (!canReadUsers) {
    return (
      <section
        className="panel users-page"
        aria-labelledby="users-access-title"
      >
        <div className="empty">
          <ShieldAlert
            size={18}
            aria-hidden="true"
          />

          <span id="users-access-title">
            You do not have permission to view
            user management.
          </span>
        </div>
      </section>
    );
  }

  /* ==========================================================================
   * Delete Modal Content
   * ======================================================================== */

  const renderDeleteModal = () => {
    if (
      !deleteConfirmationUser ||
      !canManageUsers
    ) {
      return null;
    }

    const target = deleteConfirmationUser;

    const isSelfDelete =
      deleteModalMode === "self-delete";

    const isAdminWarning =
      deleteModalMode === "admin-warning";

    return createPortal(
      <div
        className="user-delete-confirm-backdrop"
        role="presentation"
        onMouseDown={(event) => {
          if (
            event.target ===
              event.currentTarget &&
            !deletingUserId
          ) {
            handleCancelDelete();
          }
        }}
      >
        <section
          className={`user-delete-confirm-modal ${
            isSelfDelete
              ? "is-restricted"
              : ""
          } ${
            isAdminWarning
              ? "is-admin-warning"
              : ""
          }`}
          role="alertdialog"
          aria-modal="true"
          aria-labelledby="user-delete-confirm-title"
          aria-describedby="user-delete-confirm-description"
          onMouseDown={(event) => {
            event.stopPropagation();
          }}
        >
          <div
            className={`user-delete-confirm-icon ${
              isSelfDelete
                ? "is-restricted"
                : ""
            } ${
              isAdminWarning
                ? "is-admin"
                : ""
            }`}
            aria-hidden="true"
          >
            <AlertTriangle size={22} />
          </div>

          <div className="user-delete-confirm-content">
            <span className="user-delete-confirm-eyebrow">
              USER MANAGEMENT
            </span>

            <h2 id="user-delete-confirm-title">
              {isSelfDelete
                ? "Delete User"
                : isAdminWarning
                  ? "ADMIN Account Protection"
                  : "Delete User"}
            </h2>

            {isSelfDelete ? (
              <>
                <p
                  id="user-delete-confirm-description"
                  className="user-delete-confirm-primary-message"
                >
                  You cannot delete your own account.
                </p>

                <div className="user-delete-restriction-box">
                  <ShieldAlert
                    size={17}
                    aria-hidden="true"
                  />

                  <div>
                    <strong>
                      Self-delete is not allowed
                    </strong>

                    <span>
                      For security reasons, your own
                      user account cannot be deleted.
                    </span>
                  </div>
                </div>
              </>
            ) : isAdminWarning ? (
              <>
                <p
                  id="user-delete-confirm-description"
                  className="user-delete-confirm-primary-message"
                >
                  You are attempting to delete{" "}
                  <strong>
                    {target.username}
                  </strong>
                  .
                </p>

                <div className="user-delete-restriction-box is-admin">
                  <ShieldAlert
                    size={17}
                    aria-hidden="true"
                  />

                  <div>
                    <strong>
                      Active ADMIN account
                    </strong>

                    <span>
                      The backend will prevent this
                      operation if this account is the
                      last active ADMIN in the system.
                    </span>
                  </div>
                </div>

                <div className="user-delete-impact-list">
                  <div className="user-delete-impact-title">
                    Before deletion
                  </div>

                  <div className="user-delete-impact-item">
                    <span className="user-delete-impact-dot" />
                    <span>
                      Active sessions will be revoked.
                    </span>
                  </div>

                  <div className="user-delete-impact-item">
                    <span className="user-delete-impact-dot" />
                    <span>
                      The deletion will be recorded
                      in the audit log.
                    </span>
                  </div>

                  <div className="user-delete-impact-item">
                    <span className="user-delete-impact-dot" />
                    <span>
                      Backend security checks remain
                      authoritative.
                    </span>
                  </div>
                </div>
              </>
            ) : (
              <>
                <p
                  id="user-delete-confirm-description"
                  className="user-delete-confirm-primary-message"
                >
                  Are you sure you want to permanently
                  delete{" "}
                  <strong>
                    {target.username}
                  </strong>
                  ?
                </p>

                <div className="user-delete-impact-list">
                  <div className="user-delete-impact-title">
                    Before deletion
                  </div>

                  <div className="user-delete-impact-item">
                    <span className="user-delete-impact-dot" />
                    <span>
                      Active sessions will be revoked.
                    </span>
                  </div>

                  <div className="user-delete-impact-item">
                    <span className="user-delete-impact-dot" />
                    <span>
                      The deletion will be recorded
                      in the audit log.
                    </span>
                  </div>

                  <div className="user-delete-impact-item">
                    <span className="user-delete-impact-dot" />
                    <span>
                      This action cannot be undone.
                    </span>
                  </div>
                </div>
              </>
            )}
          </div>

          <div className="user-delete-confirm-actions">
            <button
              type="button"
              className="secondary-button"
              onClick={handleCancelDelete}
              disabled={Boolean(deletingUserId)}
            >
              {isSelfDelete
                ? "Close"
                : "Cancel"}
            </button>

            {!isSelfDelete && (
              <button
                type="button"
                className="users-delete-confirm-button"
                onClick={() => {
                  void handleConfirmUserDelete();
                }}
                disabled={Boolean(
                  deletingUserId,
                )}
              >
                <Trash2
                  size={15}
                  aria-hidden="true"
                />

                <span>
                  {deletingUserId
                    ? "Deleting..."
                    : "Delete User"}
                </span>
              </button>
            )}
          </div>
        </section>
      </div>,
      document.body,
    );
  };

  /* ==========================================================================
   * Render
   * ======================================================================== */

  return (
    <div className="users-page">
      {/* ================================================================== */}
      {/* Page Header                                                        */}
      {/* ================================================================== */}

      <header className="users-page-header">
        <div className="users-page-heading">
          <div className="users-breadcrumb">
            <span>Home</span>

            <span
              className="users-breadcrumb-separator"
              aria-hidden="true"
            >
              /
            </span>

            <span>User Management</span>
          </div>

          <div className="users-title-row">
            <div className="users-title-icon">
              <UsersRound
                size={19}
                aria-hidden="true"
              />
            </div>

            <div>
              <h1>User Management</h1>

              <p>
                Manage SentinelSIEM users, roles,
                account state, and security controls.
              </p>
            </div>
          </div>
        </div>

        <div className="users-toolbar">
          {canManageUsers && (
            <button
              type="button"
              className="primary-button"
              onClick={handleCreateUser}
              disabled={
                loading ||
                refreshing ||
                Boolean(deletingUserId) ||
                Boolean(deleteConfirmationUser)
              }
            >
              <UserPlus
                size={16}
                aria-hidden="true"
              />

              <span>Create User</span>
            </button>
          )}

          <button
            type="button"
            className="secondary-button"
            onClick={handleRefresh}
            disabled={
              loading ||
              refreshing ||
              Boolean(deletingUserId) ||
              Boolean(deleteConfirmationUser)
            }
            title="Refresh users"
          >
            <RefreshCw
              size={16}
              aria-hidden="true"
              className={
                refreshing
                  ? "spin"
                  : undefined
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

      {/* ================================================================== */}
      {/* Error Notice                                                       */}
      {/* ================================================================== */}

      {error && (
        <div
          className="notice warning users-error"
          role="alert"
        >
          <ShieldAlert
            size={16}
            aria-hidden="true"
          />

          <span>{error}</span>
        </div>
      )}

      {/* ================================================================== */}
      {/* Statistics                                                         */}
      {/* ================================================================== */}

      <UserStats statistics={statistics} />

      {/* ================================================================== */}
      {/* Create User                                                        */}
      {/* ================================================================== */}

      {activeView === "create" &&
        canManageUsers && (
          <CreateUserForm
            onCreated={handleUserCreated}
            onCancel={() => {
              if (
                deletingUserId ||
                deleteConfirmationUser
              ) {
                return;
              }

              setActiveView(null);
              setSelectedUser(null);
              setSecurityAction(null);
            }}
          />
        )}

      {/* ================================================================== */}
      {/* User Directory                                                     */}
      {/* ================================================================== */}

      <section className="users-directory">
        <Panel
          title="User Directory"
          subtitle={
            loading
              ? "Loading users..."
              : total === 0
                ? "No users match the current criteria"
                : `Showing ${firstItem}–${lastItem} of ${total} users`
          }
        >
          <div className="users-directory-summary">
            <div className="users-directory-summary-main">
              <div className="users-directory-summary-icon">
                <UsersRound
                  size={17}
                  aria-hidden="true"
                />
              </div>

              <div>
                <strong>User Directory</strong>

                <span>
                  {hasFilters
                    ? "Filtered results"
                    : "All registered users"}
                </span>
              </div>
            </div>

            <div className="users-directory-summary-meta">
              <span>
                {total}{" "}
                {total === 1
                  ? "user"
                  : "users"}
              </span>

              <span
                className="users-directory-summary-divider"
                aria-hidden="true"
              />

              <span>
                Page {pageNumber}
                {totalPages > 0
                  ? ` of ${totalPages}`
                  : ""}
              </span>
            </div>
          </div>

          {/* ============================================================ */}
          {/* Filters                                                       */}
          {/* ============================================================ */}

          <UserFilters
            search={search}
            activeFilter={activeFilter}
            lockedFilter={lockedFilter}
            roleFilter={roleFilter}
            loading={
              Boolean(deletingUserId) ||
              Boolean(deleteConfirmationUser)
            }
            hasFilters={hasFilters}
            onSearchChange={handleSearchChange}
            onActiveFilterChange={
              handleActiveFilterChange
            }
            onLockedFilterChange={
              handleLockedFilterChange
            }
            onRoleFilterChange={
              handleRoleFilterChange
            }
            onClear={handleClearFilters}
          />

          {/* ============================================================ */}
          {/* Table Section                                                 */}
          {/* ============================================================ */}

          <div className="users-table-section">
            <div className="users-table-heading">
              <div>
                <span className="users-section-eyebrow">
                  USER DIRECTORY
                </span>

                <h2>Registered Accounts</h2>

                <p>
                  Review identity, role, account
                  state, and available administrative
                  actions.
                </p>
              </div>

              <div className="users-table-count">
                <UsersRound
                  size={15}
                  aria-hidden="true"
                />

                <span>
                  {loading
                    ? "Loading..."
                    : `${users.length} shown`}
                </span>
              </div>
            </div>

            <UserTable
              users={users}
              loading={loading}
              hasFilters={hasFilters}
              selectedUserId={selectedUserId}
              canManageUsers={canManageUsers}
              canUseSecurityActions={
                canUseSecurityActions
              }
              onSelect={handleViewUser}
              onEdit={
                canManageUsers
                  ? handleEditUser
                  : undefined
              }
              onSecurity={
                canUseSecurityActions
                  ? handleSecurity
                  : undefined
              }
              onRole={
                canManageUsers
                  ? handleRoleEdit
                  : undefined
              }
              onAudit={handleAuditHistory}
              onDeleted={
                canManageUsers
                  ? handleDeleteRequest
                  : undefined
              }
              onSecurityAction={
                canUseSecurityActions
                  ? handleSecurityAction
                  : undefined
              }
            />
          </div>

          {/* ============================================================ */}
          {/* Pagination                                                    */}
          {/* ============================================================ */}

          <footer
            className="users-pagination"
            aria-label="User pagination"
          >
            <div className="users-pagination-summary">
              <strong>
                {total === 0
                  ? "0"
                  : `${firstItem}–${lastItem}`}
              </strong>

              <span className="users-pagination-label">
                {total === 1
                  ? "User"
                  : "Users"}
              </span>

              <span
                className="users-pagination-separator"
                aria-hidden="true"
              >
                /
              </span>

              <span className="users-pagination-total">
                Total {total}
              </span>

              <span
                className="users-pagination-separator"
                aria-hidden="true"
              >
                •
              </span>

              <span className="users-pagination-page">
                Page {pageNumber}
                {totalPages > 0
                  ? ` of ${totalPages}`
                  : ""}
              </span>
            </div>

            <div className="users-pagination-actions">
              <button
                type="button"
                className="users-pagination-button"
                onClick={handlePreviousPage}
                disabled={
                  !hasPreviousPage ||
                  loading ||
                  refreshing ||
                  Boolean(deletingUserId) ||
                  Boolean(deleteConfirmationUser)
                }
              >
                Previous
              </button>

              <button
                type="button"
                className="users-pagination-button"
                onClick={handleNextPage}
                disabled={
                  !hasNextPage ||
                  loading ||
                  refreshing ||
                  Boolean(deletingUserId) ||
                  Boolean(deleteConfirmationUser)
                }
              >
                Next
              </button>
            </div>
          </footer>
        </Panel>
      </section>

      {/* ================================================================== */}
      {/* User Workflow Drawer                                               */}
      {/* ================================================================== */}

      {selectedUser &&
        activeView &&
        activeView !== "create" && (
          <div
            className="user-drawer-backdrop"
            role="presentation"
            onMouseDown={(event) => {
              if (
                event.target ===
                  event.currentTarget &&
                !deletingUserId &&
                !deleteConfirmationUser
              ) {
                closeDrawer();
              }
            }}
          >
            <aside
              className="user-drawer"
              role="dialog"
              aria-modal="true"
              aria-labelledby="user-drawer-title"
            >
              <div className="user-drawer-header">
                <div>
                  <span className="eyebrow">
                    USER MANAGEMENT
                  </span>

                  <h2 id="user-drawer-title">
                    {activeView === "details" &&
                      "User Details"}

                    {activeView === "edit" &&
                      "Edit User"}

                    {activeView === "role" &&
                      "Change Role"}

                    {activeView === "security" &&
                      "Security Actions"}

                    {activeView === "audit" &&
                      "Audit History"}
                  </h2>

                  <p>
                    {activeView === "details" &&
                      `Review ${selectedUser.username}`}

                    {activeView === "edit" &&
                      `Edit ${selectedUser.username}`}

                    {activeView === "role" &&
                      `Manage roles for ${selectedUser.username}`}

                    {activeView === "security" &&
                      `Security controls for ${selectedUser.username}`}

                    {activeView === "audit" &&
                      `Activity history for ${selectedUser.username}`}
                  </p>
                </div>

                <button
                  type="button"
                  className="icon-button"
                  aria-label="Close user workflow"
                  title="Close"
                  onClick={closeDrawer}
                  disabled={
                    Boolean(deletingUserId) ||
                    Boolean(deleteConfirmationUser)
                  }
                >
                  <X
                    size={17}
                    aria-hidden="true"
                  />
                </button>
              </div>

              <div className="user-drawer-body">
                {/* ====================================================== */}
                {/* Details                                                 */}
                {/* ====================================================== */}

                {activeView === "details" && (
                  <UserDetailsPanel
                    user={selectedUser}
                    onEdit={
                      canManageUsers
                        ? handleEditUser
                        : undefined
                    }
                    onRole={
                      canManageUsers
                        ? handleRoleEdit
                        : undefined
                    }
                    onSecurity={
                      canUseSecurityActions
                        ? handleSecurity
                        : undefined
                    }
                    onSecurityAction={
                      canUseSecurityActions
                        ? handleSecurityAction
                        : undefined
                    }
                  />
                )}

                {/* ====================================================== */}
                {/* Edit                                                    */}
                {/* ====================================================== */}

                {activeView === "edit" &&
                  canManageUsers && (
                    <div className="users-action-panel">
                      <EditUserForm
                        user={selectedUser}
                        onUpdated={
                          handleUserUpdated
                        }
                        onCancel={() => {
                          if (
                            deletingUserId ||
                            deleteConfirmationUser
                          ) {
                            return;
                          }

                          setActiveView(
                            "details",
                          );

                          setSecurityAction(null);
                        }}
                      />
                    </div>
                  )}

                {/* ====================================================== */}
                {/* Role                                                    */}
                {/* ====================================================== */}

                {activeView === "role" &&
                  canManageUsers && (
                    <div className="users-action-panel">
                      <UserRoleEditor
                        user={selectedUser}
                        onUpdated={
                          handleUserUpdated
                        }
                        onCancel={() => {
                          if (
                            deletingUserId ||
                            deleteConfirmationUser
                          ) {
                            return;
                          }

                          setActiveView(
                            "details",
                          );

                          setSecurityAction(null);
                        }}
                      />
                    </div>
                  )}

                {/* ====================================================== */}
                {/* Security                                                */}
                {/* ====================================================== */}

                {activeView === "security" &&
                  canUseSecurityActions && (
                    <div className="users-action-panel">
                      <UserSecurityActions
                        user={selectedUser}
                        action={securityAction}
                        onUpdated={
                          handleUserUpdated
                        }
                        onSessionsRevoked={
                          handleSessionsRevoked
                        }
                        onCancel={() => {
                          if (
                            deletingUserId ||
                            deleteConfirmationUser
                          ) {
                            return;
                          }

                          setActiveView(
                            "details",
                          );

                          setSecurityAction(null);
                        }}
                      />
                    </div>
                  )}

                {/* ====================================================== */}
                {/* Audit                                                   */}
                {/* ====================================================== */}

                {activeView === "audit" && (
                  <div className="users-action-panel">
                    <UserAuditPanel
                      userId={
                        selectedUser.user_id
                      }
                    />
                  </div>
                )}
              </div>
            </aside>
          </div>
        )}

      {/* ================================================================== */}
      {/* Delete Confirmation                                                */}
      {/* ================================================================== */}

      {renderDeleteModal()}
    </div>
  );
}