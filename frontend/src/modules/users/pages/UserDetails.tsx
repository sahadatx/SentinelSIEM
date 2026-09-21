/**
 * ============================================================================
 * SentinelSIEM — User Details Page
 * ============================================================================
 *
 * User details route/container.
 *
 * Responsibilities:
 * - Load a single user from the backend
 * - Load system-wide user statistics
 * - Enforce users:read permission
 * - Provide refresh/retry handling
 * - Provide edit workflow
 * - Provide role workflow
 * - Provide generic security workflow
 * - Preserve exact security-action identity
 * - Provide delete workflow
 * - Delegate user presentation to UserDetailsPanel
 *
 * UserDetailsPanel owns the presentation of:
 *
 *   Overview
 *   Security
 *   Sessions
 *   Activity
 *
 * This page owns workflow state and backend data.
 *
 * Backend authorization remains the final security boundary.
 * ============================================================================
 */

import {
  useCallback,
  useEffect,
  useState,
} from "react";

import "../Users.css"

import {
  ArrowLeft,
  RefreshCw,
  ShieldAlert,
} from "lucide-react";

import { Panel } from "../../../components/ui/Panel";

import { useAuthStore } from "../../../store/auth";

import {
  USERS_MANAGE,
  USERS_READ,
} from "../permissions";

import { usersApi } from "../api";

import type {
  User,
  UserStatistics,
} from "../types";

import EditUserForm from "../components/EditUserForm";
import UserDeleteAction from "../components/UserDeleteAction";
import UserDetailsPanel from "../components/UserDetailsPanel";
import UserRoleEditor from "../components/UserRoleEditor";
import UserSecurityActions from "../components/UserSecurityActions";

import type {
  UserSecurityAction,
} from "../components/UserActionsMenu";

/**
 * ============================================================================
 * Types
 * ============================================================================
 */

/**
 * Currently active management workflow.
 *
 * "none" means that no mutation/security workflow
 * is currently displayed.
 */
type ActivePanel =
  | "none"
  | "edit"
  | "role"
  | "security";

/**
 * ============================================================================
 * Props
 * ============================================================================
 */

export interface UserDetailsPageProps {
  /**
   * User identifier supplied by the route/container.
   */
  userId: string;

  /**
   * Optional callback for returning to User Management.
   */
  onBack?: () => void;
}

/**
 * ============================================================================
 * Helpers
 * ============================================================================
 */

/**
 * Convert an unknown API error into a safe
 * user-facing message.
 */
function getErrorMessage(
  error: unknown,
): string {
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

  return "Unable to load user details.";
}

/**
 * ============================================================================
 * User Details Page
 * ============================================================================
 */

export default function UserDetails({
  userId,
  onBack,
}: UserDetailsPageProps) {
  /**
   * ==========================================================================
   * RBAC
   * ==========================================================================
   */

  const hasPermission = useAuthStore(
    (state) => state.hasPermission,
  );

  const canReadUsers =
    hasPermission(USERS_READ);

  const canManageUsers =
    hasPermission(USERS_MANAGE);

  /**
   * All administrative security operations
   * require users:manage.
   *
   * Backend authorization remains authoritative.
   */
  const canUseSecurityActions =
    canManageUsers;

  /**
   * ==========================================================================
   * User State
   * ==========================================================================
   */

  const [user, setUser] =
    useState<User | null>(null);

  const [statistics, setStatistics] =
    useState<UserStatistics | null>(null);

  /**
   * ==========================================================================
   * Request State
   * ==========================================================================
   */

  const [loading, setLoading] =
    useState(true);

  const [refreshing, setRefreshing] =
    useState(false);

  const [error, setError] =
    useState<string | null>(null);

  /**
   * ==========================================================================
   * Workflow State
   * ==========================================================================
   */

  const [activePanel, setActivePanel] =
    useState<ActivePanel>("none");

  /**
   * Exact security operation selected
   * by the operator.
   *
   * Examples:
   *
   *   enable_user
   *   disable_user
   *   lock_user
   *   unlock_user
   *   reset_password
   *   force_password_change
   *   active_sessions
   *   revoke_sessions
   *
   * The exact semantic identity is preserved
   * until UserSecurityActions consumes it.
   */
  const [securityAction, setSecurityAction] =
    useState<UserSecurityAction | null>(null);

  /**
   * ==========================================================================
   * Load User + Statistics
   * ==========================================================================
   */

  const loadUser = useCallback(
    async (
      showRefreshState = false,
    ) => {
      /**
       * Do not start another refresh while
       * an existing refresh is running.
       */
      if (
        showRefreshState &&
        refreshing
      ) {
        return;
      }

      /**
       * Update appropriate loading state.
       */
      if (showRefreshState) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      setError(null);

      try {
        /**
         * User details and system statistics
         * are independent requests.
         *
         * Execute them concurrently.
         */
        const [
          userResponse,
          statisticsResponse,
        ] = await Promise.all([
          usersApi.get(userId),
          usersApi.statistics(),
        ]);

        /**
         * Synchronize authoritative backend
         * state with local UI state.
         */
        setUser(userResponse);
        setStatistics(
          statisticsResponse,
        );
      } catch (requestError) {
        /**
         * During initial loading, there is no
         * trustworthy user state to preserve.
         *
         * During refresh, preserve the currently
         * displayed user and only show the error.
         */
        if (!showRefreshState) {
          setUser(null);
          setStatistics(null);
        }

        setError(
          getErrorMessage(
            requestError,
          ),
        );
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [
      refreshing,
      userId,
    ],
  );

  /**
   * ==========================================================================
   * Initial Load
   * ==========================================================================
   */

  useEffect(() => {
    /**
     * Never issue protected requests when
     * the operator lacks users:read.
     */
    if (!canReadUsers) {
      setLoading(false);
      setUser(null);
      setStatistics(null);
      setError(null);

      return;
    }

    void loadUser();
  }, [
    canReadUsers,
    loadUser,
  ]);

  /**
   * ==========================================================================
   * Refresh
   * ==========================================================================
   */

  const handleRefresh = useCallback(
    async () => {
      if (
        loading ||
        refreshing
      ) {
        return;
      }

      await loadUser(true);
    },
    [
      loadUser,
      loading,
      refreshing,
    ],
  );

  /**
   * ==========================================================================
   * Edit Workflow
   * ==========================================================================
   */

  const handleEdit = useCallback(
    () => {
      if (
        !user ||
        !canManageUsers
      ) {
        return;
      }

      /**
       * Edit workflow cannot retain
       * a previous security operation.
       */
      setSecurityAction(null);

      setActivePanel("edit");
    },
    [
      canManageUsers,
      user,
    ],
  );

  /**
   * ==========================================================================
   * Role Workflow
   * ==========================================================================
   */

  const handleRole = useCallback(
    () => {
      if (
        !user ||
        !canManageUsers
      ) {
        return;
      }

      /**
       * Role workflow cannot retain
       * a previous security operation.
       */
      setSecurityAction(null);

      setActivePanel("role");
    },
    [
      canManageUsers,
      user,
    ],
  );

  /**
   * ==========================================================================
   * Generic Security Workflow
   * ==========================================================================
   */

  const handleSecurity = useCallback(
    () => {
      if (
        !user ||
        !canUseSecurityActions
      ) {
        return;
      }

      /**
       * Generic Security view means that
       * no individual operation has been
       * selected yet.
       */
      setSecurityAction(null);

      setActivePanel("security");
    },
    [
      canUseSecurityActions,
      user,
    ],
  );

  /**
   * ==========================================================================
   * Exact Security Action
   * ==========================================================================
   *
   * IMPORTANT:
   *
   * UserDetailsPanel / UserActionsMenu may
   * provide:
   *
   *   user
   *   +
   *   exact action
   *
   * This page intentionally accepts BOTH.
   *
   * That keeps the component contract aligned:
   *
   *   UserActionsMenu
   *        ↓
   *   UserDetailsPanel
   *        ↓
   *   UserDetails
   *        ↓
   *   UserSecurityActions
   *
   * The selected action itself is stored locally.
   * ==========================================================================
   */

  const handleSecurityAction = useCallback(
    (
      selectedUser: User,
      action: UserSecurityAction,
    ) => {
      if (
        !canUseSecurityActions
      ) {
        return;
      }

      /**
       * Only accept the action when the
       * callback refers to the currently
       * displayed user.
       *
       * This prevents an accidental stale
       * callback from opening a workflow
       * for another account.
       */
      if (
        selectedUser.user_id !==
        userId
      ) {
        return;
      }

      setSecurityAction(action);
      setActivePanel("security");
    },
    [
      canUseSecurityActions,
      userId,
    ],
  );

  /**
   * ==========================================================================
   * User Updated
   * ==========================================================================
   */

  const handleUserUpdated = useCallback(
    async (
      updatedUser: User,
    ) => {
      /**
       * Immediately reflect the successful
       * mutation in the UI.
       */
      setUser(updatedUser);

      /**
       * Close the current workflow.
       */
      setActivePanel("none");

      /**
       * Clear any previously selected
       * security operation.
       */
      setSecurityAction(null);

      /**
       * Reload authoritative backend state.
       *
       * This also refreshes system-wide
       * user statistics.
       */
      await loadUser(true);
    },
    [loadUser],
  );

  /**
   * ==========================================================================
   * Sessions Revoked
   * ==========================================================================
   */

  const handleSessionsRevoked =
    useCallback(() => {
      /**
       * Revoking sessions does not necessarily
       * modify the User representation.
       *
       * Keep the security workflow open.
       */
    }, []);

  /**
   * ==========================================================================
   * User Deleted
   * ==========================================================================
   */

  const handleDeleted = useCallback(
    (
      deletedUserId: string,
    ) => {
      /**
       * Ignore callbacks that do not refer
       * to the current route user.
       */
      if (
        deletedUserId !== userId
      ) {
        return;
      }

      /**
       * Clear local state before navigation.
       */
      setUser(null);
      setStatistics(null);
      setActivePanel("none");
      setSecurityAction(null);
      setError(null);

      /**
       * Parent route/container owns
       * the actual navigation.
       */
      onBack?.();
    },
    [
      onBack,
      userId,
    ],
  );

  /**
   * ==========================================================================
   * Cancel Workflow
   * ==========================================================================
   */

  const handleCancel = useCallback(
    () => {
      setActivePanel("none");
      setSecurityAction(null);
    },
    [],
  );

  /**
   * ==========================================================================
   * Back
   * ==========================================================================
   */

  const handleBack = useCallback(
    () => {
      onBack?.();
    },
    [onBack],
  );

  /**
   * ==========================================================================
   * Permission Gate — Read
   * ==========================================================================
   */

  if (!canReadUsers) {
    return (
      <>
        <div className="page-heading">
          <div>
            <h2>
              User Details
            </h2>

            <p>
              Review user account
              information.
            </p>
          </div>

          {onBack && (
            <div className="users-toolbar">
              <button
                type="button"
                className="secondary-button"
                onClick={handleBack}
              >
                <ArrowLeft
                  size={14}
                  aria-hidden="true"
                />

                Back
              </button>
            </div>
          )}
        </div>

        <div
          className="notice warning"
          role="alert"
        >
          <ShieldAlert
            size={16}
            aria-hidden="true"
          />

          <span>
            You do not have permission
            to view user details.
          </span>
        </div>
      </>
    );
  }

  /**
   * ==========================================================================
   * Loading State
   * ==========================================================================
   */

  if (
    loading &&
    !user
  ) {
    return (
      <>
        <div className="page-heading">
          <div>
            <h2>
              User Details
            </h2>

            <p>
              Loading user
              information...
            </p>
          </div>

          {onBack && (
            <div className="users-toolbar">
              <button
                type="button"
                className="secondary-button"
                onClick={handleBack}
              >
                <ArrowLeft
                  size={14}
                  aria-hidden="true"
                />

                Back
              </button>
            </div>
          )}
        </div>

        <Panel
          title="User"
          subtitle="Loading account information."
        >
          <div
            className="empty"
            role="status"
            aria-live="polite"
          >
            Loading user details...
          </div>
        </Panel>
      </>
    );
  }

  /**
   * ==========================================================================
   * User Not Found / Initial Request Error
   * ==========================================================================
   */

  if (!user) {
    return (
      <>
        <div className="page-heading">
          <div>
            <h2>
              User Details
            </h2>

            <p>
              The requested user could
              not be loaded.
            </p>
          </div>

          <div className="users-toolbar">
            {onBack && (
              <button
                type="button"
                className="secondary-button"
                onClick={handleBack}
              >
                <ArrowLeft
                  size={14}
                  aria-hidden="true"
                />

                Back
              </button>
            )}

            <button
              type="button"
              className="secondary-button"
              onClick={handleRefresh}
              disabled={
                refreshing
              }
            >
              <RefreshCw
                size={14}
                aria-hidden="true"
                className={
                  refreshing
                    ? "spin"
                    : undefined
                }
              />

              {refreshing
                ? "Retrying..."
                : "Retry"}
            </button>
          </div>
        </div>

        <div
          className="notice warning"
          role="alert"
        >
          <ShieldAlert
            size={16}
            aria-hidden="true"
          />

          <span>
            {error ??
              "User not found."}
          </span>
        </div>
      </>
    );
  }

  /**
   * ==========================================================================
   * Main Render
   * ==========================================================================
   */

  return (
    <div className="users-page">
      {/* ================================================================== */}
      {/* Page Header                                                        */}
      {/* ================================================================== */}

      <div className="page-heading">
        <div>
          <div className="users-breadcrumb">
            <span>
              User Management
            </span>

            <span
              className="users-breadcrumb-separator"
              aria-hidden="true"
            >
              /
            </span>

            <span>
              {user.username}
            </span>
          </div>

          <h2>
            User Details
          </h2>

          <p>
            Review account information,
            security state, sessions,
            and activity.
          </p>
        </div>

        <div className="users-toolbar">
          {onBack && (
            <button
              type="button"
              className="secondary-button"
              onClick={handleBack}
            >
              <ArrowLeft
                size={14}
                aria-hidden="true"
              />

              Back
            </button>
          )}

          <button
            type="button"
            className="secondary-button"
            onClick={handleRefresh}
            disabled={
              loading ||
              refreshing
            }
            title="Refresh user details"
          >
            <RefreshCw
              size={14}
              aria-hidden="true"
              className={
                refreshing
                  ? "spin"
                  : undefined
              }
            />

            {refreshing
              ? "Refreshing..."
              : "Refresh"}
          </button>
        </div>
      </div>

      {/* ================================================================== */}
      {/* Error Notice                                                       */}
      {/* ================================================================== */}

      {error && (
        <div
          className="notice warning"
          role="alert"
        >
          <ShieldAlert
            size={16}
            aria-hidden="true"
          />

          <span>
            {error}
          </span>
        </div>
      )}

      {/* ================================================================== */}
      {/* User Details                                                       */}
      {/* ================================================================== */}

      <Panel
        title={user.username}
        subtitle="User account details"
      >
        <UserDetailsPanel
          user={user}
          onEdit={
            canManageUsers
              ? handleEdit
              : undefined
          }
          onRole={
            canManageUsers
              ? handleRole
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
      </Panel>

      {/* ================================================================== */}
      {/* Edit Workflow                                                      */}
      {/* ================================================================== */}

      {activePanel ===
        "edit" &&
        canManageUsers && (
          <Panel
            title="Edit User"
            subtitle={
              `Update ${user.username}`
            }
          >
            <EditUserForm
              user={user}
              onUpdated={
                handleUserUpdated
              }
              onCancel={
                handleCancel
              }
            />
          </Panel>
        )}

      {/* ================================================================== */}
      {/* Role Workflow                                                      */}
      {/* ================================================================== */}

      {activePanel ===
        "role" &&
        canManageUsers && (
          <Panel
            title="Change Role"
            subtitle={
              `Manage roles for ${user.username}`
            }
          >
            <UserRoleEditor
              user={user}
              onUpdated={
                handleUserUpdated
              }
              onCancel={
                handleCancel
              }
            />
          </Panel>
        )}

      {/* ================================================================== */}
      {/* Security Workflow                                                  */}
      {/* ================================================================== */}

      {activePanel ===
        "security" &&
        canUseSecurityActions && (
          <Panel
            title="Security Actions"
            subtitle={
              securityAction
                ? `Selected action: ${securityAction}`
                : `Security controls for ${user.username}`
            }
          >
            <UserSecurityActions
              user={user}
              action={securityAction}
              onUpdated={
                handleUserUpdated
              }
              onSessionsRevoked={
                handleSessionsRevoked
              }
              onCancel={
                handleCancel
              }
            />
          </Panel>
        )}

      {/* ================================================================== */}
      {/* Danger Zone                                                        */}
      {/* ================================================================== */}

      {canManageUsers && (
        <Panel
          title="Danger Zone"
          subtitle="Irreversible account management operations"
        >
          <div className="users-danger-zone">
            <div>
              <strong>
                Delete User
              </strong>

              <p>
                Permanently remove this
                user account from
                SentinelSIEM. This action
                cannot be undone.
              </p>
            </div>

            <UserDeleteAction
              user={user}
              onDeleted={
                handleDeleted
              }
            />
          </div>
        </Panel>
      )}

      {/* ================================================================== */}
      {/* System Statistics                                                 */}
      {/* ================================================================== */}

      {statistics && (
        <Panel
          title="User Statistics"
          subtitle="Current system-wide user counts"
        >
          <div className="user-details-grid">
            <Detail
              label="Total Users"
              value={
                statistics.total
              }
            />

            <Detail
              label="Active Users"
              value={
                statistics.active
              }
            />

            <Detail
              label="Disabled Users"
              value={
                statistics.disabled
              }
            />

            <Detail
              label="Locked Users"
              value={
                statistics.locked
              }
            />
          </div>
        </Panel>
      )}
    </div>
  );
}

/**
 * ============================================================================
 * Detail
 * ============================================================================
 */

interface DetailProps {
  label: string;
  value: number;
}

/**
 * Small presentation helper for
 * system-wide user statistics.
 */
function Detail({
  label,
  value,
}: DetailProps) {
  return (
    <div className="user-detail-item">
      <span className="detail-label">
        {label}
      </span>

      <strong>
        {value}
      </strong>
    </div>
  );
}