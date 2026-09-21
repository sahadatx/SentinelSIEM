/**
 * ============================================================================
 * SentinelSIEM — User Edit Page
 * ============================================================================
 *
 * Dedicated user-edit workflow.
 *
 * Responsibilities:
 * - Resolve the user ID from the route
 * - Load the requested user from the backend
 * - Enforce frontend RBAC visibility
 * - Display EditUserForm
 * - Handle loading / error / retry states
 * - Refresh the current user
 * - Navigate back to User Management
 * - Return to the users dashboard after a successful update
 *
 * The backend remains the final authorization boundary.
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

import {
  useNavigate,
  useParams,
} from "react-router-dom";

import { Panel } from "../../../components/ui/Panel";
import { useAuthStore } from "../../../store/auth";

import {
  USERS_MANAGE,
  USERS_READ,
} from "../permissions";

import { usersApi } from "../api";

import type { User } from "../types";

import EditUserForm from "../components/EditUserForm";

/**
 * ============================================================================
 * Helpers
 * ============================================================================
 */

/**
 * Convert an unknown request error into a safe UI message.
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

  return "Unable to load user.";
}

/**
 * Resolve a usable user ID from supported
 * route parameter names.
 *
 * Supported routes:
 * - /users/:userId/edit
 * - /users/:id/edit
 */
function resolveUserId(
  params: Record<
    string,
    string | undefined
  >,
): string | null {
  const userId =
    params.userId?.trim();

  if (userId) {
    return userId;
  }

  const id =
    params.id?.trim();

  if (id) {
    return id;
  }

  return null;
}

/**
 * ============================================================================
 * Permission Empty State
 * ============================================================================
 */

interface PermissionStateProps {
  message: string;
}

/**
 * Shared permission/access state.
 */
function PermissionState({
  message,
}: PermissionStateProps) {
  return (
    <section
      className="panel users-page"
      aria-live="polite"
    >
      <div className="empty">
        <ShieldAlert
          size={18}
          aria-hidden="true"
        />

        <span>
          {message}
        </span>
      </div>
    </section>
  );
}

/**
 * ============================================================================
 * User Edit Page
 * ============================================================================
 */

export default function UserEdit() {
  /**
   * ==========================================================================
   * Router
   * ==========================================================================
   */

  const navigate =
    useNavigate();

  const params =
    useParams();

  const userId =
    resolveUserId(params);

  /**
   * ==========================================================================
   * RBAC
   * ==========================================================================
   */

  const hasPermission =
    useAuthStore(
      (state) =>
        state.hasPermission,
    );

  const canReadUsers =
    hasPermission(
      USERS_READ,
    );

  const canManageUsers =
    hasPermission(
      USERS_MANAGE,
    );

  /**
   * ==========================================================================
   * User State
   * ==========================================================================
   */

  const [
    user,
    setUser,
  ] = useState<User | null>(
    null,
  );

  /**
   * ==========================================================================
   * Request State
   * ==========================================================================
   */

  const [
    loading,
    setLoading,
  ] = useState(true);

  const [
    refreshing,
    setRefreshing,
  ] = useState(false);

  const [
    error,
    setError,
  ] = useState<string | null>(
    null,
  );

  /**
   * ==========================================================================
   * Load User
   * ==========================================================================
   */

  const loadUser =
    useCallback(
      async (
        showRefreshState = false,
      ) => {
        /**
         * Route validation.
         */
        if (!userId) {
          setUser(null);
          setError(
            "User ID is missing.",
          );
          setLoading(false);
          setRefreshing(false);
          return;
        }

        /**
         * Request state.
         */
        if (showRefreshState) {
          setRefreshing(true);
        } else {
          setLoading(true);
        }

        setError(null);

        try {
          /**
           * The API layer owns the actual
           * backend request implementation.
           */
          const response =
            await usersApi.get(
              userId,
            );

          setUser(response);
        } catch (
          requestError
        ) {
          setUser(null);

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
      [userId],
    );

  /**
   * ==========================================================================
   * Initial Load
   * ==========================================================================
   */

  useEffect(() => {
    void loadUser();
  }, [loadUser]);

  /**
   * ==========================================================================
   * Navigation
   * ==========================================================================
   */

  const handleBack =
    useCallback(() => {
      navigate("/users");
    }, [navigate]);

  /**
   * ==========================================================================
   * Update Success
   * ==========================================================================
   */

  const handleUpdated =
    useCallback(
      (updatedUser: User) => {
        /**
         * Keep local state synchronized
         * before leaving the page.
         */
        setUser(
          updatedUser,
        );

        /**
         * Return to the User Management
         * dashboard after successful update.
         */
        navigate("/users");
      },
      [navigate],
    );

  /**
   * ==========================================================================
   * Cancel
   * ==========================================================================
   */

  const handleCancel =
    useCallback(() => {
      navigate("/users");
    }, [navigate]);

  /**
   * ==========================================================================
   * Permission Gate — Read
   * ==========================================================================
   */

  if (!canReadUsers) {
    return (
      <PermissionState
        message={
          "You do not have permission to view user management."
        }
      />
    );
  }

  /**
   * ==========================================================================
   * Permission Gate — Manage
   * ==========================================================================
   */

  if (!canManageUsers) {
    return (
      <PermissionState
        message={
          "You do not have permission to edit users."
        }
      />
    );
  }

  /**
   * ==========================================================================
   * Missing Route Parameter
   * ==========================================================================
   */

  if (!userId) {
    return (
      <>
        <div className="page-heading">
          <div>
            <div className="users-breadcrumb">
              <span>
                Home
              </span>

              <span
                className="users-breadcrumb-separator"
                aria-hidden="true"
              >
                /
              </span>

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
                Edit User
              </span>
            </div>

            <h2>
              Edit User
            </h2>

            <p>
              No user account was
              specified for editing.
            </p>
          </div>

          <div className="users-toolbar">
            <button
              type="button"
              className="secondary-button"
              onClick={
                handleBack
              }
            >
              <ArrowLeft
                size={15}
                aria-hidden="true"
              />

              Back
            </button>
          </div>
        </div>

        <Panel
          title="Edit User"
          subtitle="A valid user identifier is required."
        >
          <div
            className="empty"
            role="alert"
          >
            <ShieldAlert
              size={18}
              aria-hidden="true"
            />

            <span>
              No user was specified
              for editing.
            </span>
          </div>
        </Panel>
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
            <div className="users-breadcrumb">
              <span>
                Home
              </span>

              <span
                className="users-breadcrumb-separator"
                aria-hidden="true"
              >
                /
              </span>

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
                Edit User
              </span>
            </div>

            <h2>
              Edit User
            </h2>

            <p>
              Loading user
              information...
            </p>
          </div>

          <div className="users-toolbar">
            <button
              type="button"
              className="secondary-button"
              onClick={
                handleBack
              }
            >
              <ArrowLeft
                size={15}
                aria-hidden="true"
              />

              Back
            </button>
          </div>
        </div>

        <Panel
          title="Edit User"
          subtitle="Loading account information."
        >
          <div
            className="empty"
            aria-live="polite"
          >
            Loading user...
          </div>
        </Panel>
      </>
    );
  }

  /**
   * ==========================================================================
   * Error / User Not Found
   * ==========================================================================
   */

  if (!user) {
    return (
      <>
        <div className="page-heading">
          <div>
            <div className="users-breadcrumb">
              <span>
                Home
              </span>

              <span
                className="users-breadcrumb-separator"
                aria-hidden="true"
              >
                /
              </span>

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
                Edit User
              </span>
            </div>

            <h2>
              Edit User
            </h2>

            <p>
              Unable to load the
              requested account.
            </p>
          </div>

          <div className="users-toolbar">
            <button
              type="button"
              className="secondary-button"
              onClick={
                handleBack
              }
            >
              <ArrowLeft
                size={15}
                aria-hidden="true"
              />

              Back
            </button>

            <button
              type="button"
              className="secondary-button"
              onClick={() =>
                void loadUser(
                  true,
                )
              }
              disabled={
                refreshing
              }
              title="Retry loading user"
            >
              <RefreshCw
                size={15}
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

        <Panel
          title="Edit User"
          subtitle="The requested account could not be loaded."
        >
          <div
            className="empty"
            role="alert"
          >
            <ShieldAlert
              size={18}
              aria-hidden="true"
            />

            <span>
              User not found.
            </span>
          </div>
        </Panel>
      </>
    );
  }

  /**
   * ==========================================================================
   * Render
   * ==========================================================================
   */

  return (
    <div className="users-page">
      {/* ================================================================== */}
      {/* Page Header                                                        */}
      {/* ================================================================== */}

      <header className="users-page-header">
        <div className="users-page-heading">
          <div className="users-breadcrumb">
            <span>
              Home
            </span>

            <span
              className="users-breadcrumb-separator"
              aria-hidden="true"
            >
              /
            </span>

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
              Edit User
            </span>
          </div>

          <h1>
            Edit User
          </h1>

          <p>
            Update the SentinelSIEM
            user account and
            account settings.
          </p>
        </div>

        <div className="users-toolbar">
          <button
            type="button"
            className="secondary-button"
            onClick={
              handleBack
            }
            disabled={
              refreshing
            }
          >
            <ArrowLeft
              size={15}
              aria-hidden="true"
            />

            <span>
              Back
            </span>
          </button>

          <button
            type="button"
            className="secondary-button"
            onClick={() =>
              void loadUser(
                true,
              )
            }
            disabled={
              loading ||
              refreshing
            }
            title="Refresh user"
          >
            <RefreshCw
              size={15}
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

          <span>
            {error}
          </span>
        </div>
      )}

      {/* ================================================================== */}
      {/* User Summary                                                       */}
      {/* ================================================================== */}

      <section className="users-edit-summary">
        <div>
          <span className="eyebrow">
            USER ACCOUNT
          </span>

          <strong>
            {user.username}
          </strong>
        </div>

        <div>
          <span>
            Email
          </span>

          <strong>
            {user.email}
          </strong>
        </div>

        <div>
          <span>
            Account
          </span>

          <strong>
            {user.is_active
              ? "Active"
              : "Disabled"}
          </strong>
        </div>

        <div>
          <span>
            Security
          </span>

          <strong>
            {user.is_locked
              ? "Locked"
              : "Unlocked"}
          </strong>
        </div>
      </section>

      {/* ================================================================== */}
      {/* Edit Form                                                          */}
      {/* ================================================================== */}

      <section className="users-edit-form">
        <Panel
          title="Edit User"
          subtitle={`Manage ${user.username}`}
        >
          <EditUserForm
            user={user}
            onUpdated={
              handleUpdated
            }
            onCancel={
              handleCancel
            }
          />
        </Panel>
      </section>
    </div>
  );
}