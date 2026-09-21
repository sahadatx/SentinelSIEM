/**
 * ============================================================================
 * SentinelSIEM — User Actions
 * ============================================================================
 *
 * Account-state mutation component.
 *
 * Responsibilities:
 * - Enable / disable a user account
 * - Lock / unlock a user account
 * - Enforce frontend users:manage visibility
 * - Prevent duplicate mutations
 * - Display action-level errors
 * - Report successful backend mutations to the parent
 *
 * This component does NOT:
 * - Perform RBAC business authorization
 * - Handle passwords
 * - Handle sessions
 * - Handle roles
 * - Delete users
 * - Implement security policy
 *
 * Backend authorization remains the final security boundary.
 *
 * ============================================================================
 */

import {
  useState,
} from "react";

import {
  Lock,
  ShieldAlert,
  Unlock,
  UserCheck,
  UserX,
} from "lucide-react";

import {
  useAuthStore,
} from "../../../store/auth";

import {
  USERS_MANAGE,
} from "../permissions";

import {
  usersApi,
} from "../api";

import type {
  User,
} from "../types";

/* ============================================================================
 * Types
 * ========================================================================== */

/**
 * Currently executing account-state operation.
 *
 * null:
 * - No request is running.
 *
 * "active":
 * - Enable / disable request is running.
 *
 * "lock":
 * - Lock / unlock request is running.
 */
type UserAction =
  | null
  | "active"
  | "lock";

/* ============================================================================
 * Props
 * ========================================================================== */

export interface UserActionsProps {
  /**
   * Target user.
   */
  user: User;

  /**
   * Called when the backend successfully
   * returns the updated user.
   */
  onUpdated?: (
    user: User,
  ) => void;

  /**
   * Disable all controls from the parent.
   */
  disabled?: boolean;
}

/* ============================================================================
 * Error Handling
 * ========================================================================== */

/**
 * Convert an unknown API error into a safe
 * user-facing message.
 */
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
    error &&
    typeof error === "object" &&
    "message" in error &&
    typeof error.message === "string"
  ) {
    return error.message;
  }

  if (
    error instanceof Error &&
    error.message
  ) {
    return error.message;
  }

  return fallback;
}

/* ============================================================================
 * User Actions
 * ========================================================================== */

export default function UserActions({
  user,
  onUpdated,
  disabled = false,
}: UserActionsProps) {
  /* ==========================================================================
   * RBAC
   * ======================================================================== */

  const hasPermission =
    useAuthStore(
      (state) =>
        state.hasPermission,
    );

  /**
   * Account-state mutations require
   * users:manage.
   *
   * This is a frontend visibility/UX check.
   * Backend authorization remains authoritative.
   */
  const canManageUsers =
    hasPermission(
      USERS_MANAGE,
    );

  /* ==========================================================================
   * Request State
   * ======================================================================== */

  const [
    submitting,
    setSubmitting,
  ] = useState<UserAction>(
    null,
  );

  const [
    error,
    setError,
  ] = useState<string | null>(
    null,
  );

  /* ==========================================================================
   * Derived State
   * ======================================================================== */

  const isSubmitting =
    submitting !== null;

  const controlsDisabled =
    disabled ||
    isSubmitting;

  /* ==========================================================================
   * Clear Error
   * ======================================================================== */

  function clearError() {
    if (error !== null) {
      setError(null);
    }
  }

  /* ==========================================================================
   * Enable / Disable
   * ======================================================================== */

  async function handleActiveToggle() {
    /**
     * Defense-in-depth permission check.
     */
    if (
      !canManageUsers ||
      controlsDisabled
    ) {
      return;
    }

    clearError();

    setSubmitting(
      "active",
    );

    try {
      /**
       * Toggle the current backend state.
       */
      const updatedUser =
        await usersApi.setActive(
          user.user_id,
          {
            is_active:
              !user.is_active,
          },
        );

      /**
       * Parent receives the authoritative
       * backend representation.
       */
      onUpdated?.(
        updatedUser,
      );
    } catch (
      requestError
    ) {
      setError(
        getErrorMessage(
          requestError,
          "Unable to update user account state.",
        ),
      );
    } finally {
      setSubmitting(null);
    }
  }

  /* ==========================================================================
   * Lock / Unlock
   * ======================================================================== */

  async function handleLockToggle() {
    /**
     * Defense-in-depth permission check.
     */
    if (
      !canManageUsers ||
      controlsDisabled
    ) {
      return;
    }

    clearError();

    setSubmitting(
      "lock",
    );

    try {
      /**
       * Toggle the current backend state.
       */
      const updatedUser =
        await usersApi.setLocked(
          user.user_id,
          {
            is_locked:
              !user.is_locked,
          },
        );

      /**
       * Parent receives the authoritative
       * backend representation.
       */
      onUpdated?.(
        updatedUser,
      );
    } catch (
      requestError
    ) {
      setError(
        getErrorMessage(
          requestError,
          "Unable to update user lock state.",
        ),
      );
    } finally {
      setSubmitting(null);
    }
  }

  /* ==========================================================================
   * Permission Gate
   * ======================================================================== */

  if (!canManageUsers) {
    return null;
  }

  /* ==========================================================================
   * Derived Labels
   * ======================================================================== */

  const activeActionLabel =
    user.is_active
      ? "Disable"
      : "Enable";

  const lockActionLabel =
    user.is_locked
      ? "Unlock"
      : "Lock";

  const activeActionDescription =
    user.is_active
      ? `Disable user ${user.username}`
      : `Enable user ${user.username}`;

  const lockActionDescription =
    user.is_locked
      ? `Unlock user ${user.username}`
      : `Lock user ${user.username}`;

  /* ==========================================================================
   * Render
   * ======================================================================== */

  return (
    <div
      className="user-actions"
      aria-label={`Account actions for ${user.username}`}
    >
      {/* ====================================================================
          Account Active / Disabled
          ================================================================== */}

      <button
        type="button"
        className={
          user.is_active
            ? "secondary-button"
            : "primary-button"
        }
        onClick={
          handleActiveToggle
        }
        disabled={
          controlsDisabled
        }
        title={
          activeActionDescription
        }
        aria-label={
          activeActionDescription
        }
        aria-busy={
          submitting === "active"
        }
      >
        {user.is_active ? (
          <UserX
            size={14}
            aria-hidden="true"
          />
        ) : (
          <UserCheck
            size={14}
            aria-hidden="true"
          />
        )}

        <span>
          {submitting ===
          "active"
            ? "Updating..."
            : activeActionLabel}
        </span>
      </button>

      {/* ====================================================================
          Lock / Unlock
          ================================================================== */}

      <button
        type="button"
        className={
          user.is_locked
            ? "primary-button"
            : "secondary-button"
        }
        onClick={
          handleLockToggle
        }
        disabled={
          controlsDisabled
        }
        title={
          lockActionDescription
        }
        aria-label={
          lockActionDescription
        }
        aria-busy={
          submitting === "lock"
        }
      >
        {user.is_locked ? (
          <Unlock
            size={14}
            aria-hidden="true"
          />
        ) : (
          <Lock
            size={14}
            aria-hidden="true"
          />
        )}

        <span>
          {submitting ===
          "lock"
            ? "Updating..."
            : lockActionLabel}
        </span>
      </button>

      {/* ====================================================================
          Error
          ================================================================== */}

      {error && (
        <div
          className="notice warning"
          role="alert"
          aria-live="assertive"
        >
          <ShieldAlert
            size={14}
            aria-hidden="true"
          />

          <span>
            {error}
          </span>
        </div>
      )}
    </div>
  );
}