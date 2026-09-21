/**
 * ============================================================================
 * SentinelSIEM — User Security Actions
 * ============================================================================
 *
 * Responsibilities:
 * - Enable / disable user
 * - Lock / unlock user
 * - Reset password
 * - Force password change
 * - View active sessions
 * - Revoke active sessions
 * - Execute the exact action selected by UserActionsMenu
 * - Frontend RBAC visibility
 * - Loading / error / success feedback
 *
 * Backend authorization remains authoritative.
 * ============================================================================
 */

import {
  useEffect,
  useState,
} from "react";

import type {
  FormEvent,
} from "react";

import {
  Eye,
  EyeOff,
  KeyRound,
  Lock,
  LogOut,
  ShieldAlert,
  ShieldCheck,
  Unlock,
  UserCheck,
  UserX,
  UsersRound,
} from "lucide-react";

import { useAuthStore } from "../../../store/auth";

import {
  USERS_MANAGE,
} from "../permissions";

import { usersApi } from "../api";

import type {
  User,
} from "../types";

import type {
  UserSecurityAction,
} from "./UserActionsMenu";

/**
 * ============================================================================
 * Props
 * ============================================================================
 */

export interface UserSecurityActionsProps {
  user: User;

  /**
   * Exact action selected from UserActionsMenu.
   */
  action?: UserSecurityAction | null;

  /**
   * Called when user data changes successfully.
   */
  onUpdated?: (
    user: User,
  ) => void;

  /**
   * Called after sessions are revoked.
   */
  onSessionsRevoked?: () => void;

  /**
   * Close the security workflow.
   */
  onCancel?: () => void;
}

/**
 * ============================================================================
 * Internal View
 * ============================================================================
 */

type SecurityView =
  | "account"
  | "lock"
  | "password"
  | "force-password"
  | "sessions"
  | "revoke-sessions";

/**
 * ============================================================================
 * Submitting State
 * ============================================================================
 */

type SubmittingAction =
  | null
  | "active"
  | "lock"
  | "password"
  | "force-password"
  | "sessions";

/**
 * ============================================================================
 * Action → View
 * ============================================================================
 */

function getViewFromAction(
  action:
    | UserSecurityAction
    | null
    | undefined,
): SecurityView {
  switch (action) {
    case "enable_user":
    case "disable_user":
      return "account";

    case "lock_user":
    case "unlock_user":
      return "lock";

    case "reset_password":
      return "password";

    case "force_password_change":
      return "force-password";

    case "active_sessions":
      return "sessions";

    case "revoke_sessions":
      return "revoke-sessions";

    default:
      return "account";
  }
}

/**
 * ============================================================================
 * Action Label
 * ============================================================================
 */

function getActionLabel(
  action:
    | UserSecurityAction
    | null
    | undefined,
): string {
  switch (action) {
    case "enable_user":
      return "Enable User";

    case "disable_user":
      return "Disable User";

    case "lock_user":
      return "Lock User";

    case "unlock_user":
      return "Unlock User";

    case "reset_password":
      return "Reset Password";

    case "force_password_change":
      return "Force Password Change";

    case "active_sessions":
      return "Active Sessions";

    case "revoke_sessions":
      return "Revoke Sessions";

    default:
      return "Security Controls";
  }
}

/**
 * ============================================================================
 * Error Handling
 * ============================================================================
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

  if (error instanceof Error) {
    return error.message;
  }

  return fallback;
}

/**
 * ============================================================================
 * Component
 * ============================================================================
 */

export default function UserSecurityActions({
  user,
  action = null,
  onUpdated,
  onSessionsRevoked,
  onCancel,
}: UserSecurityActionsProps) {
  /**
   * ========================================================================
   * RBAC
   * ========================================================================
   */

  const hasPermission =
    useAuthStore(
      (state) =>
        state.hasPermission,
    );

  const canManageUsers =
    hasPermission(
      USERS_MANAGE,
    );

  const canResetPassword =
    canManageUsers;

  const canManageSessions =
    canManageUsers;

  const hasSecurityPermission =
    canManageUsers ||
    canResetPassword ||
    canManageSessions;

  /**
   * ========================================================================
   * View
   * ========================================================================
   */

  const [
    activeView,
    setActiveView,
  ] = useState<SecurityView>(
    getViewFromAction(action),
  );

  /**
   * ========================================================================
   * Request State
   * ========================================================================
   */

  const [
    submitting,
    setSubmitting,
  ] = useState<SubmittingAction>(
    null,
  );

  const [
    error,
    setError,
  ] = useState<string | null>(
    null,
  );

  const [
    success,
    setSuccess,
  ] = useState<string | null>(
    null,
  );

  /**
   * ========================================================================
   * Password State
   * ========================================================================
   */

  const [
    newPassword,
    setNewPassword,
  ] = useState("");

  const [
    confirmPassword,
    setConfirmPassword,
  ] = useState("");

  const [
    showNewPassword,
    setShowNewPassword,
  ] = useState(false);

  const [
    showConfirmPassword,
    setShowConfirmPassword,
  ] = useState(false);

  /**
   * ========================================================================
   * Synchronize Action
   * ========================================================================
   */

  useEffect(() => {
    setActiveView(
      getViewFromAction(action),
    );

    setSubmitting(null);
    setError(null);
    setSuccess(null);

    clearPasswordState();
  }, [
    user.user_id,
    action,
  ]);

  /**
   * ========================================================================
   * Helpers
   * ========================================================================
   */

  function clearMessages() {
    setError(null);
    setSuccess(null);
  }

  function isSubmitting() {
    return submitting !== null;
  }

  function clearPasswordState() {
    setNewPassword("");
    setConfirmPassword("");
    setShowNewPassword(false);
    setShowConfirmPassword(false);
  }

  /**
   * ========================================================================
   * Enable / Disable
   * ========================================================================
   */

  async function handleActiveChange(
    isActive: boolean,
  ) {
    if (
      !canManageUsers ||
      isSubmitting()
    ) {
      return;
    }

    clearMessages();
    setSubmitting("active");

    try {
      const updatedUser =
        await usersApi.setActive(
          user.user_id,
          {
            is_active: isActive,
          },
        );

      setSuccess(
        isActive
          ? "User account activated successfully."
          : "User account disabled successfully.",
      );

      onUpdated?.(
        updatedUser,
      );
    } catch (requestError) {
      setError(
        getErrorMessage(
          requestError,
          "Unable to update account state.",
        ),
      );
    } finally {
      setSubmitting(null);
    }
  }

  /**
   * ========================================================================
   * Lock / Unlock
   * ========================================================================
   */

  async function handleLockChange(
    isLocked: boolean,
  ) {
    if (
      !canManageUsers ||
      isSubmitting()
    ) {
      return;
    }

    clearMessages();
    setSubmitting("lock");

    try {
      const updatedUser =
        await usersApi.setLocked(
          user.user_id,
          {
            is_locked: isLocked,
          },
        );

      setSuccess(
        isLocked
          ? "User account locked successfully."
          : "User account unlocked successfully.",
      );

      onUpdated?.(
        updatedUser,
      );
    } catch (requestError) {
      setError(
        getErrorMessage(
          requestError,
          "Unable to update lock state.",
        ),
      );
    } finally {
      setSubmitting(null);
    }
  }

  /**
   * ========================================================================
   * Password Reset
   * ========================================================================
   */

  async function handlePasswordReset(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    if (
      !canResetPassword ||
      isSubmitting()
    ) {
      return;
    }

    clearMessages();

    if (!newPassword) {
      setError(
        "New password is required.",
      );
      return;
    }

    if (newPassword.length < 8) {
      setError(
        "New password must contain at least 8 characters.",
      );
      return;
    }

    if (newPassword.length > 256) {
      setError(
        "New password must not exceed 256 characters.",
      );
      return;
    }

    if (!confirmPassword) {
      setError(
        "Please confirm the new password.",
      );
      return;
    }

    if (
      newPassword !==
      confirmPassword
    ) {
      setError(
        "Passwords do not match.",
      );
      return;
    }

    setSubmitting("password");

    try {
      const response =
        await usersApi.resetPassword(
          user.user_id,
          {
            new_password:
              newPassword,
          },
        );

      clearPasswordState();

      setSuccess(
        response.message ||
          "Password reset successfully.",
      );
    } catch (requestError) {
      clearPasswordState();

      setError(
        getErrorMessage(
          requestError,
          "Unable to reset user password.",
        ),
      );
    } finally {
      setSubmitting(null);
    }
  }

  /**
   * ========================================================================
   * Force Password Change
   * ========================================================================
   *
   * No dedicated API contract was provided in the existing component.
   *
   * Do NOT silently call reset-password because that would perform a
   * different security operation.
   * ========================================================================
   */

  function handleForcePasswordChange() {
    if (
      !canManageUsers ||
      isSubmitting()
    ) {
      return;
    }

    clearMessages();

    setError(
      "Force password change requires a dedicated backend endpoint.",
    );
  }

  /**
   * ========================================================================
   * Active Sessions
   * ========================================================================
   */

  function handleActiveSessions() {
    if (
      !canManageSessions ||
      isSubmitting()
    ) {
      return;
    }

    clearMessages();

    setError(
      "Active session listing requires the backend active-sessions endpoint.",
    );
  }

  /**
   * ========================================================================
   * Revoke Sessions
   * ========================================================================
   */

  async function handleRevokeSessions() {
    if (
      !canManageSessions ||
      isSubmitting()
    ) {
      return;
    }

    clearMessages();
    setSubmitting("sessions");

    try {
      const response =
        await usersApi.revokeSessions(
          user.user_id,
        );

      setSuccess(
        response.message ||
          `Revoked ${response.revoked_count} session(s).`,
      );

      onSessionsRevoked?.();
    } catch (requestError) {
      setError(
        getErrorMessage(
          requestError,
          "Unable to revoke user sessions.",
        ),
      );
    } finally {
      setSubmitting(null);
    }
  }

  /**
   * ========================================================================
   * Permission Guard
   * ========================================================================
   */

  if (!hasSecurityPermission) {
    return (
      <section className="user-security-actions">
        <div className="form-heading">
          <div>
            <h3>
              Security Actions
            </h3>

            <p>
              Manage account state,
              password security, and
              active sessions.
            </p>
          </div>

          <ShieldAlert
            size={20}
            aria-hidden="true"
          />
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
            to manage security controls
            for this account.
          </span>
        </div>
      </section>
    );
  }

  /**
   * ========================================================================
   * Render
   * ========================================================================
   */

  return (
    <section className="user-security-actions">
      <div className="form-heading">
        <div>
          <h3>
            Security Actions
          </h3>

          <p>
            Manage security controls
            for{" "}
            <strong>
              {user.username}
            </strong>
            .
          </p>
        </div>

        <ShieldCheck
          size={20}
          aria-hidden="true"
        />
      </div>

      <div className="notice">
        <ShieldCheck
          size={16}
          aria-hidden="true"
        />

        <span>
          Selected action:{" "}
          <strong>
            {getActionLabel(action)}
          </strong>
        </span>
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

      {success && (
        <div
          className="notice healthy"
          role="status"
        >
          <ShieldCheck
            size={16}
            aria-hidden="true"
          />

          <span>
            {success}
          </span>
        </div>
      )}

      {/**
       * ====================================================================
       * ACCOUNT
       * ====================================================================
       */}

      {activeView === "account" &&
        canManageUsers && (
          <div className="security-action-group">
            <div>
              <strong>
                Account Status
              </strong>

              <p>
                {user.is_active
                  ? "This account is currently active."
                  : "This account is currently disabled."}
              </p>
            </div>

            {user.is_active ? (
              <button
                type="button"
                className="secondary-button"
                onClick={() =>
                  handleActiveChange(
                    false,
                  )
                }
                disabled={
                  isSubmitting()
                }
              >
                <UserX
                  size={14}
                  aria-hidden="true"
                />

                {submitting ===
                "active"
                  ? "Updating..."
                  : "Disable Account"}
              </button>
            ) : (
              <button
                type="button"
                className="primary-button"
                onClick={() =>
                  handleActiveChange(
                    true,
                  )
                }
                disabled={
                  isSubmitting()
                }
              >
                <UserCheck
                  size={14}
                  aria-hidden="true"
                />

                {submitting ===
                "active"
                  ? "Updating..."
                  : "Activate Account"}
              </button>
            )}
          </div>
        )}

      {/**
       * ====================================================================
       * LOCK
       * ====================================================================
       */}

      {activeView === "lock" &&
        canManageUsers && (
          <div className="security-action-group">
            <div>
              <strong>
                Lock State
              </strong>

              <p>
                {user.is_locked
                  ? "This account is currently locked."
                  : "This account is currently unlocked."}
              </p>
            </div>

            {user.is_locked ? (
              <button
                type="button"
                className="primary-button"
                onClick={() =>
                  handleLockChange(
                    false,
                  )
                }
                disabled={
                  isSubmitting()
                }
              >
                <Unlock
                  size={14}
                  aria-hidden="true"
                />

                {submitting ===
                "lock"
                  ? "Updating..."
                  : "Unlock Account"}
              </button>
            ) : (
              <button
                type="button"
                className="secondary-button"
                onClick={() =>
                  handleLockChange(
                    true,
                  )
                }
                disabled={
                  isSubmitting()
                }
              >
                <Lock
                  size={14}
                  aria-hidden="true"
                />

                {submitting ===
                "lock"
                  ? "Updating..."
                  : "Lock Account"}
              </button>
            )}
          </div>
        )}

      {/**
       * ====================================================================
       * PASSWORD RESET
       * ====================================================================
       */}

      {activeView === "password" &&
        canResetPassword && (
          <form
            className="security-form"
            onSubmit={
              handlePasswordReset
            }
            noValidate
          >
            <div className="security-action-group">
              <div>
                <strong>
                  Reset Password
                </strong>

                <p>
                  Set a new password for
                  this user account.
                </p>
              </div>
            </div>

            <div className="form-field">
              <label htmlFor="security-new-password">
                New Password
              </label>

              <div className="password-field">
                <input
                  id="security-new-password"
                  type={
                    showNewPassword
                      ? "text"
                      : "password"
                  }
                  value={
                    newPassword
                  }
                  onChange={(
                    event,
                  ) => {
                    setNewPassword(
                      event.target.value,
                    );
                    clearMessages();
                  }}
                  autoComplete="new-password"
                  disabled={
                    isSubmitting()
                  }
                  minLength={8}
                  maxLength={256}
                  required
                />

                <button
                  type="button"
                  className="icon-button"
                  onClick={() =>
                    setShowNewPassword(
                      (
                        current,
                      ) => !current,
                    )
                  }
                  disabled={
                    isSubmitting()
                  }
                  aria-label={
                    showNewPassword
                      ? "Hide new password"
                      : "Show new password"
                  }
                >
                  {showNewPassword ? (
                    <EyeOff
                      size={16}
                      aria-hidden="true"
                    />
                  ) : (
                    <Eye
                      size={16}
                      aria-hidden="true"
                    />
                  )}
                </button>
              </div>
            </div>

            <div className="form-field">
              <label htmlFor="security-confirm-password">
                Confirm Password
              </label>

              <div className="password-field">
                <input
                  id="security-confirm-password"
                  type={
                    showConfirmPassword
                      ? "text"
                      : "password"
                  }
                  value={
                    confirmPassword
                  }
                  onChange={(
                    event,
                  ) => {
                    setConfirmPassword(
                      event.target.value,
                    );
                    clearMessages();
                  }}
                  autoComplete="new-password"
                  disabled={
                    isSubmitting()
                  }
                  minLength={8}
                  maxLength={256}
                  required
                />

                <button
                  type="button"
                  className="icon-button"
                  onClick={() =>
                    setShowConfirmPassword(
                      (
                        current,
                      ) => !current,
                    )
                  }
                  disabled={
                    isSubmitting()
                  }
                  aria-label={
                    showConfirmPassword
                      ? "Hide password confirmation"
                      : "Show password confirmation"
                  }
                >
                  {showConfirmPassword ? (
                    <EyeOff
                      size={16}
                      aria-hidden="true"
                    />
                  ) : (
                    <Eye
                      size={16}
                      aria-hidden="true"
                    />
                  )}
                </button>
              </div>
            </div>

            <div className="notice">
              <ShieldAlert
                size={16}
                aria-hidden="true"
              />

              <span>
                The password is sent to the
                backend only and is cleared
                from frontend state after the
                request completes.
              </span>
            </div>

            <div className="form-actions">
              {onCancel && (
                <button
                  type="button"
                  className="secondary-button"
                  onClick={
                    onCancel
                  }
                  disabled={
                    isSubmitting()
                  }
                >
                  Cancel
                </button>
              )}

              <button
                type="submit"
                className="primary-button"
                disabled={
                  isSubmitting() ||
                  newPassword.length <
                    8 ||
                  confirmPassword.length <
                    8 ||
                  newPassword !==
                    confirmPassword
                }
              >
                <KeyRound
                  size={14}
                  aria-hidden="true"
                />

                {submitting ===
                "password"
                  ? "Resetting..."
                  : "Confirm Password Reset"}
              </button>
            </div>
          </form>
        )}

      {/**
       * ====================================================================
       * FORCE PASSWORD CHANGE
       * ====================================================================
       */}

      {activeView ===
        "force-password" &&
        canManageUsers && (
          <div className="security-action-group">
            <div>
              <strong>
                Force Password Change
              </strong>

              <p>
                Require this user to change
                their password on the next
                authentication.
              </p>
            </div>

            <button
              type="button"
              className="secondary-button"
              onClick={
                handleForcePasswordChange
              }
              disabled={
                isSubmitting()
              }
            >
              <KeyRound
                size={14}
                aria-hidden="true"
              />

              Force Password Change
            </button>
          </div>
        )}

      {/**
       * ====================================================================
       * ACTIVE SESSIONS
       * ====================================================================
       */}

      {activeView === "sessions" &&
        canManageSessions && (
          <div className="security-action-group">
            <div>
              <strong>
                Active Sessions
              </strong>

              <p>
                Review active sessions
                associated with this user.
              </p>
            </div>

            <button
              type="button"
              className="secondary-button"
              onClick={
                handleActiveSessions
              }
              disabled={
                isSubmitting()
              }
            >
              <UsersRound
                size={14}
                aria-hidden="true"
              />

              View Active Sessions
            </button>
          </div>
        )}

      {/**
       * ====================================================================
       * REVOKE SESSIONS
       * ====================================================================
       */}

      {activeView ===
        "revoke-sessions" &&
        canManageSessions && (
          <div className="security-action-group">
            <div>
              <strong>
                Revoke Active Sessions
              </strong>

              <p>
                Invalidate all active
                sessions associated with
                this user.
              </p>
            </div>

            <button
              type="button"
              className="secondary-button"
              onClick={
                handleRevokeSessions
              }
              disabled={
                isSubmitting()
              }
            >
              <LogOut
                size={14}
                aria-hidden="true"
              />

              {submitting ===
              "sessions"
                ? "Revoking..."
                : "Revoke Sessions"}
            </button>
          </div>
        )}
    </section>
  );
}