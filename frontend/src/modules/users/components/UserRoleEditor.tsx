/**
 * ============================================================================
 * SentinelSIEM — User Role Editor
 * ============================================================================
 *
 * Enterprise RBAC role-management workflow.
 *
 * Responsibilities:
 * - Display selected user identity
 * - Display current role
 * - Allow authorized administrators to select a new role
 * - Validate the selected role
 * - Submit role changes through usersApi
 * - Synchronize with the canonical backend response
 * - Provide success/error feedback
 * - Allow safe cancellation
 *
 * This component does NOT:
 * - Handle passwords
 * - Handle sessions
 * - Enable/disable accounts
 * - Lock/unlock accounts
 * - Delete users
 *
 * Security:
 * - Frontend users:manage permission is defense-in-depth only.
 * - Backend authorization remains authoritative.
 * - User ID is read-only.
 * ============================================================================
 */

import {
  useEffect,
  useState,
  type ChangeEvent,
  type FormEvent,
} from "react";

import {
  AlertTriangle,
  Check,
  CheckCircle2,
  ChevronDown,
  Copy,
  Info,
  Loader2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  UserRound,
} from "lucide-react";

import { useAuthStore } from "../../../store/auth";

import {
  ROLE_LIST,
  ROLES,
  formatRole,
  isRole,
  type Role,
} from "../../../auth/rbac";

import { USERS_MANAGE } from "../permissions";

import { usersApi } from "../api";

import type {
  ChangeRoleRequest,
  User,
} from "../types";

/* ============================================================================
 * Props
 * ========================================================================== */

export interface UserRoleEditorProps {
  /**
   * User currently being managed.
   */
  user: User;

  /**
   * Called after successful backend update.
   */
  onUpdated?: (
    user: User,
  ) => void;

  /**
   * Close/cancel the editor.
   */
  onCancel?: () => void;
}

/* ============================================================================
 * Helpers
 * ========================================================================== */

/**
 * Resolve a backend role into a trusted frontend Role.
 *
 * Unknown backend values are never trusted as
 * valid frontend RBAC roles.
 */
function resolveRole(
  user: User,
): Role {
  const candidate =
    user.roles[0]?.trim();

  if (
    candidate &&
    isRole(candidate)
  ) {
    return candidate;
  }

  return ROLES.VIEWER;
}

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

/**
 * Generate compact initials for the user.
 *
 * Safe with noUncheckedIndexedAccess.
 */
function getInitials(
  displayName:
    | string
    | null
    | undefined,
  username: string,
): string {
  const source =
    displayName?.trim() ||
    username.trim();

  if (!source) {
    return "U";
  }

  const parts = source
    .split(/\s+/)
    .filter(Boolean);

  const first = parts[0];

  if (!first) {
    return "U";
  }

  if (parts.length >= 2) {
    const last =
      parts[parts.length - 1];

    if (last) {
      return (
        `${first.charAt(0)}${last.charAt(0)}`
      ).toUpperCase();
    }
  }

  return first
    .slice(0, 2)
    .toUpperCase();
}

/* ============================================================================
 * User Role Editor
 * ========================================================================== */

export default function UserRoleEditor({
  user,
  onUpdated,
  onCancel,
}: UserRoleEditorProps) {
  /* ==========================================================================
   * RBAC
   * ======================================================================== */

  const hasPermission =
    useAuthStore(
      (state) =>
        state.hasPermission,
    );

  const canManageUsers =
    hasPermission(
      USERS_MANAGE,
    );

  /* ==========================================================================
   * Current Role
   * ======================================================================== */

  const currentRole =
    resolveRole(user);

  /* ==========================================================================
   * Form State
   * ======================================================================== */

  const [
    role,
    setRole,
  ] = useState<Role>(
    currentRole,
  );

  /* ==========================================================================
   * Request State
   * ======================================================================== */

  const [
    submitting,
    setSubmitting,
  ] = useState(false);

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

  /* ==========================================================================
   * Utility State
   * ======================================================================== */

  const [
    copiedUserId,
    setCopiedUserId,
  ] = useState(false);

  /* ==========================================================================
   * Derived Values
   * ======================================================================== */

  const displayName =
    user.display_name?.trim() ||
    user.username;

  const initials =
    getInitials(
      user.display_name,
      user.username,
    );

  const roleChanged =
    role !== currentRole;

  /* ==========================================================================
   * Synchronize User
   * ======================================================================== */

  useEffect(() => {
    setRole(
      resolveRole(user),
    );

    setSubmitting(false);
    setError(null);
    setSuccess(null);
    setCopiedUserId(false);
  }, [
    user.user_id,
    user.username,
    user.roles,
  ]);

  /* ==========================================================================
   * Clear Feedback
   * ======================================================================== */

  function clearFeedback() {
    setError(null);
    setSuccess(null);
  }

  /* ==========================================================================
   * Role Selection
   * ======================================================================== */

  function handleRoleChange(
    event: ChangeEvent<HTMLSelectElement>,
  ) {
    const nextRole =
      event.target.value;

    if (
      !isRole(nextRole)
    ) {
      setError(
        "Invalid role selection.",
      );

      setSuccess(null);

      return;
    }

    setRole(nextRole);

    clearFeedback();
  }

  /* ==========================================================================
   * Copy User ID
   * ======================================================================== */

  async function handleCopyUserId() {
    if (submitting) {
      return;
    }

    try {
      await navigator.clipboard.writeText(
        user.user_id,
      );

      setCopiedUserId(true);

      window.setTimeout(() => {
        setCopiedUserId(false);
      }, 1800);
    } catch {
      setCopiedUserId(false);
    }
  }

  /* ==========================================================================
   * Submit
   * ======================================================================== */

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    if (submitting) {
      return;
    }

    clearFeedback();

    /* ------------------------------------------------------------------------
     * Permission
     * ---------------------------------------------------------------------- */

    if (!canManageUsers) {
      setError(
        "You do not have permission to change user roles.",
      );

      return;
    }

    /* ------------------------------------------------------------------------
     * Role Validation
     * ---------------------------------------------------------------------- */

    if (!isRole(role)) {
      setError(
        "Please select a valid role.",
      );

      return;
    }

    /* ------------------------------------------------------------------------
     * No-op Protection
     * ---------------------------------------------------------------------- */

    if (!roleChanged) {
      setError(
        "Select a different role before applying the change.",
      );

      return;
    }

    /* ------------------------------------------------------------------------
     * Request Payload
     * ---------------------------------------------------------------------- */

    const payload: ChangeRoleRequest = {
      role,
    };

    setSubmitting(true);

    try {
      const updatedUser =
        await usersApi.changeRole(
          user.user_id,
          payload,
        );

      /* ----------------------------------------------------------------------
       * Canonical backend response
       * -------------------------------------------------------------------- */

      const updatedRole =
        resolveRole(
          updatedUser,
        );

      setRole(
        updatedRole,
      );

      setSuccess(
        `Role successfully changed to ${formatRole(
          updatedRole,
        )}.`,
      );

      /**
       * Parent owns authoritative user state.
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
          "Unable to update the user's role.",
        ),
      );
    } finally {
      setSubmitting(false);
    }
  }

  /* ==========================================================================
   * Cancel
   * ======================================================================== */

  function handleCancel() {
    if (submitting) {
      return;
    }

    clearFeedback();

    onCancel?.();
  }

  /* ==========================================================================
   * Permission Restricted
   * ======================================================================== */

  if (!canManageUsers) {
    return (
      <section
        className="change-role-form"
        aria-labelledby="change-role-permission-title"
      >
        {/* ==================================================================
            Header
            ================================================================== */}

        <header className="change-role-form-header">
          <div className="change-role-title-group">
            <div
              className="change-role-form-icon danger"
              aria-hidden="true"
            >
              <ShieldAlert
                size={19}
              />
            </div>

            <div>
              <span className="change-role-eyebrow">
                ACCESS CONTROL
              </span>

              <h3 id="change-role-permission-title">
                Change User Role
              </h3>

              <p>
                Manage the RBAC access level
                assigned to this account.
              </p>
            </div>
          </div>
        </header>

        {/* ==================================================================
            Restricted Body
            ================================================================== */}

        <div className="change-role-form-body">
          <section
            className="change-role-permission-card"
            role="alert"
          >
            <div
              className="change-role-permission-icon"
              aria-hidden="true"
            >
              <ShieldAlert
                size={20}
              />
            </div>

            <div>
              <strong>
                Role management restricted
              </strong>

              <p>
                Your account does not have
                the required permission to
                change this user's role.
              </p>

              <span>
                Required permission:{" "}
                <code>
                  {USERS_MANAGE}
                </code>
              </span>
            </div>
          </section>
        </div>

        {/* ==================================================================
            Footer
            ================================================================== */}

        {onCancel && (
          <footer className="change-role-form-footer">
            <div />

            <div className="change-role-form-actions">
              <button
                type="button"
                className="secondary-button change-role-cancel-button"
                onClick={
                  handleCancel
                }
              >
                Close
              </button>
            </div>
          </footer>
        )}
      </section>
    );
  }

  /* ==========================================================================
   * Main Render
   * ======================================================================== */

  return (
    <form
      className="change-role-form"
      onSubmit={
        handleSubmit
      }
      noValidate
    >
      {/* =====================================================================
          Header
          ================================================================== */}

      <header className="change-role-form-header">
        <div className="change-role-title-group">
          <div
            className="change-role-form-icon"
            aria-hidden="true"
          >
            <ShieldCheck
              size={19}
            />
          </div>

          <div>
            <span className="change-role-eyebrow">
              ACCESS CONTROL
            </span>

            <h3>
              Change User Role
            </h3>

            <p>
              Manage the RBAC access level
              assigned to this account.
            </p>
          </div>
        </div>
      </header>

      {/* =====================================================================
          Body
          ================================================================== */}

      <div className="change-role-form-body">

        {/* ===================================================================
            User Profile
            ================================================================= */}

        <section
          className="change-role-profile-card"
          aria-label="Selected user"
        >
          <div
            className="change-role-avatar"
            aria-hidden="true"
          >
            {initials}
          </div>

          <div className="change-role-profile-content">
            <strong>
              {displayName}
            </strong>

            <span>
              @{user.username}
            </span>

            <span>
              SentinelSIEM user account
            </span>
          </div>

          <div className="change-role-profile-role">
            <span>
              CURRENT ROLE
            </span>

            <strong>
              {formatRole(
                currentRole,
              )}
            </strong>
          </div>
        </section>

        {/* ===================================================================
            Error
            ================================================================= */}

        {error && (
          <div
            className="change-role-alert change-role-alert-error"
            role="alert"
            aria-live="assertive"
          >
            <div
              className="change-role-alert-icon"
              aria-hidden="true"
            >
              <AlertTriangle
                size={16}
              />
            </div>

            <div>
              <strong>
                Role update failed
              </strong>

              <span>
                {error}
              </span>
            </div>
          </div>
        )}

        {/* ===================================================================
            Success
            ================================================================= */}

        {success && (
          <div
            className="change-role-alert change-role-alert-success"
            role="status"
            aria-live="polite"
          >
            <div
              className="change-role-alert-icon"
              aria-hidden="true"
            >
              <CheckCircle2
                size={16}
              />
            </div>

            <div>
              <strong>
                Changes saved
              </strong>

              <span>
                {success}
              </span>
            </div>
          </div>
        )}

        {/* ===================================================================
            Role Assignment
            ================================================================= */}

        <section className="change-role-section">
          <div className="change-role-section-heading">
            <div>
              <span className="change-role-section-kicker">
                RBAC
              </span>

              <h4>
                Role Assignment
              </h4>

              <p>
                Review the current access
                level and select the role
                that should be assigned to
                this account.
              </p>
            </div>

            <Shield
              size={17}
              aria-hidden="true"
            />
          </div>

          {/* -----------------------------------------------------------------
              Identity
              ----------------------------------------------------------------- */}

          <div className="change-role-identity-grid">

            {/* User */}

            <div className="change-role-field">
              <label htmlFor="role-editor-user">
                User
              </label>

              <div className="change-role-input-wrap readonly">
                <UserRound
                  size={15}
                  aria-hidden="true"
                />

                <input
                  id="role-editor-user"
                  type="text"
                  value={
                    user.username
                  }
                  readOnly
                  aria-readonly="true"
                  tabIndex={-1}
                />
              </div>
            </div>

            {/* User ID */}

            <div className="change-role-field">
              <label htmlFor="role-editor-user-id">
                User ID
              </label>

              <div className="change-role-readonly">
                <UserRound
                  size={15}
                  aria-hidden="true"
                />

                <input
                  id="role-editor-user-id"
                  type="text"
                  value={
                    user.user_id
                  }
                  readOnly
                  aria-readonly="true"
                  tabIndex={-1}
                />

                <button
                  type="button"
                  className="change-role-copy-button"
                  onClick={
                    handleCopyUserId
                  }
                  disabled={
                    submitting
                  }
                  aria-label={
                    copiedUserId
                      ? "User ID copied"
                      : "Copy user ID"
                  }
                  title={
                    copiedUserId
                      ? "Copied"
                      : "Copy User ID"
                  }
                >
                  {copiedUserId ? (
                    <Check
                      size={14}
                      aria-hidden="true"
                    />
                  ) : (
                    <Copy
                      size={14}
                      aria-hidden="true"
                    />
                  )}
                </button>
              </div>
            </div>
          </div>

          {/* -----------------------------------------------------------------
              Role Comparison
              ----------------------------------------------------------------- */}

          <div className="change-role-comparison">

            {/* Current */}

            <div className="change-role-comparison-card current">
              <div className="change-role-comparison-top">
                <span>
                  CURRENT
                </span>

                <Shield
                  size={14}
                  aria-hidden="true"
                />
              </div>

              <strong>
                {formatRole(
                  currentRole,
                )}
              </strong>

              <p>
                Current access level
              </p>
            </div>

            {/* Arrow */}

            <div
              className="change-role-comparison-arrow"
              aria-hidden="true"
            >
              <span />
              →
              <span />
            </div>

            {/* Proposed */}

            <div
              className={
                roleChanged
                  ? "change-role-comparison-card proposed changed"
                  : "change-role-comparison-card proposed"
              }
            >
              <div className="change-role-comparison-top">
                <span>
                  PROPOSED
                </span>

                <ShieldCheck
                  size={14}
                  aria-hidden="true"
                />
              </div>

              <strong>
                {formatRole(role)}
              </strong>

              <p>
                {roleChanged
                  ? "New access level"
                  : "No change selected"}
              </p>
            </div>
          </div>

          {/* -----------------------------------------------------------------
              New Role
              ----------------------------------------------------------------- */}

          <div className="change-role-field change-role-new-role-field">
            <label htmlFor="user-role">
              New Role
              <span aria-hidden="true">
                *
              </span>
            </label>

            <div className="change-role-select-wrap">
              <Shield
                size={16}
                aria-hidden="true"
              />

              <select
                id="user-role"
                name="role"
                value={role}
                onChange={
                  handleRoleChange
                }
                disabled={
                  submitting
                }
                required
              >
                {ROLE_LIST.map(
                  (
                    roleOption,
                  ) => (
                    <option
                      key={
                        roleOption
                      }
                      value={
                        roleOption
                      }
                    >
                      {formatRole(
                        roleOption,
                      )}
                    </option>
                  ),
                )}
              </select>

              <ChevronDown
                size={15}
                aria-hidden="true"
              />
            </div>

            <span className="change-role-field-help">
              Select the RBAC role
              appropriate for this user's
              required access.
            </span>
          </div>
        </section>

        {/* ===================================================================
            Impact Notice
            ================================================================= */}

        <section
          className={
            roleChanged
              ? "change-role-impact-card changed"
              : "change-role-impact-card"
          }
          role="note"
        >
          <div
            className="change-role-impact-icon"
            aria-hidden="true"
          >
            {roleChanged ? (
              <ShieldAlert
                size={17}
              />
            ) : (
              <Info
                size={17}
              />
            )}
          </div>

          <div className="change-role-impact-content">
            <strong>
              {roleChanged
                ? "Permission change pending"
                : "Role assignment"}
            </strong>

            <p>
              {roleChanged
                ? `This account will change from ${formatRole(
                    currentRole,
                  )} to ${formatRole(
                    role,
                  )}. Effective permissions are determined by the SentinelSIEM RBAC policy.`
                : "Changing the assigned role changes the permissions available to this account."}
            </p>
          </div>
        </section>

        {/* ===================================================================
            Security Notice
            ================================================================= */}

        <section
          className="change-role-security-card"
          role="note"
        >
          <div
            className="change-role-security-icon"
            aria-hidden="true"
          >
            <ShieldCheck
              size={17}
            />
          </div>

          <div>
            <strong>
              Privileged security operation
            </strong>

            <p>
              Role changes affect account
              authorization. Verify that
              the selected role matches the
              user's operational
              responsibilities. Passwords,
              account state, lock state, and
              sessions are managed through
              their dedicated security
              controls.
            </p>
          </div>
        </section>

      </div>

      {/* =====================================================================
          Footer
          ================================================================== */}

      <footer className="change-role-form-footer">
        <div className="change-role-footer-meta">
          <span>
            <span
              className="change-role-required-dot"
              aria-hidden="true"
            />

            Privileged role assignment
          </span>
        </div>

        <div className="change-role-form-actions">
          {onCancel && (
            <button
              type="button"
              className="secondary-button change-role-cancel-button"
              onClick={
                handleCancel
              }
              disabled={
                submitting
              }
            >
              Cancel
            </button>
          )}

          <button
            type="submit"
            className="primary-button change-role-update-button"
            disabled={
              submitting ||
              !roleChanged
            }
          >
            {submitting ? (
              <>
                <Loader2
                  size={15}
                  className="spin"
                  aria-hidden="true"
                />

                Updating Role...
              </>
            ) : (
              <>
                <ShieldCheck
                  size={15}
                  aria-hidden="true"
                />

                Update Role
              </>
            )}
          </button>
        </div>
      </footer>
    </form>
  );
}