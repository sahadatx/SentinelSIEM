/**
 * ============================================================================
 * SentinelSIEM — Edit User Form
 * ============================================================================
 *
 * Responsibilities:
 * - Edit an existing SentinelSIEM user
 * - Update username
 * - Update email address
 * - Display immutable User ID
 * - Provide copy User ID functionality
 * - Validate editable fields
 * - Submit changes through usersApi.update()
 * - Display loading/error/success states
 * - Notify the parent after successful update
 *
 * Security:
 * - User ID is read-only
 * - No password is handled here
 * - No role changes are handled here
 * - No account-state changes are handled here
 * - No lock/unlock operations are handled here
 * - No session operations are handled here
 * - Backend authorization remains the final security boundary
 *
 * ============================================================================
 */

import {
  useEffect,
  useState,
  type ChangeEvent,
  type FormEvent,
} from "react";

import {
  Check,
  CheckCircle2,
  Copy,
  Info,
  Loader2,
  Mail,
  Save,
  ShieldCheck,
  UserRound,
} from "lucide-react";

import { usersApi } from "../api";

import type {
  UpdateUserRequest,
  User,
} from "../types";

/* ============================================================================
 * Constants
 * ========================================================================== */

const USERNAME_MIN_LENGTH = 3;
const USERNAME_MAX_LENGTH = 150;

const EMAIL_MAX_LENGTH = 320;

/* ============================================================================
 * Props
 * ========================================================================== */

export interface EditUserFormProps {
  /**
   * User currently being edited.
   */
  user: User;

  /**
   * Called after the backend successfully
   * updates the user.
   */
  onUpdated?: (
    user: User,
  ) => void;

  /**
   * Close/cancel the editing workflow.
   */
  onCancel?: () => void;
}

/* ============================================================================
 * Error Helper
 * ========================================================================== */

/**
 * Convert an unknown API error into a
 * safe user-facing message.
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

  return "Unable to update user.";
}

/* ============================================================================
 * Validation Helpers
 * ========================================================================== */

/**
 * Validate username.
 */
function validateUsername(
  value: string,
): string | null {
  if (!value) {
    return "Username is required.";
  }

  if (
    value.length <
    USERNAME_MIN_LENGTH
  ) {
    return `Username must be at least ${USERNAME_MIN_LENGTH} characters.`;
  }

  if (
    value.length >
    USERNAME_MAX_LENGTH
  ) {
    return `Username must not exceed ${USERNAME_MAX_LENGTH} characters.`;
  }

  /**
   * Keep usernames predictable and safe
   * for routing, lookup, display, and
   * backend interoperability.
   */
  if (
    !/^[a-zA-Z0-9._-]+$/.test(
      value,
    )
  ) {
    return (
      "Username may contain only letters, " +
      "numbers, dots, underscores, and hyphens."
    );
  }

  return null;
}

/**
 * Validate email.
 *
 * This intentionally remains a basic
 * frontend validation. The backend remains
 * responsible for authoritative validation.
 */
function validateEmail(
  value: string,
): string | null {
  if (!value) {
    return "Email address is required.";
  }

  if (
    value.length >
    EMAIL_MAX_LENGTH
  ) {
    return `Email address must not exceed ${EMAIL_MAX_LENGTH} characters.`;
  }

  if (
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
      value,
    )
  ) {
    return "Please enter a valid email address.";
  }

  return null;
}

/* ============================================================================
 * Initials Helper
 * ========================================================================== */

/**
 * Generate a compact avatar abbreviation.
 *
 * Examples:
 * - "John Doe" -> "JD"
 * - "John"     -> "JO"
 * - "john"     -> "JO"
 * - empty      -> "U"
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

  const parts =
    source
      .split(/\s+/)
      .filter(Boolean);

  const first =
    parts[0];

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
 * Edit User Form
 * ========================================================================== */

export default function EditUserForm({
  user,
  onUpdated,
  onCancel,
}: EditUserFormProps) {
  /* ==========================================================================
   * Form State
   * ======================================================================== */

  const [
    username,
    setUsername,
  ] = useState(
    user.username,
  );

  const [
    email,
    setEmail,
  ] = useState(
    user.email,
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
   * Synchronize User
   * ======================================================================== */

  useEffect(() => {
    /**
     * Reset the form whenever a different
     * user is supplied by the parent.
     */
    setUsername(
      user.username,
    );

    setEmail(
      user.email,
    );

    setError(null);
    setSuccess(null);
    setCopiedUserId(false);
  }, [
    user.user_id,
    user.username,
    user.email,
  ]);

  /* ==========================================================================
   * Clear Feedback
   * ======================================================================== */

  function clearFeedback() {
    setError(null);
    setSuccess(null);
  }

  /* ==========================================================================
   * Username Change
   * ======================================================================== */

  function handleUsernameChange(
    event: ChangeEvent<HTMLInputElement>,
  ) {
    setUsername(
      event.target.value,
    );

    clearFeedback();
  }

  /* ==========================================================================
   * Email Change
   * ======================================================================== */

  function handleEmailChange(
    event: ChangeEvent<HTMLInputElement>,
  ) {
    setEmail(
      event.target.value,
    );

    clearFeedback();
  }

  /* ==========================================================================
   * Copy User ID
   * ======================================================================== */

  async function handleCopyUserId() {
    if (!user.user_id) {
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
      /**
       * Clipboard access can fail because
       * of browser security restrictions.
       *
       * No error is shown because copying
       * is an optional convenience feature.
       */
      setCopiedUserId(false);
    }
  }

  /* ==========================================================================
   * Form Validation
   * ======================================================================== */

  function validateForm(): boolean {
    const normalizedUsername =
      username.trim();

    const normalizedEmail =
      email.trim();

    /* ------------------------------------------------------------------------
     * Username
     * ---------------------------------------------------------------------- */

    const usernameError =
      validateUsername(
        normalizedUsername,
      );

    if (usernameError) {
      setError(
        usernameError,
      );

      return false;
    }

    /* ------------------------------------------------------------------------
     * Email
     * ---------------------------------------------------------------------- */

    const emailError =
      validateEmail(
        normalizedEmail,
      );

    if (emailError) {
      setError(
        emailError,
      );

      return false;
    }

    return true;
  }

  /* ==========================================================================
   * Submit
   * ======================================================================== */

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    /**
     * Prevent duplicate requests.
     */
    if (submitting) {
      return;
    }

    setError(null);
    setSuccess(null);

    /**
     * Frontend validation.
     */
    if (!validateForm()) {
      return;
    }

    /**
     * Normalize editable non-secret values.
     */
    const normalizedUsername =
      username.trim();

    const normalizedEmail =
      email.trim();

    /**
     * Only send fields owned by this form.
     *
     * Role, password, account state,
     * lock state, and sessions intentionally
     * remain outside this request.
     */
    const payload: UpdateUserRequest = {
      username:
        normalizedUsername,
      email:
        normalizedEmail,
    };

    setSubmitting(true);

    try {
      /**
       * Backend update.
       */
      const updatedUser =
        await usersApi.update(
          user.user_id,
          payload,
        );

      /**
       * Synchronize the form with the
       * authoritative backend response.
       */
      setUsername(
        updatedUser.username,
      );

      setEmail(
        updatedUser.email,
      );

      setSuccess(
        "User information updated successfully.",
      );

      /**
       * Notify the parent.
       *
       * The parent can refresh the page,
       * close the workflow, or update its
       * local user state.
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
        ),
      );
    } finally {
      setSubmitting(false);
    }
  }

  /* ==========================================================================
   * Derived Display Values
   * ======================================================================== */

  const displayName =
    user.display_name?.trim() ||
    user.username;

  const initials =
    getInitials(
      user.display_name,
      user.username,
    );

  const accountStatus =
    user.is_active
      ? "Active"
      : "Disabled";

  const lockStatus =
    user.is_locked
      ? "Locked"
      : "Unlocked";

  /* ==========================================================================
   * Render
   * ======================================================================== */

  return (
    <form
      className="edit-user-form"
      onSubmit={
        handleSubmit
      }
      noValidate
    >
      {/* ====================================================================
          Header
          ================================================================== */}

      <header className="edit-user-form-header">
        <div className="edit-user-form-title-group">
          <div
            className="edit-user-form-icon"
            aria-hidden="true"
          >
            <UserRound
              size={19}
            />
          </div>

          <div>
            <span className="edit-user-form-eyebrow">
              USER ACCOUNT
            </span>

            <h3>
              Edit User
            </h3>

            <p>
              Update account identity
              information without
              changing security controls.
            </p>
          </div>
        </div>
      </header>

      {/* ====================================================================
          Body
          ================================================================== */}

      <div className="edit-user-form-body">
        {/* ==================================================================
            Profile Summary
            ================================================================== */}

        <section
          className="edit-user-profile-card"
          aria-label="User summary"
        >
          <div
            className="edit-user-profile-avatar"
            aria-hidden="true"
          >
            {initials}
          </div>

          <div className="edit-user-profile-content">
            <strong>
              {displayName}
            </strong>

            <span>
              @{user.username}
            </span>

            <span className="edit-user-profile-email">
              <Mail
                size={12}
                aria-hidden="true"
              />

              {user.email}
            </span>
          </div>

          <div className="edit-user-profile-status">
            <StatusBadge
              label="Account"
              value={
                accountStatus
              }
              healthy={
                user.is_active
              }
            />

            <StatusBadge
              label="Security"
              value={
                lockStatus
              }
              healthy={
                !user.is_locked
              }
            />
          </div>
        </section>

        {/* ==================================================================
            Error
            ================================================================== */}

        {error && (
          <div
            className="edit-user-alert edit-user-alert-error"
            role="alert"
            aria-live="assertive"
          >
            <div
              className="edit-user-alert-icon"
              aria-hidden="true"
            >
              <Info
                size={15}
              />
            </div>

            <div>
              <strong>
                Update failed
              </strong>

              <span>
                {error}
              </span>
            </div>
          </div>
        )}

        {/* ==================================================================
            Success
            ================================================================== */}

        {success && (
          <div
            className="edit-user-alert edit-user-alert-success"
            role="status"
            aria-live="polite"
          >
            <div
              className="edit-user-alert-icon"
              aria-hidden="true"
            >
              <CheckCircle2
                size={15}
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

        {/* ==================================================================
            Identity Information
            ================================================================== */}

        <section className="edit-user-section">
          <div className="edit-user-section-heading">
            <div>
              <span className="edit-user-section-kicker">
                ACCOUNT
              </span>

              <h4>
                Identity Information
              </h4>

              <p>
                Update the public identity
                information associated with
                this account.
              </p>
            </div>

            <UserRound
              size={17}
              aria-hidden="true"
            />
          </div>

          {/* ================================================================
              User ID
              ================================================================ */}

          <div className="edit-user-field">
            <label htmlFor="edit-user-id">
              User ID
            </label>

            <div className="edit-user-readonly">
              <input
                id="edit-user-id"
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
                className="edit-user-copy-button"
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

            <span className="edit-user-field-help">
              Unique identifier. This value
              cannot be changed.
            </span>
          </div>

          {/* ================================================================
              Editable Fields
              ================================================================ */}

          <div className="edit-user-fields-grid">
            {/* ============================================================
                Username
                ============================================================ */}

            <div className="edit-user-field">
              <label htmlFor="edit-user-username">
                Username
                <span
                  aria-hidden="true"
                >
                  *
                </span>
              </label>

              <div className="edit-user-input-wrap">
                <UserRound
                  size={15}
                  aria-hidden="true"
                />

                <input
                  id="edit-user-username"
                  name="username"
                  type="text"
                  value={
                    username
                  }
                  onChange={
                    handleUsernameChange
                  }
                  autoComplete="username"
                  autoCapitalize="none"
                  autoCorrect="off"
                  spellCheck={
                    false
                  }
                  disabled={
                    submitting
                  }
                  required
                  minLength={
                    USERNAME_MIN_LENGTH
                  }
                  maxLength={
                    USERNAME_MAX_LENGTH
                  }
                  placeholder="Enter username"
                />
              </div>

              <span className="edit-user-field-help">
                {USERNAME_MIN_LENGTH}–
                {USERNAME_MAX_LENGTH} characters.
              </span>
            </div>

            {/* ============================================================
                Email
                ============================================================ */}

            <div className="edit-user-field">
              <label htmlFor="edit-user-email">
                Email Address
                <span
                  aria-hidden="true"
                >
                  *
                </span>
              </label>

              <div className="edit-user-input-wrap">
                <Mail
                  size={15}
                  aria-hidden="true"
                />

                <input
                  id="edit-user-email"
                  name="email"
                  type="email"
                  value={
                    email
                  }
                  onChange={
                    handleEmailChange
                  }
                  autoComplete="email"
                  autoCapitalize="none"
                  autoCorrect="off"
                  spellCheck={
                    false
                  }
                  disabled={
                    submitting
                  }
                  required
                  maxLength={
                    EMAIL_MAX_LENGTH
                  }
                  placeholder="name@example.com"
                />
              </div>

              <span className="edit-user-field-help">
                Use a valid email address.
              </span>
            </div>
          </div>
        </section>

        {/* ==================================================================
            Security Scope
            ================================================================== */}

        <section
          className="edit-user-info-card"
          role="note"
        >
          <div
            className="edit-user-info-icon"
            aria-hidden="true"
          >
            <ShieldCheck
              size={17}
            />
          </div>

          <div className="edit-user-info-content">
            <strong>
              Security controls are
              managed separately
            </strong>

            <p>
              This form changes only the
              username and email address.
              Role assignment, account
              activation, lock state,
              password management, and
              sessions remain under their
              dedicated security controls.
            </p>
          </div>
        </section>
      </div>

      {/* ====================================================================
          Footer
          ================================================================== */}

      <footer className="edit-user-form-footer">
        <div className="edit-user-footer-meta">
          <span>
            <span
              className="edit-user-required-dot"
              aria-hidden="true"
            />

            Required fields
          </span>
        </div>

        <div className="edit-user-form-actions">
          {onCancel && (
            <button
              type="button"
              className="secondary-button edit-user-cancel-button"
              onClick={
                onCancel
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
            className="primary-button edit-user-save-button"
            disabled={
              submitting
            }
            aria-busy={
              submitting
            }
          >
            {submitting ? (
              <>
                <Loader2
                  size={15}
                  className="spin"
                  aria-hidden="true"
                />

                <span>
                  Saving Changes...
                </span>
              </>
            ) : (
              <>
                <Save
                  size={15}
                  aria-hidden="true"
                />

                <span>
                  Save Changes
                </span>
              </>
            )}
          </button>
        </div>
      </footer>
    </form>
  );
}

/* ============================================================================
 * Status Badge
 * ========================================================================== */

function StatusBadge({
  label,
  value,
  healthy,
}: {
  label: string;
  value: string;
  healthy: boolean;
}) {
  return (
    <div className="edit-user-status-item">
      <span>
        {label}
      </span>

      <strong
        className={
          healthy
            ? "health-pill healthy"
            : "health-pill critical"
        }
      >
        <span
          className="user-status-dot"
          aria-hidden="true"
        />

        <span>
          {value}
        </span>
      </strong>
    </div>
  );
}