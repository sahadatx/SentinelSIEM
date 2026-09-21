/**
 * ============================================================================
 * SentinelSIEM — Create User
 * ============================================================================
 *
 * Right-side drawer for creating a new SentinelSIEM user.
 *
 * Responsibilities:
 * - Create a new SentinelSIEM user
 * - Validate required fields
 * - Assign initial RBAC role
 * - Configure initial account state
 * - Display request errors
 * - Display successful creation state
 * - Notify parent after successful creation
 *
 * UI:
 * - Opens as a right-side drawer
 * - Main User Management page remains visible behind the drawer
 * - Drawer body is independently scrollable
 * - Custom RBAC role dropdown
 *
 * Security:
 * - Password is never trimmed
 * - Plaintext password is cleared after successful creation
 * - Backend remains the final authorization boundary
 * ============================================================================
 */

import {
  useEffect,
  useId,
  useRef,
  useState,
  type FormEvent,
  type MouseEvent,
} from "react";

import {
  AlertCircle,
  CheckCircle2,
  ChevronDown,
  Eye,
  EyeOff,
  KeyRound,
  Mail,
  Shield,
  UserPlus,
  X,
} from "lucide-react";

import {
  ROLE_LIST,
  ROLES,
  formatRole,
  isRole,
  type Role,
} from "../../../auth/rbac";

import { usersApi } from "../api";

import type {
  CreateUserRequest,
  User,
} from "../types";

/* ============================================================================
 * Props
 * ========================================================================== */

export interface CreateUserFormProps {
  /**
   * Called after backend successfully creates the user.
   */
  onCreated?: (
    user: User,
  ) => void;

  /**
   * Close/cancel the drawer.
   */
  onCancel?: () => void;
}

/* ============================================================================
 * Constants
 * ========================================================================== */

const USERNAME_MIN_LENGTH = 3;
const USERNAME_MAX_LENGTH = 64;

const EMAIL_MAX_LENGTH = 320;

const PASSWORD_MIN_LENGTH = 1;
const PASSWORD_MAX_LENGTH = 256;

/* ============================================================================
 * Helpers
 * ========================================================================== */

/**
 * Convert unknown API errors into a safe UI message.
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

  return "Unable to create user.";
}

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

  return null;
}

/**
 * Validate email.
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
    return `Email must not exceed ${EMAIL_MAX_LENGTH} characters.`;
  }

  if (
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
      value,
    )
  ) {
    return "Enter a valid email address.";
  }

  return null;
}

/**
 * Validate password.
 */
function validatePassword(
  value: string,
): string | null {
  if (!value) {
    return "Password is required.";
  }

  if (
    value.length <
    PASSWORD_MIN_LENGTH
  ) {
    return `Password must be at least ${PASSWORD_MIN_LENGTH} character.`;
  }

  if (
    value.length >
    PASSWORD_MAX_LENGTH
  ) {
    return `Password must not exceed ${PASSWORD_MAX_LENGTH} characters.`;
  }

  return null;
}

/* ============================================================================
 * Component
 * ========================================================================== */

export default function CreateUserForm({
  onCreated,
  onCancel,
}: CreateUserFormProps) {
  /* ==========================================================================
   * Form State
   * ======================================================================== */

  const [username, setUsername] =
    useState("");

  const [email, setEmail] =
    useState("");

  const [password, setPassword] =
    useState("");

  const [role, setRole] =
    useState<Role>(
      ROLES.VIEWER,
    );

  const [isActive, setIsActive] =
    useState(true);

  /* ==========================================================================
   * UI State
   * ======================================================================== */

  const [showPassword, setShowPassword] =
    useState(false);

  const [roleOpen, setRoleOpen] =
    useState(false);

  const [submitting, setSubmitting] =
    useState(false);

  const [error, setError] =
    useState<string | null>(null);

  const [success, setSuccess] =
    useState(false);

  /* ==========================================================================
   * Refs
   * ======================================================================== */

  const roleDropdownRef =
    useRef<HTMLDivElement | null>(
      null,
    );

  /* ==========================================================================
   * Accessibility IDs
   * ======================================================================== */

  const titleId = useId();

  const descriptionId =
    useId();

  const errorId =
    useId();

  const roleListId =
    useId();

  /* ==========================================================================
   * Feedback
   * ======================================================================== */

  function clearFeedback(): void {
    setError(null);
    setSuccess(false);
  }

  /* ==========================================================================
   * Escape Key
   * ======================================================================== */

  useEffect(() => {
    function handleKeyDown(
      event: KeyboardEvent,
    ): void {
      if (
        event.key !== "Escape"
      ) {
        return;
      }

      if (roleOpen) {
        setRoleOpen(false);
        return;
      }

      if (!submitting) {
        onCancel?.();
      }
    }

    document.addEventListener(
      "keydown",
      handleKeyDown,
    );

    return () => {
      document.removeEventListener(
        "keydown",
        handleKeyDown,
      );
    };
  }, [
    onCancel,
    roleOpen,
    submitting,
  ]);

  /* ==========================================================================
   * Outside Role Dropdown
   * ======================================================================== */

  useEffect(() => {
    if (!roleOpen) {
      return;
    }

    function handlePointerDown(
      event: PointerEvent,
    ): void {
      const target =
        event.target;

      if (
        target instanceof Node &&
        roleDropdownRef.current?.contains(
          target,
        )
      ) {
        return;
      }

      setRoleOpen(false);
    }

    document.addEventListener(
      "pointerdown",
      handlePointerDown,
    );

    return () => {
      document.removeEventListener(
        "pointerdown",
        handlePointerDown,
      );
    };
  }, [roleOpen]);

  /* ==========================================================================
   * Backdrop
   * ======================================================================== */

  function handleBackdropMouseDown(
    event: MouseEvent<HTMLDivElement>,
  ): void {
    if (
      submitting ||
      event.target !==
        event.currentTarget
    ) {
      return;
    }

    onCancel?.();
  }

  /* ==========================================================================
   * Role Selection
   * ======================================================================== */

  function handleRoleSelect(
    nextRole: string,
  ): void {
    if (!isRole(nextRole)) {
      return;
    }

    setRole(nextRole);
    setRoleOpen(false);
    clearFeedback();
  }

  /* ==========================================================================
   * Submit
   * ======================================================================== */

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();

    if (submitting) {
      return;
    }

    setError(null);
    setSuccess(false);

    /**
     * Non-secret fields are normalized.
     *
     * Password is intentionally NOT trimmed.
     */
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
      setError(usernameError);
      return;
    }

    /* ------------------------------------------------------------------------
     * Email
     * ---------------------------------------------------------------------- */

    const emailError =
      validateEmail(
        normalizedEmail,
      );

    if (emailError) {
      setError(emailError);
      return;
    }

    /* ------------------------------------------------------------------------
     * Password
     * ---------------------------------------------------------------------- */

    const passwordError =
      validatePassword(
        password,
      );

    if (passwordError) {
      setError(passwordError);
      return;
    }

    /* ------------------------------------------------------------------------
     * Role
     * ---------------------------------------------------------------------- */

    if (!isRole(role)) {
      setError(
        "A valid role is required.",
      );
      return;
    }

    /* ------------------------------------------------------------------------
     * Request
     * ---------------------------------------------------------------------- */

    const payload: CreateUserRequest =
      {
        username:
          normalizedUsername,

        email:
          normalizedEmail,

        password,

        role,

        is_active:
          isActive,
      };

    setSubmitting(true);

    try {
      const createdUser =
        await usersApi.create(
          payload,
        );

      /**
       * Clear plaintext password
       * immediately after success.
       */
      setPassword("");

      setShowPassword(false);

      setSuccess(true);

      onCreated?.(
        createdUser,
      );
    } catch (requestError) {
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
   * Render
   * ======================================================================== */

  return (
    <div
      className="create-user-overlay"
      role="presentation"
      onMouseDown={
        handleBackdropMouseDown
      }
    >
      <aside
        className="create-user-drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={
          descriptionId
        }
        onMouseDown={(event) =>
          event.stopPropagation()
        }
      >
        {/* ==================================================================
            Header
            ================================================================== */}

        <header className="create-user-drawer-header">
          <div className="create-user-drawer-heading">
            <div
              className="create-user-drawer-icon"
              aria-hidden="true"
            >
              <UserPlus
                size={18}
              />
            </div>

            <div className="create-user-drawer-heading-copy">
              <span className="create-user-eyebrow">
                USER MANAGEMENT
              </span>

              <h2 id={titleId}>
                Create User
              </h2>

              <p
                id={
                  descriptionId
                }
              >
                Create a new SentinelSIEM
                user account.
              </p>
            </div>
          </div>

          {onCancel && (
            <button
              type="button"
              className="create-user-close"
              onClick={onCancel}
              disabled={
                submitting
              }
              aria-label="Close create user drawer"
              title="Close"
            >
              <X
                size={18}
                aria-hidden="true"
              />
            </button>
          )}
        </header>

        {/* ==================================================================
            Form
            ================================================================== */}

        <form
          className="create-user-form"
          onSubmit={handleSubmit}
          noValidate
        >
          {/* ================================================================
              Scrollable Body
              ================================================================ */}

          <div className="create-user-body">
            {/* ==============================================================
                Error
                ============================================================== */}

            {error && (
              <div
                id={errorId}
                className="create-user-feedback create-user-feedback-error"
                role="alert"
                aria-live="assertive"
              >
                <AlertCircle
                  size={16}
                  aria-hidden="true"
                />

                <div>
                  <strong>
                    Unable to create user
                  </strong>

                  <span>
                    {error}
                  </span>
                </div>
              </div>
            )}

            {/* ==============================================================
                Success
                ============================================================== */}

            {success && (
              <div
                className="create-user-feedback create-user-feedback-success"
                role="status"
                aria-live="polite"
              >
                <CheckCircle2
                  size={16}
                  aria-hidden="true"
                />

                <div>
                  <strong>
                    User created successfully
                  </strong>

                  <span>
                    The account was created
                    successfully.
                  </span>
                </div>
              </div>
            )}

            {/* ==============================================================
                Account Information
                ============================================================== */}

            <section className="create-user-section">
              <div className="create-user-section-header">
                <div>
                  <span className="create-user-section-kicker">
                    IDENTITY
                  </span>

                  <h3>
                    Account Information
                  </h3>

                  <p>
                    Basic identity details
                    for the new account.
                  </p>
                </div>

                <UserPlus
                  size={15}
                  aria-hidden="true"
                />
              </div>

              <div className="create-user-fields">
                {/* ========================================================
                    Username
                    ======================================================== */}

                <div className="create-user-field">
                  <label
                    htmlFor="create-user-username"
                  >
                    Username
                    <span
                      className="create-user-required"
                      aria-hidden="true"
                    >
                      *
                    </span>
                  </label>

                  <div className="create-user-input">
                    <UserPlus
                      size={15}
                      aria-hidden="true"
                    />

                    <input
                      id="create-user-username"
                      name="username"
                      type="text"
                      value={username}
                      onChange={(
                        event,
                      ) => {
                        setUsername(
                          event.target
                            .value,
                        );
                        clearFeedback();
                      }}
                      autoComplete="username"
                      autoCapitalize="none"
                      autoCorrect="off"
                      spellCheck={false}
                      placeholder="Enter username"
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
                    />
                  </div>

                  <small>
                    {USERNAME_MIN_LENGTH}–
                    {USERNAME_MAX_LENGTH} characters.
                  </small>
                </div>

                {/* ========================================================
                    Email
                    ======================================================== */}

                <div className="create-user-field">
                  <label
                    htmlFor="create-user-email"
                  >
                    Email Address
                    <span
                      className="create-user-required"
                      aria-hidden="true"
                    >
                      *
                    </span>
                  </label>

                  <div className="create-user-input">
                    <Mail
                      size={15}
                      aria-hidden="true"
                    />

                    <input
                      id="create-user-email"
                      name="email"
                      type="email"
                      value={email}
                      onChange={(
                        event,
                      ) => {
                        setEmail(
                          event.target
                            .value,
                        );
                        clearFeedback();
                      }}
                      autoComplete="email"
                      autoCapitalize="none"
                      autoCorrect="off"
                      spellCheck={false}
                      placeholder="name@example.com"
                      disabled={
                        submitting
                      }
                      required
                      maxLength={
                        EMAIL_MAX_LENGTH
                      }
                    />
                  </div>

                  <small>
                    Use a valid email address.
                  </small>
                </div>
              </div>
            </section>

            {/* ==============================================================
                Authentication
                ============================================================== */}

            <section className="create-user-section">
              <div className="create-user-section-header">
                <div>
                  <span className="create-user-section-kicker">
                    CREDENTIALS
                  </span>

                  <h3>
                    Authentication
                  </h3>

                  <p>
                    Configure the initial
                    authentication credential.
                  </p>
                </div>

                <KeyRound
                  size={15}
                  aria-hidden="true"
                />
              </div>

              <div className="create-user-field">
                <label
                  htmlFor="create-user-password"
                >
                  Initial Password
                  <span
                    className="create-user-required"
                    aria-hidden="true"
                  >
                    *
                  </span>
                </label>

                <div className="create-user-input create-user-password-input">
                  <KeyRound
                    size={15}
                    aria-hidden="true"
                  />

                  <input
                    id="create-user-password"
                    name="password"
                    type={
                      showPassword
                        ? "text"
                        : "password"
                    }
                    value={password}
                    onChange={(
                      event,
                    ) => {
                      setPassword(
                        event.target
                          .value,
                      );
                      clearFeedback();
                    }}
                    autoComplete="new-password"
                    placeholder="Enter initial password"
                    disabled={
                      submitting
                    }
                    required
                    minLength={
                      PASSWORD_MIN_LENGTH
                    }
                    maxLength={
                      PASSWORD_MAX_LENGTH
                    }
                  />

                  <button
                    type="button"
                    className="create-user-password-toggle"
                    onClick={() =>
                      setShowPassword(
                        (
                          current,
                        ) =>
                          !current,
                      )
                    }
                    disabled={
                      submitting ||
                      !password
                    }
                    aria-label={
                      showPassword
                        ? "Hide password"
                        : "Show password"
                    }
                    title={
                      showPassword
                        ? "Hide password"
                        : "Show password"
                    }
                  >
                    {showPassword ? (
                      <EyeOff
                        size={15}
                        aria-hidden="true"
                      />
                    ) : (
                      <Eye
                        size={15}
                        aria-hidden="true"
                      />
                    )}
                  </button>
                </div>

                <small>
                  Password is never retained
                  after successful creation.
                </small>
              </div>
            </section>

            {/* ==============================================================
                Access Control
                ============================================================== */}

            <section className="create-user-section">
              <div className="create-user-section-header">
                <div>
                  <span className="create-user-section-kicker">
                    RBAC
                  </span>

                  <h3>
                    Access Control
                  </h3>

                  <p>
                    Define the initial role
                    and account state.
                  </p>
                </div>

                <Shield
                  size={15}
                  aria-hidden="true"
                />
              </div>

              <div className="create-user-fields">
                {/* ========================================================
                    Role
                    ======================================================== */}

                <div className="create-user-field">
                  <label>
                    Initial Role
                    <span
                      className="create-user-required"
                      aria-hidden="true"
                    >
                      *
                    </span>
                  </label>

                  <div
                    ref={
                      roleDropdownRef
                    }
                    className={
                      `create-user-role-dropdown${
                        roleOpen
                          ? " is-open"
                          : ""
                      }`
                    }
                  >
                    <button
                      type="button"
                      className="create-user-role-trigger"
                      onClick={() =>
                        setRoleOpen(
                          (
                            current,
                          ) =>
                            !current,
                        )
                      }
                      disabled={
                        submitting
                      }
                      aria-haspopup="listbox"
                      aria-expanded={
                        roleOpen
                      }
                      aria-controls={
                        roleListId
                      }
                    >
                      <span className="create-user-role-trigger-icon">
                        <Shield
                          size={15}
                          aria-hidden="true"
                        />
                      </span>

                      <span className="create-user-role-trigger-text">
                        {formatRole(
                          role,
                        )}
                      </span>

                      <ChevronDown
                        className="create-user-role-chevron"
                        size={15}
                        aria-hidden="true"
                      />
                    </button>

                    {roleOpen && (
                      <div
                        id={roleListId}
                        className="create-user-role-menu"
                        role="listbox"
                        aria-label="Select initial role"
                      >
                        {ROLE_LIST.map(
                          (
                            roleOption,
                          ) => {
                            const selected =
                              roleOption ===
                              role;

                            return (
                              <button
                                key={
                                  roleOption
                                }
                                type="button"
                                className={
                                  `create-user-role-option${
                                    selected
                                      ? " is-selected"
                                      : ""
                                  }`
                                }
                                onClick={() =>
                                  handleRoleSelect(
                                    roleOption,
                                  )
                                }
                                role="option"
                                aria-selected={
                                  selected
                                }
                              >
                                <span>
                                  {formatRole(
                                    roleOption,
                                  )}
                                </span>

                                {selected && (
                                  <CheckCircle2
                                    size={
                                      14
                                    }
                                    aria-hidden="true"
                                  />
                                )}
                              </button>
                            );
                          },
                        )}
                      </div>
                    )}
                  </div>

                  <small>
                    Determines the user's initial
                    SentinelSIEM permissions.
                  </small>
                </div>

                {/* ========================================================
                    Account State
                    ======================================================== */}

                <div className="create-user-field">
                  <label>
                    Account State
                  </label>

                  <button
                    type="button"
                    className={
                      `create-user-account-state${
                        isActive
                          ? " is-active"
                          : " is-disabled"
                      }`
                    }
                    onClick={() =>
                      setIsActive(
                        (
                          current,
                        ) =>
                          !current,
                      )
                    }
                    disabled={
                      submitting
                    }
                    aria-pressed={
                      isActive
                    }
                  >
                    <span className="create-user-state-switch">
                      <span />
                    </span>

                    <span className="create-user-state-copy">
                      <strong>
                        {isActive
                          ? "Active"
                          : "Disabled"}
                      </strong>

                      <small>
                        {isActive
                          ? "User can sign in immediately."
                          : "User will remain disabled."}
                      </small>
                    </span>
                  </button>
                </div>
              </div>
            </section>
          </div>

          {/* ==================================================================
              Footer
              ================================================================== */}

          <footer className="create-user-footer">
            <div className="create-user-security-note">
              <Shield
                size={13}
                aria-hidden="true"
              />

              <span>
                Backend authorization remains
                the final security boundary.
              </span>
            </div>

            <div className="create-user-footer-actions">
              {onCancel && (
                <button
                  type="button"
                  className="create-user-button-secondary"
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
                className="create-user-button-primary"
                disabled={
                  submitting
                }
                aria-busy={
                  submitting
                }
                aria-describedby={
                  error
                    ? errorId
                    : undefined
                }
              >
                <UserPlus
                  size={15}
                  aria-hidden="true"
                />

                <span>
                  {submitting
                    ? "Creating User..."
                    : "Create User"}
                </span>
              </button>
            </div>
          </footer>
        </form>
      </aside>
    </div>
  );
}