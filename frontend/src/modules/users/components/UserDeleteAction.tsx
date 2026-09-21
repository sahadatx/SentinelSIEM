/**
 * ============================================================================
 * SentinelSIEM — User Delete Action
 * ============================================================================
 *
 * Responsibilities:
 * - Provide the destructive user deletion action
 * - Enforce users:manage permission at component level
 * - Use a SentinelSIEM confirmation modal instead of browser-native alerts
 * - Prevent duplicate delete requests
 * - Call the backend delete endpoint
 * - Notify the parent only after successful deletion
 * - Display backend/API errors safely
 *
 * Security:
 * - Frontend authorization is defense-in-depth only.
 * - Backend authorization remains the final security boundary.
 * - No deletion callback is fired unless the API request succeeds.
 * - No passwords, tokens, or other secrets are handled by this component.
 *
 * UX:
 * - Normal delete action opens a professional confirmation modal.
 * - Backend restrictions remain authoritative.
 * - Backend errors are shown after the deletion request fails.
 * - No window.confirm() / native browser alert is used.
 * ============================================================================
 */

import {
  useEffect,
  useState,
} from "react";

import {
  AlertTriangle,
  Loader2,
  ShieldAlert,
  Trash2,
  X,
} from "lucide-react";

import {
  createPortal,
} from "react-dom";

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
 * Props
 * ========================================================================== */

export interface UserDeleteActionProps {
  user: User;

  onDeleted?: (
    userId: string,
  ) => void;

  disabled?: boolean;
}

/* ============================================================================
 * Helpers
 * ========================================================================== */

/**
 * Convert an unknown API error into a safe user-facing message.
 *
 * Supports:
 * - FastAPI-style { detail: string }
 * - Standard Error instances
 * - Generic fallback
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
    error instanceof Error
  ) {
    return error.message;
  }

  return "Unable to delete user.";
}

/**
 * Safely derive the user's avatar initials.
 */
function getUserInitial(
  username: string,
): string {
  const value =
    username.trim();

  if (!value) {
    return "U";
  }

  return value
    .charAt(0)
    .toUpperCase();
}

/* ============================================================================
 * Confirmation Modal
 * ========================================================================== */

interface DeleteConfirmationModalProps {
  username: string;
  deleting: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}

/**
 * SentinelSIEM destructive-action confirmation modal.
 *
 * Important:
 * - This is NOT a browser-native confirmation dialog.
 * - It is rendered through a portal to avoid clipping from drawers,
 *   tables, overflow containers, and action menus.
 * - Backend authorization/restrictions remain authoritative.
 */
function DeleteConfirmationModal({
  username,
  deleting,
  onCancel,
  onConfirm,
}: DeleteConfirmationModalProps) {
  /* --------------------------------------------------------------------------
   * Keyboard handling
   * ------------------------------------------------------------------------ */

  useEffect(() => {
    if (deleting) {
      return;
    }

    function handleKeyDown(
      event: KeyboardEvent,
    ) {
      if (
        event.key === "Escape"
      ) {
        event.preventDefault();
        onCancel();
        return;
      }

      if (
        event.key === "Enter"
      ) {
        event.preventDefault();
        onConfirm();
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
    deleting,
    onCancel,
    onConfirm,
  ]);

  /* --------------------------------------------------------------------------
   * Body scroll lock
   * ------------------------------------------------------------------------ */

  useEffect(() => {
    const previousOverflow =
      document.body.style.overflow;

    document.body.style.overflow =
      "hidden";

    return () => {
      document.body.style.overflow =
        previousOverflow;
    };
  }, []);

  /* --------------------------------------------------------------------------
   * Modal
   * ------------------------------------------------------------------------ */

  const modal = (
    <div
      className="user-delete-modal-root"
      role="presentation"
    >
      <div
        className="user-delete-modal-backdrop"
        onMouseDown={(event) => {
          if (
            event.target ===
              event.currentTarget &&
            !deleting
          ) {
            onCancel();
          }
        }}
      >
        <section
          className="user-delete-modal"
          role="alertdialog"
          aria-modal="true"
          aria-labelledby="user-delete-modal-title"
          aria-describedby="user-delete-modal-description"
          onMouseDown={(event) => {
            event.stopPropagation();
          }}
        >
          {/* ==================================================================
           * Header
           * ================================================================ */}

          <header className="user-delete-modal-header">
            <div
              className="user-delete-modal-icon"
              aria-hidden="true"
            >
              <AlertTriangle
                size={22}
              />
            </div>

            <div className="user-delete-modal-heading">
              <h2
                id="user-delete-modal-title"
              >
                Delete User
              </h2>

              <p>
                Permanent account removal
              </p>
            </div>

            <button
              type="button"
              className="user-delete-modal-close"
              onClick={onCancel}
              disabled={deleting}
              aria-label="Close delete confirmation"
              title="Close"
            >
              <X
                size={18}
                aria-hidden="true"
              />
            </button>
          </header>

          {/* ==================================================================
           * Body
           * ================================================================ */}

          <div className="user-delete-modal-body">
            <div className="user-delete-modal-warning">
              <div
                className="user-delete-modal-warning-icon"
                aria-hidden="true"
              >
                <ShieldAlert
                  size={18}
                />
              </div>

              <div className="user-delete-modal-warning-content">
                <strong>
                  This action cannot be undone.
                </strong>

                <p>
                  The selected user account and its
                  associated access will be permanently
                  removed.
                </p>
              </div>
            </div>

            {/* --------------------------------------------------------------
             * Selected user
             * ------------------------------------------------------------ */}

            <div
              className="user-delete-modal-user"
              aria-label={`Selected user: ${username}`}
            >
              <div className="user-delete-modal-user-label">
                Selected User
              </div>

              <div className="user-delete-modal-user-value">
                <span
                  className="user-delete-modal-user-avatar"
                  aria-hidden="true"
                >
                  {getUserInitial(
                    username,
                  )}
                </span>

                <span className="user-delete-modal-username">
                  {username}
                </span>
              </div>
            </div>

            {/* --------------------------------------------------------------
             * Confirmation text
             * ------------------------------------------------------------ */}

            <p
              id="user-delete-modal-description"
              className="user-delete-modal-description"
            >
              Are you sure you want to permanently
              delete this user account?
            </p>
          </div>

          {/* ==================================================================
           * Footer
           * ================================================================ */}

          <footer className="user-delete-modal-footer">
            <button
              type="button"
              className="user-delete-modal-cancel"
              onClick={onCancel}
              disabled={deleting}
            >
              Cancel
            </button>

            <button
              type="button"
              className="user-delete-modal-confirm"
              onClick={onConfirm}
              disabled={deleting}
              aria-busy={deleting}
            >
              {deleting ? (
                <>
                  <Loader2
                    size={15}
                    className="user-delete-spin"
                    aria-hidden="true"
                  />

                  <span>
                    Deleting...
                  </span>
                </>
              ) : (
                <>
                  <Trash2
                    size={15}
                    aria-hidden="true"
                  />

                  <span>
                    Delete User
                  </span>
                </>
              )}
            </button>
          </footer>
        </section>
      </div>
    </div>
  );

  return createPortal(
    modal,
    document.body,
  );
}

/* ============================================================================
 * User Delete Action
 * ========================================================================== */

export default function UserDeleteAction({
  user,
  onDeleted,
  disabled = false,
}: UserDeleteActionProps) {
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
   * Request state
   * ======================================================================== */

  const [
    deleting,
    setDeleting,
  ] = useState(false);

  const [
    error,
    setError,
  ] = useState<string | null>(
    null,
  );

  const [
    confirmationOpen,
    setConfirmationOpen,
  ] = useState(false);

  /* ==========================================================================
   * Open confirmation
   * ======================================================================== */

  function handleDeleteClick() {
    if (
      !canManageUsers ||
      disabled ||
      deleting
    ) {
      return;
    }

    setError(null);
    setConfirmationOpen(true);
  }

  /* ==========================================================================
   * Cancel confirmation
   * ======================================================================== */

  function handleCancelConfirmation() {
    if (deleting) {
      return;
    }

    setConfirmationOpen(false);
  }

  /* ==========================================================================
   * Confirm deletion
   * ======================================================================== */

  async function handleConfirmDelete() {
    if (
      !canManageUsers ||
      disabled ||
      deleting
    ) {
      return;
    }

    setError(null);
    setDeleting(true);

    try {
      /*
       * Backend remains authoritative.
       *
       * Do not mutate parent state before the API
       * confirms successful deletion.
       */
      await usersApi.remove(
        user.user_id,
      );

      /*
       * Close confirmation only after
       * successful API response.
       */
      setConfirmationOpen(
        false,
      );

      /*
       * Notify parent only after
       * successful deletion.
       */
      onDeleted?.(
        user.user_id,
      );
    } catch (
      requestError
    ) {
      /*
       * Keep the confirmation modal open so the
       * user can understand/retry the failed action.
       */
      setError(
        getErrorMessage(
          requestError,
        ),
      );
    } finally {
      setDeleting(false);
    }
  }

  /* ==========================================================================
   * Permission guard
   * ======================================================================== */

  if (!canManageUsers) {
    return null;
  }

  /* ==========================================================================
   * Derived state
   * ======================================================================== */

  const isDisabled =
    disabled ||
    deleting;

  const buttonLabel =
    deleting
      ? "Deleting..."
      : "Delete";

  /* ==========================================================================
   * Render
   * ======================================================================== */

  return (
    <>
      <div className="user-delete-action">
        {/* ==================================================================
         * Delete button
         * ================================================================ */}

        <button
          type="button"
          className="secondary-button user-delete-button"
          onClick={handleDeleteClick}
          disabled={isDisabled}
          title={
            deleting
              ? "Deleting user"
              : "Delete user"
          }
          aria-label={`Delete user ${user.username}`}
          aria-busy={deleting}
        >
          {deleting ? (
            <Loader2
              size={14}
              className="user-delete-spin"
              aria-hidden="true"
            />
          ) : (
            <Trash2
              size={14}
              aria-hidden="true"
            />
          )}

          <span>
            {buttonLabel}
          </span>
        </button>

        {/* ==================================================================
         * Error
         * ================================================================ */}

        {error && (
          <div
            className="user-delete-error"
            role="alert"
          >
            <ShieldAlert
              size={15}
              aria-hidden="true"
            />

            <span>
              {error}
            </span>
          </div>
        )}
      </div>

      {/* ======================================================================
       * Confirmation modal
       * ==================================================================== */}

      {confirmationOpen && (
        <DeleteConfirmationModal
          username={
            user.username
          }
          deleting={deleting}
          onCancel={
            handleCancelConfirmation
          }
          onConfirm={
            handleConfirmDelete
          }
        />
      )}
    </>
  );
}