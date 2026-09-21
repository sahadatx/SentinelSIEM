/**
 * ============================================================================
 * SentinelSIEM — User Row
 * ============================================================================
 *
 * Responsibilities:
 *
 * - Render one user inside the User Management table
 * - Display identity, roles, account status and security state
 * - Handle row/user selection
 * - Forward contextual actions to UserActionsMenu
 * - Forward exact security actions to the parent
 *
 * This component does NOT:
 *
 * - Perform API requests
 * - Make authorization decisions
 * - Mutate user state directly
 * - Implement delete/security business logic
 *
 * Backend authorization remains the final security boundary.
 * ============================================================================
 */

import {
  Lock,
  MoreVertical,
  ShieldCheck,
  UserCheck,
  UserX,
} from "lucide-react";

import type {
  KeyboardEvent,
  MouseEvent,
} from "react";

import type { User } from "../types";

import UserActionsMenu, {
  type UserSecurityAction,
} from "./UserActionsMenu";

/**
 * ============================================================================
 * Helpers
 * ============================================================================
 */

function formatDate(
  value: string | null | undefined,
): string {
  if (!value) {
    return "—";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "—";
  }

  return date.toLocaleString();
}

function formatRole(
  role: string,
): string {
  return role
    .replace(/[-_]+/g, " ")
    .replace(
      /\b\w/g,
      (character) =>
        character.toUpperCase(),
    );
}

function getUserInitials(
  displayName: string | null | undefined,
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

  const firstPart = parts.at(0);
  const lastPart = parts.at(-1);

  if (!firstPart || !lastPart) {
    return "U";
  }

  if (parts.length >= 2) {
    return (
      `${firstPart.charAt(0)}${lastPart.charAt(0)}`
    ).toUpperCase();
  }

  return firstPart
    .slice(0, 2)
    .toUpperCase();
}

/**
 * ============================================================================
 * Props
 * ============================================================================
 */

export interface UserRowProps {
  user: User;

  selected: boolean;

  canManageUsers: boolean;

  canUseSecurityActions: boolean;

  onSelect: (
    user: User,
  ) => void;

  onEdit: (
    user: User,
  ) => void;

  onSecurity: (
    user: User,
  ) => void;

  onSecurityAction: (
    user: User,
    action: UserSecurityAction,
  ) => void;

  onRole: (
    user: User,
  ) => void;

  onAudit: (
    user: User,
  ) => void;

  onDeleted: (
    userId: string,
  ) => void;
}

/**
 * ============================================================================
 * User Row
 * ============================================================================
 */

export default function UserRow({
  user,
  selected,
  canManageUsers,
  canUseSecurityActions,
  onSelect,
  onEdit,
  onSecurityAction,
  onRole,
  onAudit,
  onDeleted,
}: UserRowProps) {
  /**
   * ==========================================================================
   * Selection
   * ==========================================================================
   */

  function handleSelect() {
    onSelect(user);
  }

  /**
   * ==========================================================================
   * Keyboard Interaction
   * ==========================================================================
   */

  function handleRowKeyDown(
    event: KeyboardEvent<HTMLTableRowElement>,
  ) {
    const target =
      event.target as HTMLElement | null;

    if (
      target?.closest(
        "button, a, input, select, textarea",
      )
    ) {
      return;
    }

    if (
      event.key === "Enter" ||
      event.key === " "
    ) {
      event.preventDefault();

      handleSelect();
    }
  }

  /**
   * ==========================================================================
   * Prevent Row Interaction
   * ==========================================================================
   */

  function stopRowInteraction(
    event: MouseEvent,
  ) {
    event.stopPropagation();
  }

  /**
   * ==========================================================================
   * Delete Adapter
   * ==========================================================================
   */

  function handleDelete(
    deletedUser: User,
  ) {
    onDeleted(
      deletedUser.user_id,
    );
  }

  /**
   * ==========================================================================
   * Security Adapter
   * ==========================================================================
   */

  function handleSecurityAction(
    selectedUser: User,
    action: UserSecurityAction,
  ) {
    onSecurityAction(
      selectedUser,
      action,
    );
  }

  /**
   * ==========================================================================
   * Derived Values
   * ==========================================================================
   */

  const displayName =
    user.display_name?.trim() ||
    user.username;

  const initials =
    getUserInitials(
      user.display_name,
      user.username,
    );

  const hasActions =
    canManageUsers ||
    canUseSecurityActions;

  /**
   * ==========================================================================
   * Render
   * ==========================================================================
   */

  return (
    <tr
      className={
        selected
          ? "selected"
          : undefined
      }
      onClick={handleSelect}
      onKeyDown={handleRowKeyDown}
      aria-selected={selected}
    >
      {/* ==================================================================
          USER
          ================================================================== */}

      <td className="user-table-user-cell">
        <div
          className="user-identity"
          onClick={stopRowInteraction}
          onMouseDown={stopRowInteraction}
        >
          <div
            className="user-avatar"
            aria-hidden="true"
          >
            {initials}
          </div>

          <div className="user-identity-main">
            <button
              type="button"
              className="user-identity-button"
              onClick={(event) => {
                event.preventDefault();
                event.stopPropagation();

                handleSelect();
              }}
              aria-label={`View ${displayName}`}
              title={displayName}
            >
              <strong className="user-identity-name">
                {displayName}
              </strong>
            </button>
          </div>
        </div>
      </td>

      {/* ==================================================================
          EMAIL
          ================================================================== */}

      <td className="user-table-email-cell">
        <span
          className="user-email"
          title={user.email}
        >
          {user.email}
        </span>
      </td>

      {/* ==================================================================
          ROLES
          ================================================================== */}

      <td className="user-table-roles-cell">
        <div className="users-role-list">
          {user.roles.length === 0 ? (
            <span>—</span>
          ) : (
            user.roles.map(
              (role) => (
                <span
                  key={role}
                  className="health-pill"
                >
                  {formatRole(role)}
                </span>
              ),
            )
          )}
        </div>
      </td>

      {/* ==================================================================
          ACCOUNT STATUS
          ================================================================== */}

      <td className="user-table-status-cell">
        <span
          className={
            user.is_active
              ? "health-pill healthy"
              : "health-pill warning"
          }
        >
          {user.is_active ? (
            <>
              <UserCheck
                size={13}
                aria-hidden="true"
              />

              <span>
                Active
              </span>
            </>
          ) : (
            <>
              <UserX
                size={13}
                aria-hidden="true"
              />

              <span>
                Disabled
              </span>
            </>
          )}
        </span>
      </td>

      {/* ==================================================================
          SECURITY
          ================================================================== */}

      <td className="user-table-security-cell">
        <span
          className={
            user.is_locked
              ? "health-pill critical"
              : "health-pill healthy"
          }
        >
          {user.is_locked ? (
            <>
              <Lock
                size={13}
                aria-hidden="true"
              />

              <span>
                Locked
              </span>
            </>
          ) : (
            <>
              <ShieldCheck
                size={13}
                aria-hidden="true"
              />

              <span>
                Unlocked
              </span>
            </>
          )}
        </span>
      </td>

      {/* ==================================================================
          LAST LOGIN
          ================================================================== */}

      <td className="user-table-last-login-cell">
        <span
          className="user-date-value"
          title={formatDate(user.last_login_at)}
        >
          {formatDate(
            user.last_login_at,
          )}
        </span>
      </td>

      {/* ==================================================================
          CREATED
          ================================================================== */}

      <td className="user-table-created-cell">
        <span
          className="user-date-value"
          title={formatDate(user.created_at)}
        >
          {formatDate(
            user.created_at,
          )}
        </span>
      </td>

      {/* ==================================================================
          ACTIONS
          ================================================================== */}

      <td
        className="table-actions-cell user-table-actions-cell"
        onClick={stopRowInteraction}
        onMouseDown={stopRowInteraction}
      >
        <div
          className="user-row-actions"
          onClick={stopRowInteraction}
          onMouseDown={stopRowInteraction}
        >
          {hasActions ? (
            <UserActionsMenu
              user={user}
              canManageUsers={
                canManageUsers
              }
              canUseSecurityActions={
                canUseSecurityActions
              }
              onView={
                onSelect
              }
              onEdit={
                onEdit
              }
              onAudit={
                onAudit
              }
              onRole={
                onRole
              }
              onSecurity={
                handleSecurityAction
              }
              onDelete={
                handleDelete
              }
            />
          ) : (
            <span
              className="user-row-no-actions"
              aria-label="No available actions"
            >
              <MoreVertical
                size={16}
                aria-hidden="true"
              />
            </span>
          )}
        </div>
      </td>
    </tr>
  );
}