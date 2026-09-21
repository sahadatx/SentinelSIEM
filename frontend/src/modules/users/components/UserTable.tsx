/**
 * ============================================================================
 * SentinelSIEM — User Table
 * ============================================================================
 *
 * User Management table presentation layer.
 *
 * Responsibilities:
 *
 * - Render the User Management table
 * - Render loading state
 * - Render empty state
 * - Forward row selection
 * - Forward edit actions
 * - Forward role actions
 * - Forward audit actions
 * - Forward general security workflow
 * - Forward exact security actions
 * - Forward delete completion
 *
 * This component intentionally does NOT:
 *
 * - Perform API requests
 * - Perform authorization decisions
 * - Mutate user state
 * - Implement security workflows
 * - Implement delete workflows
 *
 * Row-level interaction is delegated to UserRow.
 *
 * Backend authorization remains the final security boundary.
 * ============================================================================
 */

import type { ReactNode } from "react";

import type { User } from "../types";

import UserRow from "./UserRow";

import type {
  UserSecurityAction,
} from "./UserActionsMenu";

/**
 * ============================================================================
 * Constants
 * ============================================================================
 */

const USER_TABLE_COLUMN_COUNT = 8;

/**
 * ============================================================================
 * Props
 * ============================================================================
 */

export interface UserTableProps {
  users: User[];

  loading?: boolean;

  hasFilters?: boolean;

  selectedUserId?: string | null;

  canManageUsers?: boolean;

  canUseSecurityActions?: boolean;

  onSelect?: (
    user: User,
  ) => void;

  onEdit?: (
    user: User,
  ) => void;

  onSecurity?: (
    user: User,
  ) => void;

  onSecurityAction?: (
    user: User,
    action: UserSecurityAction,
  ) => void;

  onRole?: (
    user: User,
  ) => void;

  onAudit?: (
    user: User,
  ) => void;

  onDeleted?: (
    userId: string,
  ) => void;

  emptyMessage?: string;
}

/**
 * ============================================================================
 * User Table
 * ============================================================================
 */

export default function UserTable({
  users,
  loading = false,
  hasFilters = false,
  selectedUserId = null,
  canManageUsers = false,
  canUseSecurityActions = false,
  onSelect,
  onEdit,
  onSecurity,
  onSecurityAction,
  onRole,
  onAudit,
  onDeleted,
  emptyMessage,
}: UserTableProps) {
  /**
   * ==========================================================================
   * Stable Handlers
   * ==========================================================================
   */

  const selectHandler =
    onSelect ??
    noopUserHandler;

  const editHandler =
    onEdit ??
    noopUserHandler;

  const securityHandler =
    onSecurity ??
    noopUserHandler;

  const securityActionHandler =
    onSecurityAction ??
    noopSecurityHandler;

  const roleHandler =
    onRole ??
    noopUserHandler;

  const auditHandler =
    onAudit ??
    noopUserHandler;

  const deleteHandler =
    onDeleted ??
    noopDeleteHandler;

  /**
   * ==========================================================================
   * Loading State
   * ==========================================================================
   */

  if (loading) {
    return (
      <TableContainer>
        <table
          className="users-table"
          aria-label="Users"
          aria-busy="true"
        >
          <UserTableColGroup />

          <UserTableHeader />

          <tbody>
            <tr>
              <td
                colSpan={
                  USER_TABLE_COLUMN_COUNT
                }
                className="empty"
              >
                <span
                  className="users-table-state"
                  role="status"
                  aria-live="polite"
                >
                  Loading users...
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </TableContainer>
    );
  }

  /**
   * ==========================================================================
   * Empty State
   * ==========================================================================
   */

  if (users.length === 0) {
    const message =
      emptyMessage ??
      (
        hasFilters
          ? "No users match the current filters."
          : "No users available."
      );

    return (
      <TableContainer>
        <table
          className="users-table"
          aria-label="Users"
        >
          <UserTableColGroup />

          <UserTableHeader />

          <tbody>
            <tr>
              <td
                colSpan={
                  USER_TABLE_COLUMN_COUNT
                }
                className="empty"
              >
                <span
                  className="users-table-state"
                  role="status"
                  aria-live="polite"
                >
                  {message}
                </span>
              </td>
            </tr>
          </tbody>
        </table>
      </TableContainer>
    );
  }

  /**
   * ==========================================================================
   * User Rows
   * ==========================================================================
   */

  return (
    <TableContainer>
      <table
        className="users-table"
        aria-label="Users"
      >
        {/*
         * Explicit column sizing prevents long user names,
         * emails or dates from visually entering another column.
         */}
        <UserTableColGroup />

        <UserTableHeader />

        <tbody>
          {users.map((user) => (
            <UserRow
              key={user.user_id}
              user={user}
              selected={
                selectedUserId ===
                user.user_id
              }
              canManageUsers={
                canManageUsers
              }
              canUseSecurityActions={
                canUseSecurityActions
              }
              onSelect={
                selectHandler
              }
              onEdit={
                editHandler
              }
              onSecurity={
                securityHandler
              }
              onSecurityAction={
                securityActionHandler
              }
              onRole={
                roleHandler
              }
              onAudit={
                auditHandler
              }
              onDeleted={
                deleteHandler
              }
            />
          ))}
        </tbody>
      </table>
    </TableContainer>
  );
}

/**
 * ============================================================================
 * Table Container
 * ============================================================================
 */

interface TableContainerProps {
  children: ReactNode;
}

function TableContainer({
  children,
}: TableContainerProps) {
  return (
    <div
      className="table-wrap"
      role="region"
      aria-label="User directory"
    >
      {children}
    </div>
  );
}

/**
 * ============================================================================
 * Column Definitions
 * ============================================================================
 *
 * Total = 100%
 *
 * User       17%
 * Email      18%
 * Roles      12%
 * Status     11%
 * Security   12%
 * Last Login 12%
 * Created    12%
 * Actions     6%
 *
 * These percentages intentionally prevent
 * content from changing the table geometry.
 * ============================================================================
 */

function UserTableColGroup() {
  return (
    <colgroup>
      <col
        className="users-col-user"
        style={{ width: "17%" }}
      />

      <col
        className="users-col-email"
        style={{ width: "18%" }}
      />

      <col
        className="users-col-roles"
        style={{ width: "12%" }}
      />

      <col
        className="users-col-status"
        style={{ width: "11%" }}
      />

      <col
        className="users-col-security"
        style={{ width: "12%" }}
      />

      <col
        className="users-col-last-login"
        style={{ width: "12%" }}
      />

      <col
        className="users-col-created"
        style={{ width: "12%" }}
      />

      <col
        className="users-col-actions"
        style={{ width: "6%" }}
      />
    </colgroup>
  );
}

/**
 * ============================================================================
 * Table Header
 * ============================================================================
 */

function UserTableHeader() {
  return (
    <thead>
      <tr>
        <th scope="col">
          User
        </th>

        <th scope="col">
          Email
        </th>

        <th scope="col">
          Roles
        </th>

        <th scope="col">
          Status
        </th>

        <th scope="col">
          Security
        </th>

        <th scope="col">
          Last Login
        </th>

        <th scope="col">
          Created
        </th>

        <th
          scope="col"
          className="table-actions-header"
        >
          Actions
        </th>
      </tr>
    </thead>
  );
}

/**
 * ============================================================================
 * No-op Handlers
 * ============================================================================
 */

function noopUserHandler(
  _user: User,
): void {
  // Intentionally empty.
}

function noopSecurityHandler(
  _user: User,
  _action: UserSecurityAction,
): void {
  // Intentionally empty.
}

function noopDeleteHandler(
  _userId: string,
): void {
  // Intentionally empty.
}