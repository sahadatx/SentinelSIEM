/**
 * ============================================================================
 * SentinelSIEM — User Actions Menu
 * ============================================================================
 *
 * Responsibilities:
 *
 * - View user details
 * - Edit user
 * - Change role
 * - Open audit history
 * - Open security actions
 * - Preserve exact security operation identifiers
 * - Delete user
 * - Frontend RBAC visibility
 * - Portal rendering
 * - Viewport-aware positioning
 * - Outside-click dismissal
 * - Escape dismissal
 * - Scroll / resize repositioning
 * - Prevent table-row interaction
 *
 * This component does NOT:
 *
 * - Perform API requests
 * - Mutate user state
 * - Implement backend authorization
 * - Implement security business logic
 *
 * Backend authorization remains authoritative.
 * ============================================================================
 */

import {
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type MouseEvent as ReactMouseEvent,
} from "react";

import {
  ChevronRight,
  Eye,
  History,
  KeyRound,
  Lock,
  LogOut,
  MoreVertical,
  Pencil,
  Shield,
  Trash2,
  Unlock,
  UserCheck,
  UserX,
  UsersRound,
  X,
} from "lucide-react";

import { createPortal } from "react-dom";

import { useAuthStore } from "../../../store/auth";

import {
  USERS_MANAGE,
  USERS_READ,
} from "../permissions";

import type { User } from "../types";

/* ============================================================================
 * Security Action
 * ========================================================================== */

export type UserSecurityAction =
  | "enable_user"
  | "disable_user"
  | "lock_user"
  | "unlock_user"
  | "reset_password"
  | "force_password_change"
  | "active_sessions"
  | "revoke_sessions";

/* ============================================================================
 * Props
 * ========================================================================== */

export interface UserActionsMenuProps {
  user: User;

  canManageUsers?: boolean;

  canUseSecurityActions?: boolean;

  /**
   * Open user details.
   */
  onView: (user: User) => void;

  /**
   * Open edit workflow.
   */
  onEdit: (user: User) => void;

  /**
   * Open audit workflow.
   */
  onAudit: (user: User) => void;

  /**
   * Open role workflow.
   */
  onRole?: (user: User) => void;

  /**
   * Open security workflow or execute
   * an exact security action.
   */
  onSecurity?: (
    user: User,
    action: UserSecurityAction,
  ) => void;

  /**
   * Delete user.
   */
  onDelete: (user: User) => void;

  /**
   * Disable interaction.
   */
  disabled?: boolean;
}

/* ============================================================================
 * Position
 * ========================================================================== */

interface MenuPosition {
  top: number;
  left: number;
}

/* ============================================================================
 * Constants
 * ========================================================================== */

const MENU_WIDTH = 205;

const SECURITY_MENU_WIDTH = 225;

const VIEWPORT_PADDING = 10;

const MENU_GAP = 6;

const SECURITY_MENU_GAP = 6;

const MAIN_MENU_Z_INDEX = 999999;

const SECURITY_MENU_Z_INDEX = 1000000;

/* ============================================================================
 * Helpers
 * ========================================================================== */

function clamp(
  value: number,
  min: number,
  max: number,
): number {
  return Math.min(
    Math.max(value, min),
    max,
  );
}

/* ============================================================================
 * Component
 * ========================================================================== */

export default function UserActionsMenu({
  user,
  canManageUsers: canManageUsersProp,
  canUseSecurityActions:
    canUseSecurityActionsProp,
  onView,
  onEdit,
  onAudit,
  onRole,
  onSecurity,
  onDelete,
  disabled = false,
}: UserActionsMenuProps) {
  /* ==========================================================================
   * RBAC
   * ======================================================================== */

  const hasPermission = useAuthStore(
    (state) => state.hasPermission,
  );

  const canReadUsers =
    hasPermission(
      USERS_READ,
    );

  const canManageUsersFromAuth =
    hasPermission(
      USERS_MANAGE,
    );

  const canManageUsers =
    canManageUsersProp ??
    canManageUsersFromAuth;

  const canUseSecurityActions =
    canUseSecurityActionsProp ??
    canManageUsersFromAuth;

  /* ==========================================================================
   * Menu State
   * ======================================================================== */

  const [
    open,
    setOpen,
  ] = useState(false);

  const [
    securityOpen,
    setSecurityOpen,
  ] = useState(false);

  /* ==========================================================================
   * Position State
   * ======================================================================== */

  const [
    menuPosition,
    setMenuPosition,
  ] = useState<MenuPosition>({
    top: 0,
    left: 0,
  });

  const [
    securityPosition,
    setSecurityPosition,
  ] = useState<MenuPosition>({
    top: 0,
    left: 0,
  });

  /* ==========================================================================
   * DOM References
   * ======================================================================== */

  const triggerRef =
    useRef<HTMLButtonElement | null>(
      null,
    );

  const menuRef =
    useRef<HTMLDivElement | null>(
      null,
    );

  const securityTriggerRef =
    useRef<HTMLButtonElement | null>(
      null,
    );

  const securityMenuRef =
    useRef<HTMLDivElement | null>(
      null,
    );

  /* ==========================================================================
   * IDs
   * ======================================================================== */

  const menuId =
    `user-actions-${user.user_id}`;

  const securityMenuId =
    `${menuId}-security`;

  /* ==========================================================================
   * Close
   * ======================================================================== */

  const closeSecurityMenu =
    () => {
      setSecurityOpen(false);
    };

  const closeMenu =
    () => {
      setSecurityOpen(false);
      setOpen(false);
    };

  /* ==========================================================================
   * Main Menu Toggle
   * ======================================================================== */

  function toggleMenu(
    event: ReactMouseEvent<HTMLButtonElement>,
  ) {
    event.preventDefault();
    event.stopPropagation();

    if (disabled) {
      return;
    }

    setOpen(
      (current) => !current,
    );

    setSecurityOpen(false);
  }

  /* ==========================================================================
   * Main Menu Position
   * ======================================================================== */

  function calculateMenuPosition() {
    const trigger =
      triggerRef.current;

    const menu =
      menuRef.current;

    if (
      !trigger ||
      !menu
    ) {
      return;
    }

    const triggerRect =
      trigger.getBoundingClientRect();

    const menuRect =
      menu.getBoundingClientRect();

    const viewportWidth =
      window.innerWidth;

    const viewportHeight =
      window.innerHeight;

    let left =
      triggerRect.right -
      menuRect.width;

    if (
      left <
      VIEWPORT_PADDING
    ) {
      left =
        VIEWPORT_PADDING;
    }

    if (
      left +
        menuRect.width >
      viewportWidth -
        VIEWPORT_PADDING
    ) {
      left =
        viewportWidth -
        menuRect.width -
        VIEWPORT_PADDING;
    }

    const spaceBelow =
      viewportHeight -
      triggerRect.bottom;

    const spaceAbove =
      triggerRect.top;

    const requiredHeight =
      menuRect.height +
      MENU_GAP;

    let top: number;

    if (
      spaceBelow >=
        requiredHeight ||
      spaceBelow >=
        spaceAbove
    ) {
      top =
        triggerRect.bottom +
        MENU_GAP;
    } else {
      top =
        triggerRect.top -
        menuRect.height -
        MENU_GAP;
    }

    top = clamp(
      top,
      VIEWPORT_PADDING,
      Math.max(
        VIEWPORT_PADDING,
        viewportHeight -
          menuRect.height -
          VIEWPORT_PADDING,
      ),
    );

    left = clamp(
      left,
      VIEWPORT_PADDING,
      Math.max(
        VIEWPORT_PADDING,
        viewportWidth -
          menuRect.width -
          VIEWPORT_PADDING,
      ),
    );

    setMenuPosition({
      top,
      left,
    });
  }

  /* ==========================================================================
   * Security Menu Position
   * ======================================================================== */

  function calculateSecurityPosition() {
    const trigger =
      securityTriggerRef.current;

    const submenu =
      securityMenuRef.current;

    if (
      !trigger ||
      !submenu
    ) {
      return;
    }

    const triggerRect =
      trigger.getBoundingClientRect();

    const submenuRect =
      submenu.getBoundingClientRect();

    const viewportWidth =
      window.innerWidth;

    const viewportHeight =
      window.innerHeight;

    let left =
      triggerRect.left -
      submenuRect.width -
      SECURITY_MENU_GAP;

    if (
      left <
      VIEWPORT_PADDING
    ) {
      left =
        triggerRect.right +
        SECURITY_MENU_GAP;
    }

    if (
      left +
        submenuRect.width >
      viewportWidth -
        VIEWPORT_PADDING
    ) {
      left =
        viewportWidth -
        submenuRect.width -
        VIEWPORT_PADDING;
    }

    let top =
      triggerRect.top;

    if (
      top +
        submenuRect.height >
      viewportHeight -
        VIEWPORT_PADDING
    ) {
      top =
        viewportHeight -
        submenuRect.height -
        VIEWPORT_PADDING;
    }

    top = clamp(
      top,
      VIEWPORT_PADDING,
      Math.max(
        VIEWPORT_PADDING,
        viewportHeight -
          submenuRect.height -
          VIEWPORT_PADDING,
      ),
    );

    left = clamp(
      left,
      VIEWPORT_PADDING,
      Math.max(
        VIEWPORT_PADDING,
        viewportWidth -
          submenuRect.width -
          VIEWPORT_PADDING,
      ),
    );

    setSecurityPosition({
      top,
      left,
    });
  }

  /* ==========================================================================
   * Position Effects
   * ======================================================================== */

  useLayoutEffect(() => {
    if (!open) {
      return;
    }

    calculateMenuPosition();
  }, [open]);

  useLayoutEffect(() => {
    if (!securityOpen) {
      return;
    }

    calculateSecurityPosition();
  }, [securityOpen]);

  /* ==========================================================================
   * Outside Click / Escape / Viewport
   * ======================================================================== */

  useEffect(() => {
    if (!open) {
      return;
    }

    function handleOutsideMouseDown(
      event: globalThis.MouseEvent,
    ) {
      const target =
        event.target;

      if (
        !(target instanceof Node)
      ) {
        return;
      }

      const trigger =
        triggerRef.current;

      const menu =
        menuRef.current;

      const securityTrigger =
        securityTriggerRef.current;

      const securityMenu =
        securityMenuRef.current;

      if (
        trigger?.contains(target) ||
        menu?.contains(target) ||
        securityTrigger?.contains(target) ||
        securityMenu?.contains(target)
      ) {
        return;
      }

      closeMenu();
    }

    function handleEscape(
      event: globalThis.KeyboardEvent,
    ) {
      if (
        event.key !==
        "Escape"
      ) {
        return;
      }

      if (securityOpen) {
        closeSecurityMenu();
        return;
      }

      closeMenu();

      triggerRef.current?.focus();
    }

    function handleViewportChange() {
      calculateMenuPosition();

      if (securityOpen) {
        calculateSecurityPosition();
      }
    }

    document.addEventListener(
      "mousedown",
      handleOutsideMouseDown,
    );

    document.addEventListener(
      "keydown",
      handleEscape,
    );

    window.addEventListener(
      "resize",
      handleViewportChange,
    );

    window.addEventListener(
      "scroll",
      handleViewportChange,
      true,
    );

    return () => {
      document.removeEventListener(
        "mousedown",
        handleOutsideMouseDown,
      );

      document.removeEventListener(
        "keydown",
        handleEscape,
      );

      window.removeEventListener(
        "resize",
        handleViewportChange,
      );

      window.removeEventListener(
        "scroll",
        handleViewportChange,
        true,
      );
    };
  }, [
    open,
    securityOpen,
  ]);

  /* ==========================================================================
   * Stop Row Interaction
   * ======================================================================== */

  function stopPropagation(
    event: ReactMouseEvent,
  ) {
    event.preventDefault();
    event.stopPropagation();
  }

  /* ==========================================================================
   * Action Dispatcher
   * ======================================================================== */

  function dispatchAction(
    callback: (user: User) => void,
  ) {
    closeMenu();

    callback(user);
  }

  /* ==========================================================================
   * View Details
   * ======================================================================== */

  function handleView(
    event: ReactMouseEvent<HTMLButtonElement>,
  ) {
    event.preventDefault();
    event.stopPropagation();

    dispatchAction(
      onView,
    );
  }

  /* ==========================================================================
   * Edit User
   * ======================================================================== */

  function handleEdit(
    event: ReactMouseEvent<HTMLButtonElement>,
  ) {
    event.preventDefault();
    event.stopPropagation();

    if (!canManageUsers) {
      return;
    }

    dispatchAction(
      onEdit,
    );
  }

  /* ==========================================================================
   * Change Role
   * ======================================================================== */

  function handleRole(
    event: ReactMouseEvent<HTMLButtonElement>,
  ) {
    event.preventDefault();
    event.stopPropagation();

    if (
      !canManageUsers ||
      !onRole
    ) {
      return;
    }

    dispatchAction(
      onRole,
    );
  }

  /* ==========================================================================
   * Audit History
   * ======================================================================== */

  function handleAudit(
    event: ReactMouseEvent<HTMLButtonElement>,
  ) {
    event.preventDefault();
    event.stopPropagation();

    dispatchAction(
      onAudit,
    );
  }

  /* ==========================================================================
   * Security Menu Toggle
   * ======================================================================== */

  function toggleSecurityMenu(
    event: ReactMouseEvent<HTMLButtonElement>,
  ) {
    event.preventDefault();
    event.stopPropagation();

    if (
      disabled ||
      !canUseSecurityActions ||
      !onSecurity
    ) {
      return;
    }

    setSecurityOpen(
      (current) => !current,
    );
  }

  /* ==========================================================================
   * Exact Security Action
   * ======================================================================== */

  function dispatchSecurityAction(
    action: UserSecurityAction,
  ) {
    if (
      !canUseSecurityActions ||
      !onSecurity
    ) {
      return;
    }

    setSecurityOpen(false);
    setOpen(false);

    onSecurity(
      user,
      action,
    );
  }

  function handleSecurityAction(
    event: ReactMouseEvent<HTMLButtonElement>,
    action: UserSecurityAction,
  ) {
    event.preventDefault();
    event.stopPropagation();

    dispatchSecurityAction(
      action,
    );
  }

  /* ==========================================================================
   * Delete User
   * ======================================================================== */

  function handleDelete(
    event: ReactMouseEvent<HTMLButtonElement>,
  ) {
    event.preventDefault();
    event.stopPropagation();

    if (!canManageUsers) {
      return;
    }

    dispatchAction(
      onDelete,
    );
  }

  /* ==========================================================================
   * Permission Gate
   * ======================================================================== */

  if (!canReadUsers) {
    return null;
  }

  /* ==========================================================================
   * Security Submenu
   * ======================================================================== */

  const securitySubmenu =
    securityOpen &&
    onSecurity &&
    canUseSecurityActions
      ? createPortal(
          <div
            ref={securityMenuRef}
            id={securityMenuId}
            className="user-actions-submenu-content"
            role="menu"
            aria-label="Security actions"
            style={{
              position: "fixed",
              top: securityPosition.top,
              left: securityPosition.left,
              width: SECURITY_MENU_WIDTH,
              zIndex:
                SECURITY_MENU_Z_INDEX,
            }}
            onClick={
              stopPropagation
            }
            onMouseDown={
              stopPropagation
            }
          >
            {/* Header */}

            <div className="user-actions-submenu-header">
              <div className="user-actions-submenu-title">
                <Shield
                  size={14}
                  aria-hidden="true"
                />

                <span>
                  Security Actions
                </span>
              </div>

              <button
                type="button"
                className="user-actions-submenu-close"
                aria-label="Close security actions"
                title="Close"
                onClick={(event) => {
                  event.preventDefault();
                  event.stopPropagation();

                  closeSecurityMenu();
                }}
              >
                <X
                  size={13}
                  aria-hidden="true"
                />
              </button>
            </div>

            <div
              className="user-actions-divider"
              role="separator"
            />

            {/* Enable / Disable */}

            <button
              type="button"
              role="menuitem"
              className="user-actions-submenu-item"
              title={
                user.is_active
                  ? "Disable user"
                  : "Enable user"
              }
              onClick={(event) =>
                handleSecurityAction(
                  event,
                  user.is_active
                    ? "disable_user"
                    : "enable_user",
                )
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
                {user.is_active
                  ? "Disable User"
                  : "Enable User"}
              </span>
            </button>

            {/* Lock / Unlock */}

            <button
              type="button"
              role="menuitem"
              className="user-actions-submenu-item"
              title={
                user.is_locked
                  ? "Unlock user"
                  : "Lock user"
              }
              onClick={(event) =>
                handleSecurityAction(
                  event,
                  user.is_locked
                    ? "unlock_user"
                    : "lock_user",
                )
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
                {user.is_locked
                  ? "Unlock User"
                  : "Lock User"}
              </span>
            </button>

            {/* Reset Password */}

            <button
              type="button"
              role="menuitem"
              className="user-actions-submenu-item"
              title="Reset password"
              onClick={(event) =>
                handleSecurityAction(
                  event,
                  "reset_password",
                )
              }
            >
              <KeyRound
                size={14}
                aria-hidden="true"
              />

              <span>
                Reset Password
              </span>
            </button>

            {/* Force Password Change */}

            <button
              type="button"
              role="menuitem"
              className="user-actions-submenu-item"
              title="Force password change"
              onClick={(event) =>
                handleSecurityAction(
                  event,
                  "force_password_change",
                )
              }
            >
              <KeyRound
                size={14}
                aria-hidden="true"
              />

              <span>
                Force Password Change
              </span>
            </button>

            {/* Active Sessions */}

            <button
              type="button"
              role="menuitem"
              className="user-actions-submenu-item"
              title="View active sessions"
              onClick={(event) =>
                handleSecurityAction(
                  event,
                  "active_sessions",
                )
              }
            >
              <UsersRound
                size={14}
                aria-hidden="true"
              />

              <span>
                Active Sessions
              </span>
            </button>

            {/* Revoke Sessions */}

            <button
              type="button"
              role="menuitem"
              className="user-actions-submenu-item"
              title="Revoke active sessions"
              onClick={(event) =>
                handleSecurityAction(
                  event,
                  "revoke_sessions",
                )
              }
            >
              <LogOut
                size={14}
                aria-hidden="true"
              />

              <span>
                Revoke Sessions
              </span>
            </button>
          </div>,
          document.body,
        )
      : null;

  /* ==========================================================================
   * Main Dropdown
   * ======================================================================== */

  const dropdown =
    open
      ? createPortal(
          <div
            ref={menuRef}
            id={menuId}
            className="user-actions-dropdown"
            role="menu"
            aria-label={
              `Actions for ${user.username}`
            }
            style={{
              position: "fixed",
              top: menuPosition.top,
              left: menuPosition.left,
              width: MENU_WIDTH,
              zIndex:
                MAIN_MENU_Z_INDEX,
            }}
            onClick={
              stopPropagation
            }
            onMouseDown={
              stopPropagation
            }
          >
            {/* View Details */}

            <button
              type="button"
              role="menuitem"
              className="user-actions-menu-item"
              onClick={
                handleView
              }
            >
              <Eye
                size={14}
                aria-hidden="true"
              />

              <span>
                View Details
              </span>
            </button>

            {/* Edit User */}

            {canManageUsers && (
              <button
                type="button"
                role="menuitem"
                className="user-actions-menu-item"
                onClick={
                  handleEdit
                }
              >
                <Pencil
                  size={14}
                  aria-hidden="true"
                />

                <span>
                  Edit User
                </span>
              </button>
            )}

            {/* Change Role */}

            {canManageUsers &&
              onRole && (
                <button
                  type="button"
                  role="menuitem"
                  className="user-actions-menu-item"
                  onClick={
                    handleRole
                  }
                >
                  <UserCheck
                    size={14}
                    aria-hidden="true"
                  />

                  <span>
                    Change Role
                  </span>
                </button>
              )}

            {/* Audit History */}

            <button
              type="button"
              role="menuitem"
              className="user-actions-menu-item"
              onClick={
                handleAudit
              }
            >
              <History
                size={14}
                aria-hidden="true"
              />

              <span>
                Audit History
              </span>
            </button>

            {/* Divider */}

            {(canManageUsers ||
              canUseSecurityActions) && (
              <div
                className="user-actions-divider"
                role="separator"
              />
            )}

            {/* Security */}

            {canUseSecurityActions &&
              onSecurity && (
                <button
                  ref={
                    securityTriggerRef
                  }
                  type="button"
                  role="menuitem"
                  className="user-actions-menu-item user-actions-security-trigger"
                  aria-haspopup="menu"
                  aria-expanded={
                    securityOpen
                  }
                  aria-controls={
                    securityOpen
                      ? securityMenuId
                      : undefined
                  }
                  onClick={
                    toggleSecurityMenu
                  }
                >
                  <Shield
                    size={14}
                    aria-hidden="true"
                  />

                  <span>
                    Security
                  </span>

                  <ChevronRight
                    size={14}
                    className={
                      securityOpen
                        ? "user-actions-chevron open"
                        : "user-actions-chevron"
                    }
                    aria-hidden="true"
                  />
                </button>
              )}

            {/* Delete Divider */}

            {canManageUsers && (
              <div
                className="user-actions-divider"
                role="separator"
              />
            )}

            {/* Delete */}

            {canManageUsers && (
              <button
                type="button"
                role="menuitem"
                className="user-actions-menu-item user-actions-menu-item-danger"
                onClick={
                  handleDelete
                }
              >
                <Trash2
                  size={14}
                  aria-hidden="true"
                />

                <span>
                  Delete User
                </span>
              </button>
            )}

            {securitySubmenu}
          </div>,
          document.body,
        )
      : null;

  /* ==========================================================================
   * Trigger
   * ======================================================================== */

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        className="icon-button user-actions-trigger"
        aria-label={
          `Actions for ${user.username}`
        }
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={
          open
            ? menuId
            : undefined
        }
        disabled={disabled}
        title="User actions"
        onMouseDown={(event) => {
          event.preventDefault();
          event.stopPropagation();
        }}
        onClick={
          toggleMenu
        }
      >
        <MoreVertical
          size={16}
          aria-hidden="true"
        />
      </button>

      {dropdown}
    </>
  );
}