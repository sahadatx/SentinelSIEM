/**
 * ============================================================================
 * SentinelSIEM — User Details Panel
 * ============================================================================
 *
 * Presentation component for a single SentinelSIEM user.
 *
 * Tabs:
 * - Overview
 * - Security
 * - Sessions
 * - Activity
 *
 * Responsibilities:
 * - Present user identity and account information
 * - Present assigned roles
 * - Present account/security state
 * - Present session-related information
 * - Present activity information
 * - Delegate mutations/workflows to the parent page
 *
 * This component does NOT:
 * - Perform API requests
 * - Perform RBAC authorization
 * - Mutate user state directly
 * - Implement security business logic
 * - Render Delete User
 *
 * Delete User remains owned by the Users page/table workflow.
 * ============================================================================
 */

import {
  useEffect,
  useState,
  type ReactNode,
} from "react";

import {
  Activity,
  Calendar,
  Clock,
  Eye,
  KeyRound,
  Mail,
  Pencil,
  Shield,
  ShieldAlert,
  ShieldCheck,
  UserRound,
  Users,
} from "lucide-react";

import {
  formatRole,
  isRole,
  ROLES,
} from "../../../auth/rbac";

import type { User } from "../types";

import type {
  UserSecurityAction,
} from "./UserActionsMenu";

/**
 * ============================================================================
 * Types
 * ============================================================================
 */

type UserDetailsTab =
  | "overview"
  | "security"
  | "sessions"
  | "activity";

/**
 * ============================================================================
 * Props
 * ============================================================================
 */

export interface UserDetailsPanelProps {
  user: User | null;

  onEdit?: (
    user: User,
  ) => void;

  onRole?: (
    user: User,
  ) => void;

  onSecurity?: (
    user: User,
  ) => void;

  onSecurityAction?: (
    user: User,
    action: UserSecurityAction,
  ) => void;
}

/**
 * ============================================================================
 * Main Component
 * ============================================================================
 */

export default function UserDetailsPanel({
  user,
  onEdit,
  onRole,
  onSecurity,
  onSecurityAction,
}: UserDetailsPanelProps) {
  const [
    activeTab,
    setActiveTab,
  ] = useState<UserDetailsTab>(
    "overview",
  );

  /**
   * Reset the panel to Overview whenever
   * the selected user changes.
   */
  useEffect(() => {
    setActiveTab("overview");
  }, [user?.user_id]);

  /**
   * Empty state.
   */
  if (!user) {
    return (
      <section
        className="user-details-panel"
        aria-label="User details"
      >
        <div className="user-details-empty">
          <div
            className="user-details-empty-icon"
            aria-hidden="true"
          >
            <UserRound size={22} />
          </div>

          <div className="user-details-empty-content">
            <strong>
              No user selected
            </strong>

            <span>
              Select a user to view
              account details.
            </span>
          </div>
        </div>
      </section>
    );
  }

  /**
   * Derived values.
   */

  const displayName =
    user.display_name?.trim() ||
    user.username;

  const primaryRole =
    resolvePrimaryRole(user);

  const accountStatus =
    user.is_active
      ? "Active"
      : "Disabled";

  const lockStatus =
    user.is_locked
      ? "Locked"
      : "Unlocked";

  const passwordChangeStatus =
    user.force_password_change
      ? "Required"
      : "Not Required";

  /**
   * Tab switch.
   */
  const handleTabChange = (
    tab: UserDetailsTab,
  ) => {
    setActiveTab(tab);
  };

  return (
    <section
      className="user-details-panel"
      aria-label={`Details for ${displayName}`}
    >
      {/* ================================================================== */}
      {/* Header                                                             */}
      {/* ================================================================== */}

      <header className="user-details-panel-header">
        <div className="user-details-panel-heading">
          <span className="user-details-eyebrow">
            USER MANAGEMENT
          </span>

          <h2>
            {displayName}
          </h2>

          <p>
            Review account, security,
            session, and activity
            information.
          </p>
        </div>

        <div
          className="user-details-header-icon"
          aria-hidden="true"
        >
          <UserRound size={21} />
        </div>
      </header>

      {/* ================================================================== */}
      {/* Identity Summary                                                   */}
      {/* ================================================================== */}

      <section
        className="user-details-summary"
        aria-label="User identity summary"
      >
        <div
          className="user-details-avatar"
          aria-hidden="true"
        >
          <UserRound size={25} />
        </div>

        <div className="user-details-summary-content">
          <div className="user-details-summary-name">
            {displayName}
          </div>

          <div className="user-details-summary-username">
            @{user.username}
          </div>

          <div className="user-details-summary-email">
            <Mail
              size={14}
              aria-hidden="true"
            />

            <span>
              {user.email}
            </span>
          </div>
        </div>

        <div className="user-details-summary-status">
          <Status
            label="Account"
            value={accountStatus}
            healthy={user.is_active}
          />

          <Status
            label="Lock"
            value={lockStatus}
            healthy={!user.is_locked}
          />
        </div>
      </section>

      {/* ================================================================== */}
      {/* Tabs                                                               */}
      {/* ================================================================== */}

      <nav
        className="user-details-tabs"
        aria-label="User details sections"
        role="tablist"
      >
        <TabButton
          id="overview-tab"
          panelId="overview-panel"
          active={
            activeTab === "overview"
          }
          icon={
            <Eye
              size={15}
              aria-hidden="true"
            />
          }
          label="Overview"
          onClick={() =>
            handleTabChange("overview")
          }
        />

        <TabButton
          id="security-tab"
          panelId="security-panel"
          active={
            activeTab === "security"
          }
          icon={
            <Shield
              size={15}
              aria-hidden="true"
            />
          }
          label="Security"
          onClick={() =>
            handleTabChange("security")
          }
        />

        <TabButton
          id="sessions-tab"
          panelId="sessions-panel"
          active={
            activeTab === "sessions"
          }
          icon={
            <Users
              size={15}
              aria-hidden="true"
            />
          }
          label="Sessions"
          onClick={() =>
            handleTabChange("sessions")
          }
        />

        <TabButton
          id="activity-tab"
          panelId="activity-panel"
          active={
            activeTab === "activity"
          }
          icon={
            <Activity
              size={15}
              aria-hidden="true"
            />
          }
          label="Activity"
          onClick={() =>
            handleTabChange("activity")
          }
        />
      </nav>

      {/* ================================================================== */}
      {/* Tab Content                                                        */}
      {/* ================================================================== */}

      <div className="user-details-tab-content">
        {/* Overview */}

        {activeTab === "overview" && (
          <div
            id="overview-panel"
            role="tabpanel"
            aria-labelledby="overview-tab"
          >
            <OverviewTab
              user={user}
              primaryRole={primaryRole}
              onEdit={onEdit}
              onRole={onRole}
            />
          </div>
        )}

        {/* Security */}

        {activeTab === "security" && (
          <div
            id="security-panel"
            role="tabpanel"
            aria-labelledby="security-tab"
          >
            <SecurityTab
              user={user}
              accountStatus={
                accountStatus
              }
              lockStatus={
                lockStatus
              }
              passwordChangeStatus={
                passwordChangeStatus
              }
              onSecurity={
                onSecurity
              }
              onSecurityAction={
                onSecurityAction
              }
            />
          </div>
        )}

        {/* Sessions */}

        {activeTab === "sessions" && (
          <div
            id="sessions-panel"
            role="tabpanel"
            aria-labelledby="sessions-tab"
          >
            <SessionsTab
              user={user}
              onSecurity={
                onSecurity
              }
              onSecurityAction={
                onSecurityAction
              }
            />
          </div>
        )}

        {/* Activity */}

        {activeTab === "activity" && (
          <div
            id="activity-panel"
            role="tabpanel"
            aria-labelledby="activity-tab"
          >
            <ActivityTab user={user} />
          </div>
        )}
      </div>
    </section>
  );
}

/**
 * ============================================================================
 * Overview Tab
 * ============================================================================
 */

function OverviewTab({
  user,
  primaryRole,
  onEdit,
  onRole,
}: {
  user: User;
  primaryRole: string;
  onEdit?: (
    user: User,
  ) => void;
  onRole?: (
    user: User,
  ) => void;
}) {
  return (
    <div className="user-details-tab">
      {/* Identity */}

      <section className="user-details-section">
        <SectionHeader
          icon={
            <UserRound
              size={17}
              aria-hidden="true"
            />
          }
          title="Identity"
          description="Account identity information."
        />

        <div className="user-details-grid">
          <Detail
            icon={
              <UserRound
                size={15}
                aria-hidden="true"
              />
            }
            label="Username"
            value={user.username}
          />

          <Detail
            icon={
              <Mail
                size={15}
                aria-hidden="true"
              />
            }
            label="Email"
            value={user.email}
          />

          <Detail
            icon={
              <Shield
                size={15}
                aria-hidden="true"
              />
            }
            label="Primary Role"
            value={formatRole(primaryRole)}
          />

          <Detail
            icon={
              <UserRound
                size={15}
                aria-hidden="true"
              />
            }
            label="Display Name"
            value={
              user.display_name?.trim() ||
              "—"
            }
          />

          <Detail
            icon={
              <KeyRound
                size={15}
                aria-hidden="true"
              />
            }
            label="User ID"
            value={user.user_id}
            mono
            fullWidth
          />
        </div>
      </section>

      {/* Assigned Roles */}

      <section className="user-details-section">
        <SectionHeader
          icon={
            <ShieldCheck
              size={17}
              aria-hidden="true"
            />
          }
          title="Assigned Roles"
          description="Roles currently assigned to this account."
        />

        {user.roles.length === 0 ? (
          <div className="user-details-empty-inline">
            No roles assigned.
          </div>
        ) : (
          <div className="user-details-role-list">
            {user.roles.map(
              (role) => (
                <span
                  key={role}
                  className="user-details-role"
                >
                  <ShieldCheck
                    size={13}
                    aria-hidden="true"
                  />

                  <span>
                    {formatRole(role)}
                  </span>
                </span>
              ),
            )}
          </div>
        )}
      </section>

      {/* Account Status */}

      <section className="user-details-section">
        <SectionHeader
          icon={
            <Shield
              size={17}
              aria-hidden="true"
            />
          }
          title="Account Status"
          description="Current account and security state."
        />

        <div className="user-status-grid">
          <Status
            label="Account"
            value={
              user.is_active
                ? "Active"
                : "Disabled"
            }
            healthy={user.is_active}
          />

          <Status
            label="Lock State"
            value={
              user.is_locked
                ? "Locked"
                : "Unlocked"
            }
            healthy={!user.is_locked}
          />

          <Status
            label="Password Change"
            value={
              user.force_password_change
                ? "Required"
                : "Not Required"
            }
            healthy={
              !user.force_password_change
            }
          />
        </div>
      </section>

      {/* Account Timeline */}

      <section className="user-details-section">
        <SectionHeader
          icon={
            <Calendar
              size={17}
              aria-hidden="true"
            />
          }
          title="Account Timeline"
          description="Important account timestamps."
        />

        <div className="user-details-grid">
          <Detail
            icon={
              <Calendar
                size={15}
                aria-hidden="true"
              />
            }
            label="Created"
            value={formatDate(user.created_at)}
          />

          <Detail
            icon={
              <Clock
                size={15}
                aria-hidden="true"
              />
            }
            label="Last Updated"
            value={formatDate(user.updated_at)}
          />

          <Detail
            icon={
              <Clock
                size={15}
                aria-hidden="true"
              />
            }
            label="Last Login"
            value={formatDate(user.last_login_at)}
          />

          <Detail
            icon={
              <KeyRound
                size={15}
                aria-hidden="true"
              />
            }
            label="Password Changed"
            value={formatDate(user.password_changed_at)}
          />
        </div>
      </section>

      {/* Management Actions */}

      {(onEdit || onRole) && (
        <div className="user-details-actions">
          {onEdit && (
            <button
              type="button"
              className="secondary-button"
              onClick={() =>
                onEdit(user)
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

          {onRole && (
            <button
              type="button"
              className="secondary-button"
              onClick={() =>
                onRole(user)
              }
            >
              <ShieldCheck
                size={14}
                aria-hidden="true"
              />

              <span>
                Change Role
              </span>
            </button>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * ============================================================================
 * Security Tab
 * ============================================================================
 */

function SecurityTab({
  user,
  accountStatus,
  lockStatus,
  passwordChangeStatus,
  onSecurity,
  onSecurityAction,
}: {
  user: User;
  accountStatus: string;
  lockStatus: string;
  passwordChangeStatus: string;
  onSecurity?: (
    user: User,
  ) => void;
  onSecurityAction?: (
    user: User,
    action: UserSecurityAction,
  ) => void;
}) {
  return (
    <div className="user-details-tab">
      {/* Security State */}

      <section className="user-details-section">
        <SectionHeader
          icon={
            <Shield
              size={17}
              aria-hidden="true"
            />
          }
          title="Account Security"
          description="Current account and authentication state."
        />

        <div className="user-status-grid">
          <Status
            label="Account"
            value={accountStatus}
            healthy={user.is_active}
          />

          <Status
            label="Lock State"
            value={lockStatus}
            healthy={!user.is_locked}
          />

          <Status
            label="Password Change"
            value={passwordChangeStatus}
            healthy={
              !user.force_password_change
            }
          />
        </div>
      </section>

      {/* Authentication */}

      <section className="user-details-section">
        <SectionHeader
          icon={
            <KeyRound
              size={17}
              aria-hidden="true"
            />
          }
          title="Authentication"
          description="Authentication-related account information."
        />

        <div className="user-details-grid">
          <Detail
            icon={
              <ShieldAlert
                size={15}
                aria-hidden="true"
              />
            }
            label="Failed Login Attempts"
            value={String(
              user.failed_login_count,
            )}
          />

          <Detail
            icon={
              <Clock
                size={15}
                aria-hidden="true"
              />
            }
            label="Last Login"
            value={formatDate(user.last_login_at)}
          />

          <Detail
            icon={
              <KeyRound
                size={15}
                aria-hidden="true"
              />
            }
            label="Password Changed"
            value={formatDate(user.password_changed_at)}
          />

          <Detail
            icon={
              <ShieldAlert
                size={15}
                aria-hidden="true"
              />
            }
            label="Force Password Change"
            value={passwordChangeStatus}
          />
        </div>
      </section>

      {/* Security Notice */}

      <Notice>
        <ShieldCheck
          size={16}
          aria-hidden="true"
        />

        <span>
          Authentication secrets and
          passwords are never displayed
          in the user details interface.
        </span>
      </Notice>

      {/* Security Actions */}

      {(onSecurity ||
        onSecurityAction) && (
        <div className="user-details-actions">
          {onSecurity && (
            <button
              type="button"
              className="primary-button"
              onClick={() =>
                onSecurity(user)
              }
            >
              <Shield
                size={14}
                aria-hidden="true"
              />

              <span>
                Security Actions
              </span>
            </button>
          )}

          {onSecurityAction && (
            <>
              <button
                type="button"
                className="secondary-button"
                onClick={() =>
                  onSecurityAction(
                    user,
                    "lock_user",
                  )
                }
              >
                <ShieldAlert
                  size={14}
                  aria-hidden="true"
                />

                <span>
                  Lock User
                </span>
              </button>

              <button
                type="button"
                className="secondary-button"
                onClick={() =>
                  onSecurityAction(
                    user,
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
            </>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * ============================================================================
 * Sessions Tab
 * ============================================================================
 */

function SessionsTab({
  user,
  onSecurity,
  onSecurityAction,
}: {
  user: User;
  onSecurity?: (
    user: User,
  ) => void;
  onSecurityAction?: (
    user: User,
    action: UserSecurityAction,
  ) => void;
}) {
  return (
    <div className="user-details-tab">
      <section className="user-details-section">
        <SectionHeader
          icon={
            <Users
              size={17}
              aria-hidden="true"
            />
          }
          title="Sessions"
          description="Active session and session-control information."
        />

        <div className="user-details-grid">
          <Detail
            icon={
              <UserRound
                size={15}
                aria-hidden="true"
              />
            }
            label="User"
            value={user.username}
          />

          <Detail
            icon={
              <Clock
                size={15}
                aria-hidden="true"
              />
            }
            label="Last Login"
            value={formatDate(user.last_login_at)}
          />
        </div>

        <Notice>
          <Users
            size={16}
            aria-hidden="true"
          />

          <span>
            Detailed active-session records
            are handled by the security
            session workflow.
          </span>
        </Notice>

        {(onSecurity ||
          onSecurityAction) && (
          <div className="user-details-actions">
            {onSecurity && (
              <button
                type="button"
                className="primary-button"
                onClick={() =>
                  onSecurity(user)
                }
              >
                <Users
                  size={14}
                  aria-hidden="true"
                />

                <span>
                  Manage Sessions
                </span>
              </button>
            )}

            {onSecurityAction && (
              <button
                type="button"
                className="secondary-button"
                onClick={() =>
                  onSecurityAction(
                    user,
                    "revoke_sessions",
                  )
                }
              >
                <ShieldAlert
                  size={14}
                  aria-hidden="true"
                />

                <span>
                  Revoke Sessions
                </span>
              </button>
            )}
          </div>
        )}
      </section>
    </div>
  );
}

/**
 * ============================================================================
 * Activity Tab
 * ============================================================================
 */

function ActivityTab({
  user,
}: {
  user: User;
}) {
  return (
    <div className="user-details-tab">
      <section className="user-details-section">
        <SectionHeader
          icon={
            <Activity
              size={17}
              aria-hidden="true"
            />
          }
          title="Activity"
          description="Important account activity information."
        />

        <div className="user-details-grid">
          <Detail
            icon={
              <Calendar
                size={15}
                aria-hidden="true"
              />
            }
            label="Account Created"
            value={formatDate(user.created_at)}
          />

          <Detail
            icon={
              <Clock
                size={15}
                aria-hidden="true"
              />
            }
            label="Last Updated"
            value={formatDate(user.updated_at)}
          />

          <Detail
            icon={
              <Clock
                size={15}
                aria-hidden="true"
              />
            }
            label="Last Login"
            value={formatDate(user.last_login_at)}
          />

          <Detail
            icon={
              <ShieldAlert
                size={15}
                aria-hidden="true"
              />
            }
            label="Failed Login Attempts"
            value={String(
              user.failed_login_count,
            )}
          />
        </div>

        <Notice>
          <Activity
            size={16}
            aria-hidden="true"
          />

          <span>
            Detailed audit events should
            be viewed through the dedicated
            User Audit workflow.
          </span>
        </Notice>
      </section>
    </div>
  );
}

/**
 * ============================================================================
 * Section Header
 * ============================================================================
 */

function SectionHeader({
  icon,
  title,
  description,
}: {
  icon: ReactNode;
  title: string;
  description: string;
}) {
  return (
    <div className="user-details-section-header">
      <div className="user-details-section-heading">
        <h3>
          {title}
        </h3>

        <p>
          {description}
        </p>
      </div>

      <div
        className="user-details-section-icon"
        aria-hidden="true"
      >
        {icon}
      </div>
    </div>
  );
}

/**
 * ============================================================================
 * Tab Button
 * ============================================================================
 */

function TabButton({
  id,
  panelId,
  active,
  icon,
  label,
  onClick,
}: {
  id: string;
  panelId: string;
  active: boolean;
  icon: ReactNode;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      id={id}
      type="button"
      className={
        active
          ? "user-details-tab-button active"
          : "user-details-tab-button"
      }
      onClick={onClick}
      role="tab"
      aria-selected={active}
      aria-controls={panelId}
      tabIndex={active ? 0 : -1}
    >
      {icon}

      <span>
        {label}
      </span>
    </button>
  );
}

/**
 * ============================================================================
 * Detail
 * ============================================================================
 */

function Detail({
  icon,
  label,
  value,
  mono = false,
  fullWidth = false,
}: {
  icon: ReactNode;
  label: string;
  value: string;
  mono?: boolean;
  fullWidth?: boolean;
}) {
  return (
    <div
      className={
        fullWidth
          ? "user-detail user-detail-full"
          : "user-detail"
      }
    >
      <div className="user-detail-label">
        {icon}

        <span>
          {label}
        </span>
      </div>

      <strong
        className={
          mono
            ? "user-detail-value mono"
            : "user-detail-value"
        }
        title={value}
      >
        {value}
      </strong>
    </div>
  );
}

/**
 * ============================================================================
 * Status
 * ============================================================================
 */

function Status({
  label,
  value,
  healthy,
}: {
  label: string;
  value: string;
  healthy: boolean;
}) {
  return (
    <div className="user-status">
      <span className="user-status-label">
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

/**
 * ============================================================================
 * Notice
 * ============================================================================
 */

function Notice({
  children,
}: {
  children: ReactNode;
}) {
  return (
    <div
      className="notice"
      role="note"
    >
      {children}
    </div>
  );
}

/**
 * ============================================================================
 * Helpers
 * ============================================================================
 */

/**
 * Resolve the user's primary role.
 *
 * Only known RBAC roles are accepted.
 */
function resolvePrimaryRole(
  user: User,
): string {
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
 * Safely format backend timestamps.
 */
function formatDate(
  value:
    | string
    | null
    | undefined,
): string {
  if (!value) {
    return "—";
  }

  const date =
    new Date(value);

  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    return "—";
  }

  return date.toLocaleString(
    undefined,
    {
      dateStyle: "medium",
      timeStyle: "short",
    },
  );
}