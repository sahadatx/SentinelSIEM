/**
 * ============================================================================
 * SentinelSIEM — Application Shell
 * ============================================================================
 *
 * Authenticated application shell.
 *
 * Responsibilities:
 * - Global application layout
 * - Permission-filtered sidebar navigation
 * - Operations navigation
 * - Administration navigation
 * - Authenticated user presentation
 * - Environment presentation
 * - Notification presentation
 * - Logout handling
 * - Routed application content
 *
 * Architecture:
 *
 *   AppShell
 *      ├── Sidebar
 *      │    ├── Brand
 *      │    ├── Operations
 *      │    ├── Administration
 *      │    └── Status Footer
 *      │
 *      ├── Topbar
 *      │    ├── Environment
 *      │    ├── Notifications
 *      │    ├── User Identity
 *      │    │    ├── Avatar
 *      │    │    ├── Username
 *      │    │    └── Role
 *      │    └── Sign Out
 *      │
 *      └── Routed Content
 *
 * Navigation ownership:
 *
 *   frontend/src/app/navigation.ts
 *
 * AppShell intentionally does not define:
 * - individual application routes
 * - individual module permissions
 * - role-specific navigation rules
 * - module ordering
 *
 * Navigation remains permission-aware through getNavigation().
 *
 * Backend authorization remains the final security boundary.
 *
 * ============================================================================
 */

import {
  useEffect,
  useState,
} from "react";

import {
  Bell,
  CircleGauge,
  LogOut,
  Radio,
} from "lucide-react";

import {
  NavLink,
  Outlet,
  useNavigate,
} from "react-router-dom";

import { getNavigation } from "../../app/navigation";
import { api } from "../../services/api";
import { useAuthStore } from "../../store/auth";

import type { SystemResponse } from "../../types/api";


/**
 * ============================================================================
 * Helpers
 * ============================================================================
 */

/**
 * Format environment name for human-readable presentation.
 */
function formatEnvironment(
  environment?: string | null,
): string {
  if (!environment) {
    return "Unavailable";
  }

  return environment
    .replace(
      /[-_]+/g,
      " ",
    )
    .replace(
      /\b\w/g,
      (character) =>
        character.toUpperCase(),
    );
}


/**
 * Format the primary authenticated role.
 *
 * The authenticated user already provides roles through the existing
 * AuthUser contract. No additional identity field is introduced here.
 */
function formatRole(
  roles?: string[],
): string {
  const role =
    roles?.[0] ??
    "Authenticated User";

  return role
    .replace(
      /[-_]+/g,
      " ",
    )
    .replace(
      /\b\w/g,
      (character) =>
        character.toUpperCase(),
    );
}


/**
 * Generate safe user initials from the existing username.
 */
function getUserInitials(
  username: string | null | undefined,
): string {
  const source =
    username?.trim() ||
    "User";

  const parts =
    source
      .split(/\s+/)
      .filter(Boolean);

  if (parts.length >= 2) {
    const first =
      parts[0]?.charAt(0) ?? "";

    const last =
      parts[parts.length - 1]?.charAt(0) ?? "";

    return (
      `${first}${last}`
    ).toUpperCase();
  }

  return source
    .slice(0, 2)
    .toUpperCase();
}


/**
 * ============================================================================
 * Navigation Item
 * ============================================================================
 *
 * Shared renderer keeps Operations and Administration navigation visually and
 * behaviorally consistent.
 */
function NavigationLink({
  to,
  label,
  icon: Icon,
  end,
}: {
  to: string;
  label: string;
  icon: typeof CircleGauge;
  end?: boolean;
}) {
  return (
    <NavLink
      to={to}
      end={
        end ??
        to === "/"
      }
      className={({ isActive }) =>
        isActive
          ? "nav-item active"
          : "nav-item"
      }
    >
      <Icon
        size={18}
        aria-hidden="true"
      />

      <span>
        {label}
      </span>
    </NavLink>
  );
}


/**
 * ============================================================================
 * App Shell
 * ============================================================================
 */
export function AppShell() {
  const navigate =
    useNavigate();


  /**
   * ==========================================================================
   * Authentication
   * ==========================================================================
   */

  const user =
    useAuthStore(
      (state) => state.user,
    );

  const hasPermission =
    useAuthStore(
      (state) =>
        state.hasPermission,
    );


  /**
   * ==========================================================================
   * System Information
   * ==========================================================================
   */

  const [system, setSystem] =
    useState<SystemResponse | null>(
      null,
    );

  const [loggingOut, setLoggingOut] =
    useState(false);


  /**
   * ==========================================================================
   * Load System Information
   * ==========================================================================
   */

  useEffect(() => {
    let mounted = true;

    async function loadSystem() {
      try {
        const response =
          await api.system();

        if (!mounted) {
          return;
        }

        setSystem(response);
      } catch {
        if (!mounted) {
          return;
        }

        setSystem(null);
      }
    }

    void loadSystem();

    return () => {
      mounted = false;
    };
  }, []);


  /**
   * ==========================================================================
   * Derived Application State
   * ==========================================================================
   */

  const environment =
    formatEnvironment(
      system?.environment,
    );

  const role =
    formatRole(
      user?.roles,
    );

  /**
   * AuthUser exposes username.
   *
   * Keep using the existing authenticated identity field. No display_name
   * field or additional backend identity contract is introduced.
   */
  const username =
    user?.username?.trim() ||
    "Unknown user";

  const initials =
    getUserInitials(
      user?.username,
    );


  /**
   * ==========================================================================
   * Realtime State
   * ==========================================================================
   *
   * Realtime WebSocket lifecycle remains intentionally outside AppShell.
   *
   * Until a dedicated realtime lifecycle owner is introduced,
   * the application operates in API/polling mode.
   */

  const live = false;


  /**
   * ==========================================================================
   * Navigation
   * ==========================================================================
   *
   * Navigation remains owned by:
   *
   *   frontend/src/app/navigation.ts
   *
   * getNavigation() is responsible for returning the permission-filtered
   * navigation registry.
   *
   * AppShell only:
   *
   *   1. receives the already filtered navigation
   *   2. separates Operations from Administration
   *   3. renders both sections in a stable order
   */

  const visibleNavigation =
    getNavigation(
      hasPermission,
    );


  /**
   * ==========================================================================
   * Navigation Grouping
   * ==========================================================================
   *
   * Items without an explicit administration section are treated as
   * Operations.
   */

  const operationsNavigation =
    visibleNavigation.filter(
      (item) =>
        !("section" in item) ||
        item.section !==
          "administration",
    );

  const administrationNavigation =
    visibleNavigation.filter(
      (item) =>
        "section" in item &&
        item.section ===
          "administration",
    );


  /**
   * ==========================================================================
   * Logout
   * ==========================================================================
   *
   * Uses the existing authentication API and existing auth store lifecycle.
   *
   * No new logout behavior is introduced.
   */

  async function handleLogout() {
    if (loggingOut) {
      return;
    }

    setLoggingOut(true);

    try {
      await api.logout();
    } finally {
      navigate(
        "/login",
        {
          replace: true,
        },
      );
    }
  }


  /**
   * ==========================================================================
   * Render
   * ==========================================================================
   */

  return (
    <div className="app-shell">

      {/* ================================================================== */}
      {/* Sidebar                                                            */}
      {/* ================================================================== */}

      <aside
        className="sidebar"
        aria-label="Application sidebar"
      >

        {/* ================================================================ */}
        {/* Brand                                                            */}
        {/* ================================================================ */}

        <div className="sidebar-brand">

          <div className="brand">

            <div
              className="brand-mark"
              aria-hidden="true"
            >
              <CircleGauge
                size={24}
              />
            </div>

            <div className="brand-copy">

              <strong>
                SentinelSIEM
              </strong>

              <span>
                SOC Platform
              </span>

            </div>

          </div>

        </div>


        {/* ================================================================ */}
        {/* Navigation                                                       */}
        {/* ================================================================ */}

        <div className="sidebar-navigation">

          {/* ============================================================ */}
          {/* Operations                                                    */}
          {/* ============================================================ */}

          {operationsNavigation.length > 0 && (
            <section
              className="sidebar-section"
              aria-labelledby="operations-navigation-label"
            >

              <div
                id="operations-navigation-label"
                className="nav-label"
              >
                OPERATIONS
              </div>

              <nav
                className="primary-navigation"
                aria-label="Operations navigation"
              >
                {operationsNavigation.map(
                  (item) => (
                    <NavigationLink
                      key={item.to}
                      to={item.to}
                      label={item.label}
                      icon={item.icon}
                      end={item.end}
                    />
                  ),
                )}
              </nav>

            </section>
          )}


          {/* ============================================================ */}
          {/* Administration                                                */}
          {/* ============================================================ */}

          {administrationNavigation.length > 0 && (
            <section
              className="sidebar-section"
              aria-labelledby="administration-navigation-label"
            >

              <div
                id="administration-navigation-label"
                className="nav-label nav-label-administration"
              >
                ADMINISTRATION
              </div>

              <nav
                className="primary-navigation"
                aria-label="Administration navigation"
              >
                {administrationNavigation.map(
                  (item) => (
                    <NavigationLink
                      key={item.to}
                      to={item.to}
                      label={item.label}
                      icon={item.icon}
                      end={item.end}
                    />
                  ),
                )}
              </nav>

            </section>
          )}

        </div>


        {/* ================================================================ */}
        {/* Sidebar Footer                                                  */}
        {/* ================================================================ */}

        <div className="sidebar-footer">

          <div
            className={
              live
                ? "live-dot online"
                : "live-dot"
            }
            aria-hidden="true"
          />

          <span>
            {live
              ? "Real-time connected"
              : "Polling/API mode"}
          </span>

        </div>

      </aside>


      {/* ================================================================== */}
      {/* Main Application                                                   */}
      {/* ================================================================== */}

      <main className="app-main">

        {/* ================================================================ */}
        {/* Topbar                                                           */}
        {/* ================================================================ */}

        <header className="topbar">

          {/* ============================================================ */}
          {/* Application Identity                                          */}
          {/* ============================================================ */}

          <div className="topbar-title">

            <span className="eyebrow">
              SECURITY OPERATIONS CENTER
            </span>

            <h1>
              SentinelSIEM
            </h1>

          </div>


          {/* ============================================================ */}
          {/* Topbar Actions                                                 */}
          {/* ============================================================ */}

          <div className="topbar-actions">

            {/* ========================================================== */}
            {/* Environment                                                 */}
            {/* ========================================================== */}

            <div
              className={
                `environment-indicator ${
                  system?.environment
                    ? `environment-${system.environment
                        .toLowerCase()
                        .replace(
                          /[^a-z0-9]+/g,
                          "-",
                        )}`
                    : "environment-unavailable"
                }`
              }
              title={
                system?.environment
                  ? `Environment: ${system.environment}`
                  : "Environment unavailable"
              }
            >

              <span
                className="environment-dot"
                aria-hidden="true"
              />

              <Radio
                size={14}
                aria-hidden="true"
              />

              <span>
                {environment}
              </span>

            </div>


            {/* ========================================================== */}
            {/* Separator                                                   */}
            {/* ========================================================== */}

            <div
              className="topbar-divider"
              aria-hidden="true"
            />


            {/* ========================================================== */}
            {/* Notifications                                               */}
            {/* ========================================================== */}

            <button
              className="icon-button notification-button"
              type="button"
              aria-label="Notifications"
              title="Notifications"
            >

              <Bell
                size={18}
                aria-hidden="true"
              />

              <span
                className="notification-indicator"
                aria-hidden="true"
              />

            </button>


            {/* ========================================================== */}
            {/* Separator                                                   */}
            {/* ========================================================== */}

            <div
              className="topbar-divider"
              aria-hidden="true"
            />


            {/* ========================================================== */}
            {/* User Identity                                               */}
            {/* ========================================================== */}

            <div className="user-identity">

              <div
                className="user-avatar"
                aria-hidden="true"
              >
                {initials}
              </div>

              <div className="user-identity-content">

                <strong>
                  {username}
                </strong>

                <span>
                  {role}
                </span>

              </div>

            </div>


            {/* ========================================================== */}
            {/* Separator                                                   */}
            {/* ========================================================== */}

            <div
              className="topbar-divider"
              aria-hidden="true"
            />


            {/* ========================================================== */}
            {/* Sign Out                                                    */}
            {/* ========================================================== */}

            <button
              className="logout-button"
              type="button"
              onClick={
                handleLogout
              }
              disabled={
                loggingOut
              }
              aria-label="Sign out"
              title="Sign out"
            >

              <LogOut
                size={16}
                aria-hidden="true"
              />

              <span>
                {loggingOut
                  ? "Signing out..."
                  : "Sign out"}
              </span>

            </button>

          </div>

        </header>


        {/* ================================================================ */}
        {/* Routed Application Content                                       */}
        {/* ================================================================ */}

        <section
          className="content"
          aria-label="Application content"
        >
          <Outlet />
        </section>

      </main>

    </div>
  );
}