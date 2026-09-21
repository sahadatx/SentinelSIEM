/**
 * ============================================================================
 * SentinelSIEM — Application Routes
 * ============================================================================
 *
 * Top-level application route registry.
 *
 * Responsibilities:
 * - Authentication
 * - Protected application shell
 * - Feature-module composition
 * - Application-level permission boundaries
 * - Fallback routing
 *
 * Feature modules own:
 * - Routes
 * - Pages
 * - API boundaries
 * - Permissions
 * - Navigation metadata
 *
 * Current locked routes:
 *
 * Users:
 *   /users
 *   /users/create
 *   /users/:userId
 *   /users/:userId/edit
 *   /users/:userId/audit
 *
 * Global Audit:
 *   /audit
 *
 * Backend remains the authoritative security boundary.
 *
 * ============================================================================
 */

import {
  Navigate,
  Route,
  Routes,
} from "react-router-dom";

import { PERMISSIONS } from "../auth/rbac";

import { AuthBootstrap } from "../components/auth/AuthBootstrap";
import { PermissionRoute } from "../components/auth/PermissionRoute";
import { ProtectedRoute } from "../components/auth/ProtectedRoute";
import { AppShell } from "../components/layout/AppShell";

import Login from "../pages/Login";

/* ============================================================================
 * Feature Module Routes
 * ========================================================================== */

import { AlertsRoutes } from "../modules/alerts/routes";
import { AssetsRoutes } from "../modules/assets/routes";
import { AuditRoutes } from "../modules/audit/routes";
import { DashboardRoutes } from "../modules/dashboard/routes";
import { DetectionRoutes } from "../modules/detections/routes";
import { EventsRoutes } from "../modules/events/routes";
import { IncidentsRoutes } from "../modules/incidents/routes";
import { MitreRoutes } from "../modules/mitre/routes";
import {
  ThreatIntelligenceRoutes,
} from "../modules/threat-intelligence/routes";
import { UsersRoutes } from "../modules/users/routes";

/* ============================================================================
 * System Module
 * ========================================================================== */

import { System } from "../modules/system";

/* ============================================================================
 * Dashboard Runtime
 * ========================================================================== */

/**
 * Authenticated SentinelSIEM application shell.
 *
 * AppShell owns the global layout and renders
 * child routes through React Router's <Outlet />.
 */
function DashboardRuntime() {
  return <AppShell />;
}

/* ============================================================================
 * Application Routes
 * ========================================================================== */

/**
 * Top-level SentinelSIEM route registry.
 *
 * Feature modules that expose route factories are invoked directly:
 *
 *   {DashboardRoutes()}
 *   {UsersRoutes()}
 *   {AuditRoutes()}
 *
 * Each factory returns valid React Router <Route> elements.
 */
export function AppRoutes() {
  return (
    <>
      {/* ====================================================================
       * Authentication Bootstrap
       * ================================================================== */}

      <AuthBootstrap />

      <Routes>
        {/* ==================================================================
         * Public Authentication
         * ================================================================== */}

        <Route
          path="/login"
          element={<Login />}
        />

        {/* ==================================================================
         * Protected Application
         * ================================================================== */}

        <Route
          element={<ProtectedRoute />}
        >
          <Route
            element={<DashboardRuntime />}
          >
            {/* ==============================================================
             * Dashboard Module
             * ============================================================== */}

            {DashboardRoutes()}

            {/* ==============================================================
             * Events Module
             * ============================================================== */}

            {EventsRoutes()}

            {/* ==============================================================
             * Alerts Module
             * ============================================================== */}

            {AlertsRoutes()}

            {/* ==============================================================
             * Incidents Module
             * ============================================================== */}

            {IncidentsRoutes()}

            {/* ==============================================================
             * Threat Intelligence Module
             * ============================================================== */}

            {ThreatIntelligenceRoutes()}

            {/* ==============================================================
             * Detection Module
             * ============================================================== */}

            {DetectionRoutes()}

            {/* ==============================================================
             * MITRE ATT&CK
             *
             * MitreRoutes owns its internal route tree.
             * Application-level permission boundary is kept here.
             * ============================================================== */}

            <Route
              path="/mitre/*"
              element={
                <PermissionRoute
                  permission={
                    PERMISSIONS.MITRE_READ
                  }
                />
              }
            >
              <Route
                path="*"
                element={<MitreRoutes />}
              />
            </Route>

            {/* ==============================================================
             * User Management Module
             * ============================================================== */}

            {UsersRoutes()}

            {/* ==============================================================
             * Global Audit Module
             *
             * Owns:
             *   /audit
             *
             * AuditLogs handles audit:read authorization.
             * ============================================================== */}

            {AuditRoutes()}

            {/* ==============================================================
             * Assets Module
             * ============================================================== */}

            {AssetsRoutes()}

            {/* ==============================================================
             * System Module
             *
             * Application-level system:read permission boundary.
             * ============================================================== */}

            <Route
              element={
                <PermissionRoute
                  permission={
                    PERMISSIONS.SYSTEM_READ
                  }
                />
              }
            >
              <Route
                path="/system"
                element={<System />}
              />
            </Route>

            {/* ==============================================================
             * Reserved Risk Route
             * ============================================================== */}

            <Route
              path="/risk"
              element={
                <Navigate
                  to="/"
                  replace
                />
              }
            />

            {/* ==============================================================
             * Unknown Application Route
             *
             * Dashboard is the application home route.
             * ============================================================== */}

            <Route
              path="*"
              element={
                <Navigate
                  to="/"
                  replace
                />
              }
            />
          </Route>
        </Route>
      </Routes>
    </>
  );
}

/* ============================================================================
 * Default Export
 * ========================================================================== */

export default AppRoutes;