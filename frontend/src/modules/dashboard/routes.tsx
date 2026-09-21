/*
 * ============================================================================
 * Dashboard Routes
 * SentinelSIEM SOC Dashboard
 * ============================================================================
 *
 * Dashboard-owned route boundary.
 *
 * The application route registry only mounts this module. Permission
 * enforcement and Dashboard page composition remain inside the module.
 * ============================================================================
 */

import { Route } from "react-router-dom";

import { PermissionRoute } from "../../components/auth/PermissionRoute";

import Dashboard from "./pages/Dashboard";
import { DASHBOARD_PERMISSIONS } from "./permissions";

/* ==========================================================================
 * Dashboard Route Registry
 * ========================================================================== */

/**
 * Register Dashboard routes under the application's protected route tree.
 *
 * The parent application route already provides:
 *
 *   - authentication
 *   - ProtectedRoute
 *   - AppShell
 *
 * This module owns:
 *
 *   - Dashboard permission boundary
 *   - Dashboard index route
 *   - Dashboard page
 */
export function DashboardRoutes() {
  return (
    <Route
      element={
        <PermissionRoute
          permission={DASHBOARD_PERMISSIONS.read}
        />
      }
    >
      <Route
        index
        element={<Dashboard />}
      />
    </Route>
  );
}

/* ==========================================================================
 * Default Export
 * ========================================================================== */

export default DashboardRoutes;
