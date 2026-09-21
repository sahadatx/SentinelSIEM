/**
 * ============================================================================
 * SentinelSIEM — User Management Routes
 * ============================================================================
 *
 * Phase 11 — User Management Routing
 *
 * Final routes:
 *
 *   /users
 *   /users/create
 *   /users/:userId
 *   /users/:userId/edit
 *   /users/:userId/audit
 *
 * Responsibilities:
 * - Protect all User Management routes
 * - Enforce users:read
 * - Resolve route parameters
 * - Validate user route parameters
 * - Redirect invalid user routes to /users
 * - Preserve legacy /user-management compatibility
 *
 * Security:
 * - Frontend route protection is defense-in-depth.
 * - Backend authorization remains the final security boundary.
 *
 * ============================================================================
 */

import {
  Navigate,
  Route,
  useParams,
} from "react-router-dom";

import { ProtectedRoute } from "../../components/auth/ProtectedRoute";
import { PermissionRoute } from "../../components/auth/PermissionRoute";

import Users from "./pages/Users";
import UserDetails from "./pages/UserDetails";
import UserEdit from "./pages/UserEdit";
import UserAudit from "./pages/UserAudit";

import { USERS_READ } from "./permissions";

import "./Users.css";

/* ============================================================================
 * Route Parameter Helpers
 * ========================================================================== */

/**
 * Resolve the user ID from the current route.
 *
 * React Router returns route parameters as:
 *
 *   string | undefined
 *
 * Empty/whitespace-only values are treated as invalid.
 */
function useNormalizedUserId(): string | null {
  const params = useParams();

  const userId = params.userId;

  const normalizedUserId =
    userId?.trim();

  return normalizedUserId
    ? normalizedUserId
    : null;
}

/* ============================================================================
 * User Details Route
 * ========================================================================== */

/**
 * Route adapter for:
 *
 *   /users/:userId
 *
 * Converts the route parameter into the explicit
 * UserDetails component prop.
 */
function UserDetailsRoute() {
  const userId =
    useNormalizedUserId();

  if (!userId) {
    return (
      <Navigate
        to="/users"
        replace
      />
    );
  }

  return (
    <UserDetails
      userId={userId}
    />
  );
}

/* ============================================================================
 * User Edit Route
 * ========================================================================== */

/**
 * Route adapter for:
 *
 *   /users/:userId/edit
 *
 * UserEdit resolves its own route parameter using
 * React Router's useParams().
 */
function UserEditRoute() {
  const userId =
    useNormalizedUserId();

  if (!userId) {
    return (
      <Navigate
        to="/users"
        replace
      />
    );
  }

  return <UserEdit />;
}

/* ============================================================================
 * User Audit Route
 * ========================================================================== */

/**
 * Route adapter for:
 *
 *   /users/:userId/audit
 *
 * Converts the route parameter into the explicit
 * UserAudit component prop.
 */
function UserAuditRoute() {
  const userId =
    useNormalizedUserId();

  if (!userId) {
    return (
      <Navigate
        to="/users"
        replace
      />
    );
  }

  return (
    <UserAudit
      userId={userId}
    />
  );
}

/* ============================================================================
 * Users Routes
 * ========================================================================== */

/**
 * Complete User Management route registry.
 *
 * Route hierarchy:
 *
 *   ProtectedRoute
 *       │
 *       └── PermissionRoute
 *               │
 *               ├── /users
 *               ├── /users/create
 *               ├── /users/:userId
 *               ├── /users/:userId/edit
 *               └── /users/:userId/audit
 *
 * All routes require users:read.
 *
 * Mutation-level authorization such as users:manage
 * remains the responsibility of the relevant page/component
 * and backend endpoint.
 */
export function UsersRoutes() {
  return (
    <Route
      element={
        <ProtectedRoute />
      }
    >
      <Route
        element={
          <PermissionRoute
            permission={USERS_READ}
          />
        }
      >
        {/* ================================================================
            Users Dashboard
            ================================================================ */}

        <Route
          path="/users"
          element={
            <Users />
          }
        />

        {/* ================================================================
            Create User
            ================================================================

            The route itself requires users:read.

            The actual creation operation must additionally
            enforce users:manage.
            ================================================================ */}

        <Route
          path="/users/create"
          element={
            <Navigate
              to="/users"
              replace
            />
          }
        />

        {/* ================================================================
            User Details
            ================================================================ */}

        <Route
          path="/users/:userId"
          element={
            <UserDetailsRoute />
          }
        />

        {/* ================================================================
            User Edit
            ================================================================ */}

        <Route
          path="/users/:userId/edit"
          element={
            <UserEditRoute />
          }
        />

        {/* ================================================================
            User Audit
            ================================================================ */}

        <Route
          path="/users/:userId/audit"
          element={
            <UserAuditRoute />
          }
        />
      </Route>

      {/* ==================================================================
          Legacy Compatibility
          ================================================================== */}

      <Route
        path="/user-management"
        element={
          <Navigate
            to="/users"
            replace
          />
        }
      />
    </Route>
  );
}

/* ============================================================================
 * Default Export
 * ========================================================================== */

export default UsersRoutes;