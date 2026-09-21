/*
 * ============================================================================
 * Asset Routes
 * SentinelSIEM SOC Dashboard
 * ============================================================================
 */

import {
  Navigate,
  Route,
  useParams,
} from "react-router-dom";

import { ProtectedRoute } from "../../components/auth/ProtectedRoute";
import { PermissionRoute } from "../../components/auth/PermissionRoute";

import Assets from "./pages/Assets";
import AssetDetails from "./pages/AssetDetails";

import { ASSETS_READ } from "./permissions";

/*
 * ============================================================================
 * Asset Details Route Adapter
 * ============================================================================
 */

/**
 * Adapts the React Router URL parameter to the AssetDetails page contract.
 *
 * Route:
 *   /assets/:assetId
 *
 * If the route parameter is missing, the user is redirected back to
 * the Assets list instead of rendering an invalid details page.
 */
function AssetDetailsRoute() {
  const {
    assetId,
  } = useParams<{
    assetId: string;
  }>();

  if (!assetId) {
    return (
      <Navigate
        to="/assets"
        replace
      />
    );
  }

  return (
    <AssetDetails
      assetId={assetId}
    />
  );
}

/*
 * ============================================================================
 * Asset Create Route
 * ============================================================================
 */

/**
 * Asset creation entry route.
 *
 * The actual create workflow is owned by Assets.tsx so that:
 *
 *   /assets
 *       ↓
 *   Add Asset
 *       ↓
 *   AssetForm modal
 *
 * The AssetForm requires controlled onSubmit/onCancel handlers and therefore
 * must not be rendered directly here without those handlers.
 *
 * Route:
 *   /assets/new
 *
 * Result:
 *   /assets
 */
function AssetCreateRoute() {
  return (
    <Navigate
      to="/assets"
      replace
    />
  );
}

/*
 * ============================================================================
 * Asset Routes
 * ============================================================================
 */

/**
 * Assets module route contract.
 *
 * Routes:
 *
 *   /assets
 *   /assets/new
 *   /assets/:assetId
 *
 * Legacy compatibility:
 *
 *   /asset-management
 *       ↓
 *   /assets
 *
 * Access:
 *
 *   ProtectedRoute
 *       ↓
 *   PermissionRoute
 *       ↓
 *   assets:read
 *
 * Mutation-level permissions:
 *
 *   assets:manage
 *       ├── Create Asset
 *       ├── Edit Asset
 *       ├── Enable Asset
 *       └── Disable Asset
 */
export function AssetsRoutes() {
  return (
    <Route
      element={
        <ProtectedRoute />
      }
    >
      <Route
        element={
          <PermissionRoute
            permission={
              ASSETS_READ
            }
          />
        }
      >

        {/* ==================================================================
            Asset List
            ================================================================== */}

        <Route
          path="/assets"
          element={
            <Assets />
          }
        />

        {/* ==================================================================
            Add Asset
            ================================================================== */}

        <Route
          path="/assets/new"
          element={
            <AssetCreateRoute />
          }
        />

        {/* ==================================================================
            Asset Details
            ================================================================== */}

        <Route
          path="/assets/:assetId"
          element={
            <AssetDetailsRoute />
          }
        />
      </Route>

      {/* ====================================================================
          Legacy Asset Route
          ====================================================================

          Keep compatibility with existing links using:

            /asset-management

          Redirect to:

            /assets
          ================================================================== */}

      <Route
        path="/asset-management"
        element={
          <Navigate
            to="/assets"
            replace
          />
        }
      />
    </Route>
  );
}

/*
 * ============================================================================
 * Default Export
 * ============================================================================
 */

export default AssetsRoutes;