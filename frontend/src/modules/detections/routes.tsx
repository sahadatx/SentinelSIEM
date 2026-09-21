import { Route } from "react-router-dom";

import { PermissionRoute } from "../../components/auth/PermissionRoute";

import Detections from "./pages/Detections";
import { DETECTION_PERMISSIONS } from "./permissions";

/* ==========================================================================
 * Detection Module Routes
 * SentinelSIEM SOC Dashboard
 *
 * Module route boundary:
 *   /detections
 *
 * READ permission:
 *   detections:read
 *
 * MANAGEMENT permission:
 *   detections:manage
 *
 * The module owns its feature-level routing.
 * Application routing only mounts <DetectionRoutes />.
 * ========================================================================== */

/* ==========================================================================
 * Detection Routes
 * ========================================================================== */

/**
 * Register all Detection feature routes.
 *
 * The Detection dashboard requires:
 *
 *   detections:read
 *
 * Future management-specific routes can additionally use:
 *
 *   detections:manage
 *
 * without changing the application-level routing architecture.
 */
export function DetectionRoutes() {
  return (
    <Route
      element={
        <PermissionRoute
          permission={DETECTION_PERMISSIONS.READ}
        />
      }
    >
      {/* ------------------------------------------------------------------
       * Detection Dashboard
       * ---------------------------------------------------------------- */}

      <Route
        path="/detections"
        element={<Detections />}
      />

      {/* ------------------------------------------------------------------
       * Future Detection Routes
       *
       * Possible routes:
       *
       *   /detections/rules
       *   /detections/rules/new
       *   /detections/rules/:ruleId
       *   /detections/rules/:ruleId/edit
       *
       * Management routes should additionally be protected with:
       *
       *   DETECTION_PERMISSIONS.MANAGE
       *
       * Keep Detection-specific routing inside this module.
       * ---------------------------------------------------------------- */}
    </Route>
  );
}

/* ==========================================================================
 * Default Export
 * ========================================================================== */

export default DetectionRoutes;