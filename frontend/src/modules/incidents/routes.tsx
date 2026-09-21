import { Route } from "react-router-dom";

import { PermissionRoute } from "../../components/auth/PermissionRoute";
import { PERMISSIONS } from "../../auth/rbac";

import Incidents from "./pages/Incidents";
import IncidentDetails from "./pages/IncidentDetails";

/* ==========================================================================
   Incidents Module Routes
   ========================================================================== */

/**
 * Incident routing remains owned by the Incidents module.
 *
 * Routes:
 *   /incidents
 *   /incidents/:incidentId
 *
 * The existing route architecture is intentionally preserved.
 * Create Incident is handled by the main Incidents page, while
 * Incident Details remains available as a dedicated route.
 */
export function IncidentsRoutes() {
  return (
    <Route
      element={
        <PermissionRoute
          permission={PERMISSIONS.INCIDENTS_READ}
        />
      }
    >
      <Route
        path="/incidents"
        element={<Incidents />}
      />

      <Route
        path="/incidents/:incidentId"
        element={<IncidentDetails />}
      />
    </Route>
  );
}

export default IncidentsRoutes;