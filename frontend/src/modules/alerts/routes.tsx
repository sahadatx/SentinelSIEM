import { Route } from "react-router-dom";

import { PermissionRoute } from "../../components/auth/PermissionRoute";

import Alerts from "./pages/Alerts";
import AlertDetails from "./pages/AlertDetails";

import { ALERTS_READ } from "./permissions";

/**
 * Alerts module route registry.
 *
 * Routing ownership remains inside the alerts module.
 */
export function AlertsRoutes() {
  return (
    <Route
      element={
        <PermissionRoute
          permission={ALERTS_READ}
        />
      }
    >
      <Route
        path="/alerts"
        element={<Alerts />}
      />

      <Route
        path="/alerts/:alertId"
        element={<AlertDetails />}
      />
    </Route>
  );
}

export default AlertsRoutes;