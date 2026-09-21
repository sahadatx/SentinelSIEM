import { Route } from "react-router-dom";

import { PermissionRoute } from "../../components/auth/PermissionRoute";
import ThreatIntelligence from "./pages/ThreatIntelligence";
import IOCDetails from "./pages/IOCDetails";
import {
  THREAT_INTELLIGENCE_PERMISSIONS,
} from "./permissions";

/* ==========================================================================
 * Threat Intelligence Routes
 * ========================================================================== */

export function ThreatIntelligenceRoutes() {
  return (
    <Route
      element={
        <PermissionRoute
          permission={THREAT_INTELLIGENCE_PERMISSIONS.READ}
        />
      }
    >
      {/* ------------------------------------------------------------------
       * IOC Inventory
       * ------------------------------------------------------------------ */}

      <Route
        path="/threat-intelligence"
        element={<ThreatIntelligence />}
      />

      {/* ------------------------------------------------------------------
       * IOC Details
       * ------------------------------------------------------------------ */}

      <Route
        path="/threat-intelligence/iocs/:iocId"
        element={<IOCDetails />}
      />
    </Route>
  );
}

export default ThreatIntelligenceRoutes;