import { Navigate, Route, useParams } from "react-router-dom";

import { PermissionRoute } from "../../components/auth/PermissionRoute";

import IOCDetails from "./pages/IOCDetails";
import ThreatIntelligence from "./pages/ThreatIntelligence";
import { THREAT_INTELLIGENCE_READ } from "./permissions";

function IOCDetailsRoute() {
  const { iocId } = useParams<{
    iocId: string;
  }>();

  if (!iocId) {
    return (
      <Navigate
        to="/threat-intelligence"
        replace
      />
    );
  }

  return (
    <IOCDetails />
  );
}

export function ThreatIntelligenceRoutes() {
  return (
    <Route
      element={
        <PermissionRoute
          permission={THREAT_INTELLIGENCE_READ}
        />
      }
    >
      <Route
        path="/threat-intelligence"
        element={
          <ThreatIntelligence />
        }
      />

      <Route
        path="/threat-intelligence/:iocId"
        element={
          <IOCDetailsRoute />
        }
      />
    </Route>
  );
}

export default ThreatIntelligenceRoutes;
