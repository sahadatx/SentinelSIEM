/* ==========================================================================
 * MITRE ATT&CK Module Routes
 * SentinelSIEM SOC Dashboard
 * ========================================================================== */

import {
  Navigate,
  Route,
  Routes,
  useParams,
} from "react-router-dom";

import MitrePage from "./pages/MitrePage";
import MitreTechniquePage from "./pages/MitreTechniquePage";

/* ==========================================================================
 * Module Routes
 * ========================================================================== */

/**
 * Route tree owned by the MITRE ATT&CK module.
 *
 * Expected application mount:
 *
 *   <Route path="/mitre/*" element={<MitreRoutes />} />
 *
 * Routes:
 *
 *   /mitre
 *   /mitre/techniques/:techniqueId
 *
 * The application-level route registry should mount this module
 * instead of defining individual MITRE routes itself.
 */
export function MitreRoutes() {
  return (
    <Routes>
      {/* --------------------------------------------------------------------
       * MITRE Overview
       * ------------------------------------------------------------------ */}

      <Route
        index
        element={<MitrePage />}
      />

      {/* --------------------------------------------------------------------
       * MITRE Technique Details
       * ------------------------------------------------------------------ */}

      <Route
        path="techniques/:techniqueId"
        element={<MitreTechniqueRoute />}
      />

      {/* --------------------------------------------------------------------
       * Unknown MITRE Route
       * ------------------------------------------------------------------ */}

      <Route
        path="*"
        element={
          <Navigate
            to="/mitre"
            replace
          />
        }
      />
    </Routes>
  );
}

/* ==========================================================================
 * Technique Route Adapter
 * ========================================================================== */

/**
 * Reads the techniqueId route parameter and passes it
 * explicitly to the page component.
 *
 * Keeping router-specific logic here prevents
 * MitreTechniquePage from depending directly on
 * React Router.
 */
function MitreTechniqueRoute() {
  const params =
    useParams<{
      techniqueId: string;
    }>();

  const techniqueId =
    params.techniqueId?.trim();

  if (!techniqueId) {
    return (
      <Navigate
        to="/mitre"
        replace
      />
    );
  }

  return (
    <MitreTechniquePage
      techniqueId={techniqueId}
    />
  );
}

/* ==========================================================================
 * Default Export
 * ========================================================================== */

export default MitreRoutes;
