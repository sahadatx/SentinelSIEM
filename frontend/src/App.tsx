import { Routes, Route } from "react-router-dom";

import { AppShell } from "./components/layout/AppShell";
import Overview from "./pages/Overview";
import {
  EventsPage,
  AlertsPage,
  IncidentsPage,
  ThreatIntelPage,
  MitrePage,
  SystemPage,
  GenericPage,
} from "./pages/ResourcePage";
import { useDashboard } from "./hooks/useDashboard";

export default function App() {
  useDashboard();

  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route path="/" element={<Overview />} />

        <Route path="/events" element={<EventsPage />} />

        <Route path="/alerts" element={<AlertsPage />} />

        <Route path="/incidents" element={<IncidentsPage />} />

        <Route
          path="/threat-intelligence"
          element={<ThreatIntelPage />}
        />

        <Route
          path="/detections"
          element={<GenericPage title="Detection Operations" />}
        />

        <Route path="/mitre" element={<MitrePage />} />

        <Route
          path="/assets"
          element={<GenericPage title="Assets" />}
        />

        <Route
          path="/risk"
          element={<GenericPage title="Risk & Prioritization" />}
        />

        <Route path="/system" element={<SystemPage />} />

        <Route path="*" element={<Overview />} />
      </Route>
    </Routes>
  );
}