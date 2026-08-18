import { useEffect } from "react";

import { api } from "../services/api";
import { useDashboardStore } from "../store/dashboard";

export function useDashboard() {
  const setSnapshot = useDashboardStore(
    (state) => state.setSnapshot,
  );

  const setError = useDashboardStore(
    (state) => state.setError,
  );

  useEffect(() => {
    let cancelled = false;

    async function loadDashboard() {
      setError(null);

      const results = await Promise.allSettled([
        api.events(),
        api.alerts(),
        api.incidents(),
        api.iocs(),
        api.mitre(),
        api.health(),
        api.system(),
      ]);

      if (cancelled) {
        return;
      }

      const [
        events,
        alerts,
        incidents,
        iocs,
        mitre,
        health,
        system,
      ] = results;

      setSnapshot({
        events:
          events.status === "fulfilled"
            ? events.value
            : null,

        alerts:
          alerts.status === "fulfilled"
            ? alerts.value
            : null,

        incidents:
          incidents.status === "fulfilled"
            ? incidents.value
            : null,

        iocs:
          iocs.status === "fulfilled"
            ? iocs.value
            : null,

        mitre:
          mitre.status === "fulfilled"
            ? mitre.value
            : null,

        health:
          health.status === "fulfilled"
            ? health.value
            : null,

        system:
          system.status === "fulfilled"
            ? system.value
            : null,
      });

      const failedEndpoints = results.filter(
        (result) => result.status === "rejected",
      );

      setError(
        failedEndpoints.length
          ? `${failedEndpoints.length} API endpoint(s) unavailable`
          : null,
      );
    }

    void loadDashboard();

    return () => {
      cancelled = true;
    };
  }, [setSnapshot, setError]);
}