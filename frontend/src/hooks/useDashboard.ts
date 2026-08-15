import { useEffect, useState } from "react";

import { api } from "../services/api";
import { useDashboardStore } from "../store/dashboard";

export function useDashboard() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(
    null,
  );

  const setSnapshot = useDashboardStore(
    (state) => state.setSnapshot,
  );

  useEffect(() => {
    let cancelled = false;

    async function loadDashboard() {
      setLoading(true);
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

      const snapshot: Parameters<
        typeof setSnapshot
      >[0] = {
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
      };

      setSnapshot(snapshot);

      const failedEndpoints = results.filter(
        (result) => result.status === "rejected",
      );

      if (failedEndpoints.length > 0) {
        setError(
          `${failedEndpoints.length} API endpoint(s) unavailable`,
        );
      } else {
        setError(null);
      }

      setLoading(false);
    }

    void loadDashboard();

    return () => {
      cancelled = true;
    };
  }, [setSnapshot]);

  return {
    loading,
    error,
  };
}