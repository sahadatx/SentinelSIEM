import {
  useCallback,
  useEffect,
  useState,
} from "react";
import {
  AlertTriangle,
  Clock3,
  RefreshCw,
} from "lucide-react";

import dashboardApi from "../api";
import type {
  DashboardSnapshot as DashboardSnapshotData,
} from "../types";

import DashboardCapabilities from "../components/DashboardCapabilities";
import DashboardMetrics from "../components/DashboardMetrics";
import DashboardPlatformStatus from "../components/DashboardPlatformStatus";
import DashboardRecentAlerts from "../components/DashboardRecentAlerts";
import DashboardSnapshot from "../components/DashboardSnapshot";

import "../Dashboard.css";

/* ==========================================================================
 * Constants
 * ========================================================================== */

const EMPTY_DASHBOARD_SNAPSHOT: DashboardSnapshotData = {
  events: null,
  alerts: null,
  incidents: null,
  iocs: null,
  mitre: null,
  health: null,
  system: null,
};

/* ==========================================================================
 * Component
 * ========================================================================== */

export default function Dashboard() {
  const [snapshot, setSnapshot] =
    useState<DashboardSnapshotData>(
      EMPTY_DASHBOARD_SNAPSHOT,
    );

  const [loading, setLoading] = useState(false);

  const [error, setError] =
    useState<string | null>(null);

  const [lastRefresh, setLastRefresh] =
    useState<Date | null>(null);

  /* ==========================================================================
   * Load Dashboard Data
   * ========================================================================== */

  const loadDashboard = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const results = await Promise.allSettled([
        dashboardApi.events(),
        dashboardApi.alerts(),
        dashboardApi.incidents(),
        dashboardApi.iocs(),
        dashboardApi.mitre(),
        dashboardApi.health(),
        dashboardApi.system(),
      ]);

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

        /*
         * dashboardApi.iocs() is responsible for
         * converting the backend IOC transport model
         * into the frontend IOC domain model.
         *
         * This keeps Dashboard.tsx independent from
         * IOCTransportResponse.
         */
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
        (result) =>
          result.status === "rejected",
      ).length;

      if (failedEndpoints > 0) {
        setError(
          `${failedEndpoints} API endpoint${
            failedEndpoints === 1 ? "" : "s"
          } unavailable`,
        );
      }

      setLastRefresh(new Date());
    } catch {
      /*
       * Promise.allSettled() normally prevents this
       * branch from being reached.
       *
       * Keep this defensive boundary in case the
       * loading implementation changes in the future.
       */
      setError(
        "Unable to load dashboard data.",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  /* ==========================================================================
   * Initial Load
   * ========================================================================== */

  useEffect(() => {
    void loadDashboard();
  }, [loadDashboard]);

  /* ==========================================================================
   * Render
   * ========================================================================== */

  return (
    <main
      className="dashboard-page"
      aria-label="SOC dashboard"
    >
      {/* =====================================================================
       * Page Header
       * ===================================================================== */}

      <header className="dashboard-page-header">
        <div className="dashboard-page-heading">
          <span className="dashboard-page-eyebrow">
            SECURITY OPERATIONS CENTER
          </span>

          <h1 className="dashboard-page-title">
            SOC Overview
          </h1>

          <p className="dashboard-page-description">
            Live security posture across the
            SentinelSIEM platform.
          </p>
        </div>

        <div className="dashboard-page-actions">
          <div
            className="dashboard-refresh-status"
            aria-live="polite"
          >
            <Clock3
              size={14}
              aria-hidden="true"
            />

            <span>
              {lastRefresh
                ? `Last refresh: ${lastRefresh.toLocaleTimeString()}`
                : "Last refresh: —"}
            </span>
          </div>

          <button
            type="button"
            className="dashboard-refresh-button"
            onClick={() => {
              void loadDashboard();
            }}
            disabled={loading}
            aria-label={
              loading
                ? "Refreshing dashboard"
                : "Refresh dashboard"
            }
          >
            <RefreshCw
              size={15}
              aria-hidden="true"
              className={
                loading
                  ? "dashboard-refresh-icon is-spinning"
                  : "dashboard-refresh-icon"
              }
            />

            <span>
              {loading
                ? "Refreshing..."
                : "Refresh"}
            </span>
          </button>
        </div>
      </header>

      {/* =====================================================================
       * Partial API Failure Notice
       * ===================================================================== */}

      {error && (
        <section
          className="dashboard-error-banner"
          role="alert"
          aria-live="assertive"
        >
          <div className="dashboard-error-icon">
            <AlertTriangle
              size={17}
              aria-hidden="true"
            />
          </div>

          <div className="dashboard-error-content">
            <strong>
              Dashboard data partially unavailable
            </strong>

            <span>
              {error}. Available dashboard data
              remains visible.
            </span>
          </div>
        </section>
      )}

      {/* =====================================================================
       * Primary Security Metrics
       * ===================================================================== */}

      <section
        className="dashboard-metrics-section"
        aria-label="Security metrics"
      >
        <DashboardMetrics
          snapshot={snapshot}
        />
      </section>

      {/* =====================================================================
       * Main Dashboard Grid
       * ===================================================================== */}

      <section
        className="dashboard-content-grid"
        aria-label="Dashboard status and intelligence"
      >
        {/* ---------------------------------------------------------------------
         * Platform Status
         * --------------------------------------------------------------------- */}

        <article className="dashboard-grid-panel dashboard-grid-panel-wide">
          <DashboardPlatformStatus
            snapshot={snapshot}
          />
        </article>

        {/* ---------------------------------------------------------------------
         * Recent Alerts
         * --------------------------------------------------------------------- */}

        <article className="dashboard-grid-panel dashboard-grid-panel-wide">
          <DashboardRecentAlerts
            snapshot={snapshot}
          />
        </article>

        {/* ---------------------------------------------------------------------
         * Platform Snapshot
         * --------------------------------------------------------------------- */}

        <article className="dashboard-grid-panel dashboard-grid-panel-half">
          <DashboardSnapshot
            snapshot={snapshot}
          />
        </article>

        {/* ---------------------------------------------------------------------
         * Platform Capabilities
         * --------------------------------------------------------------------- */}

        <article className="dashboard-grid-panel dashboard-grid-panel-half">
          <DashboardCapabilities
            snapshot={snapshot}
          />
        </article>
      </section>
    </main>
  );
}