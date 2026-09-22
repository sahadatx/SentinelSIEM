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

import { PERMISSIONS } from "../../../auth/rbac";
import { useAuthStore } from "../../../store/auth";

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


/* ============================================================================
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


/* ============================================================================
 * Component
 * ========================================================================== */

export default function Dashboard() {
  /* --------------------------------------------------------------------------
   * Authentication / Authorization
   * ------------------------------------------------------------------------ */

  const hasPermission = useAuthStore(
    (state) => state.hasPermission,
  );


  /* --------------------------------------------------------------------------
   * Dashboard State
   * ------------------------------------------------------------------------ */

  const [snapshot, setSnapshot] =
    useState<DashboardSnapshotData>(
      EMPTY_DASHBOARD_SNAPSHOT,
    );

  const [loading, setLoading] =
    useState(false);

  const [error, setError] =
    useState<string | null>(null);

  const [lastRefresh, setLastRefresh] =
    useState<Date | null>(null);


  /* ==========================================================================
   * Permission-Aware API Loading
   * ======================================================================== */

  const loadDashboard = useCallback(async () => {
    setLoading(true);
    setError(null);

    /*
     * Resolve permissions once per dashboard refresh.
     *
     * Important:
     *
     * A missing permission means that the endpoint is intentionally skipped.
     * It is NOT treated as an API failure.
     *
     * Therefore:
     *
     *   VIEWER
     *     alerts  -> skipped
     *     health  -> skipped
     *     system  -> skipped
     *
     *   INVESTIGATOR
     *     alerts  -> skipped
     *     health  -> skipped
     *     system  -> skipped
     *
     * This prevents unauthorized requests from reaching the backend.
     */

    const canReadEvents =
      hasPermission(
        PERMISSIONS.EVENTS_READ,
      );

    const canReadAlerts =
      hasPermission(
        PERMISSIONS.ALERTS_READ,
      );

    const canReadIncidents =
      hasPermission(
        PERMISSIONS.INCIDENTS_READ,
      );

    const canReadIOCs =
      hasPermission(
        PERMISSIONS.IOCS_READ,
      );

    const canReadMITRE =
      hasPermission(
        PERMISSIONS.MITRE_READ,
      );

    const canReadSystem =
      hasPermission(
        PERMISSIONS.SYSTEM_READ,
      );


    /*
     * Build only the API requests that the authenticated user is allowed
     * to perform.
     *
     * Unauthorized modules remain null in the dashboard snapshot.
     */

    const tasks = {
      events: canReadEvents
        ? dashboardApi.events()
        : Promise.resolve(null),

      alerts: canReadAlerts
        ? dashboardApi.alerts()
        : Promise.resolve(null),

      incidents: canReadIncidents
        ? dashboardApi.incidents()
        : Promise.resolve(null),

      iocs: canReadIOCs
        ? dashboardApi.iocs()
        : Promise.resolve(null),

      mitre: canReadMITRE
        ? dashboardApi.mitre()
        : Promise.resolve(null),

      health: canReadSystem
        ? dashboardApi.health()
        : Promise.resolve(null),

      system: canReadSystem
        ? dashboardApi.system()
        : Promise.resolve(null),
    };


    /*
     * Promise.allSettled() allows one authorized endpoint to fail without
     * preventing the remaining authorized dashboard data from loading.
     *
     * Permission-skipped endpoints resolve to null and therefore never count
     * as failed endpoints.
     */

    const [
      events,
      alerts,
      incidents,
      iocs,
      mitre,
      health,
      system,
    ] = await Promise.allSettled([
      tasks.events,
      tasks.alerts,
      tasks.incidents,
      tasks.iocs,
      tasks.mitre,
      tasks.health,
      tasks.system,
    ]);


    /* ------------------------------------------------------------------------
     * Extract successful responses
     * ---------------------------------------------------------------------- */

    const eventsValue =
      events.status === "fulfilled"
        ? events.value
        : null;

    const alertsValue =
      alerts.status === "fulfilled"
        ? alerts.value
        : null;

    const incidentsValue =
      incidents.status === "fulfilled"
        ? incidents.value
        : null;

    const iocsValue =
      iocs.status === "fulfilled"
        ? iocs.value
        : null;

    const mitreValue =
      mitre.status === "fulfilled"
        ? mitre.value
        : null;

    const healthValue =
      health.status === "fulfilled"
        ? health.value
        : null;

    const systemValue =
      system.status === "fulfilled"
        ? system.value
        : null;


    /* ------------------------------------------------------------------------
     * Update Snapshot
     * ---------------------------------------------------------------------- */

    setSnapshot({
      events: eventsValue,
      alerts: alertsValue,
      incidents: incidentsValue,

      /*
       * dashboardApi.iocs() is responsible for converting the backend
       * IOC transport model into the frontend IOC domain model.
       *
       * Dashboard.tsx therefore remains independent from the transport model.
       */
      iocs: iocsValue,

      mitre: mitreValue,
      health: healthValue,
      system: systemValue,
    });


    /* ------------------------------------------------------------------------
     * Count only actual authorized API failures
     * ---------------------------------------------------------------------- */

    const failedEndpoints = [
      canReadEvents
        ? events
        : null,

      canReadAlerts
        ? alerts
        : null,

      canReadIncidents
        ? incidents
        : null,

      canReadIOCs
        ? iocs
        : null,

      canReadMITRE
        ? mitre
        : null,

      canReadSystem
        ? health
        : null,

      canReadSystem
        ? system
        : null,
    ].filter(
      (
        result,
      ): result is PromiseRejectedResult =>
        result?.status === "rejected",
    ).length;


    /*
     * Only real backend failures produce the dashboard warning.
     *
     * Missing permissions do NOT produce an error banner.
     */

    if (failedEndpoints > 0) {
      setError(
        `${failedEndpoints} API endpoint${
          failedEndpoints === 1
            ? ""
            : "s"
        } unavailable`,
      );
    }


    setLastRefresh(
      new Date(),
    );

    setLoading(false);
  }, [hasPermission]);


  /* ==========================================================================
   * Initial Load
   * ======================================================================== */

  useEffect(() => {
    void loadDashboard();
  }, [loadDashboard]);


  /* ==========================================================================
   * Render
   * ======================================================================== */

  return (
    <main
      className="dashboard-page"
      aria-label="SOC dashboard"
    >

      {/* ================================================================== */}
      {/* Page Header                                                        */}
      {/* ================================================================== */}

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


      {/* ================================================================== */}
      {/* Partial API Failure Notice                                        */}
      {/* ================================================================== */}

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


      {/* ================================================================== */}
      {/* Primary Security Metrics                                           */}
      {/* ================================================================== */}

      <section
        className="dashboard-metrics-section"
        aria-label="Security metrics"
      >

        <DashboardMetrics
          snapshot={snapshot}
        />

      </section>


      {/* ================================================================== */}
      {/* Main Dashboard Grid                                                */}
      {/* ================================================================== */}

      <section
        className="dashboard-content-grid"
        aria-label="Dashboard status and intelligence"
      >

        {/* ---------------------------------------------------------------- */}
        {/* Platform Status                                                  */}
        {/* ---------------------------------------------------------------- */}

        <article className="dashboard-grid-panel dashboard-grid-panel-wide">

          <DashboardPlatformStatus
            snapshot={snapshot}
          />

        </article>


        {/* ---------------------------------------------------------------- */}
        {/* Recent Alerts                                                    */}
        {/* ---------------------------------------------------------------- */}

        <article className="dashboard-grid-panel dashboard-grid-panel-wide">

          <DashboardRecentAlerts
            snapshot={snapshot}
          />

        </article>


        {/* ---------------------------------------------------------------- */}
        {/* Platform Snapshot                                                */}
        {/* ---------------------------------------------------------------- */}

        <article className="dashboard-grid-panel dashboard-grid-panel-half">

          <DashboardSnapshot
            snapshot={snapshot}
          />

        </article>


        {/* ---------------------------------------------------------------- */}
        {/* Platform Capabilities                                             */}
        {/* ---------------------------------------------------------------- */}

        <article className="dashboard-grid-panel dashboard-grid-panel-half">

          <DashboardCapabilities
            snapshot={snapshot}
          />

        </article>

      </section>

    </main>
  );
}