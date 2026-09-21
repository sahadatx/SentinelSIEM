/*
 * ============================================================================
 * Dashboard Metrics
 * SentinelSIEM SOC Dashboard
 * ============================================================================
 *
 * High-level SOC metrics displayed on the Dashboard.
 * ============================================================================
 */

import {
  Activity,
  AlertTriangle,
  BrainCircuit,
  Siren,
} from "lucide-react";

import { MetricCard } from "../../../components/ui/MetricCard";

import type {
  DashboardMetrics as DashboardMetricsData,
  DashboardSnapshot,
} from "../types";

/* ==========================================================================
 * Helpers
 * ========================================================================== */

function getDashboardMetrics(
  snapshot: DashboardSnapshot,
): DashboardMetricsData {
  const alertItems =
    snapshot.alerts?.items ?? [];

  const incidentItems =
    snapshot.incidents?.items ?? [];

  const criticalAlerts =
    alertItems.filter(
      (alert) =>
        alert.severity === "critical",
    ).length;

  return {
    securityEvents:
      snapshot.events?.pagination.total ??
      null,

    openAlerts:
      snapshot.alerts
        ? alertItems.length
        : null,

    criticalAlerts,

    activeIncidents:
      snapshot.incidents
        ? incidentItems.length
        : null,

    mitreCoverage:
      snapshot.mitre?.coverage_percent ??
      null,
  };
}

/* ==========================================================================
 * Component
 * ========================================================================== */

interface DashboardMetricsProps {
  snapshot: DashboardSnapshot;
}

export default function DashboardMetrics({
  snapshot,
}: DashboardMetricsProps) {
  const metrics =
    getDashboardMetrics(snapshot);

  return (
    <div className="metrics-grid">
      {/* ====================================================================
       * Security Events
       * ==================================================================== */}

      <MetricCard
        label="Security Events"
        value={
          metrics.securityEvents ??
          "—"
        }
        detail={
          snapshot.events
            ? "Events available"
            : "Event repository unavailable"
        }
        icon={<Activity />}
        tone={
          snapshot.events
            ? "success"
            : "default"
        }
      />

      {/* ====================================================================
       * Open Alerts
       * ==================================================================== */}

      <MetricCard
        label="Open Alerts"
        value={
          metrics.openAlerts ??
          "—"
        }
        detail={
          snapshot.alerts
            ? `${metrics.criticalAlerts} critical`
            : "Alert API unavailable"
        }
        icon={<AlertTriangle />}
        tone={
          metrics.criticalAlerts > 0
            ? "danger"
            : "default"
        }
      />

      {/* ====================================================================
       * Active Incidents
       * ==================================================================== */}

      <MetricCard
        label="Active Incidents"
        value={
          metrics.activeIncidents ??
          "—"
        }
        detail={
          snapshot.incidents
            ? "Requires analyst attention"
            : "Incident API unavailable"
        }
        icon={<Siren />}
        tone="warning"
      />

      {/* ====================================================================
       * MITRE Coverage
       * ==================================================================== */}

      <MetricCard
        label="MITRE Coverage"
        value={
          metrics.mitreCoverage !== null
            ? `${metrics.mitreCoverage.toFixed(1)}%`
            : "—"
        }
        detail={
          snapshot.mitre
            ? `${snapshot.mitre.mapped_techniques}/${snapshot.mitre.total_techniques} techniques`
            : "MITRE service unavailable"
        }
        icon={<BrainCircuit />}
      />
    </div>
  );
}
