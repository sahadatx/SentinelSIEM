import {
  Activity,
  AlertTriangle,
  BrainCircuit,
  Clock3,
  Siren,
} from "lucide-react";

import { useDashboardStore } from "../store/dashboard";

import { MetricCard } from "../components/ui/MetricCard";
import { Panel } from "../components/ui/Panel";
import { SeverityBadge } from "../components/ui/SeverityBadge";
import { ActivityChart } from "../components/charts/ActivityChart";

export default function Overview() {
  const {
    events,
    alerts,
    incidents,
    mitre,
    health,
    system,
    error,
  } = useDashboardStore();

  const alertItems = alerts?.items ?? [];
  const incidentItems = incidents?.items ?? [];

  const criticalAlerts = alertItems.filter(
    (alert) => alert.severity === "critical",
  ).length;

  const apiState = health?.status ?? "unavailable";

  const platformHealth = [
    {
      name: "API",
      state: apiState,
    },
    {
      name: "System",
      state: system?.environment ?? "unavailable",
    },
  ];

  return (
    <>
      <div className="page-heading">
        <div>
          <h2>SOC Overview</h2>

          <p>
            Live security posture across the SentinelSIEM
            platform.
          </p>
        </div>

        <span className="timestamp">
          <Clock3 size={14} />
          Last refresh: just now
        </span>
      </div>

      {error && (
        <div className="notice warning">
          <AlertTriangle size={16} />

          <span>
            {error}. Dashboard remains available with
            partial data.
          </span>
        </div>
      )}

      <div className="metrics-grid">
        <MetricCard
          label="Security Events"
          value={
            events
              ? events.pagination.total
              : "—"
          }
          detail={
            events
              ? "Events available"
              : "Event repository unavailable"
          }
          icon={<Activity />}
          tone={
            events
              ? "success"
              : "default"
          }
        />

        <MetricCard
          label="Open Alerts"
          value={
            alerts
              ? alertItems.length
              : "—"
          }
          detail={
            alerts
              ? `${criticalAlerts} critical`
              : "Alert API unavailable"
          }
          icon={<AlertTriangle />}
          tone={
            criticalAlerts > 0
              ? "danger"
              : "default"
          }
        />

        <MetricCard
          label="Active Incidents"
          value={
            incidents
              ? incidentItems.length
              : "—"
          }
          detail={
            incidents
              ? "Requires analyst attention"
              : "Incident API unavailable"
          }
          icon={<Siren />}
          tone="warning"
        />

        <MetricCard
          label="MITRE Coverage"
          value={
            mitre
              ? `${mitre.coverage_percent.toFixed(1)}%`
              : "—"
          }
          detail={
            mitre
              ? `${mitre.mapped_techniques}/${mitre.total_techniques} techniques`
              : "MITRE service unavailable"
          }
          icon={<BrainCircuit />}
        />
      </div>

      <div className="dashboard-grid">
        <Panel
          title="Event Activity"
          subtitle="Normalized security events"
          className="span-2"
        >
          {events ? (
            <ActivityChart />
          ) : (
            <div className="empty">
              Event repository is unavailable.
            </div>
          )}
        </Panel>

        <Panel
          title="Platform Status"
          subtitle="Current API and system state"
        >
          <div className="health-list">
            {platformHealth.map(
              ({ name, state }) => (
                <div
                  className="health-row"
                  key={name}
                >
                  <span>{name}</span>

                  <span
                    className={`health-pill ${state}`}
                  >
                    {state}
                  </span>
                </div>
              ),
            )}
          </div>

          {system && (
            <div className="snapshot-list">
              <div>
                <span>Version</span>

                <strong>
                  {system.version}
                </strong>
              </div>

              <div>
                <span>Environment</span>

                <strong>
                  {system.environment}
                </strong>
              </div>
            </div>
          )}
        </Panel>

        <Panel
          title="Recent Alerts"
          subtitle={
            alerts
              ? `${alerts.pagination.total} alerts available`
              : "Alert service unavailable"
          }
          className="span-2"
        >
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Alert</th>
                  <th>Severity</th>
                  <th>Risk</th>
                  <th>Status</th>
                </tr>
              </thead>

              <tbody>
                {alertItems
                  .slice(0, 6)
                  .map((alert) => (
                    <tr key={alert.alert_id}>
                      <td>
                        <strong>
                          {alert.title}
                        </strong>

                        <small>
                          {alert.source_id}
                        </small>
                      </td>

                      <td>
                        <SeverityBadge
                          severity={alert.severity}
                        />
                      </td>

                      <td>
                        {alert.risk_score}
                      </td>

                      <td>
                        <span className="status-text">
                          {alert.status}
                        </span>
                      </td>
                    </tr>
                  ))}

                {alerts &&
                  !alertItems.length && (
                    <tr>
                      <td
                        colSpan={4}
                        className="empty"
                      >
                        No alerts available.
                      </td>
                    </tr>
                  )}

                {!alerts && (
                  <tr>
                    <td
                      colSpan={4}
                      className="empty"
                    >
                      Alert service is unavailable.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Panel>

        <Panel
          title="Platform Snapshot"
          subtitle="Current API capabilities"
        >
          <div className="snapshot-list">
            <div>
              <span>API Status</span>

              <strong>
                {health?.status ?? "Unavailable"}
              </strong>
            </div>

            <div>
              <span>Version</span>

              <strong>
                {system?.version ?? "—"}
              </strong>
            </div>

            <div>
              <span>Environment</span>

              <strong>
                {system?.environment ?? "—"}
              </strong>
            </div>

            <div>
              <span>Capabilities</span>

              <strong>
                {system?.capabilities?.length ?? "—"}
              </strong>
            </div>
          </div>
        </Panel>

        <Panel
          title="Platform Capabilities"
          subtitle="Features exposed by the backend"
        >
          {system?.capabilities?.length ? (
            <div className="snapshot-list">
              {system.capabilities.map(
                (capability) => (
                  <div key={capability}>
                    <span>
                      {capability}
                    </span>

                    <strong>
                      Available
                    </strong>
                  </div>
                ),
              )}
            </div>
          ) : (
            <div className="empty">
              System information unavailable.
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}