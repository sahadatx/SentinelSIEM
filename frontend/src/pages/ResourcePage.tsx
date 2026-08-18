import type { CSSProperties, ReactNode } from "react";

import { useDashboardStore } from "../store/dashboard";
import { Panel } from "../components/ui/Panel";
import { SeverityBadge } from "../components/ui/SeverityBadge";

export function EventsPage() {
  const events = useDashboardStore((s) => s.events);

  const items = events?.items ?? [];
  const total = events?.pagination.total ?? 0;

  return (
    <Page
      title="Security Events"
      subtitle="Canonical events delivered by the Phase 15 API"
    >
      <Panel
        title="Event stream"
        subtitle={
          events
            ? `${total} records available`
            : "Event repository is unavailable"
        }
      >
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Source</th>
                <th>Source IP</th>
                <th>User</th>
                <th>Action</th>
                <th>Outcome</th>
              </tr>
            </thead>

            <tbody>
              {items.map((event) => (
                <tr key={event.event_id}>
                  <td>
                    {new Date(event.timestamp).toLocaleTimeString()}
                  </td>

                  <td>{event.source}</td>

                  <td>{event.source_ip ?? "—"}</td>

                  <td>{event.username ?? "—"}</td>

                  <td>{event.action ?? "—"}</td>

                  <td>{event.outcome ?? "—"}</td>
                </tr>
              ))}

              {items.length === 0 && (
                <Empty
                  cols={6}
                  message={
                    events
                      ? "No security events available."
                      : "Security event data is currently unavailable."
                  }
                />
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </Page>
  );
}

export function AlertsPage() {
  const alerts = useDashboardStore((s) => s.alerts);

  const items = alerts?.items ?? [];
  const total = alerts?.pagination.total ?? 0;

  return (
    <Page
      title="Alert Management"
      subtitle="Detection and correlation alerts exposed by the backend"
    >
      <Panel
        title="Alert queue"
        subtitle={
          alerts
            ? `${total} alerts available`
            : "Alert data is currently unavailable"
        }
      >
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Alert</th>
                <th>Severity</th>
                <th>Risk</th>
                <th>Priority</th>
                <th>Status</th>
              </tr>
            </thead>

            <tbody>
              {items.map((alert) => (
                <tr key={alert.alert_id}>
                  <td>
                    <strong>{alert.title}</strong>
                    <small>{alert.source_id}</small>
                  </td>

                  <td>
                    <SeverityBadge severity={alert.severity} />
                  </td>

                  <td>{alert.risk_score}</td>

                  <td>{alert.priority}</td>

                  <td>{alert.status}</td>
                </tr>
              ))}

              {items.length === 0 && (
                <Empty
                  cols={5}
                  message={
                    alerts
                      ? "No alerts available."
                      : "Alert data is currently unavailable."
                  }
                />
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </Page>
  );
}

export function IncidentsPage() {
  const incidents = useDashboardStore((s) => s.incidents);

  const items = incidents?.items ?? [];
  const total = incidents?.pagination.total ?? 0;

  return (
    <Page
      title="Incident Management"
      subtitle="Investigation state from the incident service"
    >
      <Panel
        title="Active incidents"
        subtitle={
          incidents
            ? `${total} incidents available`
            : "Incident data is currently unavailable"
        }
      >
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Incident</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Assignee</th>
                <th>Created</th>
              </tr>
            </thead>

            <tbody>
              {items.map((incident) => (
                <tr key={incident.incident_id}>
                  <td>
                    <strong>{incident.title}</strong>
                  </td>

                  <td>
                    <SeverityBadge severity={incident.severity} />
                  </td>

                  <td>{incident.status}</td>

                  <td>
                    {incident.assigned_to ?? "Unassigned"}
                  </td>

                  <td>
                    {new Date(
                      incident.created_at,
                    ).toLocaleString()}
                  </td>
                </tr>
              ))}

              {items.length === 0 && (
                <Empty
                  cols={5}
                  message={
                    incidents
                      ? "No incidents available."
                      : "Incident data is currently unavailable."
                  }
                />
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </Page>
  );
}

export function ThreatIntelPage() {
  const iocs = useDashboardStore((s) => s.iocs);

  const items = iocs?.items ?? [];
  const total = iocs?.pagination.total ?? 0;

  return (
    <Page
      title="Threat Intelligence"
      subtitle="IOC intelligence returned by the Phase 13 service"
    >
      <Panel
        title="IOC inventory"
        subtitle={
          iocs
            ? `${total} indicators available`
            : "IOC data is currently unavailable"
        }
      >
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Type</th>
                <th>Indicator</th>
                <th>Reputation</th>
                <th>Confidence</th>
                <th>Source</th>
              </tr>
            </thead>

            <tbody>
              {items.map((ioc) => (
                <tr key={ioc.ioc_id}>
                  <td>{ioc.type}</td>

                  <td>
                    <code>{ioc.value}</code>
                  </td>

                  <td>
                    <span
                      className={`health-pill ${ioc.reputation.toLowerCase()}`}
                    >
                      {ioc.reputation}
                    </span>
                  </td>

                  <td>{ioc.confidence}%</td>

                  <td>{ioc.source}</td>
                </tr>
              ))}

              {items.length === 0 && (
                <Empty
                  cols={5}
                  message={
                    iocs
                      ? "No indicators available."
                      : "Threat intelligence data is currently unavailable."
                  }
                />
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </Page>
  );
}

export function MitrePage() {
  const mitre = useDashboardStore((s) => s.mitre);

  return (
    <Page
      title="MITRE ATT&CK Coverage"
      subtitle="Coverage data supplied by Phase 14"
    >
      <Panel title="Detection coverage">
        {mitre ? (
          <div className="coverage">
            <div
              className="coverage-ring"
              style={
                {
                  "--coverage": `${mitre.coverage_percent}%`,
                } as CSSProperties
              }
            >
              <strong>
                {mitre.coverage_percent.toFixed(0)}%
              </strong>
            </div>

            <div>
              <h3>
                {mitre.mapped_techniques} of {mitre.total_techniques} techniques covered
              </h3>

              <p>
                Navigator-compatible coverage data is consumed
                from the backend; no ATT&amp;CK business logic is
                duplicated in the frontend.
              </p>
            </div>
          </div>
        ) : (
          <Unavailable
            message="MITRE coverage data is currently unavailable."
          />
        )}
      </Panel>
    </Page>
  );
}

export function SystemPage() {
  const health = useDashboardStore((s) => s.health);
  const system = useDashboardStore((s) => s.system);

  const apiStatus = health?.status ?? "offline";

  return (
    <Page
      title="System Health"
      subtitle="Operational status from the Phase 15 system API"
    >
      <Panel title="Platform Status">
        <div className="health-list">
          <HealthRow
            name="API"
            status={apiStatus}
          />

          <HealthRow
            name="Service"
            status={health?.service ?? "unavailable"}
          />

          <HealthRow
            name="Version"
            status={health?.version ?? "—"}
          />

          <HealthRow
            name="Environment"
            status={system?.environment ?? "—"}
          />

          <HealthRow
            name="System Service"
            status={system?.service ?? "—"}
          />
        </div>
      </Panel>

      <Panel title="Capabilities">
        {system?.capabilities?.length ? (
          <div className="capability-list">
            {system.capabilities.map((capability) => (
              <span
                className="health-pill healthy"
                key={capability}
              >
                {capability}
              </span>
            ))}
          </div>
        ) : (
          <Unavailable
            message="System capability information is currently unavailable."
          />
        )}
      </Panel>
    </Page>
  );
}

export function GenericPage({
  title,
}: {
  title: string;
}) {
  return (
    <Page
      title={title}
      subtitle="This view is intentionally read-only until the corresponding backend capability is exposed."
    >
      <Panel title="Service-backed view">
        <div className="empty-state">
          <p>
            No frontend business logic is implemented here.
            Connect this page to the existing Phase 15 API
            contract when the backend endpoint is available.
          </p>
        </div>
      </Panel>
    </Page>
  );
}

function Page({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle: string;
  children: ReactNode;
}) {
  return (
    <>
      <div className="page-heading">
        <div>
          <h2>{title}</h2>
          <p>{subtitle}</p>
        </div>
      </div>

      {children}
    </>
  );
}

function Empty({
  cols,
  message = "No data available.",
}: {
  cols: number;
  message?: string;
}) {
  return (
    <tr>
      <td
        colSpan={cols}
        className="empty"
      >
        {message}
      </td>
    </tr>
  );
}

function Unavailable({
  message,
}: {
  message: string;
}) {
  return (
    <div className="empty-state">
      <p>{message}</p>
    </div>
  );
}

function HealthRow({
  name,
  status,
}: {
  name: string;
  status: string;
}) {
  const normalized = status.toLowerCase();

  const healthClass =
    normalized === "ok" ||
    normalized === "healthy" ||
    normalized === "available"
      ? "healthy"
      : normalized === "degraded"
        ? "degraded"
        : normalized === "offline" ||
            normalized === "unavailable"
          ? "offline"
          : "";

  return (
    <div className="health-row">
      <span>{name}</span>

      <span className={`health-pill ${healthClass}`}>
        {status}
      </span>
    </div>
  );
}