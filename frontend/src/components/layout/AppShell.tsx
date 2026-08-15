import { NavLink, Outlet } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  Bell,
  BrainCircuit,
  CircleGauge,
  Database,
  FileSearch,
  Gauge,
  LayoutDashboard,
  Radio,
  Server,
  Shield,
  Siren,
} from "lucide-react";

import { useDashboardStore } from "../../store/dashboard";

const navigation = [
  ["/", "Overview", LayoutDashboard],
  ["/events", "Events", Activity],
  ["/alerts", "Alerts", AlertTriangle],
  ["/incidents", "Incidents", Siren],
  ["/threat-intelligence", "Threat Intelligence", Shield],
  ["/detections", "Detection", FileSearch],
  ["/mitre", "MITRE Coverage", BrainCircuit],
  ["/assets", "Assets", Database],
  ["/risk", "Risk", Gauge],
  ["/system", "System Health", Server],
] as const;

function formatEnvironment(environment?: string | null): string {
  if (!environment) {
    return "Unavailable";
  }

  return environment
    .replace(/[-_]+/g, " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

export function AppShell() {
  const live = useDashboardStore((state) => state.live);
  const system = useDashboardStore((state) => state.system);

  const environment = formatEnvironment(system?.environment);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">
            <CircleGauge size={22} />
          </div>

          <div>
            <strong>SentinelSIEM</strong>
            <span>SOC Platform</span>
          </div>
        </div>

        <div className="nav-label">OPERATIONS</div>

        <nav aria-label="Primary navigation">
          {navigation.map(([to, label, Icon]) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) =>
                isActive ? "nav-item active" : "nav-item"
              }
            >
              <Icon size={17} />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div
            className={live ? "live-dot online" : "live-dot"}
            aria-hidden="true"
          />

          <span>
            {live ? "Real-time connected" : "Polling/API mode"}
          </span>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <span className="eyebrow">
              SECURITY OPERATIONS CENTER
            </span>

            <h1>SentinelSIEM</h1>
          </div>

          <div className="topbar-actions">
            <span
              className={`env-badge ${
                system?.environment
                  ? `env-${system.environment.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`
                  : "env-unavailable"
              }`}
              title={
                system?.environment
                  ? `Environment: ${system.environment}`
                  : "Environment unavailable"
              }
            >
              <Radio size={14} />

              {environment}
            </span>

            <button
              className="icon-button"
              type="button"
              aria-label="Notifications"
              title="Notifications"
            >
              <Bell size={18} />
            </button>
          </div>
        </header>

        <section className="content">
          <Outlet />
        </section>
      </main>
    </div>
  );
}