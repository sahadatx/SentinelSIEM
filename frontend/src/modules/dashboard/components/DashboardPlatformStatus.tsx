/**
 * ============================================================================
 * SentinelSIEM — Dashboard Platform Status
 * ============================================================================
 *
 * Displays the current API and system/platform state.
 *
 * Responsibilities:
 * - Present API health state.
 * - Present system environment state.
 * - Display platform version information.
 * - Remain presentation-focused.
 *
 * Data loading and business logic remain in the Dashboard/API layer.
 * ============================================================================
 */

import {
  Activity,
  Server,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";

import { Panel } from "../../../components/ui/Panel";

import type { DashboardSnapshot } from "../types";

/* ==========================================================================
 * Props
 * ========================================================================== */

interface DashboardPlatformStatusProps {
  snapshot: DashboardSnapshot;
}

/* ==========================================================================
 * Helpers
 * ========================================================================== */

function normalizeState(
  value: string | null | undefined,
): string {
  if (!value) {
    return "unavailable";
  }

  return value.toLowerCase();
}

function getStateLabel(
  value: string | null | undefined,
): string {
  if (!value) {
    return "Unavailable";
  }

  return value
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (character) =>
      character.toUpperCase(),
    );
}

/* ==========================================================================
 * Component
 * ========================================================================== */

export default function DashboardPlatformStatus({
  snapshot,
}: DashboardPlatformStatusProps) {
  const apiState = normalizeState(
    snapshot.health?.status,
  );

  const systemState = normalizeState(
    snapshot.system?.environment,
  );

  const apiLabel = getStateLabel(
    snapshot.health?.status,
  );

  const systemLabel = getStateLabel(
    snapshot.system?.environment,
  );

  const apiAvailable =
    Boolean(snapshot.health);

  const systemAvailable =
    Boolean(snapshot.system);

  return (
    <Panel
      title="Platform Status"
      subtitle="Current API and system state"
    >
      <div className="dashboard-platform-status">
        {/* ================================================================
         * Status Overview
         * ================================================================ */}

        <div
          className="dashboard-platform-status-grid"
          aria-label="Platform health status"
        >
          {/* ----------------------------------------------------------------
           * API Status
           * ---------------------------------------------------------------- */}

          <div
            className={`dashboard-platform-status-card ${
              apiAvailable
                ? "is-available"
                : "is-unavailable"
            }`}
          >
            <div className="dashboard-platform-status-card-header">
              <div className="dashboard-platform-status-icon">
                <Activity
                  size={16}
                  aria-hidden="true"
                />
              </div>

              <span className="dashboard-platform-status-label">
                API
              </span>
            </div>

            <div className="dashboard-platform-status-value-row">
              <strong>
                {apiLabel}
              </strong>

              <span
                className={`dashboard-platform-status-indicator ${apiState}`}
                aria-label={`API status: ${apiLabel}`}
              />
            </div>

            <span className="dashboard-platform-status-meta">
              {apiAvailable
                ? "Health endpoint responding"
                : "Health endpoint unavailable"}
            </span>
          </div>

          {/* ----------------------------------------------------------------
           * System Status
           * ---------------------------------------------------------------- */}

          <div
            className={`dashboard-platform-status-card ${
              systemAvailable
                ? "is-available"
                : "is-unavailable"
            }`}
          >
            <div className="dashboard-platform-status-card-header">
              <div className="dashboard-platform-status-icon">
                <Server
                  size={16}
                  aria-hidden="true"
                />
              </div>

              <span className="dashboard-platform-status-label">
                System
              </span>
            </div>

            <div className="dashboard-platform-status-value-row">
              <strong>
                {systemLabel}
              </strong>

              <span
                className={`dashboard-platform-status-indicator ${systemState}`}
                aria-label={`System environment: ${systemLabel}`}
              />
            </div>

            <span className="dashboard-platform-status-meta">
              {systemAvailable
                ? "Platform environment detected"
                : "System information unavailable"}
            </span>
          </div>
        </div>

        {/* ================================================================
         * Platform Information
         * ================================================================ */}

        {snapshot.system && (
          <div className="dashboard-platform-info">
            <div className="dashboard-platform-info-header">
              <div className="dashboard-platform-info-icon">
                <ShieldCheck
                  size={15}
                  aria-hidden="true"
                />
              </div>

              <div>
                <span className="dashboard-platform-info-eyebrow">
                  PLATFORM INFORMATION
                </span>

                <strong>
                  SentinelSIEM Runtime
                </strong>
              </div>
            </div>

            <div className="dashboard-platform-info-grid">
              <div className="dashboard-platform-info-item">
                <span>Version</span>

                <strong>
                  {snapshot.system.version || "—"}
                </strong>
              </div>

              <div className="dashboard-platform-info-item">
                <span>Environment</span>

                <strong>
                  {snapshot.system.environment || "—"}
                </strong>
              </div>
            </div>
          </div>
        )}

        {/* ================================================================
         * Unavailable State
         * ================================================================ */}

        {!snapshot.system && !snapshot.health && (
          <div className="dashboard-platform-empty">
            <TriangleAlert
              size={17}
              aria-hidden="true"
            />

            <div>
              <strong>
                Platform information unavailable
              </strong>

              <span>
                The dashboard could not retrieve
                current platform status.
              </span>
            </div>
          </div>
        )}
      </div>
    </Panel>
  );
}