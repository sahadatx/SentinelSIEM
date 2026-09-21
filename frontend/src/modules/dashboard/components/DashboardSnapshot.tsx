/**
 * ============================================================================
 * Dashboard Snapshot
 * SentinelSIEM SOC Dashboard
 * ============================================================================
 *
 * Displays a compact snapshot of the current SentinelSIEM platform state.
 *
 * Responsibilities:
 * - Present API health status.
 * - Present platform version.
 * - Present runtime environment.
 * - Present available API capabilities.
 *
 * Data loading and business logic remain in the Dashboard/API layer.
 * ============================================================================
 */

import {
  Activity,
  Boxes,
  Cpu,
  Layers3,
  ShieldCheck,
} from "lucide-react";

import { Panel } from "../../../components/ui/Panel";

import type {
  DashboardSnapshot as DashboardSnapshotData,
} from "../types";

/* ==========================================================================
 * Props
 * ========================================================================== */

interface DashboardSnapshotProps {
  snapshot: DashboardSnapshotData;
}

/* ==========================================================================
 * Helpers
 * ========================================================================== */

function formatValue(
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

function getHealthClass(
  value: string | null | undefined,
): string {
  if (!value) {
    return "unavailable";
  }

  const normalized =
    value.toLowerCase();

  if (
    normalized === "healthy" ||
    normalized === "ok" ||
    normalized === "running" ||
    normalized === "ready"
  ) {
    return "healthy";
  }

  if (
    normalized === "warning" ||
    normalized === "degraded"
  ) {
    return "warning";
  }

  if (
    normalized === "error" ||
    normalized === "failed" ||
    normalized === "offline"
  ) {
    return "danger";
  }

  return "default";
}

/* ==========================================================================
 * Component
 * ========================================================================== */

export default function DashboardSnapshot({
  snapshot,
}: DashboardSnapshotProps) {
  const healthStatus =
    snapshot.health?.status ?? null;

  const version =
    snapshot.system?.version ?? null;

  const environment =
    snapshot.system?.environment ?? null;

  const capabilities =
    snapshot.system?.capabilities;

  const capabilityCount =
    capabilities?.length ?? null;

  return (
    <Panel
      title="Platform Snapshot"
      subtitle="Current SentinelSIEM platform state"
    >
      <div className="dashboard-platform-snapshot">
        {/* ================================================================
         * Snapshot Status
         * ================================================================ */}

        <div className="dashboard-snapshot-status">
          <div className="dashboard-snapshot-status-icon">
            <ShieldCheck
              size={17}
              aria-hidden="true"
            />
          </div>

          <div className="dashboard-snapshot-status-content">
            <span>
              PLATFORM HEALTH
            </span>

            <strong>
              {formatValue(healthStatus)}
            </strong>
          </div>

          <span
            className={`dashboard-snapshot-health-indicator ${getHealthClass(
              healthStatus,
            )}`}
            aria-label={`Platform health: ${formatValue(
              healthStatus,
            )}`}
          />
        </div>

        {/* ================================================================
         * Snapshot Details
         * ================================================================ */}

        <div className="dashboard-snapshot-grid">
          {/* ----------------------------------------------------------------
           * API Status
           * ---------------------------------------------------------------- */}

          <div className="dashboard-snapshot-item">
            <div className="dashboard-snapshot-item-icon">
              <Activity
                size={14}
                aria-hidden="true"
              />
            </div>

            <div className="dashboard-snapshot-item-content">
              <span>API Status</span>

              <strong
                className={
                  getHealthClass(
                    healthStatus,
                  )
                }
              >
                {formatValue(
                  healthStatus,
                )}
              </strong>
            </div>
          </div>

          {/* ----------------------------------------------------------------
           * Version
           * ---------------------------------------------------------------- */}

          <div className="dashboard-snapshot-item">
            <div className="dashboard-snapshot-item-icon">
              <Cpu
                size={14}
                aria-hidden="true"
              />
            </div>

            <div className="dashboard-snapshot-item-content">
              <span>Version</span>

              <strong>
                {version || "—"}
              </strong>
            </div>
          </div>

          {/* ----------------------------------------------------------------
           * Environment
           * ---------------------------------------------------------------- */}

          <div className="dashboard-snapshot-item">
            <div className="dashboard-snapshot-item-icon">
              <Layers3
                size={14}
                aria-hidden="true"
              />
            </div>

            <div className="dashboard-snapshot-item-content">
              <span>Environment</span>

              <strong>
                {formatValue(
                  environment,
                )}
              </strong>
            </div>
          </div>

          {/* ----------------------------------------------------------------
           * Capabilities
           * ---------------------------------------------------------------- */}

          <div className="dashboard-snapshot-item">
            <div className="dashboard-snapshot-item-icon">
              <Boxes
                size={14}
                aria-hidden="true"
              />
            </div>

            <div className="dashboard-snapshot-item-content">
              <span>Capabilities</span>

              <strong>
                {capabilityCount ?? "—"}
              </strong>
            </div>
          </div>
        </div>

        {/* ================================================================
         * Capability Summary
         * ================================================================ */}

        {capabilities &&
          capabilities.length > 0 && (
            <div className="dashboard-snapshot-capabilities">
              <div className="dashboard-snapshot-capabilities-header">
                <span>
                  AVAILABLE CAPABILITIES
                </span>

                <strong>
                  {capabilities.length}
                </strong>
              </div>

              <div className="dashboard-snapshot-capability-list">
                {capabilities
                  .slice(0, 6)
                  .map((capability) => (
                    <span
                      key={String(
                        capability,
                      )}
                      className="dashboard-snapshot-capability"
                    >
                      {String(
                        capability,
                      )}
                    </span>
                  ))}
              </div>

              {capabilities.length > 6 && (
                <span className="dashboard-snapshot-capability-more">
                  +{capabilities.length - 6} more
                </span>
              )}
            </div>
          )}
      </div>
    </Panel>
  );
}