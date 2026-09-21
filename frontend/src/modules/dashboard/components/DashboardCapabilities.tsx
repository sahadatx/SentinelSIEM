/**
 * ============================================================================
 * Dashboard Capabilities
 * SentinelSIEM SOC Dashboard
 * ============================================================================
 *
 * Displays the capabilities exposed by the SentinelSIEM backend.
 *
 * Responsibilities:
 * - Present backend capabilities.
 * - Clearly distinguish available capabilities.
 * - Provide an explicit unavailable state.
 *
 * Data loading and business logic remain outside this component.
 * ============================================================================
 */

import {
  CheckCircle2,
  Layers3,
  ShieldCheck,
} from "lucide-react";

import { Panel } from "../../../components/ui/Panel";

import type {
  DashboardSnapshot,
} from "../types";

/* ==========================================================================
 * Props
 * ========================================================================== */

interface DashboardCapabilitiesProps {
  snapshot: DashboardSnapshot;
}

/* ==========================================================================
 * Component
 * ========================================================================== */

export default function DashboardCapabilities({
  snapshot,
}: DashboardCapabilitiesProps) {
  const capabilities =
    snapshot.system?.capabilities ?? [];

  return (
    <Panel
      title="Platform Capabilities"
      subtitle="Features exposed by the backend"
    >
      <div className="dashboard-capabilities">
        {/* ================================================================
         * Header Summary
         * ================================================================ */}

        <div className="dashboard-capabilities-summary">
          <div className="dashboard-capabilities-summary-icon">
            <ShieldCheck
              size={17}
              aria-hidden="true"
            />
          </div>

          <div className="dashboard-capabilities-summary-content">
            <span>
              BACKEND CAPABILITIES
            </span>

            <strong>
              {capabilities.length > 0
                ? `${capabilities.length} available`
                : "Unavailable"}
            </strong>
          </div>

          {capabilities.length > 0 && (
            <span className="dashboard-capabilities-summary-status">
              Operational
            </span>
          )}
        </div>

        {/* ================================================================
         * Capability List
         * ================================================================ */}

        {capabilities.length > 0 ? (
          <div
            className="dashboard-capabilities-list"
            aria-label="Available backend capabilities"
          >
            {capabilities.map(
              (capability) => (
                <div
                  className="dashboard-capability-item"
                  key={capability}
                >
                  <div className="dashboard-capability-icon">
                    <Layers3
                      size={13}
                      aria-hidden="true"
                    />
                  </div>

                  <span className="dashboard-capability-name">
                    {capability}
                  </span>

                  <span
                    className="dashboard-capability-status"
                    title="Capability available"
                  >
                    <CheckCircle2
                      size={13}
                      aria-hidden="true"
                    />
                  </span>
                </div>
              ),
            )}
          </div>
        ) : (
          /* ================================================================
           * Empty / Unavailable State
           * ================================================================ */

          <div className="dashboard-capabilities-empty">
            <div className="dashboard-capabilities-empty-icon">
              <ShieldCheck
                size={18}
                aria-hidden="true"
              />
            </div>

            <div className="dashboard-capabilities-empty-content">
              <strong>
                System information unavailable
              </strong>

              <span>
                Backend capability information
                could not be retrieved.
              </span>
            </div>
          </div>
        )}
      </div>
    </Panel>
  );
}