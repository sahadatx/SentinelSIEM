/**
 * ============================================================================
 * Dashboard Recent Alerts
 * SentinelSIEM SOC Dashboard
 * ============================================================================
 *
 * Displays the most recent security alerts available to the Dashboard.
 *
 * Responsibilities:
 * - Present recent alert activity.
 * - Display alert title and source.
 * - Display severity and risk score.
 * - Display current alert status.
 * - Remain presentation-focused.
 *
 * Data loading and business logic remain in the Dashboard/API layer.
 * ============================================================================
 */

import {
  AlertTriangle,
  ArrowUpRight,
  ShieldAlert,
} from "lucide-react";

import { Panel } from "../../../components/ui/Panel";
import { SeverityBadge } from "../../../components/ui/SeverityBadge";

import type { DashboardSnapshot } from "../types";

/* ==========================================================================
 * Props
 * ========================================================================== */

interface DashboardRecentAlertsProps {
  snapshot: DashboardSnapshot;
}

/* ==========================================================================
 * Helpers
 * ========================================================================== */

function formatStatus(
  status: string,
): string {
  return status
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (character) =>
      character.toUpperCase(),
    );
}

function getRiskLevel(
  score: number,
): string {
  if (score >= 80) {
    return "Critical";
  }

  if (score >= 60) {
    return "High";
  }

  if (score >= 30) {
    return "Medium";
  }

  return "Low";
}

function getRiskClass(
  score: number,
): string {
  if (score >= 80) {
    return "critical";
  }

  if (score >= 60) {
    return "high";
  }

  if (score >= 30) {
    return "medium";
  }

  return "low";
}

/* ==========================================================================
 * Component
 * ========================================================================== */

export default function DashboardRecentAlerts({
  snapshot,
}: DashboardRecentAlertsProps) {
  const alerts = snapshot.alerts;

  const alertItems =
    alerts?.items ?? [];

  const visibleAlerts =
    alertItems.slice(0, 6);

  return (
    <Panel
      title="Recent Alerts"
      subtitle={
        alerts
          ? `${alerts.pagination.total} alerts available`
          : "Alert service unavailable"
      }
      className="span-2"
    >
      <div className="dashboard-alerts-panel">
        {/* ================================================================
         * Table Header / Context
         * ================================================================ */}

        <div className="dashboard-alerts-context">
          <div className="dashboard-alerts-context-icon">
            <ShieldAlert
              size={15}
              aria-hidden="true"
            />
          </div>

          <div className="dashboard-alerts-context-content">
            <strong>
              Security Alert Activity
            </strong>

            <span>
              Most recent alerts requiring
              SOC visibility.
            </span>
          </div>

          {alerts && (
            <span className="dashboard-alerts-count">
              {visibleAlerts.length} shown
            </span>
          )}
        </div>

        {/* ================================================================
         * Alerts Table
         * ================================================================ */}

        <div className="dashboard-alerts-table-wrap">
          <table className="dashboard-alerts-table">
            <thead>
              <tr>
                <th scope="col">
                  Alert
                </th>

                <th scope="col">
                  Severity
                </th>

                <th scope="col">
                  Risk
                </th>

                <th scope="col">
                  Status
                </th>

                <th
                  scope="col"
                  className="dashboard-alerts-action-header"
                >
                  <span className="sr-only">
                    Action
                  </span>
                </th>
              </tr>
            </thead>

            <tbody>
              {visibleAlerts.map((alert) => {
                const riskScore =
                  Number(alert.risk_score) || 0;

                const riskLevel =
                  getRiskLevel(riskScore);

                const riskClass =
                  getRiskClass(riskScore);

                return (
                  <tr
                    key={alert.alert_id}
                    className="dashboard-alert-row"
                  >
                    {/* ------------------------------------------------------
                     * Alert Identity
                     * ------------------------------------------------------ */}

                    <td className="dashboard-alert-identity-cell">
                      <div className="dashboard-alert-identity">
                        <div className="dashboard-alert-icon">
                          <AlertTriangle
                            size={14}
                            aria-hidden="true"
                          />
                        </div>

                        <div className="dashboard-alert-identity-content">
                          <strong
                            title={alert.title}
                          >
                            {alert.title}
                          </strong>

                          <span
                            title={alert.source_id}
                          >
                            Source:
                            {" "}
                            {alert.source_id}
                          </span>
                        </div>
                      </div>
                    </td>

                    {/* ------------------------------------------------------
                     * Severity
                     * ------------------------------------------------------ */}

                    <td className="dashboard-alert-severity-cell">
                      <SeverityBadge
                        severity={
                          alert.severity
                        }
                      />
                    </td>

                    {/* ------------------------------------------------------
                     * Risk Score
                     * ------------------------------------------------------ */}

                    <td className="dashboard-alert-risk-cell">
                      <div
                        className={`dashboard-alert-risk ${riskClass}`}
                      >
                        <strong>
                          {riskScore}
                        </strong>

                        <span>
                          {riskLevel}
                        </span>
                      </div>
                    </td>

                    {/* ------------------------------------------------------
                     * Status
                     * ------------------------------------------------------ */}

                    <td className="dashboard-alert-status-cell">
                      <span
                        className={`dashboard-alert-status ${alert.status}`}
                      >
                        <span className="dashboard-alert-status-dot" />

                        {formatStatus(
                          alert.status,
                        )}
                      </span>
                    </td>

                    {/* ------------------------------------------------------
                     * Action Indicator
                     * ------------------------------------------------------ */}

                    <td className="dashboard-alert-action-cell">
                      <span
                        className="dashboard-alert-action"
                        aria-hidden="true"
                      >
                        <ArrowUpRight
                          size={14}
                        />
                      </span>
                    </td>
                  </tr>
                );
              })}

              {/* ==========================================================
               * Empty State
               * ========================================================== */}

              {alerts &&
                !alertItems.length && (
                  <tr>
                    <td
                      colSpan={5}
                      className="dashboard-alerts-empty"
                    >
                      <div className="dashboard-alerts-empty-content">
                        <ShieldAlert
                          size={20}
                          aria-hidden="true"
                        />

                        <strong>
                          No alerts available
                        </strong>

                        <span>
                          No security alerts are
                          currently available.
                        </span>
                      </div>
                    </td>
                  </tr>
                )}

              {/* ==========================================================
               * Service Unavailable State
               * ========================================================== */}

              {!alerts && (
                <tr>
                  <td
                    colSpan={5}
                    className="dashboard-alerts-empty is-error"
                  >
                    <div className="dashboard-alerts-empty-content">
                      <AlertTriangle
                        size={20}
                        aria-hidden="true"
                      />

                      <strong>
                        Alert service unavailable
                      </strong>

                      <span>
                        Recent alert information
                        could not be retrieved.
                      </span>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </Panel>
  );
}