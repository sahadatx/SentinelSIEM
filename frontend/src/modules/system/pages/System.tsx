/**
 * ============================================================
 * SentinelSIEM — System Health Page
 * ============================================================
 *
 * Main page for the System Health module.
 *
 * Responsibilities:
 *   - Fetch system information
 *   - Manage loading state
 *   - Manage error state
 *   - Render System Health sections
 *
 * Backend:
 *   GET /api/v1/system
 *
 * The page intentionally does not invent runtime/service
 * metrics that are not provided by the backend contract.
 * ============================================================
 */

import { useCallback, useEffect, useState } from "react";
import { AlertCircle, RefreshCw, Server } from "lucide-react";

import { getSystemInfo } from "../api";
import type { SystemInfo } from "../types";

import SystemCapabilities from "../components/SystemCapabilities";
import SystemHealth from "../components/SystemHealth";
import SystemOverview from "../components/SystemOverview";
import SystemRuntime from "../components/SystemRuntime";

import "../System.css";

/**
 * ============================================================
 * Page
 * ============================================================
 */

export function System() {
  const [system, setSystem] = useState<SystemInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  /**
   * ----------------------------------------------------------
   * Load System Information
   * ----------------------------------------------------------
   */

  const loadSystemInfo = useCallback(async (isRefresh = false) => {
    try {
      if (isRefresh) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      setError(null);

      const data = await getSystemInfo();

      setSystem(data);
    } catch (err: unknown) {
      const message =
        err instanceof Error
          ? err.message
          : "Failed to load system information.";

      setError(message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  /**
   * ----------------------------------------------------------
   * Initial Load
   * ----------------------------------------------------------
   */

  useEffect(() => {
    let mounted = true;

    const load = async () => {
      try {
        setLoading(true);
        setError(null);

        const data = await getSystemInfo();

        if (!mounted) {
          return;
        }

        setSystem(data);
      } catch (err: unknown) {
        if (!mounted) {
          return;
        }

        const message =
          err instanceof Error
            ? err.message
            : "Failed to load system information.";

        setError(message);
      } finally {
        if (mounted) {
          setLoading(false);
        }
      }
    };

    void load();

    return () => {
      mounted = false;
    };
  }, []);

  /**
   * ==========================================================
   * Loading State
   * ==========================================================
   */

  if (loading) {
    return (
      <main
        className="system-health-page"
        aria-busy="true"
        aria-live="polite"
      >
        <header className="system-health-page-header">
          <div className="system-health-page-heading">
            <div className="system-health-page-icon" aria-hidden="true">
              <Server size={20} />
            </div>

            <div>
              <h1 className="system-health-page-title">
                System Health
              </h1>

              <p className="system-health-page-description">
                Platform availability, system information and runtime status.
              </p>
            </div>
          </div>
        </header>

        <section className="system-health-loading" aria-label="Loading">
          <div className="system-health-loading-spinner" aria-hidden="true">
            <RefreshCw size={20} />
          </div>

          <div>
            <h2 className="system-health-loading-title">
              Loading system information
            </h2>

            <p className="system-health-loading-text">
              Retrieving the latest SentinelSIEM platform status.
            </p>
          </div>
        </section>
      </main>
    );
  }

  /**
   * ==========================================================
   * Error State
   * ==========================================================
   */

  if (error || !system) {
    return (
      <main className="system-health-page">
        <header className="system-health-page-header">
          <div className="system-health-page-heading">
            <div className="system-health-page-icon" aria-hidden="true">
              <Server size={20} />
            </div>

            <div>
              <h1 className="system-health-page-title">
                System Health
              </h1>

              <p className="system-health-page-description">
                Platform availability, system information and runtime status.
              </p>
            </div>
          </div>

          <button
            type="button"
            className="system-health-refresh-button"
            onClick={() => void loadSystemInfo(true)}
            disabled={refreshing}
          >
            <RefreshCw
              size={15}
              className={
                refreshing
                  ? "system-health-refresh-icon spinning"
                  : "system-health-refresh-icon"
              }
              aria-hidden="true"
            />

            <span>{refreshing ? "Refreshing..." : "Refresh"}</span>
          </button>
        </header>

        <section
          className="system-health-error"
          role="alert"
        >
          <div className="system-health-error-icon" aria-hidden="true">
            <AlertCircle size={20} />
          </div>

          <div className="system-health-error-content">
            <h2 className="system-health-error-title">
              Unable to load system information
            </h2>

            <p className="system-health-error-message">
              {error ?? "The system information is currently unavailable."}
            </p>

            <button
              type="button"
              className="system-health-error-action"
              onClick={() => void loadSystemInfo(true)}
              disabled={refreshing}
            >
              <RefreshCw
                size={14}
                className={
                  refreshing
                    ? "system-health-refresh-icon spinning"
                    : "system-health-refresh-icon"
                }
                aria-hidden="true"
              />

              <span>
                {refreshing ? "Retrying..." : "Try Again"}
              </span>
            </button>
          </div>
        </section>
      </main>
    );
  }

  /**
   * ==========================================================
   * Main System Health View
   * ==========================================================
   */

  return (
    <main className="system-health-page">
      {/* ======================================================
          Page Header
          ====================================================== */}

      <header className="system-health-page-header">
        <div className="system-health-page-heading">
          <div className="system-health-page-icon" aria-hidden="true">
            <Server size={20} />
          </div>

          <div>
            <h1 className="system-health-page-title">
              System Health
            </h1>

            <p className="system-health-page-description">
              Platform availability, system information and runtime status.
            </p>
          </div>
        </div>

        <button
          type="button"
          className="system-health-refresh-button"
          onClick={() => void loadSystemInfo(true)}
          disabled={refreshing}
          aria-label="Refresh system information"
        >
          <RefreshCw
            size={15}
            className={
              refreshing
                ? "system-health-refresh-icon spinning"
                : "system-health-refresh-icon"
            }
            aria-hidden="true"
          />

          <span>{refreshing ? "Refreshing..." : "Refresh"}</span>
        </button>
      </header>

      {/* ======================================================
          KPI / Overview
          ====================================================== */}

      <section
        className="system-health-section system-health-section-overview"
        aria-label="System overview"
      >
        <SystemOverview system={system} />
      </section>

      {/* ======================================================
          Health / Platform Status
          ====================================================== */}

      <section
        className="system-health-section"
        aria-label="Platform health"
      >
        <SystemHealth system={system} />
      </section>

      {/* ======================================================
          Platform Capabilities
          ====================================================== */}

      <section
        className="system-health-section"
        aria-label="Platform capabilities"
      >
        <SystemCapabilities system={system} />
      </section>

      {/* ======================================================
          Runtime / System Information
          ====================================================== */}

      <section
        className="system-health-section"
        aria-label="Runtime information"
      >
        <SystemRuntime system={system} />
      </section>
    </main>
  );
}

export default System;