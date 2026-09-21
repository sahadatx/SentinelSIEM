/**
 * ============================================================
 * SentinelSIEM — System Runtime
 * ============================================================
 *
 * Displays runtime identity information reported by:
 *
 *   GET /api/v1/system
 *
 * Backend contract:
 *   - service
 *   - version
 *   - environment
 *   - capabilities
 *
 * Important:
 *   The current System API does not expose internal runtime
 *   configuration or process metrics such as:
 *     - host
 *     - port
 *     - database state
 *     - Redis state
 *     - worker state
 *     - CPU usage
 *     - memory usage
 *     - process uptime
 *
 * Therefore this component only renders information that is
 * actually available in SystemInfo.
 * ============================================================
 */

import {
  Box,
  Code2,
  Globe2,
} from "lucide-react";

import type { SystemComponentProps } from "../types";

/**
 * ============================================================
 * Helpers
 * ============================================================
 */

/**
 * Format the environment for display without changing the
 * original backend value.
 *
 * Example:
 *   "production" -> "Production"
 *   "development" -> "Development"
 */
function formatEnvironment(
  environment: string,
): string {
  const value = environment.trim();

  if (!value) {
    return "Not specified";
  }

  return value.charAt(0).toUpperCase() + value.slice(1);
}

/**
 * ============================================================
 * Component
 * ============================================================
 */

export function SystemRuntime({
  system,
}: SystemComponentProps) {
  return (
    <section
      aria-labelledby="system-runtime-title"
      className="system-runtime-panel"
    >
      {/* ======================================================
          Header
          ====================================================== */}

      <div className="system-runtime-header">
        <div className="system-runtime-heading">
          <div
            className="system-runtime-icon"
            aria-hidden="true"
          >
            <Code2 size={17} />
          </div>

          <div>
            <h2
              id="system-runtime-title"
              className="system-runtime-title"
            >
              Runtime Information
            </h2>

            <p className="system-runtime-description">
              Runtime identity reported by the SentinelSIEM backend.
            </p>
          </div>
        </div>
      </div>

      {/* ======================================================
          Runtime Identity
          ====================================================== */}

      <dl className="system-runtime-grid">
        {/* ----------------------------------------------------
            Service
            ---------------------------------------------------- */}

        <div className="system-runtime-item">
          <div
            className="system-runtime-item-icon"
            aria-hidden="true"
          >
            <Box size={16} />
          </div>

          <div className="system-runtime-item-content">
            <dt className="system-runtime-label">
              Service
            </dt>

            <dd className="system-runtime-value system-runtime-value-mono">
              {system.service || "Not specified"}
            </dd>
          </div>
        </div>

        {/* ----------------------------------------------------
            Version
            ---------------------------------------------------- */}

        <div className="system-runtime-item">
          <div
            className="system-runtime-item-icon"
            aria-hidden="true"
          >
            <Code2 size={16} />
          </div>

          <div className="system-runtime-item-content">
            <dt className="system-runtime-label">
              Version
            </dt>

            <dd className="system-runtime-value system-runtime-value-mono">
              {system.version || "Not specified"}
            </dd>
          </div>
        </div>

        {/* ----------------------------------------------------
            Environment
            ---------------------------------------------------- */}

        <div className="system-runtime-item">
          <div
            className="system-runtime-item-icon"
            aria-hidden="true"
          >
            <Globe2 size={16} />
          </div>

          <div className="system-runtime-item-content">
            <dt className="system-runtime-label">
              Environment
            </dt>

            <dd className="system-runtime-value">
              {formatEnvironment(system.environment)}
            </dd>
          </div>
        </div>
      </dl>
    </section>
  );
}

export default SystemRuntime;