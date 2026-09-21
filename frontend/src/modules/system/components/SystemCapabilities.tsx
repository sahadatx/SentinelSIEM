/**
 * ============================================================
 * SentinelSIEM — System Capabilities
 * ============================================================
 *
 * Displays capabilities reported by:
 *
 *   GET /api/v1/system
 *
 * The backend is the source of truth for the capability list.
 *
 * This component:
 *   - Does not invent capabilities
 *   - Does not hard-code capability names
 *   - Preserves the backend-provided capability values
 *   - Provides a compact SOC-style presentation
 * ============================================================
 */

import {
  CheckCircle2,
  Layers3,
  ServerCog,
} from "lucide-react";

import type {
  SystemCapability,
  SystemComponentProps,
} from "../types";

/**
 * ============================================================
 * Helpers
 * ============================================================
 */

/**
 * Convert a backend capability identifier into a readable
 * display label without changing the underlying value.
 *
 * Example:
 *   "threat-intelligence" → "Threat Intelligence"
 *
 * The original capability value remains untouched and is
 * still used as the React key/data value.
 */
function formatCapabilityName(
  capability: SystemCapability,
): string {
  return capability
    .trim()
    .split(/[-_]+/)
    .filter(Boolean)
    .map(
      (word) =>
        word.charAt(0).toUpperCase() + word.slice(1),
    )
    .join(" ");
}

/**
 * ============================================================
 * Component
 * ============================================================
 */

export function SystemCapabilities({
  system,
}: SystemComponentProps) {
  const capabilities = Array.isArray(system.capabilities)
    ? system.capabilities
    : [];

  return (
    <section
      aria-labelledby="system-capabilities-title"
      className="system-capabilities-panel"
    >
      {/* ======================================================
          Header
          ====================================================== */}

      <div className="system-capabilities-header">
        <div className="system-capabilities-heading">
          <div
            className="system-capabilities-icon"
            aria-hidden="true"
          >
            <Layers3 size={17} />
          </div>

          <div>
            <h2
              id="system-capabilities-title"
              className="system-capabilities-title"
            >
              Platform Capabilities
            </h2>

            <p className="system-capabilities-description">
              Features currently exposed by the SentinelSIEM backend.
            </p>
          </div>
        </div>

        <div className="system-capabilities-count">
          <span className="system-capabilities-count-value">
            {capabilities.length}
          </span>

          <span className="system-capabilities-count-label">
            {capabilities.length === 1
              ? "Capability"
              : "Capabilities"}
          </span>
        </div>
      </div>

      {/* ======================================================
          Capability List
          ====================================================== */}

      {capabilities.length === 0 ? (
        <div
          className="system-capabilities-empty"
          role="status"
        >
          <div
            className="system-capabilities-empty-icon"
            aria-hidden="true"
          >
            <ServerCog size={20} />
          </div>

          <div>
            <h3 className="system-capabilities-empty-title">
              No capabilities reported
            </h3>

            <p className="system-capabilities-empty-description">
              The backend did not report any platform capabilities.
            </p>
          </div>
        </div>
      ) : (
        <ul
          aria-label="Platform capabilities"
          className="system-capabilities-list"
        >
          {capabilities.map((capability) => (
            <li
              key={capability}
              className="system-capability-item"
            >
              <div
                className="system-capability-status"
                aria-hidden="true"
              >
                <CheckCircle2 size={15} />
              </div>

              <div className="system-capability-content">
                <span className="system-capability-name">
                  {formatCapabilityName(capability)}
                </span>

                <span className="system-capability-value">
                  {capability}
                </span>
              </div>

              <span className="system-capability-state">
                Available
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export default SystemCapabilities;