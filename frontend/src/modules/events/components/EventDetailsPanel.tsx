import { X } from "lucide-react";

import { Panel } from "../../../components/ui/Panel";

import type { SecurityEvent } from "../types";

/* ==========================================================================
 * Props
 * ========================================================================== */

export interface EventDetailsPanelProps {
  event: SecurityEvent | null;

  onClose?: () => void;
}

/* ==========================================================================
 * Helpers
 * ========================================================================== */

function formatDate(
  value?: string | null,
): string {
  if (!value) {
    return "—";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "—";
  }

  return date.toLocaleString();
}

function formatValue(
  value: unknown,
): string {
  if (
    value === null ||
    value === undefined
  ) {
    return "—";
  }

  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return String(value) || "—";
  }

  try {
    return JSON.stringify(
      value,
      null,
      2,
    );
  } catch {
    return "Unable to display value";
  }
}

function formatLabel(
  value?: string | null,
): string {
  if (!value) {
    return "Unknown";
  }

  return value
    .replace(/[-_]+/g, " ")
    .replace(
      /\b\w/g,
      (character) =>
        character.toUpperCase(),
    );
}

function getSeverityClass(
  severity?: string | null,
): string {
  switch (severity) {
    case "critical":
      return "health-pill critical";

    case "high":
      return "health-pill warning";

    case "low":
      return "health-pill healthy";

    case "medium":
    case "info":
    default:
      return "health-pill";
  }
}

/* ==========================================================================
 * Component
 * ========================================================================== */

export default function EventDetailsPanel({
  event,
  onClose,
}: EventDetailsPanelProps) {
  if (!event) {
    return null;
  }

  return (
    <section
      className="event-details-panel"
      aria-label="Security event details"
    >
      {/* ====================================================================
       * Event Overview
       * ==================================================================== */}

      <Panel
        title="Event Details"
        subtitle={event.event_id}
      >
        {/* ------------------------------------------------------------------
         * Header Actions
         * ------------------------------------------------------------------ */}

        {onClose && (
          <div className="event-details-header-actions">
            <button
              type="button"
              className="event-details-close-button"
              onClick={onClose}
              aria-label="Close event details"
              title="Close event details"
            >
              <X
                size={15}
                aria-hidden="true"
              />

              <span>
                Close
              </span>
            </button>
          </div>
        )}

        {/* ------------------------------------------------------------------
         * Core Event Information
         * ------------------------------------------------------------------ */}

        <div className="event-details-grid">
          <Detail
            label="Event ID"
            value={event.event_id}
            mono
          />

          <Detail
            label="Timestamp"
            value={formatDate(
              event.timestamp,
            )}
          />

          <Detail
            label="Ingestion Timestamp"
            value={formatDate(
              event.ingestion_timestamp,
            )}
          />

          <Detail
            label="Source"
            value={event.source}
          />

          <Detail
            label="Source Type"
            value={event.source_type}
          />

          <Detail
            label="Hostname"
            value={event.hostname}
          />

          <Detail
            label="Source IP"
            value={event.source_ip}
            mono
          />

          <Detail
            label="Destination IP"
            value={event.destination_ip}
            mono
          />

          <Detail
            label="Source Port"
            value={event.source_port}
            mono
          />

          <Detail
            label="Destination Port"
            value={event.destination_port}
            mono
          />

          <Detail
            label="Protocol"
            value={event.protocol}
          />

          <Detail
            label="Username"
            value={event.username}
          />

          <Detail
            label="Process"
            value={event.process}
          />

          <Detail
            label="Command"
            value={event.command}
            mono
          />

          <Detail
            label="Action"
            value={event.action}
          />

          <Detail
            label="Outcome"
            value={event.outcome}
          />

          <div className="event-detail-item">
            <span className="event-detail-label">
              Severity
            </span>

            <strong className="event-detail-value">
              <span
                className={getSeverityClass(
                  event.severity,
                )}
              >
                {formatLabel(
                  event.severity,
                )}
              </span>
            </strong>
          </div>

          <Detail
            label="Category"
            value={event.category}
          />

          <Detail
            label="Stage"
            value={event.stage}
          />
        </div>
      </Panel>

      {/* ====================================================================
       * Raw Event
       * ==================================================================== */}

      <Panel
        title="Raw Event"
        subtitle="Original event payload"
      >
        <EventCodeBlock
          value={
            event.raw_event || "—"
          }
        />
      </Panel>

      {/* ====================================================================
       * Parsed Data
       * ==================================================================== */}

      <Panel
        title="Parsed Data"
        subtitle="Source-specific parsed fields"
      >
        <EventCodeBlock
          value={formatValue(
            event.parsed_data,
          )}
        />
      </Panel>

      {/* ====================================================================
       * Normalized Data
       * ==================================================================== */}

      <Panel
        title="Normalized Data"
        subtitle="Canonical normalized fields"
      >
        <EventCodeBlock
          value={formatValue(
            event.normalized_data,
          )}
        />
      </Panel>

      {/* ====================================================================
       * Enrichment
       * ==================================================================== */}

      <Panel
        title="Enrichment"
        subtitle="Additional enrichment data"
      >
        <EventCodeBlock
          value={
            event.enrichment
              ? formatValue(
                  event.enrichment,
                )
              : "No enrichment data available."
          }
        />
      </Panel>

      {/* ====================================================================
       * Metadata
       * ==================================================================== */}

      <Panel
        title="Metadata"
        subtitle="Event metadata"
      >
        <EventCodeBlock
          value={formatValue(
            event.metadata,
          )}
        />
      </Panel>
    </section>
  );
}

/* ==========================================================================
 * Detail
 * ========================================================================== */

function Detail({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: unknown;
  mono?: boolean;
}) {
  return (
    <div className="event-detail-item">
      <span className="event-detail-label">
        {label}
      </span>

      <strong
        className={
          mono
            ? "event-detail-value mono"
            : "event-detail-value"
        }
      >
        {formatValue(value)}
      </strong>
    </div>
  );
}

/* ==========================================================================
 * Code Block
 * ========================================================================== */

function EventCodeBlock({
  value,
}: {
  value: string;
}) {
  return (
    <pre className="event-details-code-block">
      {value}
    </pre>
  );
}