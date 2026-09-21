/**
 * ============================================================================
 * SentinelSIEM — Global Audit Timeline
 * ============================================================================
 *
 * Professional chronological presentation of Global Audit activity.
 *
 * Responsibilities:
 *
 * - Display audit events in reverse chronological order
 * - Display action and outcome
 * - Display timestamp
 * - Display actor and target context
 * - Display source IP context
 * - Display request correlation when available
 * - Provide access to event details
 * - Handle loading and empty states
 *
 * This component does NOT:
 *
 * - fetch audit data
 * - mutate audit records
 * - perform authorization
 * - implement backend filtering
 * - expose credential material
 *
 * Backend remains the authoritative security boundary.
 *
 * ============================================================================
 */

import {
  AlertCircle,
  CheckCircle2,
  Clock3,
  Eye,
  Globe2,
  ShieldCheck,
  UserRound,
} from "lucide-react";

import type { ReactNode } from "react";

import type { AuditEvent } from "../types";

/* ============================================================================
 * Props
 * ========================================================================== */

export interface AuditTimelineProps {
  /**
   * Audit events supplied by the parent page.
   */
  events: AuditEvent[];

  /**
   * Optional loading state.
   */
  loading?: boolean;

  /**
   * Called when the user requests event details.
   */
  onSelect?: (
    event: AuditEvent,
  ) => void;
}

/* ============================================================================
 * Component
 * ========================================================================== */

export default function AuditTimeline({
  events,
  loading = false,
  onSelect,
}: AuditTimelineProps) {
  /* --------------------------------------------------------------------------
   * Loading
   * ------------------------------------------------------------------------ */

  if (loading) {
    return (
      <section
        className="audit-timeline"
        aria-label="Audit timeline"
        aria-busy="true"
      >
        <TimelineLoadingState />
      </section>
    );
  }

  /* --------------------------------------------------------------------------
   * Empty
   * ------------------------------------------------------------------------ */

  if (events.length === 0) {
    return (
      <section
        className="audit-timeline"
        aria-label="Audit timeline"
      >
        <TimelineEmptyState />
      </section>
    );
  }

  /* --------------------------------------------------------------------------
   * Chronological Ordering
   *
   * Newest events are displayed first.
   *
   * A copy is sorted so the parent-owned events array is never mutated.
   * ------------------------------------------------------------------------ */

  const timelineEvents =
    [...events].sort(
      (first, second) =>
        getTimestamp(second) -
        getTimestamp(first),
    );

  /* --------------------------------------------------------------------------
   * Render
   * ------------------------------------------------------------------------ */

  return (
    <section
      className="audit-timeline"
      aria-label="Audit timeline"
    >
      <div className="audit-timeline-list">
        {timelineEvents.map(
          (event, index) => (
            <TimelineItem
              key={buildEventKey(
                event,
                index,
              )}
              event={event}
              onSelect={onSelect}
              isLast={
                index ===
                timelineEvents.length - 1
              }
            />
          ),
        )}
      </div>
    </section>
  );
}

/* ============================================================================
 * Loading State
 * ========================================================================== */

function TimelineLoadingState() {
  return (
    <div
      className="audit-timeline-state"
      role="status"
      aria-live="polite"
    >
      <div
        className="audit-timeline-state-icon"
        aria-hidden="true"
      >
        <Clock3
          size={18}
        />
      </div>

      <div>
        <strong>
          Loading audit timeline
        </strong>

        <span>
          Retrieving the latest security activity...
        </span>
      </div>
    </div>
  );
}

/* ============================================================================
 * Empty State
 * ========================================================================== */

function TimelineEmptyState() {
  return (
    <div
      className="audit-timeline-state"
      role="status"
      aria-live="polite"
    >
      <div
        className="audit-timeline-state-icon"
        aria-hidden="true"
      >
        <ShieldCheck
          size={18}
        />
      </div>

      <div>
        <strong>
          No audit events found
        </strong>

        <span>
          No events match the current audit filters.
        </span>
      </div>
    </div>
  );
}

/* ============================================================================
 * Timeline Item
 * ========================================================================== */

interface TimelineItemProps {
  event: AuditEvent;

  onSelect?: (
    event: AuditEvent,
  ) => void;

  isLast: boolean;
}

function TimelineItem({
  event,
  onSelect,
  isLast,
}: TimelineItemProps) {
  const outcome =
    getOutcomeState(
      event.outcome,
    );

  const actionLabel =
    formatAction(
      event.action,
    );

  return (
    <article
      className={[
        "audit-timeline-item",
        isLast
          ? "last"
          : "",
      ]
        .filter(Boolean)
        .join(" ")}
    >
      {/* ======================================================================
          Timeline Rail
          ====================================================================== */}

      <div
        className="audit-timeline-rail"
        aria-hidden="true"
      >
        <div
          className={getMarkerClassName(
            outcome.status,
          )}
        >
          {outcome.status ===
          "success" ? (
            <CheckCircle2
              size={14}
            />
          ) : (
            <AlertCircle
              size={14}
            />
          )}
        </div>

        {!isLast && (
          <div className="audit-timeline-line" />
        )}
      </div>

      {/* ======================================================================
          Content
          ====================================================================== */}

      <div className="audit-timeline-content">
        {/* --------------------------------------------------------------------
            Header
            ------------------------------------------------------------------ */}

        <div className="audit-timeline-header">
          <div className="audit-timeline-title">
            <span
              className="audit-timeline-action-icon"
              aria-hidden="true"
            >
              <ShieldCheck
                size={14}
              />
            </span>

            <strong
              title={actionLabel}
            >
              {actionLabel}
            </strong>
          </div>

          <OutcomePill
            outcome={
              event.outcome
            }
          />
        </div>

        {/* --------------------------------------------------------------------
            Timestamp
            ------------------------------------------------------------------ */}

        <div className="audit-timeline-time">
          <Clock3
            size={13}
            aria-hidden="true"
          />

          <time
            dateTime={
              event.timestamp
            }
            title={formatFullDate(
              event.timestamp,
            )}
          >
            {formatDate(
              event.timestamp,
            )}
          </time>
        </div>

        {/* --------------------------------------------------------------------
            Event Context
            ------------------------------------------------------------------ */}

        <div className="audit-timeline-context">
          <TimelineContext
            label="Actor"
            value={
              event.actor_user_id ??
              "System"
            }
            icon={
              <UserRound
                size={13}
                aria-hidden="true"
              />
            }
            muted={
              event.actor_user_id ===
              null
            }
          />

          <TimelineContext
            label="Target"
            value={
              event.target_user_id ??
              "—"
            }
            icon={
              <UserRound
                size={13}
                aria-hidden="true"
              />
            }
            muted={
              event.target_user_id ===
              null
            }
          />

          <TimelineContext
            label="Source"
            value={
              event.source_ip ??
              "—"
            }
            icon={
              <Globe2
                size={13}
                aria-hidden="true"
              />
            }
            muted={
              event.source_ip ===
              null
            }
          />
        </div>

        {/* --------------------------------------------------------------------
            Correlation
            ------------------------------------------------------------------ */}

        {(event.request_id ||
          event.session_id) && (
          <div className="audit-timeline-correlation">
            {event.request_id && (
              <CorrelationValue
                label="Request"
                value={
                  event.request_id
                }
              />
            )}

            {event.session_id && (
              <CorrelationValue
                label="Session"
                value={
                  event.session_id
                }
              />
            )}
          </div>
        )}

        {/* --------------------------------------------------------------------
            Details
            ------------------------------------------------------------------ */}

        {onSelect && (
          <div className="audit-timeline-actions">
            <button
              type="button"
              className="audit-details-button"
              onClick={() =>
                onSelect(event)
              }
              title="View audit event details"
              aria-label={`View details for ${actionLabel} audit event`}
            >
              <Eye
                size={14}
                aria-hidden="true"
              />

              <span>
                View Details
              </span>
            </button>
          </div>
        )}
      </div>
    </article>
  );
}

/* ============================================================================
 * Marker Class
 * ========================================================================== */

function getMarkerClassName(
  status: OutcomeStatus,
): string {
  switch (status) {
    case "success":
      return "audit-timeline-marker success";

    case "failure":
      return "audit-timeline-marker failure";

    default:
      return "audit-timeline-marker neutral";
  }
}

/* ============================================================================
 * Timeline Context
 * ========================================================================== */

interface TimelineContextProps {
  label: string;
  value: string;
  icon?: ReactNode;
  muted?: boolean;
}

function TimelineContext({
  label,
  value,
  icon,
  muted = false,
}: TimelineContextProps) {
  return (
    <div
      className={[
        "audit-timeline-context-item",
        muted
          ? "muted"
          : "",
      ]
        .filter(Boolean)
        .join(" ")}
    >
      <span className="audit-timeline-context-label">
        {icon}

        {label}
      </span>

      <strong
        className={
          muted
            ? "audit-timeline-context-value"
            : "mono audit-timeline-context-value"
        }
        title={value}
      >
        {value}
      </strong>
    </div>
  );
}

/* ============================================================================
 * Correlation Value
 * ========================================================================== */

interface CorrelationValueProps {
  label: string;
  value: string;
}

function CorrelationValue({
  label,
  value,
}: CorrelationValueProps) {
  return (
    <span className="audit-timeline-correlation-item">
      <span>
        {label}
      </span>

      <strong
        className="mono"
        title={value}
      >
        {value}
      </strong>
    </span>
  );
}

/* ============================================================================
 * Outcome Pill
 * ========================================================================== */

interface OutcomePillProps {
  outcome: string;
}

function OutcomePill({
  outcome,
}: OutcomePillProps) {
  const state =
    getOutcomeState(
      outcome,
    );

  return (
    <span
      className={getOutcomePillClassName(
        state.status,
      )}
      aria-label={`Outcome: ${state.label}`}
    >
      {state.status ===
      "success" ? (
        <CheckCircle2
          size={12}
          aria-hidden="true"
        />
      ) : (
        <AlertCircle
          size={12}
          aria-hidden="true"
        />
      )}

      <span>
        {state.label}
      </span>
    </span>
  );
}

/* ============================================================================
 * Outcome Pill Class
 * ========================================================================== */

function getOutcomePillClassName(
  status: OutcomeStatus,
): string {
  switch (status) {
    case "success":
      return "audit-outcome-pill success";

    case "failure":
      return "audit-outcome-pill failure";

    default:
      return "audit-outcome-pill neutral";
  }
}

/* ============================================================================
 * Outcome State
 * ========================================================================== */

type OutcomeStatus =
  | "success"
  | "failure"
  | "neutral";

interface OutcomeState {
  status: OutcomeStatus;
  label: string;
}

function getOutcomeState(
  value: string,
): OutcomeState {
  const normalized =
    value
      .trim()
      .toLowerCase();

  if (
    normalized === "success" ||
    normalized === "successful"
  ) {
    return {
      status: "success",
      label: "Successful",
    };
  }

  if (
    normalized === "failure" ||
    normalized === "failed" ||
    normalized === "error"
  ) {
    return {
      status: "failure",
      label: "Failed",
    };
  }

  return {
    status: "neutral",
    label:
      formatValue(value),
  };
}

/* ============================================================================
 * Timestamp
 * ========================================================================== */

function getTimestamp(
  event: AuditEvent,
): number {
  const timestamp =
    new Date(
      event.timestamp,
    ).getTime();

  return Number.isNaN(
    timestamp,
  )
    ? 0
    : timestamp;
}

/* ============================================================================
 * Event Key
 * ========================================================================== */

function buildEventKey(
  event: AuditEvent,
  index: number,
): string {
  const eventId =
    event.event_id?.trim();

  if (eventId) {
    return eventId;
  }

  return [
    event.timestamp,
    event.action,
    event.outcome,
    event.actor_user_id ??
      "system",
    event.target_user_id ??
      "no-target",
    event.request_id ??
      "no-request",
    event.session_id ??
      "no-session",
    index,
  ].join(":");
}

/* ============================================================================
 * Date Formatting
 * ========================================================================== */

function formatDate(
  value: string | null,
): string {
  if (!value) {
    return "—";
  }

  const date =
    new Date(value);

  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    return "—";
  }

  return new Intl.DateTimeFormat(
    "en-US",
    {
      month: "short",
      day: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    },
  ).format(date);
}

/* ============================================================================
 * Full Date Formatting
 * ========================================================================== */

function formatFullDate(
  value: string | null,
): string {
  if (!value) {
    return "Unknown timestamp";
  }

  const date =
    new Date(value);

  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    return "Unknown timestamp";
  }

  return new Intl.DateTimeFormat(
    "en-US",
    {
      dateStyle: "full",
      timeStyle: "long",
    },
  ).format(date);
}

/* ============================================================================
 * Action Formatting
 * ========================================================================== */

function formatAction(
  value: string,
): string {
  const normalized =
    value.trim();

  if (!normalized) {
    return "Unknown Action";
  }

  return normalized
    .replace(
      /[._-]+/g,
      " ",
    )
    .replace(
      /\s+/g,
      " ",
    )
    .trim()
    .replace(
      /\b\w/g,
      (character) =>
        character.toUpperCase(),
    );
}

/* ============================================================================
 * Generic Value Formatting
 * ========================================================================== */

function formatValue(
  value: string,
): string {
  const normalized =
    value.trim();

  if (!normalized) {
    return "Unknown";
  }

  return normalized
    .replace(
      /[-_]+/g,
      " ",
    )
    .replace(
      /\s+/g,
      " ",
    )
    .trim()
    .replace(
      /\b\w/g,
      (character) =>
        character.toUpperCase(),
    );
}