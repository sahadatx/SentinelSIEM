/**
 * ============================================================================
 * SentinelSIEM — Individual User Audit Table
 * ============================================================================
 *
 * Scoped table for:
 *
 * Users → User Details → Audit History
 *
 * Columns:
 *   Timestamp | Action | Outcome | Target | Source IP | Request ID
 *
 * Design rules:
 *   - No Actor column
 *   - No Details column
 *   - Whole row is clickable
 *   - Human-readable target identity when available
 *   - Technical IDs remain compact
 *   - Backend remains authoritative
 * ============================================================================
 */

import {
  AlertCircle,
  CheckCircle2,
  Clock3,
  FileSearch,
  Shield,
  UserRound,
} from "lucide-react";

import type { KeyboardEvent } from "react";

import type { UserAuditEvent } from "../types";


/* ============================================================================
 * Target User
 * ========================================================================== */

export interface UserAuditTargetUser {
  user_id: string;
  name?: string | null;
  full_name?: string | null;
  username?: string | null;
  role?: string | null;
}


/* ============================================================================
 * Props
 * ========================================================================== */

export interface UserAuditTableProps {
  activities: UserAuditEvent[];
  targetUsers?: UserAuditTargetUser[];
  loading?: boolean;
  onSelect?: (event: UserAuditEvent) => void;
}


/* ============================================================================
 * Main Component
 * ========================================================================== */

export default function UserAuditTable({
  activities,
  targetUsers = [],
  loading = false,
  onSelect,
}: UserAuditTableProps) {
  if (loading) {
    return <AuditTableSkeleton />;
  }

  if (activities.length === 0) {
    return <AuditTableEmpty />;
  }

  return (
    <section
      className="user-audit-table"
      aria-label="User audit events"
    >
      <div className="user-audit-table-heading">
        <div className="user-audit-table-heading-main">
          <div
            className="user-audit-table-heading-icon"
            aria-hidden="true"
          >
            <FileSearch size={17} />
          </div>

          <div>
            <span className="user-audit-table-eyebrow">
              AUDIT EVENTS
            </span>

            <h3>Account Activity</h3>

            <p>
              Recorded security and account-management events for this user.
            </p>
          </div>
        </div>

        <div className="user-audit-table-total">
          <strong>{activities.length}</strong>
          <span>
            {activities.length === 1 ? "event" : "events"}
          </span>
        </div>
      </div>

      <div className="user-audit-table-wrapper">
        <table className="user-audit-data-table">
          <colgroup>
            <col className="user-audit-column-timestamp" />
            <col className="user-audit-column-action" />
            <col className="user-audit-column-outcome" />
            <col className="user-audit-column-target" />
            <col className="user-audit-column-source" />
            <col className="user-audit-column-request" />
          </colgroup>

          <caption className="sr-only">
            User audit events. Select an event row to inspect its details.
          </caption>

          <thead>
            <tr>
              <th scope="col">Timestamp</th>
              <th scope="col">Action</th>
              <th scope="col">Outcome</th>
              <th scope="col">Target</th>
              <th scope="col">Source IP</th>
              <th scope="col">Request ID</th>
            </tr>
          </thead>

          <tbody>
            {activities.map((event, index) => (
              <AuditRow
                key={buildEventKey(event, index)}
                event={event}
                targetUsers={targetUsers}
                onSelect={onSelect}
              />
            ))}
          </tbody>
        </table>
      </div>

      {onSelect && (
        <div className="user-audit-table-footer-hint">
          Select an event row to inspect full audit details.
        </div>
      )}
    </section>
  );
}


/* ============================================================================
 * Row
 * ========================================================================== */

function AuditRow({
  event,
  targetUsers,
  onSelect,
}: {
  event: UserAuditEvent;
  targetUsers: UserAuditTargetUser[];
  onSelect?: (event: UserAuditEvent) => void;
}) {
  const selectable = Boolean(onSelect);
  const actionLabel = formatAction(event.action);

  const handleKeyDown = (
    keyboardEvent: KeyboardEvent<HTMLTableRowElement>,
  ) => {
    if (!onSelect) {
      return;
    }

    if (
      keyboardEvent.key === "Enter" ||
      keyboardEvent.key === " "
    ) {
      keyboardEvent.preventDefault();
      onSelect(event);
    }
  };

  return (
    <tr
      className={
        selectable
          ? "user-audit-data-row user-audit-data-row-clickable"
          : "user-audit-data-row"
      }
      onClick={
        selectable
          ? () => onSelect?.(event)
          : undefined
      }
      onKeyDown={handleKeyDown}
      tabIndex={selectable ? 0 : undefined}
      role={selectable ? "button" : undefined}
      aria-label={
        selectable
          ? `Inspect ${actionLabel} audit event`
          : undefined
      }
    >
      {/* Timestamp */}

      <td className="user-audit-data-cell user-audit-timestamp-cell">
        <div className="user-audit-timestamp">
          <span
            className="user-audit-cell-icon"
            aria-hidden="true"
          >
            <Clock3 size={14} />
          </span>

          <div className="user-audit-timestamp-text">
            <strong>
              {formatDateTime(event.timestamp)}
            </strong>
          </div>
        </div>
      </td>


      {/* Action */}

      <td className="user-audit-data-cell user-audit-action-cell">
        <div className="user-audit-action">
          <span
            className="user-audit-action-icon"
            aria-hidden="true"
          >
            <Shield size={14} />
          </span>

          <strong title={String(event.action ?? "")}>
            {actionLabel}
          </strong>
        </div>
      </td>


      {/* Outcome */}

      <td className="user-audit-data-cell user-audit-outcome-cell">
        <OutcomeBadge outcome={event.outcome} />
      </td>


      {/* Target */}

      <td className="user-audit-data-cell user-audit-target-cell">
        <AuditTarget
          value={event.target_user_id}
          targetUsers={targetUsers}
        />
      </td>


      {/* Source IP */}

      <td className="user-audit-data-cell user-audit-source-cell">
        <TechnicalValue
          value={event.source_ip}
          fallback="—"
          title="Source IP"
        />
      </td>


      {/* Request ID */}

      <td className="user-audit-data-cell user-audit-request-cell">
        <TechnicalValue
          value={event.request_id}
          fallback="—"
          title="Request ID"
          maxLength={18}
        />
      </td>
    </tr>
  );
}


/* ============================================================================
 * Outcome
 * ========================================================================== */

function OutcomeBadge({
  outcome,
}: {
  outcome: string;
}) {
  const state = getOutcomeState(outcome);

  return (
    <span
      className={`user-audit-outcome-badge user-audit-outcome-${state.type}`}
      title={`Audit outcome: ${state.label}`}
    >
      {state.type === "success" && (
        <CheckCircle2 size={13} aria-hidden="true" />
      )}

      {state.type === "failure" && (
        <AlertCircle size={13} aria-hidden="true" />
      )}

      {state.type === "denied" && (
        <Shield size={13} aria-hidden="true" />
      )}

      <span>{state.label}</span>
    </span>
  );
}


function getOutcomeState(
  value: string | null | undefined,
): {
  type: "success" | "failure" | "denied";
  label: string;
} {
  const normalized = String(value ?? "")
    .trim()
    .toLowerCase();

  if (
    normalized === "success" ||
    normalized === "successful" ||
    normalized === "succeeded"
  ) {
    return {
      type: "success",
      label: "Success",
    };
  }

  if (
    normalized === "denied" ||
    normalized === "deny"
  ) {
    return {
      type: "denied",
      label: "Denied",
    };
  }

  if (
    normalized === "failure" ||
    normalized === "failed" ||
    normalized === "error"
  ) {
    return {
      type: "failure",
      label: "Failure",
    };
  }

  return {
    type: "failure",
    label: formatAction(value) || "Unknown",
  };
}


/* ============================================================================
 * Target
 * ========================================================================== */

function AuditTarget({
  value,
  targetUsers,
}: {
  value: string | null;
  targetUsers: UserAuditTargetUser[];
}) {
  const normalized = value?.trim();

  if (!normalized) {
    return (
      <div className="user-audit-target">
        <span
          className="user-audit-target-icon user-audit-target-muted"
          aria-hidden="true"
        >
          <UserRound size={14} />
        </span>

        <div className="user-audit-target-text">
          <strong>—</strong>
          <span>NO TARGET</span>
        </div>
      </div>
    );
  }

  const targetUser = targetUsers.find(
    (user) =>
      String(user.user_id).trim().toLowerCase() ===
      normalized.toLowerCase(),
  );

  if (targetUser) {
    const displayName =
      targetUser.name?.trim() ||
      targetUser.full_name?.trim() ||
      targetUser.username?.trim() ||
      "Unknown User";

    const role =
      targetUser.role?.trim() ||
      "User";

    return (
      <div className="user-audit-target">
        <span
          className="user-audit-target-icon"
          aria-hidden="true"
        >
          <UserRound size={14} />
        </span>

        <div className="user-audit-target-text">
          <strong title={`${displayName} · ${role}`}>
            👤 {displayName}
          </strong>

          <span>{role}</span>
        </div>
      </div>
    );
  }

  return (
    <div className="user-audit-target">
      <span
        className="user-audit-target-icon"
        aria-hidden="true"
      >
        <UserRound size={14} />
      </span>

      <div className="user-audit-target-text">
        <strong
          className="mono"
          title={normalized}
        >
          {truncate(normalized, 14)}
        </strong>

        <span>TARGET USER</span>
      </div>
    </div>
  );
}


/* ============================================================================
 * Technical Value
 * ========================================================================== */

function TechnicalValue({
  value,
  fallback,
  title,
  maxLength = 22,
}: {
  value: string | null;
  fallback: string;
  title: string;
  maxLength?: number;
}) {
  const normalized = value?.trim();

  if (!normalized) {
    return (
      <span className="user-audit-technical-empty">
        {fallback}
      </span>
    );
  }

  return (
    <span
      className="user-audit-technical-value mono"
      title={`${title}: ${normalized}`}
    >
      {truncate(normalized, maxLength)}
    </span>
  );
}


/* ============================================================================
 * Skeleton
 * ========================================================================== */

function AuditTableSkeleton() {
  return (
    <section
      className="user-audit-table"
      aria-busy="true"
      aria-label="Loading user audit history"
    >
      <div className="user-audit-table-heading">
        <div className="user-audit-table-heading-main">
          <div className="user-audit-table-heading-icon">
            <FileSearch size={17} />
          </div>

          <div>
            <span className="user-audit-table-eyebrow">
              AUDIT EVENTS
            </span>

            <h3>Account Activity</h3>

            <p>Retrieving recorded security events...</p>
          </div>
        </div>
      </div>

      <div className="user-audit-table-wrapper">
        <table className="user-audit-data-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Action</th>
              <th>Outcome</th>
              <th>Target</th>
              <th>Source IP</th>
              <th>Request ID</th>
            </tr>
          </thead>

          <tbody>
            {Array.from({ length: 6 }).map((_, rowIndex) => (
              <tr key={rowIndex}>
                {Array.from({ length: 6 }).map((__, cellIndex) => (
                  <td key={cellIndex}>
                    <span className="user-audit-skeleton" />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}


/* ============================================================================
 * Empty
 * ========================================================================== */

function AuditTableEmpty() {
  return (
    <section
      className="user-audit-empty"
      aria-label="User audit history"
    >
      <div
        className="user-audit-empty-icon"
        aria-hidden="true"
      >
        <FileSearch size={22} />
      </div>

      <div>
        <strong>No audit activity</strong>

        <p>
          No recorded security or account-management events are
          available for this user.
        </p>
      </div>
    </section>
  );
}


/* ============================================================================
 * Helpers
 * ========================================================================== */

function buildEventKey(
  event: UserAuditEvent,
  index: number,
): string {
  return [
    event.timestamp,
    event.action,
    event.outcome,
    event.target_user_id ?? "no-target",
    event.request_id ?? "no-request",
    event.session_id ?? "no-session",
    index,
  ].join("|");
}


function formatAction(
  value: string | null | undefined,
): string {
  if (value === null || value === undefined) {
    return "—";
  }

  const normalized = String(value)
    .trim()
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/[._-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  if (!normalized) {
    return "—";
  }

  return normalized.replace(
    /\b\w/g,
    (character) => character.toUpperCase(),
  );
}


function formatDateTime(
  value: string | null | undefined,
): string {
  if (!value) {
    return "Unknown date";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "Unknown date";
  }

  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(date);
}


function truncate(
  value: string,
  maxLength: number,
): string {
  if (value.length <= maxLength) {
    return value;
  }

  return `${value.slice(0, Math.max(1, maxLength - 1))}…`;
}