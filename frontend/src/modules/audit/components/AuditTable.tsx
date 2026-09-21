/**
 * ============================================================================
 * SentinelSIEM — Global Audit Event Table
 * ============================================================================
 *
 * Read-only SOC/SIEM event table for Global Audit.
 *
 * Responsibilities
 * ----------------
 *
 * - Render canonical audit events
 * - Display human-readable action labels
 * - Display outcome
 * - Display resolved actor identity
 * - Display resolved target identity
 * - Display source IP
 * - Display compact request correlation ID
 * - Preserve full request ID through tooltip/event details
 * - Provide View action
 *
 * Identity Resolution
 * ------------------
 *
 * Authoritative source:
 *
 *     User Management directory
 *
 * Resolution priority:
 *
 *     1. User Management directory by user_id
 *     2. Backend-resolved actor / target object
 *     3. Unknown User fallback
 *     4. null = System / No Target
 *
 * Request ID Presentation
 * ----------------------
 *
 * Table:
 *
 *     4e03c359…b8fcd
 *
 * Tooltip:
 *
 *     Full Request ID
 *
 * Details:
 *
 *     Full Request ID
 *
 * Technical identifiers are never rendered as
 * human-readable actor or target names.
 *
 * Security boundary
 * -----------------
 *
 * - No authentication
 * - No authorization
 * - No API requests
 * - No mutation
 * - No filtering
 * - No metadata rendering
 * - No credential rendering
 *
 * Backend remains authoritative.
 *
 * ============================================================================
 */

import {
  AlertCircle,
  CheckCircle2,
  Clock3,
  Eye,
  Minus,
  ShieldAlert,
  ShieldCheck,
  UserRound,
} from "lucide-react";

import type {
  AuditActor,
  AuditEvent,
  AuditTarget,
} from "../types";


/* ============================================================================
 * Identity User
 * ========================================================================== */

export interface AuditIdentityUser {
  user_id: string;

  display_name:
    | string
    | null;

  username: string;

  role:
    | string
    | null;
}


/* ============================================================================
 * Props
 * ========================================================================== */

export interface AuditTableProps {
  events: AuditEvent[];

  loading?: boolean;

  onSelect?: (
    event: AuditEvent,
  ) => void;

  /**
   * Authoritative User Management directory
   * used for actor / target resolution.
   */
  identityUsers?: AuditIdentityUser[];
}


/* ============================================================================
 * Canonical Backend Audit Action Labels
 * ========================================================================== */

const ACTION_LABELS: Record<string, string> = {
  "authentication.login_success":
    "Login Success",

  "authentication.login_failure":
    "Login Failure",

  "authentication.logout":
    "Logout",

  "authentication.token_validation":
    "Token Validation Failure",

  "authentication.session_created":
    "Session Created",

  "authentication.session_revoked":
    "Session Revoked",

  "authentication.sessions_revoked":
    "Sessions Revoked",

  "authentication.password_changed":
    "Password Changed",

  "authentication.password_change_failure":
    "Password Change Failure",

  "users.password_reset":
    "Password Reset",

  "authentication.password_reset_failure":
    "Password Reset Failure",

  "authentication.force_password_change":
    "Force Password Change",

  "users.created":
    "User Created",

  "users.updated":
    "User Updated",

  "users.enabled":
    "User Enabled",

  "users.disabled":
    "User Disabled",

  "users.locked":
    "User Locked",

  "users.unlocked":
    "User Unlocked",

  "users.deleted":
    "User Deleted",

  "users.role_changed":
    "Role Changed",

  "role.created":
    "Role Created",

  "role.updated":
    "Role Updated",

  "role.deleted":
    "Role Deleted",

  "role.permissions_changed":
    "Permissions Changed",

  "users.listed":
    "Users Listed",

  "users.viewed":
    "User Viewed",

  "users.statistics_viewed":
    "User Statistics Viewed",

  "authorization.permission_denied":
    "Permission Denied",

  "authorization.denied":
    "Authorization Denied",
};


/* ============================================================================
 * Component
 * ========================================================================== */

export default function AuditTable({
  events,
  loading = false,
  onSelect,
  identityUsers = [],
}: AuditTableProps) {

  /* ==========================================================================
   * Loading
   * ======================================================================== */

  if (loading) {
    return (
      <section
        className="audit-table"
        aria-label="Global audit events"
        aria-busy="true"
      >
        <TableLoadingState />
      </section>
    );
  }


  /* ==========================================================================
   * Empty
   * ======================================================================== */

  if (
    !Array.isArray(events) ||
    events.length === 0
  ) {
    return (
      <section
        className="audit-table"
        aria-label="Global audit events"
      >
        <TableEmptyState />
      </section>
    );
  }


  /* ==========================================================================
   * Render
   * ======================================================================== */

  return (
    <section
      className="audit-table"
      aria-label="Global audit events"
    >
      <div className="table-container">

        <table className="data-table audit-data-table">

          <caption className="sr-only">
            Global SentinelSIEM audit events
          </caption>


          <thead>
            <tr>

              <th scope="col">
                Timestamp
              </th>

              <th scope="col">
                Action
              </th>

              <th scope="col">
                Outcome
              </th>

              <th scope="col">
                Actor
              </th>

              <th scope="col">
                Target
              </th>

              <th scope="col">
                Source IP
              </th>

              <th
                scope="col"
                className="audit-request-id-column"
              >
                Request ID
              </th>

              <th
                scope="col"
                className="audit-details-column"
              >
                <span className="sr-only">
                  Details
                </span>
              </th>

            </tr>
          </thead>


          <tbody>

            {events.map(
              (
                event,
                index,
              ) => (
                <AuditRow
                  key={
                    buildEventKey(
                      event,
                      index,
                    )
                  }
                  event={event}
                  onSelect={onSelect}
                  identityUsers={
                    identityUsers
                  }
                />
              ),
            )}

          </tbody>

        </table>

      </div>
    </section>
  );
}


/* ============================================================================
 * Loading State
 * ========================================================================== */

function TableLoadingState() {
  return (
    <div
      className="audit-table-state"
      role="status"
      aria-live="polite"
    >

      <div
        className="audit-table-loading-icon"
        aria-hidden="true"
      >
        <Clock3 size={18} />
      </div>


      <div>

        <strong>
          Loading audit events
        </strong>

        <span>
          Retrieving security activity...
        </span>

      </div>

    </div>
  );
}


/* ============================================================================
 * Empty State
 * ========================================================================== */

function TableEmptyState() {
  return (
    <div
      className="audit-table-state"
      role="status"
      aria-live="polite"
    >

      <div
        className="audit-table-empty-icon"
        aria-hidden="true"
      >
        <ShieldCheck size={18} />
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
 * Audit Row
 * ========================================================================== */

interface AuditRowProps {
  event: AuditEvent;

  onSelect?: (
    event: AuditEvent,
  ) => void;

  identityUsers: AuditIdentityUser[];
}


function AuditRow({
  event,
  onSelect,
  identityUsers,
}: AuditRowProps) {

  const actionLabel =
    formatAction(
      event.action,
    );


  const sourceIp =
    normalizeDisplayValue(
      event.source_ip ??
      event.source,
    );


  const fullRequestId =
    normalizeNullableText(
      event.request_id,
    );


  const timestamp =
    normalizeTimestamp(
      event.timestamp ??
      event.created_at,
    );


  const actor =
    resolveActor(
      event,
      identityUsers,
    );


  const target =
    resolveTarget(
      event,
      identityUsers,
    );


  return (
    <tr className="audit-table-row">

      {/* ====================================================================
          Timestamp
          ================================================================== */}

      <td>
        <div className="audit-time">

          <Clock3
            size={14}
            aria-hidden="true"
          />

          <time
            dateTime={
              timestamp ||
              undefined
            }
            title={
              formatFullDate(
                timestamp,
              )
            }
          >
            {formatDate(
              timestamp,
            )}
          </time>

        </div>
      </td>


      {/* ====================================================================
          Action
          ================================================================== */}

      <td>
        <div className="audit-action">

          <span
            className="audit-action-icon"
            aria-hidden="true"
          >
            <ShieldCheck size={14} />
          </span>


          <span
            className="audit-action-label"
            title={event.action}
          >
            {actionLabel}
          </span>

        </div>
      </td>


      {/* ====================================================================
          Outcome
          ================================================================== */}

      <td>
        <OutcomePill
          outcome={event.outcome}
        />
      </td>


      {/* ====================================================================
          Actor
          ================================================================== */}

      <td>
        <AuditIdentity
          identity={actor}
          type="actor"
        />
      </td>


      {/* ====================================================================
          Target
          ================================================================== */}

      <td>
        <AuditIdentity
          identity={target}
          type="target"
        />
      </td>


      {/* ====================================================================
          Source IP
          ================================================================== */}

      <td>
        <span
          className="mono audit-source-ip"
          title={
            event.source_ip ??
            event.source ??
            undefined
          }
        >
          {sourceIp}
        </span>
      </td>


      {/* ====================================================================
          Request ID
          ================================================================== */}

      <td className="audit-request-id-column">

        {fullRequestId ? (

          <span
            className="mono audit-request-id"
            title={
              `Full Request ID: ${fullRequestId}`
            }
            aria-label={
              `Request ID: ${fullRequestId}`
            }
          >
            {formatCompactRequestId(
              fullRequestId,
            )}
          </span>

        ) : (

          <span
            className={[
              "mono",
              "audit-request-id",
              "audit-request-id-empty",
            ].join(" ")}
            aria-label="No request ID"
          >
            —
          </span>

        )}

      </td>


      {/* ====================================================================
          Details
          ================================================================== */}

      <td className="audit-details-column">

        {onSelect ? (

          <button
            type="button"
            className="audit-details-button"
            onClick={() =>
              onSelect(event)
            }
            title="View audit event details"
            aria-label={
              `View details for ${actionLabel} audit event`
            }
          >

            <Eye
              size={14}
              aria-hidden="true"
            />

            <span>
              View
            </span>

          </button>

        ) : (

          <span
            className="muted"
            aria-label="Details unavailable"
          >
            <Minus
              size={14}
              aria-hidden="true"
            />
          </span>

        )}

      </td>

    </tr>
  );
}


/* ============================================================================
 * Actor Resolution
 * ========================================================================== */

function resolveActor(
  event: AuditEvent,
  users: AuditIdentityUser[],
): AuditActor | null {

  const backendActor =
    event.actor &&
    typeof event.actor === "object"
      ? event.actor
      : null;


  const actorUserId =
    normalizeNullableText(
      event.actor_user_id ??
      backendActor?.user_id,
    );


  /*
   * No actor user ID means System.
   */
  if (!actorUserId) {
    return null;
  }


  /*
   * User Management directory is authoritative.
   */
  const user =
    findUserById(
      users,
      actorUserId,
    );


  if (user) {
    return {
      user_id:
        actorUserId,

      username:
        getUserDisplayName(
          user,
        ),

      role:
        getUserRole(
          user,
        ),
    };
  }


  /*
   * Backend identity is the fallback.
   */
  if (backendActor) {
    return {
      user_id:
        actorUserId,

      username:
        normalizeNullableText(
          backendActor.username,
        ) ??
        "Unknown User",

      role:
        normalizeNullableText(
          backendActor.role,
        ) ??
        "User",
    };
  }


  return {
    user_id:
      actorUserId,

    username:
      "Unknown User",

    role:
      "User",
  };
}


/* ============================================================================
 * Target Resolution
 * ========================================================================== */

function resolveTarget(
  event: AuditEvent,
  users: AuditIdentityUser[],
): AuditTarget | null {

  const backendTarget =
    event.target &&
    typeof event.target === "object"
      ? event.target
      : null;


  const targetUserId =
    normalizeNullableText(
      event.target_user_id ??
      backendTarget?.user_id,
    );


  /*
   * No target is a legitimate audit state.
   */
  if (!targetUserId) {
    return null;
  }


  /*
   * User Management directory is authoritative.
   */
  const user =
    findUserById(
      users,
      targetUserId,
    );


  if (user) {
    return {
      user_id:
        targetUserId,

      username:
        getUserDisplayName(
          user,
        ),

      role:
        getUserRole(
          user,
        ),
    };
  }


  /*
   * Backend identity is the fallback.
   */
  if (backendTarget) {
    return {
      user_id:
        targetUserId,

      username:
        normalizeNullableText(
          backendTarget.username,
        ) ??
        "Unknown User",

      role:
        normalizeNullableText(
          backendTarget.role,
        ) ??
        "User",
    };
  }


  return {
    user_id:
      targetUserId,

    username:
      "Unknown User",

    role:
      "User",
  };
}


/* ============================================================================
 * User Lookup
 * ========================================================================== */

function findUserById(
  users: AuditIdentityUser[],
  userId: string,
): AuditIdentityUser | null {

  const normalizedId =
    normalizeNullableText(
      userId,
    );


  if (!normalizedId) {
    return null;
  }


  return (
    users.find(
      (
        user,
      ) =>
        normalizeNullableText(
          user.user_id,
        ) ===
        normalizedId,
    )
    ??
    null
  );
}


/* ============================================================================
 * User Display Name
 * ========================================================================== */

function getUserDisplayName(
  user: AuditIdentityUser,
): string {

  const displayName =
    normalizeNullableText(
      user.display_name,
    );


  if (displayName) {
    return displayName;
  }


  const username =
    normalizeNullableText(
      user.username,
    );


  if (username) {
    return username;
  }


  return "Unknown User";
}


/* ============================================================================
 * User Role
 * ========================================================================== */

function getUserRole(
  user: AuditIdentityUser,
): string {

  const role =
    normalizeNullableText(
      user.role,
    );


  if (!role) {
    return "User";
  }


  return formatRole(
    role,
  );
}


/* ============================================================================
 * Identity Renderer
 * ========================================================================== */

interface AuditIdentityProps {
  identity:
    | AuditActor
    | AuditTarget
    | null;

  type:
    | "actor"
    | "target";
}


function AuditIdentity({
  identity,
  type,
}: AuditIdentityProps) {

  /*
   * System Actor
   */
  if (
    identity === null &&
    type === "actor"
  ) {
    return (
      <div
        className="audit-identity audit-identity-system"
        title="System-generated event"
      >

        <span
          className="audit-identity-icon"
          aria-hidden="true"
        >
          <ShieldCheck size={13} />
        </span>


        <div className="audit-identity-content">

          <span className="audit-identity-name">
            System
          </span>

          <span className="audit-identity-role">
            System
          </span>

        </div>

      </div>
    );
  }


  /*
   * No Target
   */
  if (identity === null) {
    return (
      <div
        className="audit-identity audit-identity-muted"
        title="No target user"
      >

        <span
          className="audit-identity-icon"
          aria-hidden="true"
        >
          <UserRound size={13} />
        </span>


        <div className="audit-identity-content">

          <span className="audit-identity-name">
            —
          </span>

          <span className="audit-identity-role">
            No target
          </span>

        </div>

      </div>
    );
  }


  const userId =
    normalizeNullableText(
      identity.user_id,
    );


  const identityName =
    normalizeNullableText(
      identity.username,
    ) ??
    "Unknown User";


  const identityRole =
    normalizeNullableText(
      identity.role,
    ) ??
    "User";


  return (
    <div
      className={[
        "audit-identity",

        type === "actor"
          ? "audit-identity-actor"
          : "audit-identity-target",

      ].join(" ")}
      title={
        userId
          ? `User ID: ${userId}`
          : undefined
      }
    >

      <span
        className="audit-identity-marker"
        aria-hidden="true"
      />


      <div className="audit-identity-content">

        <span
          className="audit-identity-name"
          title={identityName}
        >
          {identityName}
        </span>

        <span className="audit-identity-role">
          {formatRole(
            identityRole,
          )}
        </span>

      </div>

    </div>
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

  const normalized =
    normalizeOutcome(
      outcome,
    );


  const successful =
    normalized === "success";


  const failed =
    normalized === "failure";


  const denied =
    normalized === "denied";


  const label =
    formatOutcome(
      outcome,
    );


  let className =
    "audit-outcome-pill neutral";


  if (successful) {
    className =
      "audit-outcome-pill success";
  } else if (failed) {
    className =
      "audit-outcome-pill failure";
  } else if (denied) {
    className =
      "audit-outcome-pill denied";
  }


  return (
    <span
      className={className}
      aria-label={
        `Outcome: ${label}`
      }
    >

      {successful ? (

        <CheckCircle2
          size={12}
          aria-hidden="true"
        />

      ) : denied ? (

        <ShieldAlert
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
        {label}
      </span>

    </span>
  );
}


/* ============================================================================
 * Request ID Presentation
 * ========================================================================== */

function formatCompactRequestId(
  value: string,
): string {

  const normalized =
    value.trim();


  if (!normalized) {
    return "—";
  }


  /*
   * Short IDs remain untouched.
   */
  if (
    normalized.length <= 16
  ) {
    return normalized;
  }


  /*
   * Example:
   *
   * 4e03c359e5cb4cd9aba6be1766db8fcd
   *
   * becomes:
   *
   * 4e03c359…b8fcd
   */
  const prefix =
    normalized.slice(
      0,
      8,
    );


  const suffix =
    normalized.slice(
      -5,
    );


  return `${prefix}…${suffix}`;
}


/* ============================================================================
 * Event Key
 * ========================================================================== */

function buildEventKey(
  event: AuditEvent,
  index: number,
): string {

  const auditId =
    normalizeNullableText(
      event.audit_id,
    );


  if (auditId) {
    return auditId;
  }


  return [
    event.timestamp ??
      event.created_at ??
      "unknown-time",

    event.action ??
      "unknown-action",

    event.outcome ??
      "unknown-outcome",

    event.actor?.user_id ??
      event.actor_user_id ??
      "system",

    event.target?.user_id ??
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
 * Timestamp
 * ========================================================================== */

function normalizeTimestamp(
  value:
    | string
    | null
    | undefined,
): string {

  return (
    normalizeNullableText(
      value,
    )
    ??
    ""
  );
}


function formatDate(
  value:
    | string
    | null
    | undefined,
): string {

  if (
    !value ||
    !value.trim()
  ) {
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


  try {
    return new Intl.DateTimeFormat(
      "en-US",
      {
        month:
          "short",

        day:
          "2-digit",

        year:
          "numeric",

        hour:
          "2-digit",

        minute:
          "2-digit",

        second:
          "2-digit",
      },
    ).format(date);

  } catch {
    return "—";
  }
}


function formatFullDate(
  value:
    | string
    | null
    | undefined,
): string {

  if (
    !value ||
    !value.trim()
  ) {
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


  try {
    return new Intl.DateTimeFormat(
      "en-US",
      {
        dateStyle:
          "full",

        timeStyle:
          "long",
      },
    ).format(date);

  } catch {
    return "Unknown timestamp";
  }
}


/* ============================================================================
 * Action
 * ========================================================================== */

function formatAction(
  value: string,
): string {

  const normalized =
    typeof value === "string"
      ? value.trim()
      : "";


  if (!normalized) {
    return "Unknown Action";
  }


  const canonicalLabel =
    ACTION_LABELS[
      normalized
    ];


  if (canonicalLabel) {
    return canonicalLabel;
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
      (
        character,
      ) =>
        character.toUpperCase(),
    );
}


/* ============================================================================
 * Outcome
 * ========================================================================== */

function normalizeOutcome(
  value: string,
): string {

  return typeof value === "string"
    ? value.trim().toLowerCase()
    : "";
}


function formatOutcome(
  value: string,
): string {

  const normalized =
    typeof value === "string"
      ? value.trim()
      : "";


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
      (
        character,
      ) =>
        character.toUpperCase(),
    );
}


/* ============================================================================
 * Role
 * ========================================================================== */

function formatRole(
  value: string,
): string {

  const normalized =
    value
      .trim()
      .replace(
        /[-_]+/g,
        " ",
      )
      .replace(
        /\s+/g,
        " ",
      );


  if (!normalized) {
    return "User";
  }


  return normalized.replace(
    /\b\w/g,
    (
      character,
    ) =>
      character.toUpperCase(),
  );
}


/* ============================================================================
 * Nullable Text
 * ========================================================================== */

function normalizeNullableText(
  value:
    | string
    | null
    | undefined,
): string | null {

  if (
    typeof value !== "string"
  ) {
    return null;
  }


  const normalized =
    value.trim();


  return normalized
    ? normalized
    : null;
}


/* ============================================================================
 * Display Value
 * ========================================================================== */

function normalizeDisplayValue(
  value:
    | string
    | null
    | undefined,
): string {

  return (
    normalizeNullableText(
      value,
    )
    ??
    "—"
  );
}


/* ============================================================================
 * End of File
 * ============================================================================
 */