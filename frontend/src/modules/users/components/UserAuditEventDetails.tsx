/**
 * ============================================================================
 * SentinelSIEM — Individual User Audit Event Details
 * ============================================================================
 *
 * Read-only inspection view for one selected Individual User Audit event.
 *
 * Navigation:
 *
 *   Users
 *      ↓
 *   User Details
 *      ↓
 *   Audit History
 *      ↓
 *   Audit Event Details
 *
 * Responsibilities
 * ----------------
 *
 *   - Present one selected audit event
 *   - Present human-readable target identity
 *   - Present action and outcome
 *   - Present timestamp and source IP
 *   - Present request/session/actor identifiers
 *   - Present sanitized metadata
 *   - Provide safe copy controls
 *
 * Security
 * --------
 *
 *   - Read-only
 *   - No API calls
 *   - No database access
 *   - No authorization decisions
 *   - No mutation
 *   - No credential processing
 *
 * ============================================================================
 */

import {
  AlertCircle,
  CheckCircle2,
  Clock3,
  Copy,
  FileText,
  Shield,
  UserRound,
  X,
} from "lucide-react";

import type { ReactNode } from "react";

import type {
  UserAuditEvent,
} from "../types";

import type {
  UserAuditTargetUser,
} from "./UserAuditTable";


/* ============================================================================
 * Constants
 * ========================================================================== */

const EMPTY_VALUE = "—";


/* ============================================================================
 * Props
 * ========================================================================== */

export interface UserAuditEventDetailsProps {
  /**
   * Selected audit event.
   */
  event: UserAuditEvent | null;

  /**
   * User Management directory.
   *
   * Used to resolve target_user_id into:
   *
   *   👤 Display Name
   *   role
   */
  targetUsers?: UserAuditTargetUser[];

  /**
   * Close callback.
   */
  onClose?: () => void;
}


/* ============================================================================
 * Component
 * ========================================================================== */

export default function UserAuditEventDetails({
  event,
  targetUsers = [],
  onClose,
}: UserAuditEventDetailsProps) {
  if (!event) {
    return null;
  }


  /* ==========================================================================
   * Derived Values
   * ======================================================================== */

  const outcome =
    getOutcomeState(
      event.outcome,
    );

  const actionLabel =
    formatAction(
      event.action,
    );

  const target =
    resolveTarget(
      event.target_user_id,
      targetUsers,
    );


  /* ==========================================================================
   * Render
   * ======================================================================== */

  return (
    <section
      className="user-audit-event-details"
      aria-labelledby="user-audit-event-details-title"
    >

      {/* ======================================================================
       * Header
       * ==================================================================== */}

      <header className="user-audit-details-header">

        <div className="user-audit-details-heading">

          <div
            className="user-audit-details-icon"
            aria-hidden="true"
          >
            <Shield size={18} />
          </div>

          <div>

            <span className="user-audit-details-eyebrow">
              AUDIT EVENT
            </span>

            <h3
              id="user-audit-event-details-title"
            >
              Event Details
            </h3>

            <p>
              Read-only details for the selected audit event.
            </p>

          </div>

        </div>


        {onClose && (
          <button
            type="button"
            className="user-audit-details-close"
            onClick={onClose}
            aria-label="Close audit event details"
            title="Close"
          >
            <X
              size={17}
              aria-hidden="true"
            />
          </button>
        )}

      </header>


      {/* ======================================================================
       * Event Summary
       * ==================================================================== */}

      <section
        className={
          `user-audit-event-summary ` +
          `user-audit-event-summary-${outcome.type}`
        }
        aria-label="Audit event summary"
      >

        <div
          className={
            `user-audit-event-summary-icon ` +
            `user-audit-event-summary-icon-${outcome.type}`
          }
          aria-hidden="true"
        >

          {outcome.type === "success" && (
            <CheckCircle2 size={20} />
          )}

          {outcome.type === "failure" && (
            <AlertCircle size={20} />
          )}

          {outcome.type === "denied" && (
            <Shield size={20} />
          )}

        </div>


        <div className="user-audit-event-summary-content">

          <span className="user-audit-event-summary-kicker">
            AUDIT OPERATION
          </span>

          <h4>
            {actionLabel}
          </h4>

          <p>
            {outcome.message}
          </p>

        </div>


        <div
          className={
            `user-audit-event-summary-status ` +
            `user-audit-event-summary-status-${outcome.type}`
          }
        >

          {outcome.type === "success" && (
            <CheckCircle2
              size={13}
              aria-hidden="true"
            />
          )}

          {outcome.type === "failure" && (
            <AlertCircle
              size={13}
              aria-hidden="true"
            />
          )}

          {outcome.type === "denied" && (
            <Shield
              size={13}
              aria-hidden="true"
            />
          )}

          <span>
            {outcome.label}
          </span>

        </div>

      </section>


      {/* ======================================================================
       * Event Information
       * ==================================================================== */}

      <AuditDetailsSection
        kicker="EVENT"
        title="Event Information"
        description="Core information recorded for this audit event."
        icon={
          <FileText
            size={16}
            aria-hidden="true"
          />
        }
      >

        <div className="user-audit-detail-grid">

          <Detail
            label="Action"
            value={actionLabel}
          />

          <Detail
            label="Outcome"
            value={outcome.label}
          />

          <Detail
            label="Timestamp"
            value={
              formatDate(
                event.timestamp,
              )
            }
            icon={
              <Clock3
                size={14}
                aria-hidden="true"
              />
            }
          />

          <Detail
            label="Source IP"
            value={
              event.source_ip?.trim() ||
              EMPTY_VALUE
            }
            mono
          />

        </div>

      </AuditDetailsSection>


      {/* ======================================================================
       * Target Context
       * ==================================================================== */}

      <AuditDetailsSection
        kicker="TARGET"
        title="Target Context"
        description="User affected by this audit event, when applicable."
        icon={
          <UserRound
            size={16}
            aria-hidden="true"
          />
        }
      >

        <div className="user-audit-detail-grid">

          <TargetDetail
            target={target}
          />

        </div>

      </AuditDetailsSection>


      {/* ======================================================================
       * Correlation Context
       * ==================================================================== */}

      <AuditDetailsSection
        kicker="CORRELATION"
        title="Request Context"
        description="Technical identifiers useful for event correlation and investigation."
        icon={
          <Shield
            size={16}
            aria-hidden="true"
          />
        }
      >

        <div className="user-audit-detail-grid">

          <CopyableDetail
            label="Request ID"
            value={
              event.request_id?.trim() ||
              EMPTY_VALUE
            }
          />

          <CopyableDetail
            label="Session ID"
            value={
              event.session_id?.trim() ||
              EMPTY_VALUE
            }
          />

        </div>

      </AuditDetailsSection>


      {/* ======================================================================
       * Actor Reference
       * ==================================================================== */}

      <AuditDetailsSection
        kicker="ACTOR"
        title="Actor Reference"
        description="Technical reference for the user that initiated the event."
        icon={
          <UserRound
            size={16}
            aria-hidden="true"
          />
        }
      >

        <div className="user-audit-detail-grid">

          <CopyableDetail
            label="Actor User ID"
            value={
              event.actor_user_id?.trim() ||
              EMPTY_VALUE
            }
          />

        </div>

      </AuditDetailsSection>


      {/* ======================================================================
       * Metadata
       * ==================================================================== */}

      <AuditDetailsSection
        kicker="CONTEXT"
        title="Event Metadata"
        description="Sanitized contextual metadata returned by the backend."
      >

        <div className="user-audit-metadata">

          <div className="user-audit-metadata-header">

            <span>
              Sanitized Event Metadata
            </span>

          </div>

          <pre
            aria-label="Audit event metadata"
          >
            {formatMetadata(
              event.metadata,
            )}
          </pre>

        </div>

      </AuditDetailsSection>


      {/* ======================================================================
       * Security Notice
       * ==================================================================== */}

      <section
        className="user-audit-security-notice"
        role="note"
      >

        <div
          className="user-audit-security-notice-icon"
          aria-hidden="true"
        >
          <Shield size={16} />
        </div>

        <div>

          <strong>
            Read-only security record
          </strong>

          <p>
            Audit records are displayed for investigation only.
            This interface does not intentionally display or process
            passwords, tokens, API keys, secrets, or other credential
            material.
          </p>

        </div>

      </section>


      {/* ======================================================================
       * Footer
       * ==================================================================== */}

      {onClose && (
        <footer className="user-audit-details-footer">

          <span className="user-audit-details-footer-status">

            <span
              className="user-audit-footer-dot"
              aria-hidden="true"
            />

            Read-only audit record

          </span>


          <button
            type="button"
            className="user-audit-details-close-button"
            onClick={onClose}
          >

            <X
              size={14}
              aria-hidden="true"
            />

            <span>
              Close
            </span>

          </button>

        </footer>
      )}

    </section>
  );
}


/* ============================================================================
 * Section
 * ========================================================================== */

function AuditDetailsSection({
  kicker,
  title,
  description,
  icon,
  children,
}: {
  kicker: string;
  title: string;
  description: string;
  icon?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="user-audit-details-section">

      <div className="user-audit-details-section-heading">

        <div className="user-audit-details-section-heading-main">

          {icon && (
            <div
              className="user-audit-details-section-icon"
              aria-hidden="true"
            >
              {icon}
            </div>
          )}

          <div>

            <span>
              {kicker}
            </span>

            <h4>
              {title}
            </h4>

            <p>
              {description}
            </p>

          </div>

        </div>

      </div>


      <div className="user-audit-details-section-content">
        {children}
      </div>

    </section>
  );
}


/* ============================================================================
 * Detail Card
 * ========================================================================== */

function Detail({
  label,
  value,
  icon,
  mono = false,
}: {
  label: string;
  value: string;
  icon?: ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="user-audit-detail-card">

      <div className="user-audit-detail-label">

        {icon}

        <span>
          {label}
        </span>

      </div>


      <strong
        className={
          mono
            ? "user-audit-detail-value mono"
            : "user-audit-detail-value"
        }
      >
        {value}
      </strong>

    </div>
  );
}


/* ============================================================================
 * Target Detail
 * ========================================================================== */

function TargetDetail({
  target,
}: {
  target: ResolvedTarget;
}) {
  if (!target.userId) {
    return (
      <div className="user-audit-detail-card">

        <div className="user-audit-detail-label">
          <UserRound size={14} />
          <span>Target</span>
        </div>

        <div className="user-audit-target-detail">

          <strong>
            No Target
          </strong>

          <span>
            No target user was recorded for this event.
          </span>

        </div>

      </div>
    );
  }


  return (
    <div className="user-audit-detail-card">

      <div className="user-audit-detail-label">
        <UserRound size={14} />
        <span>Target</span>
      </div>

      <div className="user-audit-target-detail">

        <strong
          title={
            target.userId
          }
        >
          👤 {target.displayName}
        </strong>

        <span>
          {target.role}
        </span>

        <span className="mono user-audit-target-id">
          {target.userId}
        </span>

      </div>

    </div>
  );
}


/* ============================================================================
 * Copyable Detail
 * ========================================================================== */

function CopyableDetail({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  const canCopy =
    value !== EMPTY_VALUE;


  const handleCopy =
    async () => {
      if (!canCopy) {
        return;
      }

      try {
        await navigator.clipboard.writeText(
          value,
        );
      } catch {
        /*
         * Clipboard access can be unavailable
         * in restricted browser contexts.
         */
      }
    };


  return (
    <div className="user-audit-detail-card">

      <div className="user-audit-detail-label">
        <span>
          {label}
        </span>
      </div>


      <div className="user-audit-copy-row">

        <strong className="user-audit-detail-value mono">
          {value}
        </strong>


        {canCopy && (
          <button
            type="button"
            className="user-audit-copy-button"
            onClick={handleCopy}
            aria-label={`Copy ${label}`}
            title={`Copy ${label}`}
          >
            <Copy
              size={13}
              aria-hidden="true"
            />
          </button>
        )}

      </div>

    </div>
  );
}


/* ============================================================================
 * Target Resolution
 * ========================================================================== */

interface ResolvedTarget {
  userId: string | null;
  displayName: string;
  role: string;
}


function resolveTarget(
  value: string | null,
  targetUsers: UserAuditTargetUser[],
): ResolvedTarget {
  const normalized =
    value?.trim();

  if (!normalized) {
    return {
      userId: null,
      displayName: EMPTY_VALUE,
      role: "NO TARGET",
    };
  }


  const targetUser =
    targetUsers.find(
      (user) =>
        String(
          user.user_id,
        )
          .trim()
          .toLowerCase() ===
        normalized.toLowerCase(),
    );


  if (!targetUser) {
    return {
      userId: normalized,
      displayName: truncate(
        normalized,
        18,
      ),
      role: "TARGET USER",
    };
  }


  const displayName =
    targetUser.name?.trim() ||
    targetUser.full_name?.trim() ||
    targetUser.username?.trim() ||
    "Unknown User";


  const role =
    targetUser.role?.trim() ||
    "User";


  return {
    userId: normalized,
    displayName,
    role,
  };
}


/* ============================================================================
 * Outcome
 * ========================================================================== */

function getOutcomeState(
  value: string | null | undefined,
): {
  type:
    | "success"
    | "failure"
    | "denied";

  label: string;

  message: string;
} {
  const normalized =
    String(
      value ?? "",
    )
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
      message:
        "Operation completed successfully.",
    };
  }


  if (
    normalized === "denied" ||
    normalized === "deny"
  ) {
    return {
      type: "denied",
      label: "Denied",
      message:
        "Operation was denied.",
    };
  }


  return {
    type: "failure",
    label:
      formatAction(
        value,
      ) || "Failure",
    message:
      "Operation did not complete successfully.",
  };
}


/* ============================================================================
 * Action Formatting
 * ========================================================================== */

function formatAction(
  value: string | null | undefined,
): string {
  if (
    value === null ||
    value === undefined
  ) {
    return EMPTY_VALUE;
  }


  const normalized =
    String(value)
      .trim()
      .replace(
        /([a-z])([A-Z])/g,
        "$1 $2",
      )
      .replace(
        /[._-]+/g,
        " ",
      )
      .replace(
        /\s+/g,
        " ",
      )
      .trim();


  if (!normalized) {
    return EMPTY_VALUE;
  }


  return normalized.replace(
    /\b\w/g,
    (character) =>
      character.toUpperCase(),
  );
}


/* ============================================================================
 * Date Formatting
 * ========================================================================== */

function formatDate(
  value:
    | string
    | null
    | undefined,
): string {
  if (!value) {
    return EMPTY_VALUE;
  }


  const date =
    new Date(value);


  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    return EMPTY_VALUE;
  }


  return new Intl.DateTimeFormat(
    undefined,
    {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "numeric",
      minute: "2-digit",
      second: "2-digit",
    },
  ).format(date);
}


/* ============================================================================
 * Metadata Formatting
 * ========================================================================== */

function formatMetadata(
  metadata:
    | Record<string, unknown>
    | null
    | undefined,
): string {
  if (
    !metadata ||
    typeof metadata !== "object"
  ) {
    return "{}";
  }


  try {
    return (
      JSON.stringify(
        metadata,
        null,
        2,
      ) ?? "{}"
    );
  } catch {
    return "Unable to display metadata.";
  }
}


/* ============================================================================
 * Truncate
 * ========================================================================== */

function truncate(
  value: string,
  maxLength: number,
): string {
  if (
    value.length <=
    maxLength
  ) {
    return value;
  }

  return `${value.slice(
    0,
    Math.max(
      1,
      maxLength - 1,
    ),
  )}…`;
}