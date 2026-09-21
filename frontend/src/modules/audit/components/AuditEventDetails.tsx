/**
 * ============================================================================
 * SentinelSIEM — Global Audit Event Details
 * ============================================================================
 *
 * Professional read-only detail panel for one Global Audit event.
 *
 * ============================================================================
 * Responsibilities
 * ============================================================================
 *
 * - Display one immutable audit event
 * - Display event identity
 * - Display action / category / outcome
 * - Display timestamp
 * - Display backend-provided actor identity
 * - Display backend-provided target identity
 * - Display request / session correlation
 * - Display source IP
 * - Display source information
 * - Display user agent when available
 * - Display sanitized metadata
 * - Allow safe copying of non-secret identifiers
 * - Allow closing the detail panel
 *
 * ============================================================================
 * Security Boundary
 * ============================================================================
 *
 * This component:
 *
 * - does NOT authenticate
 * - does NOT authorize
 * - does NOT fetch audit data
 * - does NOT mutate audit data
 * - does NOT modify the selected event
 * - does NOT invent identity information
 * - does NOT make backend security decisions
 *
 * Backend remains authoritative.
 *
 * ============================================================================
 * Identity Contract
 * ============================================================================
 *
 * Preferred backend representation:
 *
 *     actor.user_id
 *     actor.username
 *     actor.role
 *
 *     target.user_id
 *     target.username
 *     target.role
 *
 * Legacy compatibility:
 *
 *     actor_user_id
 *     target_user_id
 *
 * Legacy IDs are displayed only as User ID.
 * They are NEVER converted into usernames or roles.
 *
 * ============================================================================
 */

import {
  AlertCircle,
  CheckCircle2,
  Clipboard,
  Clock3,
  Copy,
  Globe2,
  ShieldAlert,
  ShieldCheck,
  UserRound,
  X,
} from "lucide-react";

import type {
  ReactNode,
} from "react";

import type {
  AuditActor,
  AuditEvent,
  AuditTarget,
} from "../types";


/* ============================================================================
 * Props
 * ========================================================================== */

export interface AuditEventDetailsProps {

  /**
   * Selected immutable audit event.
   */
  event:
    | AuditEvent
    | null;

  /**
   * Close callback.
   */
  onClose?: () => void;
}


/* ============================================================================
 * Component
 * ========================================================================== */

export default function AuditEventDetails({
  event,
  onClose,
}: AuditEventDetailsProps) {

  /* ==========================================================================
   * No Selection
   * ======================================================================== */

  if (!event) {
    return null;
  }


  /* ==========================================================================
   * Backend Values
   * ======================================================================== */

  const outcome =
    getOutcomeState(
      event.outcome,
    );


  const actionLabel =
    formatAction(
      event.action,
    );


  const categoryLabel =
    formatValue(
      event.category,
    );


  const timestamp =
    resolveTimestamp(
      event,
    );


  const timestampLabel =
    formatDateTime(
      timestamp,
    );


  const actor =
    resolveActor(
      event,
    );


  const target =
    resolveTarget(
      event,
    );


  const sourceIp =
    resolveSourceIp(
      event,
    );


  const metadata =
    resolveMetadata(
      event,
    );


  /* ==========================================================================
   * Render
   * ======================================================================== */

  return (
    <div
      className="audit-details-overlay"
      role="presentation"
    >

      {/* ======================================================================
          Backdrop
          ==================================================================== */}

      {onClose && (
        <button
          type="button"
          className="audit-details-backdrop"
          aria-label="Close audit event details"
          onClick={onClose}
          tabIndex={-1}
        />
      )}


      {/* ======================================================================
          Panel
          ==================================================================== */}

      <section
        className="audit-event-details"
        role="dialog"
        aria-modal="true"
        aria-labelledby="audit-event-details-title"
      >

        {/* ====================================================================
            Header
            ================================================================== */}

        <header className="panel-header">

          <div>

            <span className="audit-section-kicker">
              AUDIT EVENT
            </span>


            <h3 id="audit-event-details-title">
              Event Details
            </h3>


            <p>
              Detailed read-only information for
              the selected security audit event.
            </p>

          </div>


          <div className="audit-event-header-actions">

            <ShieldCheck
              size={18}
              aria-hidden="true"
            />


            {onClose && (
              <button
                type="button"
                className="icon-button"
                onClick={onClose}
                title="Close event details"
                aria-label="Close event details"
              >

                <X
                  size={17}
                  aria-hidden="true"
                />

              </button>
            )}

          </div>

        </header>


        {/* ====================================================================
            Outcome Banner
            ================================================================== */}

        <OutcomeBanner
          outcome={
            outcome
          }
        />


        {/* ====================================================================
            Event Information
            ================================================================== */}

        <section
          className="user-details-section audit-details-section"
          aria-labelledby="audit-event-information-title"
        >

          <SectionHeading
            id="audit-event-information-title"
            kicker="EVENT"
            title="Event Information"
            icon={
              <ShieldCheck
                size={16}
                aria-hidden="true"
              />
            }
          />


          <div className="user-details-grid">

            <CopyableDetail
              label="Audit ID"
              value={
                normalizeDisplayValue(
                  event.audit_id,
                )
              }
            />


            <Detail
              label="Action"
              value={
                actionLabel
              }
              mono={false}
            />


            <Detail
              label="Category"
              value={
                categoryLabel
              }
              mono={false}
            />


            <Detail
              label="Outcome"
              value={
                outcome.label
              }
              mono={false}
            />


            <Detail
              label="Timestamp"
              value={
                timestampLabel
              }
              icon={
                <Clock3
                  size={14}
                  aria-hidden="true"
                />
              }
              mono={false}
            />

          </div>

        </section>


        {/* ====================================================================
            Actor Context
            ================================================================== */}

        <section
          className="user-details-section audit-details-section"
          aria-labelledby="audit-actor-context-title"
        >

          <SectionHeading
            id="audit-actor-context-title"
            kicker="ACTOR"
            title="Actor Identity"
            icon={
              <UserRound
                size={16}
                aria-hidden="true"
              />
            }
          />


          <IdentityDetail
            identity={
              actor
            }
            type="actor"
            fallbackUserId={
              normalizeNullableText(
                event.actor_user_id,
              )
            }
          />

        </section>


        {/* ====================================================================
            Target Context
            ================================================================== */}

        <section
          className="user-details-section audit-details-section"
          aria-labelledby="audit-target-context-title"
        >

          <SectionHeading
            id="audit-target-context-title"
            kicker="TARGET"
            title="Target Identity"
            icon={
              <UserRound
                size={16}
                aria-hidden="true"
              />
            }
          />


          <IdentityDetail
            identity={
              target
            }
            type="target"
            fallbackUserId={
              normalizeNullableText(
                event.target_user_id,
              )
            }
          />

        </section>


        {/* ====================================================================
            Request Context
            ================================================================== */}

        <section
          className="user-details-section audit-details-section"
          aria-labelledby="audit-request-context-title"
        >

          <SectionHeading
            id="audit-request-context-title"
            kicker="CORRELATION"
            title="Request Context"
            icon={
              <Globe2
                size={16}
                aria-hidden="true"
              />
            }
          />


          <div className="user-details-grid">

            <CopyableDetail
              label="Request ID"
              value={
                normalizeDisplayValue(
                  event.request_id,
                )
              }
            />


            <CopyableDetail
              label="Session ID"
              value={
                normalizeDisplayValue(
                  event.session_id,
                )
              }
            />


            <CopyableDetail
              label="Source IP"
              value={
                sourceIp
              }
              mono={false}
            />


            <Detail
              label="Source"
              value={
                normalizeDisplayValue(
                  event.source,
                )
              }
              mono={false}
            />


            <Detail
              label="User Agent"
              value={
                normalizeDisplayValue(
                  event.user_agent,
                )
              }
              mono={false}
            />

          </div>

        </section>


        {/* ====================================================================
            Metadata
            ================================================================== */}

        <section
          className="user-details-section audit-details-section"
          aria-labelledby="audit-metadata-title"
        >

          <SectionHeading
            id="audit-metadata-title"
            kicker="CONTEXT"
            title="Event Metadata"
            icon={
              <Clipboard
                size={16}
                aria-hidden="true"
              />
            }
          />


          <div className="form-field">

            <div className="audit-metadata-header">

              <label htmlFor="audit-event-metadata">
                Sanitized Event Metadata
              </label>


              <span className="audit-metadata-badge">
                READ ONLY
              </span>

            </div>


            <pre
              id="audit-event-metadata"
              className="audit-metadata"
              aria-label="Sanitized audit event metadata"
            >
              {formatMetadata(
                metadata,
              )}
            </pre>

          </div>

        </section>


        {/* ====================================================================
            Security Notice
            ================================================================== */}

        <div
          className="notice audit-security-notice"
          role="note"
        >

          <ShieldCheck
            size={16}
            aria-hidden="true"
          />


          <span>
            Audit records are immutable and
            read-only. Metadata shown here is
            expected to be sanitized by the
            backend and must not contain
            passwords, tokens, API keys,
            secrets, private keys, authorization
            credentials, cookies, or other
            credential material.
          </span>

        </div>


        {/* ====================================================================
            Footer
            ================================================================== */}

        {onClose && (
          <footer className="form-actions audit-details-footer">

            <button
              type="button"
              className="secondary-button"
              onClick={onClose}
            >

              <X
                size={14}
                aria-hidden="true"
              />

              Close Details

            </button>

          </footer>
        )}

      </section>

    </div>
  );
}


/* ============================================================================
 * Outcome Banner
 * ========================================================================== */

interface OutcomeBannerProps {
  outcome:
    AuditOutcomeState;
}


function OutcomeBanner({
  outcome,
}: OutcomeBannerProps) {

  const className =
    outcome.status === "success"
      ? "notice healthy audit-outcome-banner"
      : outcome.status === "failure"
        ? "notice warning audit-outcome-banner"
        : "notice audit-outcome-banner";


  return (
    <div
      className={
        className
      }
      role="status"
    >

      {outcome.status === "success" ? (

        <CheckCircle2
          size={17}
          aria-hidden="true"
        />

      ) : outcome.status === "failure" ? (

        <AlertCircle
          size={17}
          aria-hidden="true"
        />

      ) : (

        <ShieldAlert
          size={17}
          aria-hidden="true"
        />

      )}


      <div>

        <strong>
          {outcome.label}
        </strong>


        <span>
          Audit operation completed with
          this outcome.
        </span>

      </div>

    </div>
  );
}


/* ============================================================================
 * Section Heading
 * ========================================================================== */

interface SectionHeadingProps {

  id:
    string;

  kicker:
    string;

  title:
    string;

  icon:
    ReactNode;
}


function SectionHeading({
  id,
  kicker,
  title,
  icon,
}: SectionHeadingProps) {

  return (
    <div
      className="audit-details-section-heading"
    >

      <div>

        <span className="audit-section-kicker">
          {kicker}
        </span>


        <h4 id={id}>
          {title}
        </h4>

      </div>


      <span
        className="audit-details-section-icon"
        aria-hidden="true"
      >
        {icon}
      </span>

    </div>
  );
}


/* ============================================================================
 * Basic Detail
 * ========================================================================== */

interface DetailProps {

  label:
    string;

  value:
    string;

  icon?:
    ReactNode;

  mono?:
    boolean;
}


function Detail({
  label,
  value,
  icon,
  mono = false,
}: DetailProps) {

  return (
    <div className="user-detail">

      <div className="user-detail-label">

        {icon}


        <span>
          {label}
        </span>

      </div>


      <strong
        className={
          mono
            ? "user-detail-value mono"
            : "user-detail-value"
        }
        title={value}
      >
        {value}
      </strong>

    </div>
  );
}


/* ============================================================================
 * Copyable Detail
 * ========================================================================== */

interface CopyableDetailProps {

  label:
    string;

  value:
    string;

  mono?:
    boolean;
}


function CopyableDetail({
  label,
  value,
  mono = true,
}: CopyableDetailProps) {

  const canCopy =
    value !== "—" &&
    value.trim().length > 0;


  return (
    <div className="user-detail">

      <div className="user-detail-label">

        <span>
          {label}
        </span>

      </div>


      <div className="user-detail-copy-row">

        <strong
          className={
            mono
              ? "user-detail-value mono"
              : "user-detail-value"
          }
          title={value}
        >
          {value}
        </strong>


        {canCopy && (
          <CopyButton
            value={
              value
            }
            label={
              label
            }
          />
        )}

      </div>

    </div>
  );
}


/* ============================================================================
 * Identity Detail
 * ========================================================================== */

interface IdentityDetailProps {

  identity:
    | AuditActor
    | AuditTarget
    | null;

  type:
    | "actor"
    | "target";

  fallbackUserId:
    | string
    | null;
}


function IdentityDetail({
  identity,
  type,
  fallbackUserId,
}: IdentityDetailProps) {

  /* ==========================================================================
   * System Actor
   *
   * Backend actor object is absent and there is no actor_user_id.
   * This is the canonical system-event representation.
   * ======================================================================== */

  if (
    identity === null &&
    type === "actor" &&
    !fallbackUserId
  ) {

    return (
      <div className="user-details-grid">

        <Detail
          label="Username"
          value="System"
          mono={false}
        />


        <Detail
          label="Role"
          value="System"
          mono={false}
        />


        <CopyableDetail
          label="User ID"
          value="—"
        />

      </div>
    );
  }


  /* ==========================================================================
   * Legacy Actor ID
   *
   * Only display the backend-provided ID.
   * Never derive username or role from the UUID.
   * ======================================================================== */

  if (
    identity === null &&
    type === "actor" &&
    fallbackUserId
  ) {

    return (
      <div className="user-details-grid">

        <Detail
          label="Username"
          value="—"
          mono={false}
        />


        <Detail
          label="Role"
          value="—"
          mono={false}
        />


        <CopyableDetail
          label="User ID"
          value={
            fallbackUserId
          }
        />

      </div>
    );
  }


  /* ==========================================================================
   * Missing Target
   * ======================================================================== */

  if (
    identity === null &&
    type === "target"
  ) {

    return (
      <div className="user-details-grid">

        <Detail
          label="Username"
          value="—"
          mono={false}
        />


        <Detail
          label="Role"
          value="—"
          mono={false}
        />


        <CopyableDetail
          label="User ID"
          value={
            fallbackUserId ??
            "—"
          }
        />

      </div>
    );
  }


  /* ==========================================================================
   * Backend Identity Object
   * ======================================================================== */

  if (!identity) {
    return null;
  }


  const userId =
    normalizeNullableText(
      identity.user_id,
    );


  const username =
    normalizeNullableText(
      identity.username,
    );


  const role =
    normalizeNullableText(
      identity.role,
    );


  /* ==========================================================================
   * Render Backend Values
   * ======================================================================== */

  return (
    <div className="user-details-grid">

      <Detail
        label="Username"
        value={
          username ??
          "—"
        }
        mono={false}
      />


      <Detail
        label="Role"
        value={
          role
            ? formatRole(role)
            : "—"
        }
        mono={false}
      />


      <CopyableDetail
        label="User ID"
        value={
          userId ??
          "—"
        }
      />

    </div>
  );
}


/* ============================================================================
 * Copy Button
 * ========================================================================== */

interface CopyButtonProps {

  value:
    string;

  label:
    string;
}


function CopyButton({
  value,
  label,
}: CopyButtonProps) {

  async function handleCopy() {

    if (
      typeof navigator === "undefined" ||
      !navigator.clipboard
    ) {
      return;
    }


    try {

      await navigator.clipboard.writeText(
        value,
      );

    } catch {

      /*
       * Clipboard permission may be unavailable.
       *
       * No copied value is logged.
       */

    }
  }


  return (
    <button
      type="button"
      className="icon-button audit-copy-button"
      onClick={handleCopy}
      title={
        `Copy ${label}`
      }
      aria-label={
        `Copy ${label}`
      }
    >

      <Copy
        size={13}
        aria-hidden="true"
      />

    </button>
  );
}


/* ============================================================================
 * Outcome State
 * ========================================================================== */

type AuditOutcomeStatus =
  | "success"
  | "failure"
  | "neutral";


interface AuditOutcomeState {

  status:
    AuditOutcomeStatus;

  label:
    string;
}


function getOutcomeState(
  value:
    string,
): AuditOutcomeState {

  const normalized =
    normalizeText(
      value,
    ).toLowerCase();


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


  if (
    normalized === "denied"
  ) {

    return {
      status: "neutral",
      label: "Denied",
    };
  }


  return {
    status: "neutral",
    label: formatValue(
      value,
    ),
  };
}


/* ============================================================================
 * Resolve Actor
 * ========================================================================== */

function resolveActor(
  event:
    AuditEvent,
): AuditActor | null {

  if (
    event.actor &&
    typeof event.actor === "object"
  ) {
    return event.actor;
  }


  /*
   * Do not construct an actor object from actor_user_id.
   *
   * The legacy ID is handled separately by IdentityDetail().
   */

  return null;
}


/* ============================================================================
 * Resolve Target
 * ========================================================================== */

function resolveTarget(
  event:
    AuditEvent,
): AuditTarget | null {

  if (
    event.target &&
    typeof event.target === "object"
  ) {
    return event.target;
  }


  /*
   * Do not construct a target object from target_user_id.
   *
   * The legacy ID is handled separately by IdentityDetail().
   */

  return null;
}


/* ============================================================================
 * Resolve Source IP
 * ========================================================================== */

function resolveSourceIp(
  event:
    AuditEvent,
): string {

  return (
    normalizeNullableText(
      event.source_ip,
    ) ??
    "—"
  );
}


/* ============================================================================
 * Resolve Timestamp
 * ========================================================================== */

function resolveTimestamp(
  event:
    AuditEvent,
): string {

  return (
    normalizeNullableText(
      event.timestamp,
    ) ??
    normalizeNullableText(
      event.created_at,
    ) ??
    ""
  );
}


/* ============================================================================
 * Resolve Metadata
 * ========================================================================== */

function resolveMetadata(
  event:
    AuditEvent,
): Record<
  string,
  unknown
> {

  if (
    event.metadata &&
    typeof event.metadata === "object" &&
    !Array.isArray(event.metadata)
  ) {
    return event.metadata;
  }


  if (
    event.metadata_json &&
    typeof event.metadata_json === "object" &&
    !Array.isArray(event.metadata_json)
  ) {
    return event.metadata_json;
  }


  return {};
}


/* ============================================================================
 * Action Formatting
 * ========================================================================== */

function formatAction(
  value:
    string,
): string {

  const normalized =
    normalizeText(
      value,
    );


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
      (
        character,
      ) =>
        character.toUpperCase(),
    );
}


/* ============================================================================
 * Generic Value Formatting
 * ========================================================================== */

function formatValue(
  value:
    | string
    | null
    | undefined,
): string {

  const normalized =
    normalizeText(
      value,
    );


  if (!normalized) {
    return "—";
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
 * Role Formatting
 * ========================================================================== */

function formatRole(
  value:
    string,
): string {

  const normalized =
    normalizeText(
      value,
    );


  if (!normalized) {
    return "—";
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
 * Text Normalization
 * ========================================================================== */

function normalizeText(
  value:
    | string
    | null
    | undefined,
): string {

  if (
    typeof value !== "string"
  ) {
    return "";
  }


  return value.trim();
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

  const normalized =
    normalizeText(
      value,
    );


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
    ) ??
    "—"
  );
}


/* ============================================================================
 * Date Formatting
 * ========================================================================== */

function formatDateTime(
  value:
    | string
    | null
    | undefined,
): string {

  const normalized =
    normalizeText(
      value,
    );


  if (!normalized) {
    return "Unknown timestamp";
  }


  const date =
    new Date(
      normalized,
    );


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
          "medium",

        timeStyle:
          "medium",
      },
    ).format(
      date,
    );

  } catch {

    return "Unknown timestamp";
  }
}


/* ============================================================================
 * Metadata Formatting
 * ========================================================================== */

function formatMetadata(
  metadata:
    | Record<
        string,
        unknown
      >
    | null
    | undefined,
): string {

  if (
    !metadata ||
    typeof metadata !== "object" ||
    Array.isArray(metadata)
  ) {
    return "{}";
  }


  if (
    Object.keys(
      metadata,
    ).length === 0
  ) {
    return "{}";
  }


  try {

    return (
      JSON.stringify(
        metadata,
        null,
        2,
      ) ??
      "{}"
    );

  } catch {

    return "Unable to display metadata.";
  }
}


/* ============================================================================
 * End of File
 * ============================================================================
 */