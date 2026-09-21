import {
  useCallback,
  useEffect,
  useState,
} from "react";

import {
  Activity,
  ArrowLeft,
  CheckCircle2,
  CircleAlert,
  Clock3,
  Copy,
  Database,
  Globe2,
  Info,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  Terminal,
  User,
  X,
} from "lucide-react";

import {
  createPortal,
} from "react-dom";

import {
  useNavigate,
  useParams,
} from "react-router-dom";

import { ApiError } from "../../../services/api";

import { api } from "../api";

import type {
  SecurityEvent,
} from "../types";

import "../Events.css";

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
    .replace(/\s+/g, " ")
    .trim()
    .replace(
      /\b\w/g,
      (character) =>
        character.toUpperCase(),
    );
}

function getSeverityClass(
  severity?: string | null,
): string {
  switch (
    severity?.toLowerCase()
  ) {
    case "critical":
      return "events-details-pill events-details-pill-critical";

    case "high":
      return "events-details-pill events-details-pill-high";

    case "medium":
      return "events-details-pill events-details-pill-medium";

    case "low":
      return "events-details-pill events-details-pill-low";

    case "info":
      return "events-details-pill events-details-pill-info";

    default:
      return "events-details-pill events-details-pill-default";
  }
}

function getOutcomeLabel(
  outcome?: string | null,
): string {
  if (!outcome) {
    return "Unknown";
  }

  switch (
    outcome.toLowerCase()
  ) {
    case "success":
      return "Successful";

    case "successful":
      return "Successful";

    case "succeeded":
      return "Successful";

    case "failure":
      return "Failure";

    case "failed":
      return "Failure";

    case "error":
      return "Error";

    case "denied":
      return "Denied";

    case "blocked":
      return "Blocked";

    default:
      return formatLabel(
        outcome,
      );
  }
}

function getApiErrorMessage(
  error: unknown,
): string {
  if (error instanceof ApiError) {
    return error.detail;
  }

  if (error instanceof Error) {
    return error.message;
  }

  return "Unable to load security event.";
}

/* ==========================================================================
 * Page
 * ========================================================================== */

export default function EventDetails() {
  const navigate = useNavigate();

  const { eventId } =
    useParams<{
      eventId: string;
    }>();

  const [event, setEvent] =
    useState<SecurityEvent | null>(
      null,
    );

  const [loading, setLoading] =
    useState(true);

  const [refreshing, setRefreshing] =
    useState(false);

  const [error, setError] =
    useState<string | null>(null);

  const [copied, setCopied] =
    useState(false);

  /* ==========================================================================
   * Load Event
   * ========================================================================== */

  const loadEvent =
    useCallback(
      async (
        showRefreshState = false,
      ) => {
        if (!eventId) {
          setEvent(null);
          setError(
            "Event ID is missing.",
          );
          setLoading(false);
          return;
        }

        if (showRefreshState) {
          setRefreshing(true);
        } else {
          setLoading(true);
        }

        setError(null);

        try {
          const response =
            await api.getEvent(
              eventId,
            );

          setEvent(response);
        } catch (requestError) {
          setEvent(null);

          setError(
            getApiErrorMessage(
              requestError,
            ),
          );
        } finally {
          setLoading(false);
          setRefreshing(false);
        }
      },
      [eventId],
    );

  /* ==========================================================================
   * Initial Load
   * ========================================================================== */

  useEffect(() => {
    void loadEvent();
  }, [loadEvent]);

  /* ==========================================================================
   * Escape Key
   * ========================================================================== */

  useEffect(() => {
    function handleKeyDown(
      keyboardEvent: KeyboardEvent,
    ): void {
      if (
        keyboardEvent.key ===
        "Escape"
      ) {
        navigate("/events");
      }
    }

    window.addEventListener(
      "keydown",
      handleKeyDown,
    );

    return () => {
      window.removeEventListener(
        "keydown",
        handleKeyDown,
      );
    };
  }, [navigate]);

  /* ==========================================================================
   * Copy Event ID
   * ========================================================================== */

  async function handleCopyEventId(): Promise<void> {
    if (!event?.event_id) {
      return;
    }

    try {
      await navigator.clipboard.writeText(
        event.event_id,
      );

      setCopied(true);

      window.setTimeout(
        () => {
          setCopied(false);
        },
        1600,
      );
    } catch {
      setCopied(false);
    }
  }

  /* ==========================================================================
   * Backdrop
   * ========================================================================== */

  function handleBackdropClick(
    mouseEvent: React.MouseEvent<HTMLDivElement>,
  ): void {
    if (
      mouseEvent.target ===
      mouseEvent.currentTarget
    ) {
      navigate("/events");
    }
  }

  /* ==========================================================================
   * Sidebar Content
   * ========================================================================== */

  const content = (
    <>
      <div
        className="event-details-backdrop"
        onMouseDown={
          handleBackdropClick
        }
        aria-hidden="true"
      />

      <aside
        className="event-details-sidebar"
        role="dialog"
        aria-modal="true"
        aria-label="Security event details"
      >
        {/* ==================================================================
         * Sidebar Header
         * ================================================================== */}

        <header className="event-details-sidebar-header">
          <div className="event-details-sidebar-heading">
            <div className="event-details-sidebar-eyebrow">
              <Shield
                size={14}
                aria-hidden="true"
              />

              <span>
                SECURITY EVENT
              </span>
            </div>

            <h1>
              Event Details
            </h1>

            <p>
              Detailed read-only information
              for the selected security event.
            </p>
          </div>

          <div className="event-details-sidebar-header-actions">
            <div
              className="event-details-header-icon"
              title="Security event"
            >
              <Shield
                size={18}
                aria-hidden="true"
              />
            </div>

            <button
              type="button"
              className="event-details-close-button"
              onClick={() =>
                navigate("/events")
              }
              aria-label="Close event details"
              title="Close"
            >
              <X
                size={20}
                aria-hidden="true"
              />
            </button>
          </div>
        </header>

        {/* ==================================================================
         * Sidebar Body
         * ================================================================== */}

        <div className="event-details-sidebar-body">
          {/* ================================================================
           * Loading
           * ================================================================ */}

          {loading && (
            <div className="event-details-sidebar-loading">
              <RefreshCw
                size={20}
                className="is-spinning"
                aria-hidden="true"
              />

              <span>
                Loading event details...
              </span>
            </div>
          )}

          {/* ================================================================
           * Error
           * ================================================================ */}

          {!loading &&
            error && (
              <section
                className="event-details-sidebar-error"
                role="alert"
              >
                <div className="event-details-sidebar-error-icon">
                  <ShieldAlert
                    size={19}
                    aria-hidden="true"
                  />
                </div>

                <div className="event-details-sidebar-error-content">
                  <strong>
                    Event unavailable
                  </strong>

                  <span>
                    {error}
                  </span>
                </div>

                <button
                  type="button"
                  className="event-details-retry-button"
                  onClick={() =>
                    void loadEvent(
                      true,
                    )
                  }
                  disabled={refreshing}
                >
                  <RefreshCw
                    size={14}
                    className={
                      refreshing
                        ? "is-spinning"
                        : undefined
                    }
                    aria-hidden="true"
                  />

                  <span>
                    Retry
                  </span>
                </button>
              </section>
            )}

          {/* ================================================================
           * Event Content
           * ================================================================ */}

          {!loading &&
            !error &&
            event && (
              <>
                {/* ----------------------------------------------------------
                 * Outcome Banner
                 * ---------------------------------------------------------- */}

                <section
                  className={`event-details-result-banner ${
                    event.outcome
                      ?.toLowerCase()
                      .includes("success")
                      ? "is-success"
                      : event.outcome
                            ?.toLowerCase()
                            .includes(
                              "fail",
                            )
                        ? "is-failure"
                        : "is-neutral"
                  }`}
                >
                  <div className="event-details-result-icon">
                    {event.outcome
                      ?.toLowerCase()
                      .includes(
                        "success",
                      ) ? (
                      <CheckCircle2
                        size={20}
                        aria-hidden="true"
                      />
                    ) : event.outcome
                        ?.toLowerCase()
                        .includes(
                          "fail",
                        ) ? (
                      <CircleAlert
                        size={20}
                        aria-hidden="true"
                      />
                    ) : (
                      <Info
                        size={20}
                        aria-hidden="true"
                      />
                    )}
                  </div>

                  <div className="event-details-result-content">
                    <strong>
                      {getOutcomeLabel(
                        event.outcome,
                      )}
                    </strong>

                    <span>
                      {event.outcome
                        ?.toLowerCase()
                        .includes(
                          "success",
                        )
                        ? "Event operation completed successfully."
                        : event.outcome
                              ?.toLowerCase()
                              .includes(
                                "fail",
                              )
                          ? "Event operation completed with a failure outcome."
                          : "Event was recorded with the reported outcome."}
                    </span>
                  </div>
                </section>

                {/* ----------------------------------------------------------
                 * Event Information
                 * ---------------------------------------------------------- */}

                <section className="event-details-card">
                  <SectionHeader
                    eyebrow="EVENT"
                    title="Event Information"
                    icon={
                      <Database
                        size={17}
                        aria-hidden="true"
                      />
                    }
                  />

                  <div className="event-details-information-grid">
                    <DetailCard
                      label="Event ID"
                      value={
                        event.event_id
                      }
                      mono
                      copyable
                      copied={copied}
                      onCopy={
                        handleCopyEventId
                      }
                    />

                    <DetailCard
                      label="Action"
                      value={
                        formatLabel(
                          event.action,
                        )
                      }
                    />

                    <DetailCard
                      label="Category"
                      value={
                        formatLabel(
                          event.category,
                        )
                      }
                    />

                    <DetailCard
                      label="Outcome"
                      value={
                        getOutcomeLabel(
                          event.outcome,
                        )
                      }
                    />

                    <DetailCard
                      label="Timestamp"
                      value={formatDate(
                        event.timestamp,
                      )}
                      icon={
                        <Clock3
                          size={14}
                          aria-hidden="true"
                        />
                      }
                    />

                    <DetailCard
                      label="Severity"
                      value={
                        formatLabel(
                          event.severity,
                        )
                      }
                      badge
                      severity={
                        event.severity
                      }
                    />
                  </div>
                </section>

                {/* ----------------------------------------------------------
                 * Source / User
                 * ---------------------------------------------------------- */}

                <section className="event-details-card">
                  <SectionHeader
                    eyebrow="IDENTITY"
                    title="Source & Identity"
                    icon={
                      <User
                        size={17}
                        aria-hidden="true"
                      />
                    }
                  />

                  <div className="event-details-information-grid">
                    <DetailCard
                      label="Source"
                      value={
                        event.source
                      }
                    />

                    <DetailCard
                      label="Source Type"
                      value={
                        formatLabel(
                          event.source_type,
                        )
                      }
                    />

                    <DetailCard
                      label="Hostname"
                      value={
                        event.hostname
                      }
                    />

                    <DetailCard
                      label="Username"
                      value={
                        event.username
                      }
                    />
                  </div>
                </section>

                {/* ----------------------------------------------------------
                 * Network
                 * ---------------------------------------------------------- */}

                <section className="event-details-card">
                  <SectionHeader
                    eyebrow="NETWORK"
                    title="Network Information"
                    icon={
                      <Globe2
                        size={17}
                        aria-hidden="true"
                      />
                    }
                  />

                  <div className="event-details-information-grid">
                    <DetailCard
                      label="Source IP"
                      value={
                        event.source_ip
                      }
                      mono
                    />

                    <DetailCard
                      label="Destination IP"
                      value={
                        event.destination_ip
                      }
                      mono
                    />

                    <DetailCard
                      label="Source Port"
                      value={
                        event.source_port
                      }
                      mono
                    />

                    <DetailCard
                      label="Destination Port"
                      value={
                        event.destination_port
                      }
                      mono
                    />

                    <DetailCard
                      label="Protocol"
                      value={
                        event.protocol
                      }
                    />
                  </div>
                </section>

                {/* ----------------------------------------------------------
                 * Process / Execution
                 * ---------------------------------------------------------- */}

                <section className="event-details-card">
                  <SectionHeader
                    eyebrow="EXECUTION"
                    title="Process & Command"
                    icon={
                      <Terminal
                        size={17}
                        aria-hidden="true"
                      />
                    }
                  />

                  <div className="event-details-information-grid">
                    <DetailCard
                      label="Process"
                      value={
                        event.process
                      }
                    />

                    <DetailCard
                      label="Stage"
                      value={
                        formatLabel(
                          event.stage,
                        )
                      }
                    />
                  </div>

                  <div className="event-details-full-field">
                    <span className="event-details-field-label">
                      Command
                    </span>

                    <pre className="event-details-inline-code">
                      {formatValue(
                        event.command,
                      )}
                    </pre>
                  </div>
                </section>

                {/* ----------------------------------------------------------
                 * Ingestion
                 * ---------------------------------------------------------- */}

                <section className="event-details-card">
                  <SectionHeader
                    eyebrow="INGESTION"
                    title="Event Processing"
                    icon={
                      <Server
                        size={17}
                        aria-hidden="true"
                      />
                    }
                  />

                  <div className="event-details-information-grid">
                    <DetailCard
                      label="Ingestion Timestamp"
                      value={formatDate(
                        event.ingestion_timestamp,
                      )}
                    />

                    <DetailCard
                      label="Source"
                      value={
                        event.source
                      }
                    />
                  </div>
                </section>

                {/* ----------------------------------------------------------
                 * Raw Event
                 * ---------------------------------------------------------- */}

                <section className="event-details-card">
                  <SectionHeader
                    eyebrow="RAW EVENT"
                    title="Original Payload"
                    icon={
                      <Activity
                        size={17}
                        aria-hidden="true"
                      />
                    }
                  />

                  <pre className="event-details-code-block">
                    {event.raw_event ||
                      "No raw event payload available."}
                  </pre>
                </section>

                {/* ----------------------------------------------------------
                 * Parsed Data
                 * ---------------------------------------------------------- */}

                <section className="event-details-card">
                  <SectionHeader
                    eyebrow="PARSED"
                    title="Parsed Data"
                    icon={
                      <Database
                        size={17}
                        aria-hidden="true"
                      />
                    }
                  />

                  <pre className="event-details-code-block">
                    {formatValue(
                      event.parsed_data,
                    )}
                  </pre>
                </section>

                {/* ----------------------------------------------------------
                 * Normalized Data
                 * ---------------------------------------------------------- */}

                <section className="event-details-card">
                  <SectionHeader
                    eyebrow="NORMALIZED"
                    title="Normalized Data"
                    icon={
                      <Shield
                        size={17}
                        aria-hidden="true"
                      />
                    }
                  />

                  <pre className="event-details-code-block">
                    {formatValue(
                      event.normalized_data,
                    )}
                  </pre>
                </section>

                {/* ----------------------------------------------------------
                 * Enrichment
                 * ---------------------------------------------------------- */}

                <section className="event-details-card">
                  <SectionHeader
                    eyebrow="ENRICHMENT"
                    title="Enrichment Data"
                    icon={
                      <Info
                        size={17}
                        aria-hidden="true"
                      />
                    }
                  />

                  <pre className="event-details-code-block">
                    {event.enrichment
                      ? formatValue(
                          event.enrichment,
                        )
                      : "No enrichment data available."}
                  </pre>
                </section>

                {/* ----------------------------------------------------------
                 * Metadata
                 * ---------------------------------------------------------- */}

                <section className="event-details-card">
                  <SectionHeader
                    eyebrow="METADATA"
                    title="Event Metadata"
                    icon={
                      <Database
                        size={17}
                        aria-hidden="true"
                      />
                    }
                  />

                  <pre className="event-details-code-block">
                    {formatValue(
                      event.metadata,
                    )}
                  </pre>
                </section>
              </>
            )}
        </div>

        {/* ==================================================================
         * Sidebar Footer
         * ================================================================== */}

        {!loading &&
          !error &&
          event && (
            <footer className="event-details-sidebar-footer">
              <button
                type="button"
                className="event-details-footer-button"
                onClick={() =>
                  navigate(
                    "/events",
                  )
                }
              >
                <ArrowLeft
                  size={14}
                  aria-hidden="true"
                />

                <span>
                  Back to Events
                </span>
              </button>

              <button
                type="button"
                className="event-details-footer-button"
                onClick={() =>
                  void loadEvent(
                    true,
                  )
                }
                disabled={refreshing}
              >
                <RefreshCw
                  size={14}
                  aria-hidden="true"
                  className={
                    refreshing
                      ? "is-spinning"
                      : undefined
                  }
                />

                <span>
                  {refreshing
                    ? "Refreshing..."
                    : "Refresh"}
                </span>
              </button>
            </footer>
          )}
      </aside>
    </>
  );

  return createPortal(
    content,
    document.body,
  );
}

/* ==========================================================================
 * Section Header
 * ========================================================================== */

function SectionHeader({
  eyebrow,
  title,
  icon,
}: {
  eyebrow: string;
  title: string;
  icon: ReactNode;
}) {
  return (
    <div className="event-details-section-header">
      <div className="event-details-section-heading">
        <span className="event-details-section-eyebrow">
          {eyebrow}
        </span>

        <h2>
          {title}
        </h2>
      </div>

      <div className="event-details-section-icon">
        {icon}
      </div>
    </div>
  );
}

/* ==========================================================================
 * Detail Card
 * ========================================================================== */

function DetailCard({
  label,
  value,
  mono = false,
  badge = false,
  severity,
  icon,
  copyable = false,
  copied = false,
  onCopy,
}: {
  label: string;
  value: unknown;
  mono?: boolean;
  badge?: boolean;
  severity?: string | null;
  icon?: ReactNode;
  copyable?: boolean;
  copied?: boolean;
  onCopy?: () => void;
}) {
  return (
    <div className="event-details-detail-card">
      <span className="event-details-field-label">
        {icon}

        {label}
      </span>

      <div className="event-details-detail-value-row">
        {badge ? (
          <span
            className={getSeverityClass(
              severity,
            )}
          >
            {formatValue(
              value,
            )}
          </span>
        ) : (
          <strong
            className={
              mono
                ? "event-details-detail-value mono"
                : "event-details-detail-value"
            }
            title={
              mono
                ? String(
                    value ??
                      "",
                  )
                : undefined
            }
          >
            {formatValue(
              value,
            )}
          </strong>
        )}

        {copyable &&
          onCopy && (
            <button
              type="button"
              className="event-details-copy-button"
              onClick={onCopy}
              title={
                copied
                  ? "Copied"
                  : "Copy event ID"
              }
              aria-label={
                copied
                  ? "Event ID copied"
                  : "Copy event ID"
              }
            >
              {copied ? (
                <CheckCircle2
                  size={14}
                  aria-hidden="true"
                />
              ) : (
                <Copy
                  size={14}
                  aria-hidden="true"
                />
              )}
            </button>
          )}
      </div>
    </div>
  );
}

/* ==========================================================================
 * ReactNode import helper
 * ========================================================================== */

import type {
  ReactNode,
} from "react";