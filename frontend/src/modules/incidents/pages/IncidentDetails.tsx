/**
 * ============================================================================
 * SentinelSIEM — Incident Details
 * ============================================================================
 *
 * Final read-only Incident Details drawer.
 *
 * Access:
 *
 *   ADMIN
 *   SECURITY_ANALYST
 *   SOC_ANALYST
 *   INVESTIGATOR
 *   VIEWER
 *       -> View Incident
 *
 * Management actions such as:
 *   - Edit Incident
 *   - Change Severity
 *   - Change Status
 *   - Assign / Reassign
 *
 * are owned by the parent Incident workflow.
 *
 * This component is intentionally READ-ONLY.
 *
 * No:
 *   - Delete
 *   - Archive
 *   - Direct status mutation
 *   - Direct assignment mutation
 *   - Priority
 *   - Ownership Group
 *
 * Assignee identity:
 *   - User Management is the source of truth.
 *   - The incident backend stores assigned_to as UUID.
 *   - If the backend detail response hydrates the assignee,
 *     display Name + Role.
 *   - Never invent identity from UUID.
 *
 * ============================================================================
 */

import {
  useCallback,
  useEffect,
  useState,
} from "react";

import "../Incidents.css";

import {
  Link,
  useNavigate,
  useParams,
} from "react-router-dom";

import { incidentsApi } from "../api";

import type {
  IncidentDetail,
  IncidentSeverity,
  IncidentStatus,
} from "../types";

/* ============================================================================
 * Helpers
 * ========================================================================== */

function formatLabel(
  value: string | null | undefined,
): string {
  if (!value) {
    return "—";
  }

  return value
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (character) =>
      character.toUpperCase(),
    );
}

/* ============================================================================
 * Status
 * ========================================================================== */

function formatStatus(
  status:
    | IncidentStatus
    | string
    | null
    | undefined,
): string {
  if (!status) {
    return "—";
  }

  const labels: Record<
    string,
    string
  > = {
    open: "Open",
    investigating: "Investigating",
    contained: "Contained",
    resolved: "Resolved",
    closed: "Closed",
  };

  return (
    labels[status] ??
    formatLabel(status)
  );
}

/* ============================================================================
 * Severity
 * ========================================================================== */

function formatSeverity(
  severity:
    | IncidentSeverity
    | string
    | null
    | undefined,
): string {
  if (!severity) {
    return "—";
  }

  return formatLabel(severity);
}

/* ============================================================================
 * Date / Time
 * ========================================================================== */

function formatDateTime(
  value:
    | string
    | null
    | undefined,
): string {
  if (!value) {
    return "—";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString();
}

/* ============================================================================
 * Actor
 * ========================================================================== */

function formatActor(
  value:
    | string
    | null
    | undefined,
): string {
  if (!value) {
    return "System";
  }

  return value;
}

/* ============================================================================
 * CSS Classes
 * ========================================================================== */

function getStatusClass(
  status:
    | string
    | null
    | undefined,
): string {
  if (!status) {
    return "status-unknown";
  }

  return `status-${status}`;
}

function getSeverityClass(
  severity:
    | string
    | null
    | undefined,
): string {
  if (!severity) {
    return "severity-unknown";
  }

  return `severity-${severity}`;
}

/* ============================================================================
 * Assignee Types
 * ========================================================================== */

interface HydratedAssignee {
  user_id?: string;

  display_name?: string | null;

  username?: string | null;

  roles?: unknown;

  is_active?: boolean;

  is_locked?: boolean;
}

/* ============================================================================
 * Assignee Helpers
 * ========================================================================== */

function getHydratedAssignee(
  incident: IncidentDetail,
): HydratedAssignee | null {
  const assignedTo =
    incident.assigned_to;

  if (
    !assignedTo ||
    typeof assignedTo !== "object"
  ) {
    return null;
  }

  return assignedTo as unknown as HydratedAssignee;
}

function getAssigneeName(
  incident: IncidentDetail,
): string {
  if (!incident.assigned_to) {
    return "Unassigned";
  }

  const hydrated =
    getHydratedAssignee(
      incident,
    );

  if (!hydrated) {
    return "Assigned";
  }

  const displayName =
    typeof hydrated.display_name ===
    "string"
      ? hydrated.display_name.trim()
      : "";

  const username =
    typeof hydrated.username ===
    "string"
      ? hydrated.username.trim()
      : "";

  return (
    displayName ||
    username ||
    "Assigned"
  );
}

function getAssigneeRole(
  incident: IncidentDetail,
): string {
  const hydrated =
    getHydratedAssignee(
      incident,
    );

  if (!hydrated) {
    return "";
  }

  if (
    !Array.isArray(
      hydrated.roles,
    )
  ) {
    return "";
  }

  const role =
    hydrated.roles.find(
      (candidate): candidate is string => {
        if (
          typeof candidate !==
          "string"
        ) {
          return false;
        }

        const normalized =
          candidate
            .trim()
            .toUpperCase();

        return (
          normalized.length > 0 &&
          normalized !== "VIEWER"
        );
      },
    );

  return role?.trim() ?? "";
}

/* ============================================================================
 * Assignee Presentation
 * ========================================================================== */

function AssigneeDisplay({
  incident,
}: {
  incident: IncidentDetail;
}) {
  if (!incident.assigned_to) {
    return (
      <div className="assignee unassigned">
        <span>
          Unassigned
        </span>
      </div>
    );
  }

  const name =
    getAssigneeName(
      incident,
    );

  const role =
    getAssigneeRole(
      incident,
    );

  return (
    <div className="assignee">
      <span>
        {name}
      </span>

      {role && (
        <small>
          {role}
        </small>
      )}
    </div>
  );
}

/* ============================================================================
 * Resource Empty State
 * ========================================================================== */

function ResourceEmptyState({
  children,
}: {
  children: string;
}) {
  return (
    <div className="empty-state">
      <p>{children}</p>
    </div>
  );
}

/* ============================================================================
 * Incident Details
 * ========================================================================== */

export default function IncidentDetails() {
  const {
    incidentId,
  } = useParams<{
    incidentId: string;
  }>();

  const navigate =
    useNavigate();

  /* ==========================================================================
   * State
   * ======================================================================== */

  const [
    incident,
    setIncident,
  ] =
    useState<IncidentDetail | null>(
      null,
    );

  const [
    loading,
    setLoading,
  ] =
    useState(true);

  const [
    error,
    setError,
  ] =
    useState<string | null>(
      null,
    );

  const [
    refreshing,
    setRefreshing,
  ] =
    useState(false);

  /* ==========================================================================
   * Close
   * ======================================================================== */

  const closeDrawer =
    useCallback(() => {
      navigate("/incidents");
    }, [navigate]);

  /* ==========================================================================
   * Escape
   * ======================================================================== */

  useEffect(() => {
    const handleKeyDown = (
      event: KeyboardEvent,
    ): void => {
      if (
        event.key ===
        "Escape"
      ) {
        closeDrawer();
      }
    };

    document.addEventListener(
      "keydown",
      handleKeyDown,
    );

    return () => {
      document.removeEventListener(
        "keydown",
        handleKeyDown,
      );
    };
  }, [closeDrawer]);

  /* ==========================================================================
   * Background Scroll Lock
   *
   * IMPORTANT:
   * Only body overflow is changed.
   * No background color is changed.
   * ======================================================================== */

  useEffect(() => {
    const originalOverflow =
      document.body.style.overflow;

    document.body.style.overflow =
      "hidden";

    return () => {
      document.body.style.overflow =
        originalOverflow;
    };
  }, []);

  /* ==========================================================================
   * Load Incident
   * ======================================================================== */

  const loadIncident =
    useCallback(
      async (
        currentIncidentId: string,
        isRefresh = false,
      ): Promise<void> => {
        if (
          !currentIncidentId.trim()
        ) {
          setIncident(null);
          setError(
            "Incident ID is missing.",
          );
          setLoading(false);

          return;
        }

        try {
          if (isRefresh) {
            setRefreshing(true);
          } else {
            setLoading(true);
          }

          setError(null);

          const result =
            await incidentsApi.getDetail(
              currentIncidentId,
            );

          setIncident(result);
        } catch (
          err: unknown
        ) {
          setIncident(null);

          setError(
            err instanceof Error
              ? err.message
              : "Failed to load incident.",
          );
        } finally {
          if (isRefresh) {
            setRefreshing(false);
          } else {
            setLoading(false);
          }
        }
      },
      [],
    );

  /* ==========================================================================
   * Initial Load / ID Change
   * ======================================================================== */

  useEffect(() => {
    if (
      typeof incidentId !==
        "string" ||
      !incidentId.trim()
    ) {
      setIncident(null);

      setError(
        "Incident ID is missing.",
      );

      setLoading(false);

      return;
    }

    let cancelled =
      false;

    const run =
      async (): Promise<void> => {
        try {
          setLoading(true);
          setError(null);

          const result =
            await incidentsApi.getDetail(
              incidentId,
            );

          if (cancelled) {
            return;
          }

          setIncident(result);
        } catch (
          err: unknown
        ) {
          if (cancelled) {
            return;
          }

          setIncident(null);

          setError(
            err instanceof Error
              ? err.message
              : "Failed to load incident.",
          );
        } finally {
          if (!cancelled) {
            setLoading(false);
          }
        }
      };

    void run();

    return () => {
      cancelled = true;
    };
  }, [incidentId]);

  /* ==========================================================================
   * Refresh
   * ======================================================================== */

  const refreshIncident =
    useCallback(
      async (): Promise<void> => {
        if (
          typeof incidentId !==
            "string" ||
          !incidentId.trim()
        ) {
          return;
        }

        await loadIncident(
          incidentId,
          true,
        );
      },
      [
        incidentId,
        loadIncident,
      ],
    );

  /* ==========================================================================
   * Render
   * ======================================================================== */

  return (
    <div
      className="incident-drawer-overlay"
      role="presentation"
      onMouseDown={(
        event,
      ) => {
        if (
          event.target ===
          event.currentTarget
        ) {
          closeDrawer();
        }
      }}
    >
      <aside
        className="incident-drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby="incident-drawer-title"
        onMouseDown={(
          event,
        ) =>
          event.stopPropagation()
        }
      >
        {/* ==================================================================
            Header
            ================================================================== */}

        <header className="incident-drawer-header">
          <div className="incident-drawer-header-main">
            <span className="incident-drawer-eyebrow">
              INCIDENT
            </span>

            <h2 id="incident-drawer-title">
              {incident?.incident_number ??
                "Incident Details"}
            </h2>

            {incident?.title && (
              <p>
                {incident.title}
              </p>
            )}
          </div>

          <button
            type="button"
            className="icon-button"
            aria-label="Close incident details"
            onClick={
              closeDrawer
            }
          >
            ×
          </button>
        </header>

        {/* ==================================================================
            Body
            ================================================================== */}

        <div className="incident-drawer-body">
          {/* ================================================================
              Loading
              ============================================================ */}

          {loading && (
            <ResourceEmptyState>
              Loading incident
              details...
            </ResourceEmptyState>
          )}

          {/* ================================================================
              Error
              ============================================================ */}

          {!loading &&
            error && (
              <div className="empty-state">
                <p>{error}</p>

                <button
                  type="button"
                  className="secondary-button"
                  disabled={
                    refreshing
                  }
                  onClick={() =>
                    void loadIncident(
                      incidentId ??
                        "",
                      true,
                    )
                  }
                >
                  {refreshing
                    ? "Retrying..."
                    : "Retry"}
                </button>
              </div>
            )}

          {/* ================================================================
              Content
              ============================================================ */}

          {!loading &&
            !error &&
            incident && (
              <div className="incident-drawer-content">
                {/* ==========================================================
                    Summary
                    ====================================================== */}

                <section className="incident-drawer-section incident-summary">
                  <div className="incident-summary-main">
                    <span className="incident-number">
                      {
                        incident.incident_number
                      }
                    </span>

                    <h3>
                      {incident.title}
                    </h3>

                    <p>
                      {incident.description ||
                        "No incident description provided."}
                    </p>
                  </div>

                  <div className="incident-hero-badges">
                    <span
                      className={`severity-badge ${getSeverityClass(
                        incident.severity,
                      )}`}
                    >
                      {formatSeverity(
                        incident.severity,
                      )}
                    </span>

                    <span
                      className={`status-badge ${getStatusClass(
                        incident.status,
                      )}`}
                    >
                      {formatStatus(
                        incident.status,
                      )}
                    </span>
                  </div>
                </section>

                {/* ==========================================================
                    Overview
                    ====================================================== */}

                <section className="incident-drawer-section">
                  <div className="section-heading">
                    <div>
                      <h3>
                        Overview
                      </h3>

                      <p>
                        Core incident
                        information
                      </p>
                    </div>
                  </div>

                  <div className="incident-overview-grid">
                    <div className="detail-field">
                      <span>
                        Incident ID
                      </span>

                      <code>
                        {
                          incident.incident_id
                        }
                      </code>
                    </div>

                    <div className="detail-field">
                      <span>
                        Incident Number
                      </span>

                      <strong>
                        {
                          incident.incident_number
                        }
                      </strong>
                    </div>

                    <div className="detail-field">
                      <span>
                        Severity
                      </span>

                      <strong>
                        {formatSeverity(
                          incident.severity,
                        )}
                      </strong>
                    </div>

                    <div className="detail-field">
                      <span>
                        Status
                      </span>

                      <strong>
                        {formatStatus(
                          incident.status,
                        )}
                      </strong>
                    </div>

                    <div className="detail-field">
                      <span>
                        Created By
                      </span>

                      <strong>
                        {formatActor(
                          incident.created_by,
                        )}
                      </strong>
                    </div>

                    <div className="detail-field">
                      <span>
                        Created At
                      </span>

                      <strong>
                        {formatDateTime(
                          incident.created_at,
                        )}
                      </strong>
                    </div>

                    <div className="detail-field">
                      <span>
                        Last Updated
                      </span>

                      <strong>
                        {formatDateTime(
                          incident.updated_at,
                        )}
                      </strong>
                    </div>

                    <div className="detail-field">
                      <span>
                        Resolved
                      </span>

                      <strong>
                        {formatDateTime(
                          incident.resolved_at,
                        )}
                      </strong>
                    </div>

                    <div className="detail-field">
                      <span>
                        Closed
                      </span>

                      <strong>
                        {formatDateTime(
                          incident.closed_at,
                        )}
                      </strong>
                    </div>
                  </div>
                </section>

                {/* ==========================================================
                    Assignment
                    ====================================================== */}

                <section className="incident-drawer-section">
                  <div className="section-heading">
                    <div>
                      <h3>
                        Assignment
                      </h3>

                      <p>
                        Current incident
                        assignee
                      </p>
                    </div>
                  </div>

                  <div className="assignment-card">
                    <div className="detail-field">
                      <span>
                        Assignee
                      </span>

                      <AssigneeDisplay
                        incident={
                          incident
                        }
                      />
                    </div>
                  </div>
                </section>

                {/* ==========================================================
                    Related Alerts
                    ====================================================== */}

                <section className="incident-drawer-section">
                  <div className="section-heading">
                    <div>
                      <h3>
                        Related Alerts
                      </h3>

                      <p>
                        Detection alerts
                        associated with
                        this incident
                      </p>
                    </div>

                    <span className="section-count">
                      {
                        incident.alert_ids
                          .length
                      }
                    </span>
                  </div>

                  {incident.related_alerts &&
                  incident
                    .related_alerts
                    .length >
                    0 ? (
                    <div className="soc-resource-list">
                      {incident.related_alerts.map(
                        (
                          alert,
                        ) => (
                          <div
                            key={
                              alert.alert_id
                            }
                            className="soc-resource-card"
                          >
                            <div>
                              <strong>
                                {
                                  alert.title
                                }
                              </strong>

                              <p>
                                {alert.description ||
                                  "No alert description."}
                              </p>

                              <div className="resource-meta">
                                <span>
                                  Severity:{" "}
                                  {formatLabel(
                                    alert.severity,
                                  )}
                                </span>

                                <span>
                                  Status:{" "}
                                  {formatLabel(
                                    alert.status,
                                  )}
                                </span>

                                {alert.rule_name && (
                                  <span>
                                    Rule:{" "}
                                    {
                                      alert.rule_name
                                    }
                                  </span>
                                )}

                                <span>
                                  Last Seen:{" "}
                                  {formatDateTime(
                                    alert.last_seen_at,
                                  )}
                                </span>
                              </div>
                            </div>

                            <Link
                              to={`/alerts/${encodeURIComponent(
                                alert.alert_id,
                              )}`}
                              className="secondary-button"
                            >
                              View Alert
                            </Link>
                          </div>
                        ),
                      )}
                    </div>
                  ) : incident.alert_ids.length >
                    0 ? (
                    <div className="soc-resource-list">
                      {incident.alert_ids.map(
                        (
                          alertId,
                        ) => (
                          <div
                            key={
                              alertId
                            }
                            className="soc-resource-card"
                          >
                            <div>
                              <strong>
                                Related Alert
                              </strong>

                              <p>
                                Alert details
                                are available
                                through the
                                alert workflow.
                              </p>

                              <code>
                                {alertId}
                              </code>
                            </div>

                            <Link
                              to={`/alerts/${encodeURIComponent(
                                alertId,
                              )}`}
                              className="secondary-button"
                            >
                              View Alert
                            </Link>
                          </div>
                        ),
                      )}
                    </div>
                  ) : (
                    <ResourceEmptyState>
                      No related
                      alerts.
                    </ResourceEmptyState>
                  )}
                </section>

                {/* ==========================================================
                    Investigation Notes
                    ====================================================== */}

                <section className="incident-drawer-section">
                  <div className="section-heading">
                    <div>
                      <h3>
                        Investigation
                      </h3>

                      <p>
                        Analyst notes and
                        investigation
                        context
                      </p>
                    </div>

                    <span className="section-count">
                      {incident.notes
                        ?.length ??
                        0}
                    </span>
                  </div>

                  {incident.notes &&
                  incident.notes
                    .length >
                    0 ? (
                    <div className="investigation-notes">
                      {incident.notes.map(
                        (
                          note,
                        ) => (
                          <article
                            key={
                              note.note_id
                            }
                            className="investigation-note"
                          >
                            <div className="note-header">
                              <strong>
                                {
                                  note.author
                                }
                              </strong>

                              <time>
                                {formatDateTime(
                                  note.created_at,
                                )}
                              </time>
                            </div>

                            <p>
                              {
                                note.content
                              }
                            </p>
                          </article>
                        ),
                      )}
                    </div>
                  ) : (
                    <ResourceEmptyState>
                      No analyst
                      notes have
                      been added
                      yet.
                    </ResourceEmptyState>
                  )}
                </section>

                {/* ==========================================================
                    Evidence
                    ====================================================== */}

                <section className="incident-drawer-section">
                  <div className="section-heading">
                    <div>
                      <h3>
                        Evidence
                      </h3>

                      <p>
                        Evidence
                        collected
                        during
                        investigation
                      </p>
                    </div>

                    <span className="section-count">
                      {
                        incident
                          .evidence_ids
                          .length
                      }
                    </span>
                  </div>

                  {incident.evidence &&
                  incident.evidence
                    .length >
                    0 ? (
                    <div className="soc-resource-list">
                      {incident.evidence.map(
                        (
                          evidence,
                        ) => (
                          <div
                            key={
                              evidence.evidence_id
                            }
                            className="soc-resource-card"
                          >
                            <div>
                              <strong>
                                {
                                  evidence.evidence_type
                                }
                              </strong>

                              <p>
                                {
                                  evidence.reference
                                }
                              </p>

                              <div className="resource-meta">
                                <span>
                                  Collected
                                  By:{" "}
                                  {
                                    evidence.collected_by
                                  }
                                </span>

                                <span>
                                  {formatDateTime(
                                    evidence.created_at,
                                  )}
                                </span>
                              </div>
                            </div>
                          </div>
                        ),
                      )}
                    </div>
                  ) : incident.evidence_ids.length >
                    0 ? (
                    <div className="soc-resource-list">
                      {incident.evidence_ids.map(
                        (
                          evidenceId,
                        ) => (
                          <div
                            key={
                              evidenceId
                            }
                            className="soc-resource-card"
                          >
                            <div>
                              <strong>
                                Evidence
                              </strong>

                              <code>
                                {
                                  evidenceId
                                }
                              </code>
                            </div>
                          </div>
                        ),
                      )}
                    </div>
                  ) : (
                    <ResourceEmptyState>
                      No evidence
                      attached.
                    </ResourceEmptyState>
                  )}
                </section>

                {/* ==========================================================
                    Related Events
                    ====================================================== */}

                <section className="incident-drawer-section">
                  <div className="section-heading">
                    <div>
                      <h3>
                        Related Events
                      </h3>

                      <p>
                        Security
                        events
                        contributing
                        to the
                        incident
                      </p>
                    </div>

                    <span className="section-count">
                      {
                        incident
                          .related_event_ids
                          .length
                      }
                    </span>
                  </div>

                  {incident.related_events &&
                  incident
                    .related_events
                    .length >
                    0 ? (
                    <div className="soc-resource-list">
                      {incident.related_events.map(
                        (
                          event,
                        ) => (
                          <div
                            key={
                              event.event_id
                            }
                            className="soc-resource-card"
                          >
                            <div>
                              <strong>
                                {formatLabel(
                                  event.action ??
                                    "Security Event",
                                )}
                              </strong>

                              <p>
                                {formatLabel(
                                  event.category ??
                                    "other",
                                )}{" "}
                                ·{" "}
                                {formatLabel(
                                  event.outcome ??
                                    "unknown",
                                )}
                              </p>

                              <div className="resource-meta">
                                <span>
                                  Severity:{" "}
                                  {formatLabel(
                                    event.severity ??
                                      "unknown",
                                  )}
                                </span>

                                {event.source_ip && (
                                  <span>
                                    Source IP:{" "}
                                    {
                                      event.source_ip
                                    }
                                  </span>
                                )}

                                <span>
                                  {formatDateTime(
                                    event.timestamp,
                                  )}
                                </span>
                              </div>
                            </div>
                          </div>
                        ),
                      )}
                    </div>
                  ) : (
                    <ResourceEmptyState>
                      {incident
                        .related_event_ids
                        .length >
                      0
                        ? `${incident.related_event_ids.length} related event(s) linked. Detailed event information is not currently available.`
                        : "No related events."}
                    </ResourceEmptyState>
                  )}
                </section>

                {/* ==========================================================
                    Related IOCs
                    ====================================================== */}

                <section className="incident-drawer-section">
                  <div className="section-heading">
                    <div>
                      <h3>
                        Threat
                        Intelligence
                      </h3>

                      <p>
                        Related
                        indicators
                        of
                        compromise
                      </p>
                    </div>

                    <span className="section-count">
                      {
                        incident
                          .related_ioc_ids
                          .length
                      }
                    </span>
                  </div>

                  {incident.related_iocs &&
                  incident
                    .related_iocs
                    .length >
                    0 ? (
                    <div className="soc-resource-list">
                      {incident.related_iocs.map(
                        (
                          ioc,
                        ) => (
                          <div
                            key={
                              ioc.ioc_id
                            }
                            className="soc-resource-card"
                          >
                            <div>
                              <strong>
                                {
                                  ioc.indicator
                                }
                              </strong>

                              <p>
                                {formatLabel(
                                  ioc.indicator_type,
                                )}
                              </p>

                              <div className="resource-meta">
                                <span>
                                  Confidence:{" "}
                                  {
                                    ioc.confidence ??
                                    "—"
                                  }
                                </span>

                                <span>
                                  Severity:{" "}
                                  {formatLabel(
                                    ioc.severity,
                                  )}
                                </span>

                                <span>
                                  Status:{" "}
                                  {formatLabel(
                                    ioc.status,
                                  )}
                                </span>
                              </div>
                            </div>
                          </div>
                        ),
                      )}
                    </div>
                  ) : (
                    <ResourceEmptyState>
                      {incident
                        .related_ioc_ids
                        .length >
                      0
                        ? `${incident.related_ioc_ids.length} IOC(s) linked. Detailed IOC information is not currently available.`
                        : "No related IOCs."}
                    </ResourceEmptyState>
                  )}
                </section>

                {/* ==========================================================
                    Affected Assets
                    ====================================================== */}

                <section className="incident-drawer-section">
                  <div className="section-heading">
                    <div>
                      <h3>
                        Affected
                        Assets
                      </h3>

                      <p>
                        Assets
                        associated
                        with the
                        incident
                      </p>
                    </div>

                    <span className="section-count">
                      {
                        incident
                          .asset_ids
                          .length
                      }
                    </span>
                  </div>

                  {incident.affected_assets &&
                  incident
                    .affected_assets
                    .length >
                    0 ? (
                    <div className="soc-resource-list">
                      {incident.affected_assets.map(
                        (
                          asset,
                        ) => (
                          <div
                            key={
                              asset.asset_id
                            }
                            className="soc-resource-card"
                          >
                            <div>
                              <strong>
                                {asset.name}
                              </strong>

                              <p>
                                {asset.hostname ||
                                  asset.asset_type}
                              </p>

                              <div className="resource-meta">
                                <span>
                                  Status:{" "}
                                  {formatLabel(
                                    asset.status,
                                  )}
                                </span>

                                <span>
                                  Criticality:{" "}
                                  {formatLabel(
                                    asset.criticality,
                                  )}
                                </span>

                                {asset.ip_address && (
                                  <span>
                                    IP:{" "}
                                    {
                                      asset.ip_address
                                    }
                                  </span>
                                )}
                              </div>
                            </div>
                          </div>
                        ),
                      )}
                    </div>
                  ) : (
                    <ResourceEmptyState>
                      {incident.asset_ids
                        .length >
                      0
                        ? `${incident.asset_ids.length} affected asset(s) linked. Detailed asset information is not currently available.`
                        : "No affected assets."}
                    </ResourceEmptyState>
                  )}
                </section>

                {/* ==========================================================
                    Lifecycle Timeline
                    ====================================================== */}

                <section className="incident-drawer-section">
                  <div className="section-heading">
                    <div>
                      <h3>
                        Lifecycle
                      </h3>

                      <p>
                        Incident status
                        history
                      </p>
                    </div>

                    <span className="section-count">
                      {incident
                        .timeline
                        ?.length ??
                        0}
                    </span>
                  </div>

                  {incident.timeline &&
                  incident.timeline
                    .length >
                    0 ? (
                    <div className="incident-timeline">
                      {incident.timeline.map(
                        (
                          entry,
                        ) => (
                          <div
                            key={
                              entry.entry_id
                            }
                            className="incident-timeline-item"
                          >
                            <div className="timeline-marker" />

                            <div className="timeline-content">
                              <div className="timeline-header">
                                <strong>
                                  {formatLabel(
                                    entry.event_type,
                                  )}
                                </strong>

                                <time>
                                  {formatDateTime(
                                    entry.occurred_at,
                                  )}
                                </time>
                              </div>

                              <p>
                                {
                                  entry.description
                                }
                              </p>

                              <small>
                                Actor:{" "}
                                {formatActor(
                                  entry.actor,
                                )}
                              </small>
                            </div>
                          </div>
                        ),
                      )}
                    </div>
                  ) : (
                    <ResourceEmptyState>
                      No lifecycle
                      events
                      recorded.
                    </ResourceEmptyState>
                  )}
                </section>

                {/* ==========================================================
                    Audit History
                    ====================================================== */}

                <section className="incident-drawer-section">
                  <div className="section-heading">
                    <div>
                      <h3>
                        Audit History
                      </h3>

                      <p>
                        Recorded
                        incident
                        actions
                      </p>
                    </div>

                    <span className="section-count">
                      {incident
                        .audit_history
                        ?.length ??
                        0}
                    </span>
                  </div>

                  {incident.audit_history &&
                  incident
                    .audit_history
                    .length >
                    0 ? (
                    <div className="audit-list">
                      {incident.audit_history.map(
                        (
                          audit,
                        ) => (
                          <div
                            key={
                              audit.audit_id
                            }
                            className="audit-item"
                          >
                            <div>
                              <strong>
                                {formatLabel(
                                  audit.action,
                                )}
                              </strong>

                              <p>
                                {audit.reason ||
                                  "No reason provided."}
                              </p>

                              {audit.field_name && (
                                <small>
                                  Field:{" "}
                                  {
                                    audit.field_name
                                  }
                                </small>
                              )}
                            </div>

                            <div className="audit-values">
                              {audit.from_value && (
                                <span>
                                  {
                                    audit.from_value
                                  }
                                </span>
                              )}

                              {audit.to_value && (
                                <span>
                                  {" "}
                                  →{" "}
                                  {
                                    audit.to_value
                                  }
                                </span>
                              )}

                              <small>
                                {formatActor(
                                  audit.actor,
                                )}{" "}
                                ·{" "}
                                {formatDateTime(
                                  audit.created_at,
                                )}
                              </small>
                            </div>
                          </div>
                        ),
                      )}
                    </div>
                  ) : (
                    <ResourceEmptyState>
                      No audit
                      history
                      available.
                    </ResourceEmptyState>
                  )}
                </section>
              </div>
            )}
        </div>

        {/* ==================================================================
            Footer
            ================================================================== */}

        <footer className="incident-drawer-footer">
          <Link
            to="/incidents"
            className="secondary-button"
            onClick={
              closeDrawer
            }
          >
            Back to Incidents
          </Link>

          {incident && (
            <button
              type="button"
              className="secondary-button"
              disabled={refreshing}
              onClick={() =>
                void refreshIncident()
              }
            >
              {refreshing
                ? "Refreshing..."
                : "Refresh"}
            </button>
          )}
        </footer>
      </aside>
    </div>
  );
}