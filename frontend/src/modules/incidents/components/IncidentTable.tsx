/**
 * ============================================================================
 * SentinelSIEM — Incident Table
 * ============================================================================
 *
 * Presentation-only Incident table.
 *
 * Columns:
 *   Incident
 *   Severity
 *   Status
 *   Related Alerts
 *   Assignee
 *   Created
 *   Actions
 *
 * Assignee identity:
 *   User Management is the source of truth.
 *
 *   Incident backend stores:
 *     assigned_to = UUID
 *
 *   This component receives the User Management
 *   directory from the parent and resolves:
 *
 *     UUID -> Name + Role
 *
 * Display:
 *
 *   John Doe
 *   SECURITY_ANALYST
 *
 * VIEWER:
 *   View Incident only.
 *
 * Manage roles:
 *   ADMIN
 *   SECURITY_ANALYST
 *   SOC_ANALYST
 *   INVESTIGATOR
 *
 *   -> View Incident
 *   -> Edit Incident
 *
 * No Delete.
 * No Archive.
 * No Priority.
 * No Ownership Group.
 * ============================================================================
 */

import {
  useEffect,
  useRef,
  useState,
} from "react";

import type { Incident, IncidentAssignee } from "../types";

/* ============================================================================
 * Props
 * ========================================================================== */

export interface IncidentTableProps {
  incidents: Incident[];

  canManage: boolean;

  /**
   * User Management directory.
   *
   * The parent page owns loading and validation.
   * This component only resolves UUID -> identity.
   */
  assignees: IncidentAssignee[];

  onView: (incident: Incident) => void;

  onEdit: (incident: Incident) => void;

  onRelatedAlerts: (incident: Incident) => void;
}

/* ============================================================================
 * Helpers
 * ========================================================================== */

function formatStatus(
  status: Incident["status"],
): string {
  const labels: Record<
    Incident["status"],
    string
  > = {
    open: "Open",
    investigating: "Investigating",
    contained: "Contained",
    resolved: "Resolved",
    closed: "Closed",
  };

  return labels[status] ?? status;
}

function formatSeverity(
  severity: Incident["severity"],
): string {
  const labels: Record<
    Incident["severity"],
    string
  > = {
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
    informational: "Informational",
  };

  return labels[severity] ?? severity;
}

function formatDate(
  value: string | null | undefined,
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
 * Assignee Resolution
 * ========================================================================== */

function findAssignee(
  incident: Incident,
  assignees: IncidentAssignee[],
): IncidentAssignee | null {
  const assignedTo =
    incident.assigned_to;

  if (
    !assignedTo ||
    typeof assignedTo !== "string"
  ) {
    return null;
  }

  const normalizedId =
    assignedTo.trim();

  if (!normalizedId) {
    return null;
  }

  return (
    assignees.find(
      (user) =>
        user.user_id ===
        normalizedId,
    ) ?? null
  );
}

function getAssigneeName(
  incident: Incident,
  assignees: IncidentAssignee[],
): string {
  if (!incident.assigned_to) {
    return "Unassigned";
  }

  const user =
    findAssignee(
      incident,
      assignees,
    );

  if (!user) {
    /*
     * Never expose UUID as a human identity.
     * The backend/User Management directory remains
     * the source of truth.
     */
    return "Assigned";
  }

  return (
    user.display_name?.trim() ||
    user.username?.trim() ||
    "Assigned"
  );
}

function getAssigneeRole(
  incident: Incident,
  assignees: IncidentAssignee[],
): string {
  const user =
    findAssignee(
      incident,
      assignees,
    );

  if (!user) {
    return "";
  }

  if (
    !Array.isArray(
      user.roles,
    )
  ) {
    return "";
  }

  const role =
    user.roles.find(
      (candidate) =>
        typeof candidate ===
          "string" &&
        candidate
          .trim()
          .toUpperCase() !==
          "VIEWER",
    );

  return role
    ? String(role).trim()
    : "";
}

function isViewerOnly(
  incident: Incident,
  assignees: IncidentAssignee[],
): boolean {
  const user =
    findAssignee(
      incident,
      assignees,
    );

  if (!user) {
    return false;
  }

  if (
    !Array.isArray(
      user.roles,
    )
  ) {
    return false;
  }

  const roles =
    user.roles
      .filter(
        (role) =>
          typeof role ===
          "string",
      )
      .map((role) =>
        String(role)
          .trim()
          .toUpperCase(),
      )
      .filter(Boolean);

  return (
    roles.length > 0 &&
    roles.every(
      (role) =>
        role === "VIEWER",
    )
  );
}

function AssigneeCell({
  incident,
  assignees,
}: {
  incident: Incident;
  assignees: IncidentAssignee[];
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

  if (
    isViewerOnly(
      incident,
      assignees,
    )
  ) {
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
      assignees,
    );

  const role =
    getAssigneeRole(
      incident,
      assignees,
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
 * Related Alerts
 * ========================================================================== */

function getRelatedAlertCount(
  incident: Incident,
): number {
  return Array.isArray(
    incident.alert_ids,
  )
    ? incident.alert_ids.length
    : 0;
}

/* ============================================================================
 * Component
 * ========================================================================== */

export function IncidentTable({
  incidents,
  canManage,
  assignees,
  onView,
  onEdit,
  onRelatedAlerts,
}: IncidentTableProps) {
  const [
    openMenuId,
    setOpenMenuId,
  ] = useState<string | null>(
    null,
  );

  const menuContainerRef =
    useRef<HTMLDivElement | null>(
      null,
    );

  /* --------------------------------------------------------------------------
   * Close menu on outside click / Escape
   * ------------------------------------------------------------------------ */

  useEffect(() => {
    if (!openMenuId) {
      return;
    }

    const handlePointerDown = (
      event: MouseEvent,
    ) => {
      const target =
        event.target;

      if (
        !(target instanceof Node)
      ) {
        return;
      }

      if (
        menuContainerRef.current &&
        !menuContainerRef.current.contains(
          target,
        )
      ) {
        setOpenMenuId(null);
      }
    };

    const handleKeyDown = (
      event: KeyboardEvent,
    ) => {
      if (
        event.key ===
        "Escape"
      ) {
        setOpenMenuId(null);
      }
    };

    document.addEventListener(
      "mousedown",
      handlePointerDown,
    );

    document.addEventListener(
      "keydown",
      handleKeyDown,
    );

    return () => {
      document.removeEventListener(
        "mousedown",
        handlePointerDown,
      );

      document.removeEventListener(
        "keydown",
        handleKeyDown,
      );
    };
  }, [openMenuId]);

  /* --------------------------------------------------------------------------
   * Empty
   * ------------------------------------------------------------------------ */

  if (
    !Array.isArray(
      incidents,
    ) ||
    incidents.length === 0
  ) {
    return (
      <div className="empty-state">
        <p>
          No incidents available.
        </p>
      </div>
    );
  }

  /* --------------------------------------------------------------------------
   * Table
   * ------------------------------------------------------------------------ */

  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">
              Incident
            </th>

            <th scope="col">
              Severity
            </th>

            <th scope="col">
              Status
            </th>

            <th scope="col">
              Related Alerts
            </th>

            <th scope="col">
              Assignee
            </th>

            <th scope="col">
              Created
            </th>

            <th scope="col">
              Actions
            </th>
          </tr>
        </thead>

        <tbody>
          {incidents.map(
            (incident) => {
              const alertCount =
                getRelatedAlertCount(
                  incident,
                );

              const isMenuOpen =
                openMenuId ===
                incident.incident_id;

              return (
                <tr
                  key={
                    incident.incident_id
                  }
                >
                  {/* ========================================================
                   * Incident
                   * ====================================================== */}

                  <td>
                    <button
                      type="button"
                      className="incident-link"
                      onClick={() => {
                        setOpenMenuId(
                          null,
                        );

                        onView(
                          incident,
                        );
                      }}
                      aria-label={`View incident ${incident.incident_number}`}
                    >
                      <strong>
                        {incident.title}
                      </strong>

                      <small>
                        {
                          incident.incident_number
                        }
                      </small>
                    </button>
                  </td>

                  {/* ========================================================
                   * Severity
                   * ====================================================== */}

                  <td>
                    <span
                      className={`severity-badge severity-${incident.severity}`}
                    >
                      {formatSeverity(
                        incident.severity,
                      )}
                    </span>
                  </td>

                  {/* ========================================================
                   * Status
                   * ====================================================== */}

                  <td>
                    <span
                      className={`status-badge status-${incident.status}`}
                    >
                      {formatStatus(
                        incident.status,
                      )}
                    </span>
                  </td>

                  {/* ========================================================
                   * Related Alerts
                   * ====================================================== */}

                  <td>
                    {alertCount > 0 ? (
                      <button
                        type="button"
                        className="related-count-link"
                        onClick={() => {
                          setOpenMenuId(
                            null,
                          );

                          onRelatedAlerts(
                            incident,
                          );
                        }}
                        aria-label={`${alertCount} related alerts`}
                      >
                        {alertCount}
                      </button>
                    ) : (
                      <span className="related-count-empty">
                        0
                      </span>
                    )}
                  </td>

                  {/* ========================================================
                   * Assignee
                   * ====================================================== */}

                  <td>
                    <AssigneeCell
                      incident={
                        incident
                      }
                      assignees={
                        assignees
                      }
                    />
                  </td>

                  {/* ========================================================
                   * Created
                   * ====================================================== */}

                  <td>
                    <time
                      dateTime={
                        incident.created_at
                      }
                    >
                      {formatDate(
                        incident.created_at,
                      )}
                    </time>
                  </td>

                  {/* ========================================================
                   * Actions
                   * ====================================================== */}

                  <td>
                    <div
                      className="table-actions"
                      ref={
                        isMenuOpen
                          ? menuContainerRef
                          : undefined
                      }
                    >
                      <button
                        type="button"
                        className="action-menu-trigger"
                        onClick={() => {
                          setOpenMenuId(
                            isMenuOpen
                              ? null
                              : incident.incident_id,
                          );
                        }}
                        aria-label={`Actions for ${incident.incident_number}`}
                        aria-haspopup="menu"
                        aria-expanded={
                          isMenuOpen
                        }
                        title="Actions"
                      >
                        <span aria-hidden="true">
                          ⋮
                        </span>
                      </button>

                      {isMenuOpen && (
                        <div
                          className="action-menu"
                          role="menu"
                        >
                          <button
                            type="button"
                            className="action-menu-item"
                            role="menuitem"
                            onClick={() => {
                              setOpenMenuId(
                                null,
                              );

                              onView(
                                incident,
                              );
                            }}
                          >
                            <span
                              className="action-menu-icon"
                              aria-hidden="true"
                            >
                              👁
                            </span>

                            <span>
                              View Incident
                            </span>
                          </button>

                          {canManage && (
                            <button
                              type="button"
                              className="action-menu-item"
                              role="menuitem"
                              onClick={() => {
                                setOpenMenuId(
                                  null,
                                );

                                onEdit(
                                  incident,
                                );
                              }}
                            >
                              <span
                                className="action-menu-icon"
                                aria-hidden="true"
                              >
                                ✏️
                              </span>

                              <span>
                                Edit Incident
                              </span>
                            </button>
                          )}
                        </div>
                      )}
                    </div>
                  </td>
                </tr>
              );
            },
          )}
        </tbody>
      </table>
    </div>
  );
}

export default IncidentTable;
