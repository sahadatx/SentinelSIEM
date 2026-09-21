/**
 * ============================================================================
 * SentinelSIEM — Incident Types
 * ============================================================================
 *
 * Frontend contract for the Incident / SOC Investigation module.
 *
 * Backend source of truth:
 *
 *   /api/v1/incidents
 *   /api/v1/incidents/statistics
 *   /api/v1/incidents/filter-options
 *
 * Canonical Incident lifecycle:
 *
 *   open
 *     ↓
 *   investigating
 *     ↓
 *   contained
 *     ↓
 *   resolved
 *     ↓
 *   closed
 *
 * Canonical Incident severity:
 *
 *   critical
 *   high
 *   medium
 *   low
 *   informational
 *
 * IMPORTANT
 * ----------------------------------------------------------------------------
 * - KPI values come from the backend.
 * - Filter dropdown values come from the backend.
 * - Assignee/user data comes from the backend.
 * - Frontend must not calculate KPI values.
 * - Frontend must not invent dynamic dropdown values.
 * - Frontend must not hardcode users or roles.
 * - Status transition validation belongs to the backend.
 * - Assignee validation belongs to the backend.
 * - UI label mappings are presentation-only.
 * - No Priority field exists in the final Incident contract.
 * - No Ownership Group field exists in the final Incident contract.
 *
 * ============================================================================
 */


/* ============================================================================
 * Incident Status
 * ========================================================================== */

/**
 * Canonical backend Incident lifecycle state.
 *
 * Backend:
 *
 *   open
 *   investigating
 *   contained
 *   resolved
 *   closed
 *
 * The frontend must not add additional status values.
 */
export type IncidentStatus =
  | "open"
  | "investigating"
  | "contained"
  | "resolved"
  | "closed";


/* ============================================================================
 * Incident Severity
 * ========================================================================== */

/**
 * Canonical backend Incident severity.
 *
 * Backend catalogue:
 *
 *   critical
 *   high
 *   medium
 *   low
 *   informational
 */
export type IncidentSeverity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "informational";


/* ============================================================================
 * Incident Assignee
 * ========================================================================== */

/**
 * Backend user information used by Incident assignment UI.
 *
 * The user UUID is the value sent to the backend.
 *
 * The human-readable name and role are presentation data returned
 * by the User Management / backend user directory.
 */
export interface IncidentAssignee {
  /**
   * Backend user UUID.
   */
  user_id: string;

  /**
   * Human-readable user name.
   */
  display_name: string;

  /**
   * Username/login identifier.
   */
  username?: string;

  /**
   * Backend role names.
   *
   * A user may have more than one role.
   */
  roles: string[];

  /**
   * Whether the user is active.
   */
  is_active?: boolean;

  /**
   * Whether the user is locked.
   */
  is_locked?: boolean;
}


/* ============================================================================
 * Related Alert
 * ========================================================================== */

/**
 * Alert returned by:
 *
 *   GET /api/v1/incidents/{incident_id}/alerts
 *
 * Incident does not duplicate Alert ownership/data.
 *
 * The Alerts module remains the source of truth for Alert details.
 */
export interface IncidentRelatedAlert {
  /**
   * Alert UUID.
   */
  alert_id: string;

  /**
   * Human-readable alert title.
   */
  title: string;

  /**
   * Alert description.
   */
  description: string;

  /**
   * Alert severity.
   *
   * Kept as string because the Alerts module owns its own
   * severity contract.
   */
  severity: string;

  /**
   * Alert lifecycle status.
   */
  status: string;

  /**
   * Alert source type.
   */
  source_type: string;

  /**
   * Detection/correlation rule identifier.
   */
  rule_id: string | null;

  /**
   * Human-readable rule name.
   */
  rule_name: string | null;

  /**
   * Related event UUIDs.
   */
  event_ids: string[];

  /**
   * First observed timestamp.
   */
  first_seen_at: string | null;

  /**
   * Last observed timestamp.
   */
  last_seen_at: string | null;
}


/* ============================================================================
 * Related Event
 * ========================================================================== */

/**
 * Event associated with an Incident.
 *
 * Event remains owned by the Events module.
 */
export interface IncidentRelatedEvent {
  /**
   * Event UUID.
   */
  event_id: string;

  /**
   * Event timestamp.
   */
  timestamp: string;

  /**
   * Event action.
   */
  action: string | null;

  /**
   * Event outcome.
   */
  outcome: string | null;

  /**
   * Event severity.
   */
  severity: string | null;

  /**
   * Event category.
   */
  category: string | null;

  /**
   * Source IP address.
   */
  source_ip: string | null;

  /**
   * Event source.
   */
  source: string | null;

  /**
   * Event actor.
   */
  actor: string | null;

  /**
   * Event target.
   */
  target: string | null;
}


/* ============================================================================
 * Related IOC
 * ========================================================================== */

/**
 * IOC associated with an Incident.
 *
 * IOC remains owned by the Threat Intelligence / IOC module.
 */
export interface IncidentRelatedIoc {
  /**
   * IOC UUID.
   */
  ioc_id: string;

  /**
   * IOC display indicator.
   */
  indicator: string;

  /**
   * IOC indicator type.
   */
  indicator_type: string;

  /**
   * IOC value.
   */
  value: string;

  /**
   * IOC confidence score.
   */
  confidence: number | null;

  /**
   * IOC severity.
   */
  severity: string | null;

  /**
   * IOC status.
   */
  status: string | null;

  /**
   * IOC source.
   */
  source: string | null;
}


/* ============================================================================
 * Related Asset
 * ========================================================================== */

/**
 * Asset affected by an Incident.
 *
 * Asset remains owned by the Assets module.
 */
export interface IncidentRelatedAsset {
  /**
   * Asset UUID.
   */
  asset_id: string;

  /**
   * Asset name.
   */
  name: string;

  /**
   * Asset hostname.
   */
  hostname: string;

  /**
   * Asset type.
   */
  asset_type: string;

  /**
   * Asset status.
   */
  status: string;

  /**
   * Asset criticality.
   */
  criticality: string;

  /**
   * IP address.
   */
  ip_address: string | null;
}


/* ============================================================================
 * Incident Evidence
 * ========================================================================== */

/**
 * Investigation evidence record.
 */
export interface IncidentEvidence {
  /**
   * Evidence UUID.
   */
  evidence_id: string;

  /**
   * Parent Incident UUID.
   */
  incident_id: string;

  /**
   * Evidence classification.
   */
  evidence_type: string;

  /**
   * Evidence reference.
   */
  reference: string;

  /**
   * User UUID / identifier that collected the evidence.
   */
  collected_by: string;

  /**
   * Creation timestamp.
   */
  created_at: string;
}


/* ============================================================================
 * Investigation Note
 * ========================================================================== */

/**
 * Investigation note.
 */
export interface IncidentNote {
  /**
   * Note UUID.
   */
  note_id: string;

  /**
   * Parent Incident UUID.
   */
  incident_id: string;

  /**
   * Author user UUID / identifier.
   */
  author: string;

  /**
   * Note content.
   */
  content: string;

  /**
   * Creation timestamp.
   */
  created_at: string;
}


/* ============================================================================
 * Incident Timeline
 * ========================================================================== */

/**
 * Incident investigation timeline entry.
 */
export interface IncidentTimelineEntry {
  /**
   * Timeline entry UUID.
   */
  entry_id: string;

  /**
   * Parent Incident UUID.
   */
  incident_id: string;

  /**
   * Timeline event type.
   */
  event_type: string;

  /**
   * Human-readable event description.
   */
  description: string;

  /**
   * Actor user UUID / identifier.
   */
  actor: string;

  /**
   * Event timestamp.
   */
  occurred_at: string;
}


/* ============================================================================
 * Incident Audit History
 * ========================================================================== */

/**
 * Incident audit record.
 *
 * Audit is backend-generated.
 *
 * The frontend displays audit history but does not construct audit records.
 */
export interface IncidentAuditEntry {
  /**
   * Audit UUID.
   */
  audit_id: string;

  /**
   * Parent Incident UUID.
   */
  incident_id: string;

  /**
   * Audit action.
   *
   * Examples:
   *
   *   incident_created
   *   incident_updated
   *   incident_assigned
   *   incident_reassigned
   *   incident_severity_changed
   *   incident_status_changed
   *
   * Legacy backend values may also exist in historical data.
   */
  action: string;

  /**
   * Actor user UUID / identifier.
   */
  actor: string;

  /**
   * Generic field name for field-level changes.
   */
  field_name?: string | null;

  /**
   * Generic previous field value.
   */
  from_value?: string | null;

  /**
   * Generic new field value.
   */
  to_value?: string | null;

  /**
   * Previous Incident status.
   */
  from_status: IncidentStatus | null;

  /**
   * New Incident status.
   */
  to_status: IncidentStatus | null;

  /**
   * Previous Incident severity.
   */
  from_severity: IncidentSeverity | null;

  /**
   * New Incident severity.
   */
  to_severity: IncidentSeverity | null;

  /**
   * Previous assignee UUID.
   */
  from_assignee: string | null;

  /**
   * New assignee UUID.
   */
  to_assignee: string | null;

  /**
   * Optional audit reason.
   */
  reason: string | null;

  /**
   * Audit creation timestamp.
   */
  created_at: string;
}


/* ============================================================================
 * Incident
 * ========================================================================== */

/**
 * Core Incident entity.
 *
 * This is the canonical list/table contract.
 */
export interface Incident {
  /**
   * Internal Incident UUID.
   */
  incident_id: string;

  /**
   * Human-readable Incident number.
   *
   * Example:
   *
   *   INC-2026-00021
   */
  incident_number: string;

  /**
   * Incident title.
   */
  title: string;

  /**
   * Incident description.
   */
  description: string;

  /**
   * Canonical Incident severity.
   */
  severity: IncidentSeverity;

  /**
   * Current canonical Incident lifecycle status.
   */
  status: IncidentStatus;

  /**
   * Incident tags.
   */
  tags: string[];

  /**
   * Related Alert UUIDs.
   */
  alert_ids: string[];

  /**
   * Related evidence identifiers.
   */
  evidence_ids: string[];

  /**
   * Related Event UUIDs.
   */
  related_event_ids: string[];

  /**
   * Related IOC UUIDs.
   */
  related_ioc_ids: string[];

  /**
   * Affected Asset UUIDs.
   */
  asset_ids: string[];

  /**
   * Assigned analyst/user UUID.
   *
   * Null means unassigned.
   */
  assigned_to: string | null;

  /**
   * Backend creation actor.
   *
   * Usually the authenticated user's UUID/identifier.
   */
  created_by: string;

  /**
   * Backend creation timestamp.
   */
  created_at: string;

  /**
   * Backend last update timestamp.
   */
  updated_at: string;

  /**
   * Resolution timestamp.
   */
  resolved_at: string | null;

  /**
   * Closure timestamp.
   */
  closed_at: string | null;

  /**
   * Expanded related alerts.
   *
   * The dedicated Related Alerts endpoint remains the preferred
   * source for the Related Alerts drawer.
   */
  related_alerts?: IncidentRelatedAlert[];

  /**
   * Expanded related events.
   */
  related_events?: IncidentRelatedEvent[];

  /**
   * Expanded related IOCs.
   */
  related_iocs?: IncidentRelatedIoc[];

  /**
   * Expanded affected assets.
   */
  affected_assets?: IncidentRelatedAsset[];

  /**
   * Investigation notes.
   */
  notes?: IncidentNote[];

  /**
   * Investigation evidence.
   */
  evidence?: IncidentEvidence[];

  /**
   * Investigation timeline.
   */
  timeline?: IncidentTimelineEntry[];

  /**
   * Audit history.
   */
  audit_history?: IncidentAuditEntry[];
}


/* ============================================================================
 * Incident Detail
 * ========================================================================== */

/**
 * Complete Incident detail contract.
 *
 * Used by the View Incident drawer.
 */
export interface IncidentDetail extends Incident {
  related_alerts: IncidentRelatedAlert[];

  related_events: IncidentRelatedEvent[];

  related_iocs: IncidentRelatedIoc[];

  affected_assets: IncidentRelatedAsset[];

  notes: IncidentNote[];

  evidence: IncidentEvidence[];

  timeline: IncidentTimelineEntry[];

  audit_history: IncidentAuditEntry[];
}


/* ============================================================================
 * Incident Pagination
 * ========================================================================== */

/**
 * Backend pagination metadata.
 *
 * Frontend displays these values directly.
 *
 * Frontend must not derive total_pages locally.
 */
export interface IncidentPagination {
  /**
   * Current page number.
   */
  page: number;

  /**
   * Number of records requested per page.
   */
  page_size: number;

  /**
   * Total number of matching incidents.
   */
  total: number;

  /**
   * Backend-calculated total number of pages.
   */
  total_pages: number;
}


/* ============================================================================
 * Incident List Response
 * ========================================================================== */

/**
 * GET /api/v1/incidents
 */
export interface IncidentListResponse {
  /**
   * Incidents for the requested page.
   */
  items: Incident[];

  /**
   * Backend pagination metadata.
   */
  pagination: IncidentPagination;
}


/* ============================================================================
 * Incident Statistics
 * ========================================================================== */

/**
 * Backend Incident KPI statistics.
 *
 * Endpoint:
 *
 *   GET /api/v1/incidents/statistics
 *
 * Final KPI cards:
 *
 *   Total Incidents
 *   Open
 *   Investigating
 *   Critical
 *   High
 *   Resolved
 *
 * IMPORTANT:
 *
 * These values are authoritative backend values.
 *
 * Frontend MUST:
 *
 *   - display them directly;
 *   - never calculate them from the Incident list;
 *   - never derive them from pagination;
 *   - never use hardcoded fallback numbers.
 */
export interface IncidentStatistics {
  /**
   * Total number of Incidents.
   */
  total: number;

  /**
   * Number of OPEN Incidents.
   */
  open: number;

  /**
   * Number of INVESTIGATING Incidents.
   */
  investigating: number;

  /**
   * Number of CRITICAL Incidents.
   */
  critical: number;

  /**
   * Number of HIGH severity Incidents.
   */
  high: number;

  /**
   * Number of RESOLVED Incidents.
   */
  resolved: number;
}


/* ============================================================================
 * Incident Statistics Response
 * ========================================================================== */

/**
 * GET /api/v1/incidents/statistics
 *
 * Backend returns IncidentStatistics directly.
 */
export type IncidentStatisticsResponse = IncidentStatistics;


/* ============================================================================
 * Incident Filter Options
 * ========================================================================== */

/**
 * Backend-driven Incident filter options.
 *
 * Endpoint:
 *
 *   GET /api/v1/incidents/filter-options
 *
 * Final UI filters:
 *
 *   Search
 *   Severity
 *   Status
 *   Assignee
 *
 * IMPORTANT:
 *
 * The frontend must not hardcode the values contained in these arrays.
 */
export interface IncidentFilterOptions {
  /**
   * Backend lifecycle statuses.
   *
   * Expected canonical values:
   *
   *   open
   *   investigating
   *   contained
   *   resolved
   *   closed
   */
  statuses: string[];

  /**
   * Backend severity catalogue.
   *
   * Expected canonical values:
   *
   *   critical
   *   high
   *   medium
   *   low
   *   informational
   */
  severities: string[];

  /**
   * Backend assignee/user options.
   *
   * Depending on the backend contract, this may contain user UUIDs
   * or richer user objects.
   *
   * The API layer should normalize the backend representation.
   */
  assignees: IncidentAssignee[];
}


/* ============================================================================
 * Incident Filter Options Response
 * ========================================================================== */

/**
 * GET /api/v1/incidents/filter-options
 */
export type IncidentFilterOptionsResponse = IncidentFilterOptions;


/* ============================================================================
 * Incident List Filters
 * ========================================================================== */

/**
 * Filters accepted by:
 *
 *   GET /api/v1/incidents
 *
 * Final UI filters:
 *
 *   Search
 *   Severity
 *   Status
 *   Assignee
 *
 * There is:
 *
 *   ❌ no Priority filter
 *   ❌ no Ownership Group filter
 *   ❌ no Assignee Role filter
 *   ❌ no Apply button
 */
export interface IncidentListFilters {
  /**
   * Backend free-text search query.
   */
  query?: string;

  /**
   * UI compatibility alias for query.
   *
   * API layer may normalize `search` into `query`.
   */
  search?: string;

  /**
   * Incident status.
   */
  status?: IncidentStatus | "";

  /**
   * Incident severity.
   */
  severity?: IncidentSeverity | "";

  /**
   * Assigned user UUID.
   */
  assigned_to?: string;

  /**
   * Pagination page.
   */
  page?: number;

  /**
   * Pagination page size.
   */
  page_size?: number;
}


/* ============================================================================
 * Create Incident
 * ========================================================================== */

/**
 * POST /api/v1/incidents
 *
 * Create Incident request.
 *
 * Backend generates:
 *
 *   incident_id
 *   incident_number
 *   status
 *   created_by
 *   created_at
 *   updated_at
 *
 * Status is NOT supplied by the create form.
 *
 * Backend initial status:
 *
 *   open
 */
export interface IncidentCreateRequest {
  /**
   * Incident title.
   *
   * Required.
   */
  title: string;

  /**
   * Incident description.
   *
   * Required by the final UI workflow.
   */
  description: string;

  /**
   * Incident severity.
   *
   * Required.
   *
   * Must originate from backend-supported severity options.
   */
  severity: IncidentSeverity;

  /**
   * Initial assignee UUID.
   *
   * Optional.
   *
   * This is the backend value selected through:
   *
   *   Assignee Role
   *        ↓
   *   Assignee
   */
  assigned_to?: string | null;

  /**
   * Related Alert UUIDs.
   *
   * Optional.
   */
  alert_ids?: string[];

  /**
   * Related evidence identifiers.
   *
   * Optional.
   */
  evidence_ids?: string[];

  /**
   * Related Event UUIDs.
   *
   * Optional.
   */
  related_event_ids?: string[];

  /**
   * Related IOC UUIDs.
   *
   * Optional.
   */
  related_ioc_ids?: string[];

  /**
   * Affected Asset UUIDs.
   *
   * Optional.
   */
  asset_ids?: string[];

  /**
   * Incident tags.
   *
   * Optional.
   */
  tags?: string[];
}


/* ============================================================================
 * Update Incident
 * ========================================================================== */

/**
 * PATCH /api/v1/incidents/{incident_id}
 *
 * Unified Incident edit contract.
 *
 * Final Edit UI fields:
 *
 *   Title
 *   Description
 *   Severity
 *   Status
 *   Assignee Role
 *   Assignee
 *
 * The Assignee Role is a UI/backend-directory selection helper.
 * The persisted Incident stores the selected user UUID in `assigned_to`.
 *
 * Backend is responsible for:
 *
 *   - authentication
 *   - incidents:manage permission
 *   - field validation
 *   - status transition validation
 *   - assignee validation
 *   - audit generation
 */
export interface IncidentUpdateRequest {
  /**
   * Updated Incident title.
   */
  title?: string;

  /**
   * Updated Incident description.
   */
  description?: string;

  /**
   * Updated Incident severity.
   */
  severity?: IncidentSeverity;

  /**
   * Updated Incident status.
   *
   * Backend validates the transition.
   */
  status?: IncidentStatus;

  /**
   * Updated assignee UUID.
   *
   * Null explicitly unassigns the Incident.
   */
  assigned_to?: string | null;
}


/* ============================================================================
 * Incident Assignment
 * ========================================================================== */

/**
 * Optional dedicated assignment request.
 *
 * Use only if the backend keeps the dedicated:
 *
 *   POST /api/v1/incidents/{incident_id}/assign
 *
 * endpoint.
 *
 * The frontend should not duplicate the same operation through multiple
 * UI actions. The API layer decides which backend operation is used.
 */
export interface IncidentAssignmentRequest {
  /**
   * Analyst/user UUID.
   *
   * Null means unassign.
   */
  assigned_to: string | null;
}


/* ============================================================================
 * Incident Lifecycle Transition
 * ========================================================================== */

/**
 * Optional dedicated lifecycle transition request.
 *
 * Use only if the backend keeps:
 *
 *   POST /api/v1/incidents/{incident_id}/transition
 *
 * The backend remains authoritative for transition validation.
 */
export interface IncidentTransitionRequest {
  /**
   * Target lifecycle state.
   */
  status: IncidentStatus;

  /**
   * Optional transition reason.
   */
  reason?: string;
}


/* ============================================================================
 * Investigation Note Creation
 * ========================================================================== */

/**
 * Optional investigation note creation contract.
 *
 * Kept for compatibility with the existing investigation infrastructure.
 */
export interface IncidentNoteCreateRequest {
  /**
   * Author user UUID / identifier.
   *
   * Backend may override this using the authenticated principal.
   */
  author?: string;

  /**
   * Note content.
   *
   * Required.
   */
  content: string;
}


/* ============================================================================
 * Evidence Creation
 * ========================================================================== */

/**
 * Optional investigation evidence creation contract.
 *
 * Kept for compatibility with existing investigation infrastructure.
 */
export interface IncidentEvidenceCreateRequest {
  /**
   * Evidence UUID.
   */
  evidence_id: string;

  /**
   * Evidence classification.
   */
  evidence_type: string;

  /**
   * Evidence reference.
   */
  reference: string;

  /**
   * User UUID / identifier that collected the evidence.
   */
  collected_by: string;
}


/* ============================================================================
 * Incident Status Labels
 * ========================================================================== */

/**
 * Canonical backend status -> human-readable UI label.
 *
 * IMPORTANT:
 *
 * This object is presentation-only.
 *
 * It is NOT the source of filter values.
 *
 * Dynamic filter options must come from:
 *
 *   IncidentFilterOptions.statuses
 */
export const INCIDENT_STATUS_LABELS: Record<
  IncidentStatus,
  string
> = {
  open: "Open",
  investigating: "Investigating",
  contained: "Contained",
  resolved: "Resolved",
  closed: "Closed",
};


/* ============================================================================
 * Incident Severity Labels
 * ========================================================================== */

/**
 * Canonical backend severity -> human-readable UI label.
 *
 * Presentation-only.
 */
export const INCIDENT_SEVERITY_LABELS: Record<
  IncidentSeverity,
  string
> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "Informational",
};


/* ============================================================================
 * Status Label Helper
 * ========================================================================== */

/**
 * Convert a backend status into its UI label.
 *
 * Unknown backend values are returned unchanged.
 *
 * Example:
 *
 *   open -> Open
 */
export const getIncidentStatusLabel = (
  value: string,
): string => {
  const normalized = value.trim().toLowerCase();

  if (
    normalized in INCIDENT_STATUS_LABELS
  ) {
    return INCIDENT_STATUS_LABELS[
      normalized as IncidentStatus
    ];
  }

  return value;
};


/* ============================================================================
 * Severity Label Helper
 * ========================================================================== */

/**
 * Convert a backend severity into its UI label.
 *
 * Unknown backend values are returned unchanged.
 *
 * Example:
 *
 *   informational -> Informational
 */
export const getIncidentSeverityLabel = (
  value: string,
): string => {
  const normalized = value.trim().toLowerCase();

  if (
    normalized in INCIDENT_SEVERITY_LABELS
  ) {
    return INCIDENT_SEVERITY_LABELS[
      normalized as IncidentSeverity
    ];
  }

  return value;
};


/* ============================================================================
 * Status Type Guard
 * ========================================================================== */

/**
 * Runtime check for a canonical Incident status.
 *
 * Useful when consuming dynamic backend filter values.
 */
export const isIncidentStatus = (
  value: string,
): value is IncidentStatus => {
  return (
    value === "open" ||
    value === "investigating" ||
    value === "contained" ||
    value === "resolved" ||
    value === "closed"
  );
};


/* ============================================================================
 * Severity Type Guard
 * ========================================================================== */

/**
 * Runtime check for a canonical Incident severity.
 */
export const isIncidentSeverity = (
  value: string,
): value is IncidentSeverity => {
  return (
    value === "critical" ||
    value === "high" ||
    value === "medium" ||
    value === "low" ||
    value === "informational"
  );
};


/* ============================================================================
 * End of File
 * ============================================================================
 */