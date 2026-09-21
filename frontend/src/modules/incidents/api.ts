/**
 * ============================================================================
 * SentinelSIEM — Incidents API
 * ============================================================================
 *
 * Feature-level API boundary for the Incident / SOC Investigation module.
 *
 * Responsibilities:
 *
 *   - Incident listing
 *   - Incident filtering
 *   - Backend-driven filter options
 *   - Incident detail
 *   - Incident statistics / dashboard KPIs
 *   - Incident creation
 *   - Incident unified update
 *   - Related alerts
 *   - Timeline
 *
 * Transport, authentication, request serialization and centralized error
 * handling remain in:
 *
 *   frontend/src/services/api.ts
 *
 * FINAL INCIDENT CONTRACT
 * ----------------------------------------------------------------------------
 *
 * Lifecycle:
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
 * Severity:
 *
 *   critical
 *   high
 *   medium
 *   low
 *   informational
 *
 * Filters:
 *
 *   Search
 *   Severity
 *   Status
 *   Assignee
 *
 * No:
 *
 *   - Priority
 *   - Ownership Group
 *   - Assignee Role filter
 *   - frontend KPI calculation
 *   - frontend dropdown invention
 *
 * ============================================================================
 */

import { api as sharedApi } from "../../services/api";

import type {
  Incident,
  IncidentAuditEntry,
  IncidentCreateRequest,
  IncidentDetail,
  IncidentEvidence,
  IncidentEvidenceCreateRequest,
  IncidentFilterOptions,
  IncidentListFilters,
  IncidentListResponse,
  IncidentNote,
  IncidentNoteCreateRequest,
  IncidentStatistics,
  IncidentTimelineEntry,
  IncidentUpdateRequest,
} from "./types";


/* ============================================================================
 * Incidents API
 * ========================================================================== */

export const incidentsApi = {

  /* ==========================================================================
   * List
   * ======================================================================== */

  /**
   * List Incidents using the default pagination contract.
   *
   * Backend:
   *
   *   GET /api/v1/incidents
   *
   * The backend owns:
   *
   *   - filtering
   *   - pagination
   *   - total
   *   - total_pages
   */
  list(
    page = 1,
    pageSize = 30,
  ): Promise<IncidentListResponse> {
    return sharedApi.incidents(
      page,
      pageSize,
    );
  },


  /**
   * List Incidents using backend-supported filters.
   *
   * Final UI filters:
   *
   *   Search
   *   Severity
   *   Status
   *   Assignee
   *
   * Supported filter fields:
   *
   *   query
   *   search
   *   status
   *   severity
   *   assigned_to
   *   page
   *   page_size
   *
   * IMPORTANT:
   *
   * Dynamic select values must come from:
   *
   *   filterOptions()
   *
   * This API layer must not invent or calculate filter values.
   */
  listWithFilters(
    filters: IncidentListFilters = {},
  ): Promise<IncidentListResponse> {
    return sharedApi.incidentsWithFilters(
      filters,
    );
  },


  /* ==========================================================================
   * Filter Options
   * ======================================================================== */

  /**
   * Get backend-supported Incident filter options.
   *
   * Backend:
   *
   *   GET /api/v1/incidents/filter-options
   *
   * Expected response:
   *
   *   {
   *     statuses: string[],
   *     severities: string[],
   *     assignees: ...
   *   }
   *
   * IMPORTANT:
   *
   * The frontend must not hardcode:
   *
   *   - status options
   *   - severity options
   *   - assignee options
   *
   * Backend remains the source of truth.
   */
  filterOptions(): Promise<IncidentFilterOptions> {
    return sharedApi.getIncidentFilterOptions();
  },


  /* ==========================================================================
   * Detail
   * ======================================================================== */

  /**
   * Get a single Incident.
   *
   * Backend:
   *
   *   GET /api/v1/incidents/{incident_id}
   *
   * The backend may return the complete Incident detail payload.
   */
  get(
    incidentId: string,
  ): Promise<IncidentDetail> {
    return sharedApi.getIncident(
      incidentId,
    ) as Promise<IncidentDetail>;
  },


  /**
   * Get complete Incident detail.
   *
   * Includes:
   *
   *   - Incident metadata
   *   - Related alerts
   *   - Related events
   *   - Related IOCs
   *   - Affected assets
   *   - Notes
   *   - Evidence
   *   - Timeline
   *   - Audit history
   *
   * Backend:
   *
   *   GET /api/v1/incidents/{incident_id}
   */
  getDetail(
    incidentId: string,
  ): Promise<IncidentDetail> {
    return sharedApi.getIncidentDetail(
      incidentId,
    );
  },


  /* ==========================================================================
   * Statistics
   * ======================================================================== */

  /**
   * Get backend Incident dashboard KPI statistics.
   *
   * Backend:
   *
   *   GET /api/v1/incidents/statistics
   *
   * Final KPI fields:
   *
   *   total
   *   open
   *   investigating
   *   critical
   *   high
   *   resolved
   *
   * IMPORTANT:
   *
   * These values are authoritative backend values.
   *
   * Frontend must:
   *
   *   - display them directly;
   *   - never calculate them from the Incident list;
   *   - never calculate them from pagination;
   *   - never use hardcoded fallback numbers.
   */
  statistics(): Promise<IncidentStatistics> {
    return sharedApi.getIncidentStatistics();
  },


  /* ==========================================================================
   * Create
   * ======================================================================== */

  /**
   * Create an Incident.
   *
   * Backend:
   *
   *   POST /api/v1/incidents
   *
   * Backend generates:
   *
   *   - incident_id
   *   - incident_number
   *   - status
   *   - created_by
   *   - created_at
   *   - updated_at
   *
   * Initial status is determined by the backend:
   *
   *   open
   *
   * The create request must not send a user-selected status.
   */
  create(
    payload: IncidentCreateRequest,
  ): Promise<Incident> {
    return sharedApi.createIncident(
      payload,
    );
  },


  /* ==========================================================================
   * Unified Update
   * ======================================================================== */

  /**
   * Update an Incident.
   *
   * Backend:
   *
   *   PATCH /api/v1/incidents/{incident_id}
   *
   * Supported edit fields:
   *
   *   - title
   *   - description
   *   - severity
   *   - status
   *   - assigned_to
   *
   * The backend is responsible for:
   *
   *   - authentication
   *   - incidents:manage permission
   *   - field validation
   *   - lifecycle transition validation
   *   - assignee validation
   *   - audit generation
   *
   * This is the primary Incident mutation method.
   *
   * The frontend should not duplicate the same operation through separate
   * assignment/transition calls when unified PATCH is available.
   */
  update(
    incidentId: string,
    payload: IncidentUpdateRequest,
  ): Promise<Incident> {
    return sharedApi.updateIncident(
      incidentId,
      payload,
    );
  },


  /* ==========================================================================
   * Related Alerts
   * ======================================================================== */

  /**
   * Get Alerts related to an Incident.
   *
   * Backend:
   *
   *   GET /api/v1/incidents/{incident_id}/alerts
   *
   * The Alerts module remains the source of truth for Alert data.
   *
   * Incident must not maintain a duplicate full Alert dataset.
   */
  getRelatedAlerts(
    incidentId: string,
  ): Promise<IncidentRelatedAlert[]> {
    return sharedApi.getIncidentRelatedAlerts(
      incidentId,
    );
  },


  /* ==========================================================================
   * Timeline
   * ======================================================================== */

  /**
   * Get Incident investigation timeline.
   *
   * Backend:
   *
   *   GET /api/v1/incidents/{incident_id}/timeline
   */
  getTimeline(
    incidentId: string,
  ): Promise<IncidentTimelineEntry[]> {
    return sharedApi.getIncidentTimeline(
      incidentId,
    );
  },


  /* ==========================================================================
   * Audit
   * ======================================================================== */

  /**
   * Get Incident audit history.
   *
   * Backend:
   *
   *   GET /api/v1/incidents/{incident_id}/audit
   *
   * Audit records are generated by the backend.
   */
  getAudit(
    incidentId: string,
  ): Promise<IncidentAuditEntry[]> {
    return sharedApi.getIncidentAudit(
      incidentId,
    );
  },


  /* ==========================================================================
   * Investigation Notes
   * ======================================================================== */

  /**
   * Add an investigation note.
   *
   * Kept as a feature API boundary for the existing investigation
   * infrastructure.
   *
   * This is not part of the current primary Incident page workflow.
   */
  addNote(
    incidentId: string,
    payload: IncidentNoteCreateRequest,
  ): Promise<IncidentNote> {
    return sharedApi.addIncidentNote(
      incidentId,
      payload,
    );
  },


  /**
   * Get Incident investigation notes.
   */
  getNotes(
    incidentId: string,
  ): Promise<IncidentNote[]> {
    return sharedApi.getIncidentNotes(
      incidentId,
    );
  },


  /* ==========================================================================
   * Evidence
   * ======================================================================== */

  /**
   * Add Incident evidence.
   *
   * Kept for the existing investigation infrastructure.
   */
  addEvidence(
    incidentId: string,
    payload: IncidentEvidenceCreateRequest,
  ): Promise<IncidentEvidence> {
    return sharedApi.addIncidentEvidence(
      incidentId,
      payload,
    );
  },


  /**
   * Get Incident evidence.
   */
  getEvidence(
    incidentId: string,
  ): Promise<IncidentEvidence[]> {
    return sharedApi.getIncidentEvidence(
      incidentId,
    );
  },

} as const;


/* ============================================================================
 * Related Alert Type Import
 * ========================================================================== */

/**
 * Imported separately to keep the main type import section organized.
 */
import type {
  IncidentRelatedAlert,
} from "./types";


/* ============================================================================
 * Backward-Compatible Named Helpers
 * ========================================================================== */

/**
 * List Incidents.
 */
export const listIncidents = (
  page = 1,
  pageSize = 30,
): Promise<IncidentListResponse> =>
  incidentsApi.list(
    page,
    pageSize,
  );


/**
 * List Incidents with backend filters.
 */
export const listIncidentsWithFilters = (
  filters: IncidentListFilters = {},
): Promise<IncidentListResponse> =>
  incidentsApi.listWithFilters(
    filters,
  );


/**
 * Get backend-driven Incident filter options.
 */
export const getIncidentFilterOptions = ():
  Promise<IncidentFilterOptions> =>
  incidentsApi.filterOptions();


/**
 * Get an Incident.
 */
export const getIncident = (
  incidentId: string,
): Promise<IncidentDetail> =>
  incidentsApi.get(
    incidentId,
  );


/**
 * Get complete Incident detail.
 */
export const getIncidentDetail = (
  incidentId: string,
): Promise<IncidentDetail> =>
  incidentsApi.getDetail(
    incidentId,
  );


/**
 * Get backend Incident KPI statistics.
 */
export const getIncidentStatistics = ():
  Promise<IncidentStatistics> =>
  incidentsApi.statistics();


/**
 * Create an Incident.
 */
export const createIncident = (
  payload: IncidentCreateRequest,
): Promise<Incident> =>
  incidentsApi.create(
    payload,
  );


/**
 * Update an Incident.
 *
 * Primary mutation path for:
 *
 *   - title
 *   - description
 *   - severity
 *   - status
 *   - assignee
 */
export const updateIncident = (
  incidentId: string,
  payload: IncidentUpdateRequest,
): Promise<Incident> =>
  incidentsApi.update(
    incidentId,
    payload,
  );


/**
 * Get related Alerts.
 */
export const getIncidentRelatedAlerts = (
  incidentId: string,
): Promise<IncidentRelatedAlert[]> =>
  incidentsApi.getRelatedAlerts(
    incidentId,
  );


/**
 * Get Incident timeline.
 */
export const getIncidentTimeline = (
  incidentId: string,
): Promise<IncidentTimelineEntry[]> =>
  incidentsApi.getTimeline(
    incidentId,
  );


/**
 * Get Incident audit history.
 */
export const getIncidentAudit = (
  incidentId: string,
): Promise<IncidentAuditEntry[]> =>
  incidentsApi.getAudit(
    incidentId,
  );


/**
 * Add an Incident investigation note.
 */
export const addIncidentNote = (
  incidentId: string,
  payload: IncidentNoteCreateRequest,
): Promise<IncidentNote> =>
  incidentsApi.addNote(
    incidentId,
    payload,
  );


/**
 * Get Incident investigation notes.
 */
export const getIncidentNotes = (
  incidentId: string,
): Promise<IncidentNote[]> =>
  incidentsApi.getNotes(
    incidentId,
  );


/**
 * Add Incident evidence.
 */
export const addIncidentEvidence = (
  incidentId: string,
  payload: IncidentEvidenceCreateRequest,
): Promise<IncidentEvidence> =>
  incidentsApi.addEvidence(
    incidentId,
    payload,
  );


/**
 * Get Incident evidence.
 */
export const getIncidentEvidence = (
  incidentId: string,
): Promise<IncidentEvidence[]> =>
  incidentsApi.getEvidence(
    incidentId,
  );


/* ============================================================================
 * Default Export
 * ========================================================================== */

export default incidentsApi;


/* ============================================================================
 * End of File
 * ============================================================================
 */