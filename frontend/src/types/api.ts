/* ==========================================================================
 * Shared API Types
 * SentinelSIEM SOC Dashboard
 * ========================================================================== */

/* ==========================================================================
 * Common Types
 * ========================================================================== */

export type Severity =
  | "info"
  | "low"
  | "medium"
  | "high"
  | "critical";

export type HealthState =
  | "healthy"
  | "degraded"
  | "offline"
  | "unknown";

/* ==========================================================================
 * Security Events
 * ========================================================================== */

/**
 * Public API representation of a canonical SentinelSIEM security event.
 *
 * Backend:
 *   GET /api/v1/events
 *   GET /api/v1/events/{event_id}
 *
 * Mirrors:
 *   backend/app/api/schemas/events.py::EventResponse
 */
export interface SecurityEvent {
  event_id: string;

  timestamp: string;
  ingestion_timestamp: string;

  source: string;
  source_type: string;

  hostname: string | null;

  source_ip: string | null;
  destination_ip: string | null;

  source_port: number | null;
  destination_port: number | null;

  protocol: string | null;

  username: string | null;
  process: string | null;
  command: string | null;

  action: string | null;
  outcome: string;

  severity: Severity;
  category: string;

  raw_event: string;

  /**
   * Source-specific parsed fields.
   *
   * Backend:
   *   dict[str, Any]
   */
  parsed_data: Record<string, unknown>;

  /**
   * Normalized canonical event fields.
   *
   * Backend:
   *   dict[str, Any]
   */
  normalized_data: Record<string, unknown>;

  /**
   * Optional enrichment data.
   */
  enrichment: Record<string, unknown> | null;

  /**
   * Event metadata.
   */
  metadata: Record<string, unknown>;

  stage: string;
}

/* ==========================================================================
 * Indicators of Compromise
 * ========================================================================== */

/**
 * Public API representation of an IOC.
 *
 * Backend:
 *   GET /api/v1/iocs
 *   GET /api/v1/iocs/{ioc_id}
 */
export interface IOC {
  ioc_id: string;

  ioc_type: string;
  value: string;

  confidence: number;

  source: string;

  first_seen: string;
  last_seen: string;

  expiration: string | null;

  feed: string | null;

  reputation: string;
  status: string;

  metadata: Record<string, unknown>;
}

/**
 * IOC match response.
 *
 * Backend:
 *   GET /api/v1/iocs/match?observable=...
 */
export interface IOCMatch {
  ioc_id: string;

  ioc_type: string;
  value: string;

  confidence: number;
  reputation: string;
}

/* ==========================================================================
 * MITRE ATT&CK
 * ========================================================================== */

/**
 * MITRE ATT&CK tactic transport response.
 *
 * Backend:
 *   backend/app/api/schemas/mitre.py::MitreTacticResponse
 *
 * Endpoint:
 *   GET /api/v1/mitre/tactics
 */
export interface MitreTacticResponse {
  id: string;
  name: string;
  description: string;
}

/**
 * MITRE ATT&CK technique transport response.
 *
 * Backend:
 *   backend/app/api/schemas/mitre.py::MitreTechniqueResponse
 *
 * Endpoint:
 *   GET /api/v1/mitre/techniques
 *   GET /api/v1/mitre/techniques/{technique_id}
 */
export interface MitreTechniqueResponse {
  id: string;
  name: string;

  /**
   * MITRE tactic IDs associated with this technique.
   *
   * Backend:
   *   tuple[str, ...]
   *
   * JSON:
   *   string[]
   */
  tactic_ids: string[];

  description: string;
}

/**
 * MITRE ATT&CK coverage transport response.
 *
 * Backend:
 *   backend/app/api/schemas/mitre.py::MitreCoverageResponse
 *
 * Endpoint:
 *   GET /api/v1/mitre/coverage
 *
 * Coverage is calculated by the backend.
 * The frontend must not recalculate the percentage.
 */
export interface MitreCoverageResponse {
  /**
   * Total number of techniques known by the backend.
   */
  total_techniques: number;

  /**
   * Number of techniques mapped to detections.
   */
  mapped_techniques: number;

  /**
   * Backend-provided coverage percentage.
   */
  coverage_percent: number;

  /**
   * Technique IDs currently covered by detections.
   *
   * Backend:
   *   tuple[str, ...]
   *
   * JSON:
   *   string[]
   */
  mapped_technique_ids: string[];

  /**
   * Technique IDs currently without detection mappings.
   *
   * Backend:
   *   tuple[str, ...]
   *
   * JSON:
   *   string[]
   */
  unmapped_technique_ids: string[];
}

/**
 * Shared MITRE coverage contract.
 *
 * Existing dashboard code uses `MitreCoverage`.
 *
 * Keeping this alias avoids breaking:
 *
 *   - store/dashboard.ts
 *   - hooks/useDashboard.ts
 *   - pages/Overview.tsx
 *   - existing shared API consumers
 */
export type MitreCoverage =
  MitreCoverageResponse;

/* ==========================================================================
 * Pagination
 * ========================================================================== */

export interface Pagination {
  page: number;
  page_size: number;
  total: number;
}

export interface PaginatedResponse<T> {
  items: T[];
  pagination: Pagination;
}

/* ==========================================================================
 * Health / System
 * ========================================================================== */

/**
 * GET /api/v1/health
 */
export interface HealthResponse {
  status: string;
  service: string;
  version: string;
}

/**
 * GET /api/v1/system
 */
export interface SystemResponse {
  service: string;
  version: string;
  environment: string;
  capabilities: string[];
}

/* ==========================================================================
 * User Management
 * ========================================================================== */

/**
 * Public-safe SentinelSIEM user representation.
 *
 * SECURITY:
 * The backend does not expose:
 * - password
 * - password_hash
 * - access token
 * - refresh token
 * - API key
 * - secret
 */
export interface User {
  user_id: string;

  username: string;
  email: string;

  roles: string[];

  is_active: boolean;
  is_locked: boolean;

  failed_login_count: number;

  display_name: string | null;

  force_password_change: boolean;

  password_changed_at: string | null;
  last_login_at: string | null;

  created_at: string;
  updated_at: string;
}

/**
 * GET /api/v1/users
 *
 * Uses limit/offset pagination.
 */
export interface UserListResponse {
  users: User[];

  limit: number;
  offset: number;
}

/**
 * GET /api/v1/users/statistics
 */
export interface UserStatistics {
  total: number;
  active: number;
  disabled: number;
  locked: number;
}

/* ==========================================================================
 * User Management Requests
 * ========================================================================== */

/**
 * POST /api/v1/users
 */
export interface CreateUserRequest {
  username: string;
  email: string;
  password: string;
  role: string;
  is_active?: boolean;
}

/**
 * PATCH /api/v1/users/{user_id}
 *
 * Backend accepts:
 * - username
 * - email
 */
export interface UpdateUserRequest {
  username: string;
  email: string;
}

/**
 * PATCH /api/v1/users/{user_id}/role
 */
export interface ChangeRoleRequest {
  role: string;
}

/**
 * PATCH /api/v1/users/{user_id}/active
 */
export interface SetActiveRequest {
  is_active: boolean;
}

/**
 * PATCH /api/v1/users/{user_id}/lock
 */
export interface SetLockedRequest {
  is_locked: boolean;
}

/**
 * POST /api/v1/users/{user_id}/password/reset
 *
 * SECURITY:
 * Plaintext password must never be persisted
 * in frontend state after submission.
 */
export interface ResetPasswordRequest {
  new_password: string;
}

/* ==========================================================================
 * User Management Responses
 * ========================================================================== */

/**
 * Generic user mutation response.
 */
export interface UserMutationResponse {
  success: boolean;
  message: string;
}

/**
 * POST /api/v1/users/{user_id}/password/reset
 */
export interface ResetPasswordResponse {
  success: boolean;
  message: string;
  sessions_revoked: number;
}

/**
 * POST /api/v1/users/{user_id}/sessions/revoke
 */
export interface RevokeSessionsResponse {
  success: boolean;
  message: string;
  revoked_count: number;
}

/**
 * DELETE /api/v1/users/{user_id}
 */
export interface DeleteUserResponse {
  success: boolean;
  message: string;
}

/* ==========================================================================
 * User Sessions
 * ========================================================================== */

/**
 * Safe session representation.
 *
 * SECURITY:
 * token_id is intentionally not represented.
 */
export interface Session {
  session_id: string;
  user_id: string;

  created_at: string;
  expires_at: string;
  revoked_at: string | null;

  ip_address: string | null;
  user_agent: string | null;

  is_active: boolean;
}

export interface SessionListResponse {
  sessions: Session[];
}

/* ==========================================================================
 * User Activity / Audit
 * ========================================================================== */

/**
 * Safe user-related audit activity representation.
 *
 * Backend metadata must already be sanitized.
 */
export interface UserActivity {
  action: string;
  outcome: string;

  actor_user_id: string | null;
  target_user_id: string | null;

  request_id: string | null;
  session_id: string | null;

  source_ip: string | null;

  metadata: Record<string, unknown>;

  timestamp: string;
}

export interface UserActivityListResponse {
  activities: UserActivity[];

  limit: number;
  offset: number;
}

/* ==========================================================================
 * Authentication
 * ========================================================================== */

/**
 * Authenticated user information.
 */
export interface AuthUser {
  user_id: string;

  username: string;

  roles: string[];
  permissions: string[];

  session_id: string;
}

/**
 * POST /api/v1/auth/login
 */
export interface LoginResponse {
  access_token: string;
  token_type: string;

  user: AuthUser;
}
