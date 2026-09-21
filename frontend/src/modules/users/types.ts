/**
 * ============================================================================
 * SentinelSIEM — User Management Module Types
 * ============================================================================
 *
 * Canonical frontend contracts for the SentinelSIEM User Management module.
 *
 * Backend API namespace:
 *
 *   /api/v1/users
 *
 * Security boundary:
 * - Password hashes are never represented.
 * - Access tokens are never represented.
 * - Refresh tokens are never represented.
 * - JWTs are never represented.
 * - API keys are never represented.
 * - Client secrets are never represented.
 * - Session tokens are never represented.
 * - Credential material is never represented.
 *
 * Backend remains authoritative for:
 * - Authentication
 * - Authorization
 * - Role validation
 * - Password policy
 * - Session revocation
 * - Audit generation
 * - User-management invariants
 * - User-list total count
 * - User-list total page count
 * - Individual Audit total count
 * - Individual Audit statistics
 *
 * User pagination:
 *
 *   Default user page size = 30
 *   Maximum user page size = 200
 *
 * Individual Audit pagination:
 *
 *   Default UI page size = 30
 *   Maximum page size = 200
 *
 * Individual Audit filter contract:
 *
 *   Action
 *   Outcome
 *   Target
 *   Source IP
 *   From
 *   To
 *
 * Intentionally excluded from Individual Audit filter UI:
 *
 *   Actor
 *   Category
 *   Search
 *
 * Actor information remains available inside the audit event/detail model,
 * but is not exposed as a user-scoped filter.
 *
 * Individual Audit statistics:
 *
 *   total
 *   success
 *   failure
 *   denied
 *
 * IMPORTANT:
 *
 * Individual Audit statistics represent the COMPLETE FILTERED DATASET.
 *
 * They are NOT calculated from the current 30-row page.
 *
 * ============================================================================
 */

import type { Role } from "../../auth/rbac";


/* ============================================================================
 * Constants
 * ========================================================================== */

/**
 * Canonical User Management page size.
 *
 * The Users page requests 30 users at a time.
 */
export const DEFAULT_USER_PAGE_SIZE = 30;


/**
 * Maximum page size accepted by the backend User Management API.
 */
export const MAX_USER_PAGE_SIZE = 200;


/**
 * Canonical Individual User Audit page size.
 *
 * Individual Audit always requests 30 events per page.
 */
export const DEFAULT_USER_AUDIT_PAGE_SIZE = 30;


/**
 * Maximum Individual User Audit page size accepted by the frontend contract.
 *
 * The backend may enforce its own maximum independently.
 */
export const MAX_USER_AUDIT_PAGE_SIZE = 200;


/* ============================================================================
 * Primitive Types
 * ========================================================================== */

/**
 * Canonical ISO-8601 timestamp returned by the backend.
 */
export type ISODateString = string;


/**
 * Canonical SentinelSIEM user identifier.
 *
 * This is an identifier only.
 * It must never contain authentication secrets.
 */
export type UserId = string;


/**
 * Safe audit metadata.
 *
 * The backend is responsible for sanitizing metadata before returning it.
 *
 * Credential material must NEVER be included.
 */
export type AuditMetadata =
  Record<string, unknown>;


/* ============================================================================
 * User
 * ========================================================================== */

/**
 * Canonical public-safe SentinelSIEM user representation.
 *
 * Backend endpoints:
 *
 * GET    /api/v1/users
 * GET    /api/v1/users/{user_id}
 * POST   /api/v1/users
 * PATCH  /api/v1/users/{user_id}
 * PATCH  /api/v1/users/{user_id}/role
 * PATCH  /api/v1/users/{user_id}/active
 * PATCH  /api/v1/users/{user_id}/lock
 */
export interface User {
  /**
   * Canonical user identifier.
   */
  user_id: UserId;

  /**
   * Unique login username.
   *
   * NOTE:
   * The username remains part of the API/domain contract.
   * The Users table may intentionally hide the @username presentation.
   */
  username: string;

  /**
   * User email address.
   */
  email: string;

  /**
   * Canonical SentinelSIEM roles.
   *
   * The backend may technically return multiple roles.
   */
  roles: Role[];

  /**
   * Whether the account is currently enabled.
   */
  is_active: boolean;

  /**
   * Whether the account is currently locked.
   */
  is_locked: boolean;

  /**
   * Current failed-login count.
   */
  failed_login_count: number;

  /**
   * Optional human-readable display name.
   */
  display_name: string | null;

  /**
   * Whether the account must change its password.
   */
  force_password_change: boolean;

  /**
   * Timestamp of the last successful password change.
   */
  password_changed_at:
    ISODateString | null;

  /**
   * Timestamp of the last successful login.
   */
  last_login_at:
    ISODateString | null;

  /**
   * Account creation timestamp.
   */
  created_at: ISODateString;

  /**
   * Last account-record update timestamp.
   */
  updated_at: ISODateString;
}


/* ============================================================================
 * User List
 * ========================================================================== */

/**
 * GET /api/v1/users
 *
 * Backend-authoritative paginated user-directory response.
 *
 * IMPORTANT:
 *
 * `total` and `total_pages` describe the CURRENT FILTERED RESULT SET,
 * not necessarily the system-wide user statistics.
 */
export interface UserListResponse {
  /**
   * Users returned for the current page.
   */
  users: User[];

  /**
   * Total number of users matching the current filters.
   *
   * Backend authoritative.
   */
  total: number;

  /**
   * Total number of pages for the current filtered result set.
   *
   * Backend authoritative.
   */
  total_pages: number;

  /**
   * Page size used by the backend for this response.
   *
   * Normal Users UI value:
   *
   *   30
   */
  limit: number;

  /**
   * Number of records skipped.
   */
  offset: number;
}


/* ============================================================================
 * User List Query Parameters
 * ========================================================================== */

/**
 * User-directory query parameters.
 *
 * These map to the backend UserListQuery contract.
 */
export interface UserListParams {
  /**
   * Free-text search.
   *
   * Backend may search:
   * - username
   * - email
   * - display name
   */
  search?: string;

  /**
   * Filter by account state.
   *
   * true  = active
   * false = disabled
   */
  is_active?: boolean;

  /**
   * Filter by lock state.
   *
   * true  = locked
   * false = unlocked
   */
  is_locked?: boolean;

  /**
   * Filter by role.
   */
  role?: Role;

  /**
   * Filter by forced password-change state.
   */
  force_password_change?: boolean;

  /**
   * Maximum number of users to return.
   *
   * Users UI normally sends:
   *
   *   30
   */
  limit?: number;

  /**
   * Number of users to skip.
   */
  offset?: number;

  /**
   * Filter users created from this timestamp.
   */
  created_from?: ISODateString;

  /**
   * Filter users created until this timestamp.
   */
  created_to?: ISODateString;

  /**
   * Filter users whose last login occurred from this timestamp.
   */
  last_login_from?: ISODateString;

  /**
   * Filter users whose last login occurred until this timestamp.
   */
  last_login_to?: ISODateString;
}


/* ============================================================================
 * User Statistics
 * ========================================================================== */

/**
 * GET /api/v1/users/statistics
 *
 * System-wide user statistics.
 *
 * IMPORTANT:
 *
 * These statistics are separate from UserListResponse.total.
 *
 * UserListResponse.total is filter-aware.
 * UserStatistics.total is system-wide.
 */
export interface UserStatistics {
  /**
   * Total users.
   */
  total: number;

  /**
   * Active users.
   */
  active: number;

  /**
   * Disabled users.
   */
  disabled: number;

  /**
   * Locked users.
   */
  locked: number;
}


/* ============================================================================
 * Create User
 * ========================================================================== */

/**
 * POST /api/v1/users
 *
 * Permission:
 *
 *   users:manage
 */
export interface CreateUserRequest {
  /**
   * Login username.
   */
  username: string;

  /**
   * User email address.
   */
  email: string;

  /**
   * Initial plaintext password.
   *
   * SECURITY:
   *
   * - Exists only for request/form lifetime.
   * - Must never be persisted directly.
   * - Must never be logged.
   * - Must never be cached.
   * - Must never be included in audit metadata.
   */
  password: string;

  /**
   * Initial canonical RBAC role.
   */
  role: Role;

  /**
   * Optional initial account state.
   *
   * Backend controls defaults when omitted.
   */
  is_active?: boolean;

  /**
   * Optional human-readable display name.
   */
  display_name?: string;
}


/* ============================================================================
 * User Profile Update
 * ========================================================================== */

/**
 * PATCH /api/v1/users/{user_id}
 *
 * Profile-level editable fields.
 *
 * Security-sensitive fields intentionally do NOT belong here.
 *
 * Managed separately:
 *
 * - Role
 * - Active/disabled state
 * - Lock/unlock state
 * - Password
 * - Sessions
 */
export interface UpdateUserRequest {
  /**
   * Updated username.
   */
  username: string;

  /**
   * Updated email address.
   */
  email: string;

  /**
   * Optional updated display name.
   */
  display_name?: string | null;
}


/* ============================================================================
 * Role Management
 * ========================================================================== */

/**
 * PATCH /api/v1/users/{user_id}/role
 *
 * Permission:
 *
 *   users:manage
 */
export interface ChangeRoleRequest {
  /**
   * New canonical SentinelSIEM role.
   */
  role: Role;
}


/* ============================================================================
 * Account Active State
 * ========================================================================== */

/**
 * PATCH /api/v1/users/{user_id}/active
 *
 * Permission:
 *
 *   users:manage
 */
export interface SetActiveRequest {
  /**
   * true  -> enable user
   * false -> disable user
   */
  is_active: boolean;
}


/* ============================================================================
 * Account Lock State
 * ========================================================================== */

/**
 * PATCH /api/v1/users/{user_id}/lock
 *
 * Permission:
 *
 *   users:manage
 */
export interface SetLockedRequest {
  /**
   * true  -> lock user
   * false -> unlock user
   */
  is_locked: boolean;
}


/* ============================================================================
 * Force Password Change
 * ========================================================================== */

/**
 * Backend schema exists for force-password-change state.
 *
 * Dedicated route exposure remains controlled by the backend route contract.
 */
export interface SetForcePasswordChangeRequest {
  /**
   * true  -> force password change
   * false -> clear forced password-change state
   */
  force_password_change: boolean;
}


/* ============================================================================
 * Password Management
 * ========================================================================== */

/**
 * POST /api/v1/users/{user_id}/password/reset
 *
 * Permission:
 *
 *   users:manage
 */
export interface ResetPasswordRequest {
  /**
   * New plaintext password.
   *
   * SECURITY:
   *
   * - Never persist.
   * - Never log.
   * - Never cache.
   * - Never include in audit metadata.
   */
  new_password: string;
}


/**
 * Password reset result.
 */
export interface ResetPasswordResponse {
  /**
   * Whether the operation succeeded.
   */
  success: boolean;

  /**
   * Safe human-readable result.
   */
  message: string;

  /**
   * Number of sessions revoked because of the reset.
   */
  sessions_revoked: number;
}


/* ============================================================================
 * Session Management
 * ========================================================================== */

/**
 * Safe active-session representation.
 *
 * SECURITY:
 *
 * This interface intentionally contains no session secret/token.
 */
export interface Session {
  /**
   * Application/session record identifier.
   *
   * IMPORTANT:
   *
   * This is NOT a session token.
   */
  session_id: string;

  /**
   * User associated with this session.
   */
  user_id: UserId;

  /**
   * Session creation timestamp.
   */
  created_at: ISODateString;

  /**
   * Session expiration timestamp.
   */
  expires_at: ISODateString;

  /**
   * Session revocation timestamp.
   *
   * null means it has not been revoked.
   */
  revoked_at: ISODateString | null;

  /**
   * Source IP address, when available.
   */
  ip_address: string | null;

  /**
   * User-Agent, when available.
   */
  user_agent: string | null;

  /**
   * Whether this session is currently active.
   */
  is_active: boolean;
}


/**
 * Session collection response.
 */
export interface SessionListResponse {
  /**
   * Sessions associated with the user.
   */
  sessions: Session[];
}


/**
 * POST /api/v1/users/{user_id}/sessions/revoke
 *
 * Permission:
 *
 *   users:manage
 */
export interface RevokeSessionsResponse {
  /**
   * Whether the operation succeeded.
   */
  success: boolean;

  /**
   * Safe human-readable operation result.
   */
  message: string;

  /**
   * Number of sessions revoked.
   */
  revoked_count: number;
}


/* ============================================================================
 * User Audit
 * ========================================================================== */

/**
 * Canonical audit outcome.
 *
 * Kept as string intentionally so backend additions do not immediately
 * require frontend type migration.
 */
export type UserAuditOutcome = string;


/**
 * Canonical audit action.
 *
 * Examples:
 *
 * authentication.login_success
 * authentication.login_failure
 * authentication.logout
 * users.created
 * users.updated
 * users.deleted
 * users.role_changed
 * users.enabled
 * users.disabled
 * users.locked
 * users.unlocked
 * users.password_reset
 * users.sessions_revoked
 * users.listed
 * users.viewed
 * users.statistics_viewed
 */
export type UserAuditAction = string;


/**
 * Safe user-related audit event.
 *
 * This represents the backend audit event returned by:
 *
 *   GET /api/v1/users/{user_id}/audit
 *
 * IMPORTANT:
 *
 * Actor remains part of the event data for investigation/detail purposes.
 * Actor is NOT part of UserAuditListParams and is NOT exposed as an
 * Individual Audit filter.
 */
export interface UserAuditEvent {
  /**
   * Optional backend audit identifier.
   */
  audit_id?: string | null;

  /**
   * Canonical audit action.
   */
  action: UserAuditAction;

  /**
   * Audit outcome.
   */
  outcome: UserAuditOutcome;

  /**
   * Audit category.
   *
   * Retained as event/detail data.
   * Not exposed as an Individual Audit filter.
   */
  category: string | null;

  /**
   * User who performed the action.
   *
   * null = no authenticated actor.
   *
   * Retained for event details.
   * Not exposed as a filter.
   */
  actor_user_id: UserId | null;

  /**
   * User affected by the action.
   *
   * This field is also used by the Individual Audit Target filter.
   */
  target_user_id: UserId | null;

  /**
   * Optional session record identifier.
   *
   * IMPORTANT:
   *
   * This is an identifier only.
   * It is NOT a session token.
   */
  session_id?: string | null;

  /**
   * Request correlation identifier.
   */
  request_id: string | null;

  /**
   * Source IP address.
   *
   * This field is also used by the Individual Audit Source IP filter.
   */
  source_ip: string | null;

  /**
   * Backend-sanitized contextual metadata.
   *
   * Credential material must never be returned.
   */
  metadata: AuditMetadata;

  /**
   * Canonical event timestamp.
   */
  timestamp: ISODateString;
}


/* ============================================================================
 * Individual User Audit Statistics
 * ========================================================================== */

/**
 * Backend-authoritative Individual User Audit statistics.
 *
 * IMPORTANT:
 *
 * These statistics represent the COMPLETE FILTERED DATASET.
 *
 * They are NOT calculated from the current page.
 *
 * Example:
 *
 *   total   = 143
 *   success = 30
 *   failure = 113
 *   denied  = 0
 *
 * If the user changes from page 1 to page 2 without changing filters,
 * these values remain the same.
 *
 * If the user changes Action, Outcome, Target, Source IP, From, or To,
 * these values must be refreshed from the backend.
 */
export interface UserAuditStatistics {
  /**
   * Total number of audit events matching the current filters.
   *
   * This must match UserAuditListResponse.total.
   */
  total: number;

  /**
   * Total successful events matching the current filters.
   *
   * This is NOT limited to the current page.
   */
  success: number;

  /**
   * Total failed events matching the current filters.
   *
   * This is NOT limited to the current page.
   */
  failure: number;

  /**
   * Total denied events matching the current filters.
   *
   * This is NOT limited to the current page.
   */
  denied: number;
}


/* ============================================================================
 * User Audit List
 * ========================================================================== */

/**
 * GET /api/v1/users/{user_id}/audit
 *
 * Backend-authoritative paginated Individual User Audit response.
 *
 * Response contract:
 *
 *   activities
 *   total
 *   limit
 *   offset
 *   statistics
 *
 * IMPORTANT:
 *
 * `activities` contains ONLY the current page.
 *
 * `statistics` describes the COMPLETE FILTERED RESULT SET.
 */
export interface UserAuditListResponse {
  /**
   * Audit events associated with the selected user.
   *
   * Only the current page is returned.
   *
   * Normal UI page size:
   *
   *   30
   */
  activities: UserAuditEvent[];

  /**
   * Total number of audit events matching the current filters.
   *
   * Backend authoritative.
   *
   * This is NOT the number of events in `activities`.
   */
  total: number;

  /**
   * Requested/returned page size.
   *
   * Individual Audit UI uses:
   *
   *   30
   */
  limit: number;

  /**
   * Number of records skipped.
   *
   * Example:
   *
   * Page 1 = 0
   * Page 2 = 30
   * Page 3 = 60
   */
  offset: number;

  /**
   * Backend-authoritative statistics for the COMPLETE FILTERED DATASET.
   *
   * Do NOT calculate these values from `activities`.
   */
  statistics: UserAuditStatistics;
}


/* ============================================================================
 * Individual User Audit Filter Contract
 * ========================================================================== */

/**
 * GET /api/v1/users/{user_id}/audit
 *
 * Individual Audit query parameters.
 *
 * FINAL UI CONTRACT:
 *
 *   Action
 *   Outcome
 *   Target
 *   Source IP
 *   From
 *   To
 *
 * INTENTIONALLY EXCLUDED:
 *
 *   Actor
 *   Category
 *   Search
 *
 * Filter changes are applied immediately by the frontend.
 *
 * Filter changes MUST reset:
 *
 *   page = 1
 *
 * Normal request:
 *
 *   page_size = 30
 */
export interface UserAuditListParams {
  /**
   * Filter by audit action.
   *
   * Example:
   *
   *   users.listed
   *   users.updated
   *   authentication.login_success
   */
  action?: UserAuditAction;

  /**
   * Filter by audit outcome.
   *
   * Canonical values commonly include:
   *
   *   success
   *   failure
   *   denied
   */
  outcome?: UserAuditOutcome;

  /**
   * Filter by target user.
   *
   * The value is the canonical backend user UUID.
   *
   * The UI label is resolved from User Management data.
   */
  target_user_id?: UserId;

  /**
   * Filter by source IP address.
   *
   * Example:
   *
   *   127.0.0.1
   */
  source_ip?: string;

  /**
   * Return events from this timestamp onward.
   */
  date_from?: ISODateString;

  /**
   * Return events until this timestamp.
   */
  date_to?: ISODateString;

  /**
   * Audit page number.
   *
   * Individual Audit UI starts from:
   *
   *   1
   *
   * Filter changes should reset this to:
   *
   *   1
   */
  page?: number;

  /**
   * Number of audit events per page.
   *
   * Individual Audit UI uses:
   *
   *   30
   */
  page_size?: number;
}


/* ============================================================================
 * Audit Presentation Model
 * ========================================================================== */

/**
 * Presentation-layer representation of an audit event.
 *
 * IMPORTANT:
 *
 * This is derived from UserAuditEvent.
 * It does not replace the canonical backend contract.
 */
export interface UserAuditEventView {
  /**
   * Original backend event.
   */
  event: UserAuditEvent;

  /**
   * Human-readable event title.
   *
   * Example:
   *
   *   "Role Changed"
   */
  title: string;

  /**
   * Human-readable event description.
   */
  description: string;

  /**
   * UI severity.
   */
  severity:
    | "info"
    | "success"
    | "warning"
    | "critical";

  /**
   * Whether the event represents a successful operation.
   */
  is_success: boolean;
}


/* ============================================================================
 * Generic Mutation Response
 * ========================================================================== */

/**
 * Generic successful user-management mutation.
 *
 * Useful for operations where the backend does not need to return the
 * complete User object.
 */
export interface UserMutationResponse {
  /**
   * Whether the operation succeeded.
   */
  success: boolean;

  /**
   * Safe human-readable result.
   */
  message: string;
}


/* ============================================================================
 * User Delete
 * ========================================================================== */

/**
 * DELETE /api/v1/users/{user_id}
 *
 * Permission:
 *
 *   users:manage
 */
export interface DeleteUserResponse {
  /**
   * Whether deletion succeeded.
   */
  success: boolean;

  /**
   * Safe operation result.
   */
  message: string;
}


/* ============================================================================
 * User Pagination Helpers
 * ========================================================================== */

/**
 * Calculate the first visible item number for a current backend page.
 *
 * Example:
 *
 *   offset = 0
 *   users.length = 30
 *
 *   first item = 1
 */
export function getUserPageFirstItem(
  offset: number,
  userCount: number,
): number {
  if (userCount <= 0) {
    return 0;
  }

  return offset + 1;
}


/**
 * Calculate the last visible item number for a current backend page.
 *
 * Example:
 *
 *   offset = 30
 *   users.length = 30
 *
 *   last item = 60
 */
export function getUserPageLastItem(
  offset: number,
  userCount: number,
): number {
  if (userCount <= 0) {
    return 0;
  }

  return offset + userCount;
}


/**
 * Determine whether a previous backend page exists.
 *
 * The frontend only needs the current offset.
 */
export function hasPreviousUserPage(
  offset: number,
): boolean {
  return offset > 0;
}


/**
 * Determine whether a next backend page exists.
 *
 * Backend total_pages is authoritative for User Management pagination.
 */
export function hasNextUserPage(
  pageNumber: number,
  totalPages: number,
): boolean {
  return (
    totalPages > 0 &&
    pageNumber < totalPages
  );
}


/* ============================================================================
 * Individual Audit Pagination Helpers
 * ========================================================================== */

/**
 * Calculate the current Individual Audit page from offset/page size.
 *
 * Example:
 *
 *   offset = 0
 *   page_size = 30
 *
 *   page = 1
 */
export function getUserAuditPageNumber(
  offset: number,
  pageSize: number =
    DEFAULT_USER_AUDIT_PAGE_SIZE,
): number {
  if (
    pageSize <= 0 ||
    offset < 0
  ) {
    return 1;
  }

  return (
    Math.floor(
      offset / pageSize,
    ) + 1
  );
}


/**
 * Calculate total Individual Audit pages from backend total.
 *
 * Backend returns `total`.
 *
 * Example:
 *
 *   total = 94
 *   page_size = 30
 *
 *   total pages = 4
 */
export function getUserAuditTotalPages(
  total: number,
  pageSize: number =
    DEFAULT_USER_AUDIT_PAGE_SIZE,
): number {
  if (
    total <= 0 ||
    pageSize <= 0
  ) {
    return 0;
  }

  return Math.ceil(
    total / pageSize,
  );
}


/**
 * Calculate the first visible Individual Audit item.
 *
 * Example:
 *
 *   offset = 30
 *   activities.length = 30
 *
 *   first item = 31
 */
export function getUserAuditPageFirstItem(
  offset: number,
  activityCount: number,
): number {
  if (activityCount <= 0) {
    return 0;
  }

  return offset + 1;
}


/**
 * Calculate the last visible Individual Audit item.
 *
 * Example:
 *
 *   offset = 30
 *   activities.length = 30
 *
 *   last item = 60
 */
export function getUserAuditPageLastItem(
  offset: number,
  activityCount: number,
): number {
  if (activityCount <= 0) {
    return 0;
  }

  return offset + activityCount;
}


/**
 * Determine whether a previous Individual Audit page exists.
 */
export function hasPreviousUserAuditPage(
  page: number,
): boolean {
  return page > 1;
}


/**
 * Determine whether a next Individual Audit page exists.
 *
 * The total count comes from the backend response.
 */
export function hasNextUserAuditPage(
  page: number,
  totalPages: number,
): boolean {
  return (
    totalPages > 0 &&
    page < totalPages
  );
}


/**
 * Create a clean Individual Audit pagination request.
 *
 * Filter changes should call this with page = 1.
 *
 * The canonical page size is always 30.
 */
export function buildUserAuditPageParams(
  filters: UserAuditListParams,
  page: number,
): UserAuditListParams {
  return {
    ...filters,
    page:
      page > 0
        ? page
        : 1,
    page_size:
      DEFAULT_USER_AUDIT_PAGE_SIZE,
  };
}


/* ============================================================================
 * Individual Audit Statistics Helpers
 * ========================================================================== */

/**
 * Create safe default Individual Audit statistics.
 *
 * Useful for initial/loading UI state.
 */
export function createEmptyUserAuditStatistics(): UserAuditStatistics {
  return {
    total: 0,
    success: 0,
    failure: 0,
    denied: 0,
  };
}


/**
 * Validate basic Individual Audit statistics consistency.
 *
 * The backend remains authoritative.
 *
 * This helper is only for frontend defensive validation and must NOT be used
 * to calculate statistics from the current page.
 */
export function isValidUserAuditStatistics(
  statistics: UserAuditStatistics,
): boolean {
  if (
    statistics.total < 0 ||
    statistics.success < 0 ||
    statistics.failure < 0 ||
    statistics.denied < 0
  ) {
    return false;
  }

  const counted =
    statistics.success
    + statistics.failure
    + statistics.denied;

  return counted <= statistics.total;
}


/**
 * Return the backend-authoritative statistics from an audit response.
 *
 * This helper intentionally does not calculate anything from `activities`.
 */
export function getUserAuditStatistics(
  response: UserAuditListResponse,
): UserAuditStatistics {
  return response.statistics;
}


/* ============================================================================
 * Backward Compatibility
 * ========================================================================== */

/**
 * Legacy activity name.
 *
 * New code should use UserAuditEvent.
 */
export type UserActivity =
  UserAuditEvent;


/**
 * Legacy activity-list response name.
 *
 * New code should use UserAuditListResponse.
 */
export type UserActivityListResponse =
  UserAuditListResponse;


/**
 * Legacy statistics alias.
 *
 * New code should use UserAuditStatistics.
 */
export type UserAuditStats =
  UserAuditStatistics;


/* ============================================================================
 * Public API
 * ========================================================================== */

export type { Role };