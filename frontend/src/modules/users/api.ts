/**
 * ============================================================================
 * SentinelSIEM — User Management Module API
 * ============================================================================
 *
 * Feature-level API boundary for the SentinelSIEM User Management module.
 *
 * Architecture
 * ------------
 *
 *   Users Pages / Components
 *            |
 *            v
 *   modules/users/api.ts
 *            |
 *            v
 *   services/api.ts
 *            |
 *            v
 *   /api/v1/users/*
 *
 * Responsibilities
 * ----------------
 *
 * This module:
 *
 *   - exposes the User Management feature API
 *   - provides strongly typed request/response boundaries
 *   - delegates HTTP transport to the shared API client
 *   - keeps Users components independent from the global API client
 *   - keeps User Management API calls centralized
 *
 * This module does NOT:
 *
 *   - implement authentication
 *   - implement authorization
 *   - implement RBAC policy
 *   - implement business/security rules
 *   - store credentials
 *   - store access/refresh tokens
 *   - validate passwords
 *   - make authorization decisions
 *
 * Backend remains the authoritative security boundary.
 *
 * ============================================================================
 */

import { api as sharedApi } from "../../services/api";

import type {
  ChangeRoleRequest,
  CreateUserRequest,
  DeleteUserResponse,
  RevokeSessionsResponse,
  ResetPasswordRequest,
  ResetPasswordResponse,
  SetActiveRequest,
  SetForcePasswordChangeRequest,
  SetLockedRequest,
  UpdateUserRequest,
  User,
  UserAuditListResponse,
  UserListParams,
  UserListResponse,
  UserStatistics,
} from "./types";


/* ============================================================================
 * Constants
 * ========================================================================== */

/**
 * Canonical Individual User Audit page size.
 */
export const USER_AUDIT_PAGE_SIZE = 30;


/**
 * First Individual User Audit page.
 */
export const USER_AUDIT_FIRST_PAGE = 1;


/* ============================================================================
 * Individual User Audit Parameters
 * ========================================================================== */

/**
 * Canonical Individual User Audit request contract.
 *
 * IMPORTANT
 * ---------
 *
 * Backend Individual User Audit is page-based.
 *
 * Therefore:
 *
 *   page
 *   page_size
 *
 * are passed through to services/api.ts.
 *
 * NO limit/offset conversion happens here.
 */
export interface UserAuditApiParams {
  page?: number;
  page_size?: number;

  action?: string;
  outcome?: string;
  target_user_id?: string;
  source_ip?: string;
  date_from?: string;
  date_to?: string;
}


/* ============================================================================
 * Users API
 * ========================================================================== */

export const usersApi = {

  /* ==========================================================================
   * User Listing
   * ======================================================================== */

  list(
    params?: UserListParams,
  ): Promise<UserListResponse> {
    return sharedApi.listUsers(
      params,
    );
  },


  /* ==========================================================================
   * User Details
   * ======================================================================== */

  get(
    userId: string,
  ): Promise<User> {
    return sharedApi.getUser(
      userId,
    );
  },


  /* ==========================================================================
   * User Creation
   * ======================================================================== */

  create(
    payload: CreateUserRequest,
  ): Promise<User> {
    return sharedApi.createUser(
      payload,
    );
  },


  /* ==========================================================================
   * Profile Update
   * ======================================================================== */

  update(
    userId: string,
    payload: UpdateUserRequest,
  ): Promise<User> {
    return sharedApi.updateUser(
      userId,
      payload,
    );
  },


  /* ==========================================================================
   * Role Management
   * ======================================================================== */

  changeRole(
    userId: string,
    payload: ChangeRoleRequest,
  ): Promise<User> {
    return sharedApi.changeUserRole(
      userId,
      payload,
    );
  },


  /* ==========================================================================
   * Account Active State
   * ======================================================================== */

  setActive(
    userId: string,
    payload: SetActiveRequest,
  ): Promise<User> {
    return sharedApi.setUserActive(
      userId,
      payload,
    );
  },


  /* ==========================================================================
   * Account Lock State
   * ======================================================================== */

  setLocked(
    userId: string,
    payload: SetLockedRequest,
  ): Promise<User> {
    return sharedApi.setUserLocked(
      userId,
      payload,
    );
  },


  /* ==========================================================================
   * Force Password Change
   * ======================================================================== */

  setForcePasswordChange(
    userId: string,
    payload: SetForcePasswordChangeRequest,
  ): Promise<User> {
    return sharedApi.setForcePasswordChange(
      userId,
      payload,
    );
  },


  /* ==========================================================================
   * Password Reset
   * ======================================================================== */

  resetPassword(
    userId: string,
    payload: ResetPasswordRequest,
  ): Promise<ResetPasswordResponse> {
    return sharedApi.resetUserPassword(
      userId,
      payload,
    );
  },


  /* ==========================================================================
   * Session Management
   * ======================================================================== */

  revokeSessions(
    userId: string,
  ): Promise<RevokeSessionsResponse> {
    return sharedApi.revokeUserSessions(
      userId,
    );
  },


  /* ==========================================================================
   * User Deletion
   * ======================================================================== */

  remove(
    userId: string,
  ): Promise<DeleteUserResponse> {
    return sharedApi.deleteUser(
      userId,
    );
  },


  /* ==========================================================================
   * User Statistics
   * ======================================================================== */

  statistics(): Promise<UserStatistics> {
    return sharedApi.getUserStatistics();
  },


  /* ==========================================================================
   * Individual User Audit
   * ======================================================================== */

  /**
   * GET /api/v1/users/{user_id}/audit
   *
   * Canonical backend contract:
   *
   *   page
   *   page_size
   *
   * Examples:
   *
   *   page=1&page_size=30
   *   page=2&page_size=30
   *   page=3&page_size=30
   *
   * IMPORTANT
   * ---------
   *
   * Do NOT convert these values to limit/offset here.
   *
   * The backend AuditService itself owns:
   *
   *   offset = (page - 1) * page_size
   *
   * and the repository applies the resulting offset.
   */
  audit(
    userId: string,
    params?: UserAuditApiParams,
  ): Promise<UserAuditListResponse> {
    return sharedApi.getUserAudit(
      userId,
      params,
    );
  },

} as const;


/* ============================================================================
 * Named API Functions
 * ========================================================================== */

export function listUsers(
  params?: UserListParams,
): Promise<UserListResponse> {
  return usersApi.list(
    params,
  );
}


export function getUser(
  userId: string,
): Promise<User> {
  return usersApi.get(
    userId,
  );
}


export function createUser(
  payload: CreateUserRequest,
): Promise<User> {
  return usersApi.create(
    payload,
  );
}


export function updateUser(
  userId: string,
  payload: UpdateUserRequest,
): Promise<User> {
  return usersApi.update(
    userId,
    payload,
  );
}


export function changeUserRole(
  userId: string,
  payload: ChangeRoleRequest,
): Promise<User> {
  return usersApi.changeRole(
    userId,
    payload,
  );
}


export function setUserActive(
  userId: string,
  payload: SetActiveRequest,
): Promise<User> {
  return usersApi.setActive(
    userId,
    payload,
  );
}


export function setUserLocked(
  userId: string,
  payload: SetLockedRequest,
): Promise<User> {
  return usersApi.setLocked(
    userId,
    payload,
  );
}


export function setForcePasswordChange(
  userId: string,
  payload: SetForcePasswordChangeRequest,
): Promise<User> {
  return usersApi.setForcePasswordChange(
    userId,
    payload,
  );
}


export function resetUserPassword(
  userId: string,
  payload: ResetPasswordRequest,
): Promise<ResetPasswordResponse> {
  return usersApi.resetPassword(
    userId,
    payload,
  );
}


export function revokeUserSessions(
  userId: string,
): Promise<RevokeSessionsResponse> {
  return usersApi.revokeSessions(
    userId,
  );
}


export function deleteUser(
  userId: string,
): Promise<DeleteUserResponse> {
  return usersApi.remove(
    userId,
  );
}


export function getUserStatistics(): Promise<UserStatistics> {
  return usersApi.statistics();
}


/**
 * Retrieve Individual User Audit History.
 *
 * Canonical pagination:
 *
 *   page
 *   page_size
 *
 * Example:
 *
 *   getUserAudit(
 *     userId,
 *     {
 *       page: 1,
 *       page_size: 30,
 *     },
 *   );
 *
 *   getUserAudit(
 *     userId,
 *     {
 *       page: 2,
 *       page_size: 30,
 *     },
 *   );
 */
export function getUserAudit(
  userId: string,
  params?: UserAuditApiParams,
): Promise<UserAuditListResponse> {
  return usersApi.audit(
    userId,
    params,
  );
}


/* ============================================================================
 * Public API Type
 * ========================================================================== */

export type UsersApi =
  typeof usersApi;


/* ============================================================================
 * Default Export
 * ========================================================================== */

export default usersApi;