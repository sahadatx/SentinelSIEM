import { PERMISSIONS } from "../../auth/rbac";

/**
 * Events module read permission.
 *
 * Backend / RBAC contract:
 *   events:read
 */
export const EVENTS_READ =
  PERMISSIONS.EVENTS_READ;

/**
 * Backward-compatible descriptive alias.
 */
export const EVENT_PERMISSION =
  EVENTS_READ;

/**
 * Events module permissions.
 */
export const EVENTS_PERMISSIONS = {
  read: EVENTS_READ,
} as const;