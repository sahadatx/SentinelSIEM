/**
 * ============================================================
 * SentinelSIEM — System Module Types
 * ============================================================
 *
 * Module-level types for the System feature.
 *
 * Backend:
 *   GET /api/v1/system
 *
 * Global API contract:
 *   frontend/src/types/api.ts
 * ============================================================
 */

import type { SystemResponse } from "../../types/api";

/**
 * System information returned by the backend.
 *
 * This intentionally reuses the shared API contract instead
 * of duplicating the response structure.
 */
export type SystemInfo = SystemResponse;

/**
 * System capability displayed by the System module.
 *
 * The backend currently returns capability names as strings,
 * therefore we keep this type open rather than hard-coding
 * a union that could become outdated when new capabilities
 * are added on the backend.
 */
export type SystemCapability = string;

/**
 * Props shared by System presentation components.
 */
export interface SystemComponentProps {
  system: SystemInfo;
}

/**
 * Props for components that may display loading state.
 */
export interface SystemLoadingProps {
  loading?: boolean;
}

/**
 * Props for components that may display an error state.
 */
export interface SystemErrorProps {
  error?: string | null;
}
