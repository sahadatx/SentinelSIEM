/**
 * ============================================================
 * SentinelSIEM — System Module API
 * ============================================================
 *
 * Module-level API functions for the System feature.
 *
 * Backend:
 *   GET /api/v1/system
 *
 * The shared HTTP client remains centralized in:
 *   frontend/src/services/api.ts
 * ============================================================
 */

import api from "../../services/api";

import type { SystemInfo } from "./types";

/**
 * Fetch public SentinelSIEM system information.
 *
 * Backend endpoint:
 *   GET /api/v1/system
 *
 * Returns:
 *   - service
 *   - version
 *   - environment
 *   - capabilities
 */
export async function getSystemInfo(): Promise<SystemInfo> {
  return api.system();
}
