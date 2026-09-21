/**
 * ============================================================================
 * Asset API
 * SentinelSIEM SOC Dashboard
 * ============================================================================
 *
 * Feature-level API contract for Asset Management.
 *
 * Backend endpoints:
 *
 * GET    /api/v1/assets
 * GET    /api/v1/assets/{asset_id}
 * GET    /api/v1/assets/statistics
 * POST   /api/v1/assets
 * PATCH  /api/v1/assets/{asset_id}
 * PATCH  /api/v1/assets/{asset_id}/status
 *
 * DELETE is intentionally NOT supported.
 * ============================================================================
 */

import api from "../../services/api";

import type {
  Asset,
  AssetCreateRequest,
  AssetListParams,
  AssetListResponse,
  AssetStatisticsResponse,
  AssetStatusUpdateRequest,
  AssetUpdateRequest,
} from "./types";

/**
 * ============================================================================
 * List Assets
 * ============================================================================
 *
 * GET /api/v1/assets
 *
 * Permission:
 *   assets:read
 *
 * Supports:
 * - search
 * - asset_type
 * - status
 * - risk
 * - os
 * - environment
 * - page
 * - page_size
 */

export async function listAssets(
  params?: AssetListParams,
): Promise<AssetListResponse> {
  return api.listAssets(params);
}

/**
 * ============================================================================
 * Get Asset
 * ============================================================================
 *
 * GET /api/v1/assets/{asset_id}
 *
 * Permission:
 *   assets:read
 */

export async function getAsset(
  assetId: string,
): Promise<Asset> {
  return api.getAsset(assetId);
}

/**
 * ============================================================================
 * Create Asset
 * ============================================================================
 *
 * POST /api/v1/assets
 *
 * Permission:
 *   assets:manage
 *
 * Lifecycle status is NOT submitted here.
 *
 * Backend defaults:
 *   lifecycle_status   -> ENABLED
 *   operational_status -> UNKNOWN
 */

export async function createAsset(
  payload: AssetCreateRequest,
): Promise<Asset> {
  return api.createAsset(payload);
}

/**
 * ============================================================================
 * Update Asset
 * ============================================================================
 *
 * PATCH /api/v1/assets/{asset_id}
 *
 * Permission:
 *   assets:manage
 *
 * IMPORTANT:
 * Lifecycle status is intentionally NOT updated through this function.
 *
 * Use updateAssetStatus() for Enable / Disable operations.
 */

export async function updateAsset(
  assetId: string,
  payload: AssetUpdateRequest,
): Promise<Asset> {
  return api.updateAsset(
    assetId,
    payload,
  );
}

/**
 * ============================================================================
 * Update Asset Lifecycle Status
 * ============================================================================
 *
 * PATCH /api/v1/assets/{asset_id}/status
 *
 * Permission:
 *   assets:manage
 *
 * Supported lifecycle states:
 *   ENABLED
 *   DISABLED
 *
 * This is the ONLY frontend API function responsible for
 * enabling/disabling an asset.
 */

export async function updateAssetStatus(
  assetId: string,
  payload: AssetStatusUpdateRequest,
): Promise<Asset> {
  return api.updateAssetStatus(
    assetId,
    payload,
  );
}

/**
 * ============================================================================
 * Enable Asset
 * ============================================================================
 *
 * Convenience wrapper around the lifecycle status endpoint.
 *
 * PATCH /api/v1/assets/{asset_id}/status
 */

export async function enableAsset(
  assetId: string,
): Promise<Asset> {
  return updateAssetStatus(
    assetId,
    {
      lifecycle_status: "ENABLED",
    },
  );
}

/**
 * ============================================================================
 * Disable Asset
 * ============================================================================
 *
 * Convenience wrapper around the lifecycle status endpoint.
 *
 * PATCH /api/v1/assets/{asset_id}/status
 */

export async function disableAsset(
  assetId: string,
): Promise<Asset> {
  return updateAssetStatus(
    assetId,
    {
      lifecycle_status: "DISABLED",
    },
  );
}

/**
 * ============================================================================
 * Get Asset Statistics
 * ============================================================================
 *
 * GET /api/v1/assets/statistics
 *
 * Permission:
 *   assets:read
 */

export async function getAssetStatistics(): Promise<AssetStatisticsResponse> {
  return api.getAssetStatistics();
}

/**
 * ============================================================================
 * Named Assets API Object
 * ============================================================================
 *
 * Primary module-level API contract.
 *
 * Supported operations:
 *
 *   assetsApi.list()
 *   assetsApi.get()
 *   assetsApi.create()
 *   assetsApi.update()
 *   assetsApi.updateStatus()
 *   assetsApi.enable()
 *   assetsApi.disable()
 *   assetsApi.statistics()
 *
 * No delete/remove operation exists.
 */

export const assetsApi = {
  list: listAssets,

  get: getAsset,

  create: createAsset,

  update: updateAsset,

  updateStatus: updateAssetStatus,

  enable: enableAsset,

  disable: disableAsset,

  statistics: getAssetStatistics,
};

/**
 * ============================================================================
 * Backward-Compatible Singular API Object
 * ============================================================================
 *
 * Preserved for existing module consumers that use `assetApi`.
 *
 * IMPORTANT:
 * `delete` is intentionally NOT included.
 */

export const assetApi = {
  list: listAssets,

  get: getAsset,

  create: createAsset,

  update: updateAsset,

  updateStatus: updateAssetStatus,

  enable: enableAsset,

  disable: disableAsset,

  statistics: getAssetStatistics,
};

/**
 * ============================================================================
 * Default Export
 * ============================================================================
 *
 * Default export uses the plural Assets API contract.
 */

export default assetsApi;