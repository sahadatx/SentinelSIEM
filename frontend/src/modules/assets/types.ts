/**
 * ============================================================================
 * Asset Management Module Types
 * SentinelSIEM SOC Dashboard
 * ============================================================================
 *
 * Frontend types are intentionally aligned with the current backend Asset API.
 *
 * Backend endpoints:
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

/**
 * ============================================================================
 * Asset Type
 * ============================================================================
 */

export type AssetType =
  | "SERVER"
  | "WORKSTATION"
  | "LAPTOP"
  | "DESKTOP"
  | "NETWORK_DEVICE"
  | "ROUTER"
  | "SWITCH"
  | "FIREWALL"
  | "LOAD_BALANCER"
  | "DATABASE"
  | "WEB_SERVER"
  | "APPLICATION_SERVER"
  | "MAIL_SERVER"
  | "DNS_SERVER"
  | "PROXY_SERVER"
  | "VIRTUAL_MACHINE"
  | "CONTAINER"
  | "CLOUD_RESOURCE"
  | "STORAGE"
  | "IOT_DEVICE"
  | "SECURITY_APPLIANCE"
  | "OTHER";

/**
 * ============================================================================
 * Lifecycle Status
 * ============================================================================
 *
 * Lifecycle status is intentionally separate from operational status.
 *
 * ENABLED  -> Asset is enabled in the inventory.
 * DISABLED -> Asset is disabled in the inventory.
 */

export type AssetLifecycleStatus =
  | "ENABLED"
  | "DISABLED";

/**
 * ============================================================================
 * Operational Status
 * ============================================================================
 *
 * Operational status describes the current operational condition.
 *
 * IMPORTANT:
 * DISABLED is NOT an operational status.
 * OFFLINE is NOT the same as DISABLED.
 */

export type AssetOperationalStatus =
  | "ONLINE"
  | "OFFLINE"
  | "UNKNOWN"
  | "MAINTENANCE";

/**
 * ============================================================================
 * Backward-compatible semantic status type
 * ============================================================================
 *
 * Used where a component needs a generic "status" filter.
 *
 * The backend accepts the same `status` query parameter for:
 * - lifecycle status
 * - operational status
 */

export type AssetStatus =
  | AssetLifecycleStatus
  | AssetOperationalStatus;

/**
 * ============================================================================
 * Asset Risk
 * ============================================================================
 */

export type AssetRisk =
  | "CRITICAL"
  | "HIGH"
  | "MEDIUM"
  | "LOW"
  | "INFORMATIONAL";

/**
 * ============================================================================
 * Operating System
 * ============================================================================
 */

export type AssetOperatingSystem =
  | "WINDOWS"
  | "WINDOWS_SERVER"
  | "LINUX"
  | "UBUNTU"
  | "DEBIAN"
  | "CENTOS"
  | "RHEL"
  | "FEDORA"
  | "ROCKY_LINUX"
  | "ALMALINUX"
  | "KALI_LINUX"
  | "MACOS"
  | "FREEBSD"
  | "ANDROID"
  | "IOS"
  | "NETWORK_OS"
  | "OTHER";

/**
 * ============================================================================
 * Environment
 * ============================================================================
 */

export type AssetEnvironment =
  | "PRODUCTION"
  | "STAGING"
  | "DEVELOPMENT"
  | "TESTING"
  | "QA"
  | "UAT"
  | "DISASTER_RECOVERY"
  | "OTHER";

/**
 * ============================================================================
 * Asset
 * ============================================================================
 *
 * Public SentinelSIEM asset representation.
 */

export interface Asset {
  asset_id: string;

  name: string;

  hostname: string | null;

  ip_address: string;

  mac_address: string | null;

  asset_type: string;

  operating_system: string | null;

  environment: string | null;

  risk: AssetRisk;

  lifecycle_status: AssetLifecycleStatus;

  operational_status: AssetOperationalStatus;

  owner: string | null;

  location: string | null;

  tags: string[];

  description: string | null;

  metadata: Record<string, unknown>;

  first_seen: string | null;

  last_seen: string | null;

  created_at: string;

  updated_at: string;
}

/**
 * ============================================================================
 * Asset List Query
 * ============================================================================
 *
 * Backend:
 *
 * GET /api/v1/assets
 *
 * Pagination:
 * - page
 * - page_size
 *
 * Filtering:
 * - search
 * - asset_type
 * - status
 * - risk
 * - os
 * - environment
 *
 * Search applies only to:
 * - Asset Name
 * - Hostname
 * - IP Address
 * - MAC Address
 *
 * NOTE:
 * `owner` is intentionally NOT a supported search/filter parameter.
 */

export interface AssetListParams {
  search?: string;

  asset_type?: string;

  status?: AssetStatus;

  risk?: AssetRisk;

  os?: string;

  environment?: string;

  page?: number;

  page_size?: number;
}

/**
 * ============================================================================
 * Asset List Response
 * ============================================================================
 *
 * Backend response:
 *
 * {
 *   items: Asset[],
 *   total: number,
 *   page: number,
 *   page_size: number,
 *   total_pages: number
 * }
 */

export interface AssetListResponse {
  items: Asset[];

  total: number;

  page: number;

  page_size: number;

  total_pages: number;
}

/**
 * ============================================================================
 * Asset Pagination
 * ============================================================================
 */

export interface AssetPagination {
  total: number;

  page: number;

  page_size: number;

  total_pages: number;
}

/**
 * ============================================================================
 * Asset Statistics
 * ============================================================================
 *
 * Backend:
 * GET /api/v1/assets/statistics
 */

export interface AssetStatisticsResponse {
  total: number;

  enabled: number;

  disabled: number;

  critical: number;

  by_type: Record<string, number>;

  by_risk: Record<string, number>;

  by_lifecycle_status: Record<string, number>;

  by_operational_status: Record<string, number>;
}

/**
 * Backward-compatible alias.
 */

export type AssetStatistics = AssetStatisticsResponse;

/**
 * ============================================================================
 * Asset Create Request
 * ============================================================================
 *
 * Backend:
 * POST /api/v1/assets
 *
 * Lifecycle status and operational status are NOT submitted here.
 *
 * Backend defaults:
 * lifecycle_status   -> ENABLED
 * operational_status -> UNKNOWN
 */

export interface AssetCreateRequest {
  name: string;

  asset_type: string;

  hostname?: string | null;

  ip_address: string;

  mac_address?: string | null;

  operating_system?: string | null;

  environment?: string | null;

  risk?: AssetRisk;

  owner?: string | null;

  location?: string | null;

  tags?: string[];

  description?: string | null;

  metadata?: Record<string, unknown>;
}

/**
 * ============================================================================
 * Asset Update Request
 * ============================================================================
 *
 * Backend:
 * PATCH /api/v1/assets/{asset_id}
 *
 * IMPORTANT:
 * Lifecycle status MUST NOT be changed through this endpoint.
 *
 * Status changes use:
 *
 * PATCH /api/v1/assets/{asset_id}/status
 */

export interface AssetUpdateRequest {
  name?: string;

  hostname?: string | null;

  ip_address?: string;

  mac_address?: string | null;

  asset_type?: string;

  operating_system?: string | null;

  environment?: string | null;

  risk?: AssetRisk;

  owner?: string | null;

  location?: string | null;

  tags?: string[];

  description?: string | null;

  metadata?: Record<string, unknown>;
}

/**
 * ============================================================================
 * Asset Status Update Request
 * ============================================================================
 *
 * Backend:
 * PATCH /api/v1/assets/{asset_id}/status
 *
 * Only lifecycle status is changed here.
 */

export interface AssetStatusUpdateRequest {
  lifecycle_status: AssetLifecycleStatus;
}

/**
 * ============================================================================
 * Asset Mutation Response
 * ============================================================================
 *
 * Generic mutation response for frontend operations.
 *
 * Actual POST/PATCH asset endpoints return the updated Asset object,
 * so this interface is primarily useful for future mutation wrappers.
 */

export interface AssetMutationResponse {
  success: boolean;

  message: string;
}

/**
 * ============================================================================
 * Asset Form Values
 * ============================================================================
 *
 * Frontend create/edit form state.
 *
 * React inputs remain controlled using strings.
 *
 * Lifecycle status is intentionally excluded because:
 *
 * - Create defaults to ENABLED.
 * - Edit must not change lifecycle status.
 * - Enable/Disable has a dedicated operation.
 */

export interface AssetFormValues {
  name: string;

  asset_type: string;

  hostname: string;

  ip_address: string;

  mac_address: string;

  operating_system: string;

  environment: string;

  risk: AssetRisk;

  owner: string;

  location: string;

  tags: string[];

  description: string;

  metadata: Record<string, unknown>;
}

/**
 * ============================================================================
 * Asset Filter Values
 * ============================================================================
 *
 * Empty strings represent "no filter".
 *
 * Filter changes should immediately trigger a new backend request.
 */

export interface AssetFilterValues {
  search: string;

  asset_type: string;

  status: AssetStatus | "";

  risk: AssetRisk | "";

  os: string;

  environment: string;
}

/**
 * ============================================================================
 * Asset Editable Fields
 * ============================================================================
 *
 * Lifecycle status is intentionally excluded.
 *
 * Operational status is also excluded because the current Asset Edit
 * workflow does not modify operational state.
 */

export type AssetEditableField =
  | "name"
  | "hostname"
  | "ip_address"
  | "mac_address"
  | "asset_type"
  | "operating_system"
  | "environment"
  | "risk"
  | "owner"
  | "location"
  | "tags"
  | "description"
  | "metadata";

/**
 * ============================================================================
 * Asset Type Constants
 * ============================================================================
 */

export const ASSET_TYPES = [
  "SERVER",
  "WORKSTATION",
  "LAPTOP",
  "DESKTOP",
  "NETWORK_DEVICE",
  "ROUTER",
  "SWITCH",
  "FIREWALL",
  "LOAD_BALANCER",
  "DATABASE",
  "WEB_SERVER",
  "APPLICATION_SERVER",
  "MAIL_SERVER",
  "DNS_SERVER",
  "PROXY_SERVER",
  "VIRTUAL_MACHINE",
  "CONTAINER",
  "CLOUD_RESOURCE",
  "STORAGE",
  "IOT_DEVICE",
  "SECURITY_APPLIANCE",
  "OTHER",
] as const;

/**
 * ============================================================================
 * Lifecycle Status Constants
 * ============================================================================
 */

export const ASSET_LIFECYCLE_STATUSES = [
  "ENABLED",
  "DISABLED",
] as const;

/**
 * ============================================================================
 * Operational Status Constants
 * ============================================================================
 */

export const ASSET_OPERATIONAL_STATUSES = [
  "ONLINE",
  "OFFLINE",
  "UNKNOWN",
  "MAINTENANCE",
] as const;

/**
 * ============================================================================
 * Combined Status Constants
 * ============================================================================
 */

export const ASSET_STATUSES = [
  "ENABLED",
  "DISABLED",
  "ONLINE",
  "OFFLINE",
  "UNKNOWN",
  "MAINTENANCE",
] as const;

/**
 * ============================================================================
 * Risk Constants
 * ============================================================================
 */

export const ASSET_RISKS = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFORMATIONAL",
] as const;

/**
 * ============================================================================
 * Operating System Constants
 * ============================================================================
 */

export const ASSET_OPERATING_SYSTEMS = [
  "WINDOWS",
  "WINDOWS_SERVER",
  "LINUX",
  "UBUNTU",
  "DEBIAN",
  "CENTOS",
  "RHEL",
  "FEDORA",
  "ROCKY_LINUX",
  "ALMALINUX",
  "KALI_LINUX",
  "MACOS",
  "FREEBSD",
  "ANDROID",
  "IOS",
  "NETWORK_OS",
  "OTHER",
] as const;

/**
 * ============================================================================
 * Environment Constants
 * ============================================================================
 */

export const ASSET_ENVIRONMENTS = [
  "PRODUCTION",
  "STAGING",
  "DEVELOPMENT",
  "TESTING",
  "QA",
  "UAT",
  "DISASTER_RECOVERY",
  "OTHER",
] as const;

/**
 * ============================================================================
 * Default Values
 * ============================================================================
 */

export const DEFAULT_ASSET_LIFECYCLE_STATUS: AssetLifecycleStatus =
  "ENABLED";

export const DEFAULT_ASSET_OPERATIONAL_STATUS: AssetOperationalStatus =
  "UNKNOWN";

export const DEFAULT_ASSET_RISK: AssetRisk =
  "INFORMATIONAL";

/**
 * ============================================================================
 * Default Form Values
 * ============================================================================
 */

export const DEFAULT_ASSET_FORM_VALUES: AssetFormValues = {
  name: "",

  asset_type: "",

  hostname: "",

  ip_address: "",

  mac_address: "",

  operating_system: "",

  environment: "",

  risk: DEFAULT_ASSET_RISK,

  owner: "",

  location: "",

  tags: [],

  description: "",

  metadata: {},
};

/**
 * ============================================================================
 * Default Filter Values
 * ============================================================================
 */

export const DEFAULT_ASSET_FILTER_VALUES: AssetFilterValues = {
  search: "",

  asset_type: "",

  status: "",

  risk: "",

  os: "",

  environment: "",
};

/**
 * ============================================================================
 * Pagination Constants
 * ============================================================================
 *
 * Locked Asset Management pagination:
 * - 30 assets per page.
 * - No page-number buttons.
 * - Previous / Next only.
 */

export const DEFAULT_ASSET_PAGE = 1;

export const DEFAULT_ASSET_PAGE_SIZE = 30;

export const MAX_ASSET_PAGE_SIZE = 30;

/**
 * ============================================================================
 * Type Guards
 * ============================================================================
 */

export function isAssetLifecycleStatus(
  value: string,
): value is AssetLifecycleStatus {
  return (
    value === "ENABLED" ||
    value === "DISABLED"
  );
}

export function isAssetOperationalStatus(
  value: string,
): value is AssetOperationalStatus {
  return (
    value === "ONLINE" ||
    value === "OFFLINE" ||
    value === "UNKNOWN" ||
    value === "MAINTENANCE"
  );
}

export function isAssetStatus(
  value: string,
): value is AssetStatus {
  return (
    isAssetLifecycleStatus(value) ||
    isAssetOperationalStatus(value)
  );
}

export function isAssetRisk(
  value: string,
): value is AssetRisk {
  return (
    value === "CRITICAL" ||
    value === "HIGH" ||
    value === "MEDIUM" ||
    value === "LOW" ||
    value === "INFORMATIONAL"
  );
}

export function isAssetType(
  value: string,
): value is AssetType {
  return (
    ASSET_TYPES.includes(
      value as AssetType,
    )
  );
}

export function isAssetEnvironment(
  value: string,
): value is AssetEnvironment {
  return (
    ASSET_ENVIRONMENTS.includes(
      value as AssetEnvironment,
    )
  );
}

/**
 * ============================================================================
 * Utility Helpers
 * ============================================================================
 */

/**
 * Returns true when the asset is lifecycle-enabled.
 */
export function isAssetEnabled(
  asset: Asset,
): boolean {
  return asset.lifecycle_status === "ENABLED";
}

/**
 * Returns true when the asset is lifecycle-disabled.
 */
export function isAssetDisabled(
  asset: Asset,
): boolean {
  return asset.lifecycle_status === "DISABLED";
}

/**
 * Returns true when the asset is operationally online.
 */
export function isAssetOnline(
  asset: Asset,
): boolean {
  return asset.operational_status === "ONLINE";
}

/**
 * Returns true when the asset is operationally offline.
 */
export function isAssetOffline(
  asset: Asset,
): boolean {
  return asset.operational_status === "OFFLINE";
}