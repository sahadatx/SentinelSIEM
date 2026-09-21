/*
 * ============================================================================
 * Asset Form
 * SentinelSIEM SOC Dashboard
 * ============================================================================
 */

import {
  useEffect,
  useState,
} from "react";

import type {
  ChangeEvent,
  FormEvent,
  ReactNode,
} from "react";

import type {
  Asset,
  AssetCreateRequest,
  AssetEnvironment,
  AssetOperatingSystem,
  AssetRisk,
  AssetType,
  AssetUpdateRequest,
} from "../types";

/*
 * ============================================================================
 * Props
 * ============================================================================
 */

export interface AssetFormProps {
  asset?: Asset | null;

  loading?: boolean;

  error?: string | null;

  onSubmit: (
    payload:
      | AssetCreateRequest
      | AssetUpdateRequest,
  ) => void | Promise<void>;

  onCancel?: () => void;
}

/*
 * ============================================================================
 * Constants
 * ============================================================================
 */

const ASSET_TYPE_OPTIONS: readonly AssetType[] = [
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
];

const OS_OPTIONS: readonly AssetOperatingSystem[] = [
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
];

const ENVIRONMENT_OPTIONS: readonly AssetEnvironment[] = [
  "PRODUCTION",
  "STAGING",
  "DEVELOPMENT",
  "TESTING",
  "QA",
  "UAT",
  "DISASTER_RECOVERY",
  "OTHER",
];

const RISK_OPTIONS: readonly AssetRisk[] = [
  "CRITICAL",
  "HIGH",
  "MEDIUM",
  "LOW",
  "INFORMATIONAL",
];

const DEFAULT_RISK: AssetRisk =
  "INFORMATIONAL";

/*
 * ============================================================================
 * Helpers
 * ============================================================================
 */

function formatOptionLabel(
  value: string | null | undefined,
): string {
  if (!value?.trim()) {
    return "";
  }

  return value
    .trim()
    .toLowerCase()
    .split(/[\s_-]+/)
    .filter(Boolean)
    .map(
      (part) =>
        part.charAt(0).toUpperCase() +
        part.slice(1),
    )
    .join(" ");
}

function optionalValue(
  value: string,
): string | null {
  const normalized =
    value.trim();

  return normalized || null;
}

function normalizeOption<T extends string>(
  value: string | null | undefined,
  options: readonly T[],
): T | "" {
  if (!value?.trim()) {
    return "";
  }

  const normalized =
    value.trim().toUpperCase();

  return (
    options.find(
      (option) =>
        option === normalized,
    ) ?? ""
  );
}

function parseTags(
  value: string,
): string[] {
  const seen =
    new Set<string>();

  const result: string[] = [];

  for (const rawTag of value.split(",")) {
    const tag =
      rawTag.trim();

    if (!tag) {
      continue;
    }

    const normalized =
      tag.toLowerCase();

    if (
      seen.has(normalized)
    ) {
      continue;
    }

    seen.add(normalized);
    result.push(tag);
  }

  return result;
}

function isValidIpAddress(
  value: string,
): boolean {
  /*
   * IPv4
   */

  const ipv4Parts =
    value.split(".");

  if (
    ipv4Parts.length === 4
  ) {
    const validIPv4 =
      ipv4Parts.every(
        (part) => {
          if (
            !/^\d+$/.test(part)
          ) {
            return false;
          }

          if (
            part.length > 1 &&
            part.startsWith("0")
          ) {
            return false;
          }

          const number =
            Number(part);

          return (
            Number.isInteger(
              number,
            ) &&
            number >= 0 &&
            number <= 255
          );
        },
      );

    if (validIPv4) {
      return true;
    }
  }

  /*
   * Lightweight IPv6 validation.
   *
   * Backend validation remains authoritative.
   */

  if (
    value.includes(":") &&
    /^[0-9a-fA-F:]+$/.test(
      value,
    )
  ) {
    return true;
  }

  return false;
}

function isValidMacAddress(
  value: string,
): boolean {
  return /^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/.test(
    value,
  );
}

/*
 * ============================================================================
 * Component
 * ============================================================================
 */

export default function AssetForm({
  asset = null,
  loading = false,
  error = null,
  onSubmit,
  onCancel,
}: AssetFormProps) {
  const isEditMode =
    Boolean(asset);

  /*
   * ==========================================================================
   * Form State
   * ==========================================================================
   */

  const [name, setName] =
    useState(
      asset?.name ?? "",
    );

  const [assetType, setAssetType] =
    useState<AssetType | "">(
      normalizeOption(
        asset?.asset_type,
        ASSET_TYPE_OPTIONS,
      ),
    );

  const [hostname, setHostname] =
    useState(
      asset?.hostname ?? "",
    );

  const [ipAddress, setIpAddress] =
    useState(
      asset?.ip_address ?? "",
    );

  const [macAddress, setMacAddress] =
    useState(
      asset?.mac_address ?? "",
    );

  const [
    operatingSystem,
    setOperatingSystem,
  ] = useState<
    AssetOperatingSystem | ""
  >(
    normalizeOption(
      asset?.operating_system,
      OS_OPTIONS,
    ),
  );

  const [
    environment,
    setEnvironment,
  ] = useState<
    AssetEnvironment | ""
  >(
    normalizeOption(
      asset?.environment,
      ENVIRONMENT_OPTIONS,
    ),
  );

  const [risk, setRisk] =
    useState<AssetRisk>(
      normalizeOption(
        asset?.risk,
        RISK_OPTIONS,
      ) || DEFAULT_RISK,
    );

  const [owner, setOwner] =
    useState(
      asset?.owner ?? "",
    );

  const [location, setLocation] =
    useState(
      asset?.location ?? "",
    );

  const [tags, setTags] =
    useState(
      Array.isArray(asset?.tags)
        ? asset.tags.join(", ")
        : "",
    );

  const [
    description,
    setDescription,
  ] = useState(
    asset?.description ?? "",
  );

  const [
    metadata,
    setMetadata,
  ] = useState(
    asset?.metadata
      ? JSON.stringify(
          asset.metadata,
          null,
          2,
        )
      : "",
  );

  const [
    validationError,
    setValidationError,
  ] = useState<string | null>(
    null,
  );

  /*
   * ==========================================================================
   * Synchronize Form
   * ==========================================================================
   */

  useEffect(() => {
    setName(
      asset?.name ?? "",
    );

    setAssetType(
      normalizeOption(
        asset?.asset_type,
        ASSET_TYPE_OPTIONS,
      ),
    );

    setHostname(
      asset?.hostname ?? "",
    );

    setIpAddress(
      asset?.ip_address ?? "",
    );

    setMacAddress(
      asset?.mac_address ?? "",
    );

    setOperatingSystem(
      normalizeOption(
        asset?.operating_system,
        OS_OPTIONS,
      ),
    );

    setEnvironment(
      normalizeOption(
        asset?.environment,
        ENVIRONMENT_OPTIONS,
      ),
    );

    setRisk(
      normalizeOption(
        asset?.risk,
        RISK_OPTIONS,
      ) || DEFAULT_RISK,
    );

    setOwner(
      asset?.owner ?? "",
    );

    setLocation(
      asset?.location ?? "",
    );

    setTags(
      Array.isArray(asset?.tags)
        ? asset.tags.join(", ")
        : "",
    );

    setDescription(
      asset?.description ?? "",
    );

    setMetadata(
      asset?.metadata
        ? JSON.stringify(
            asset.metadata,
            null,
            2,
          )
        : "",
    );

    setValidationError(null);
  }, [asset]);

  /*
   * ==========================================================================
   * Submit
   * ==========================================================================
   */

  const handleSubmit = async (
    event: FormEvent<HTMLFormElement>,
  ): Promise<void> => {
    event.preventDefault();

    if (loading) {
      return;
    }

    setValidationError(null);

    /*
     * ------------------------------------------------------------------------
     * Asset Name
     * ------------------------------------------------------------------------
     */

    const normalizedName =
      name.trim();

    if (!normalizedName) {
      setValidationError(
        "Asset name is required.",
      );
      return;
    }

    /*
     * ------------------------------------------------------------------------
     * Asset Type
     * ------------------------------------------------------------------------
     */

    if (!assetType) {
      setValidationError(
        "Asset type is required.",
      );
      return;
    }

    /*
     * ------------------------------------------------------------------------
     * IP Address
     * ------------------------------------------------------------------------
     */

    const normalizedIpAddress =
      ipAddress.trim();

    if (!normalizedIpAddress) {
      setValidationError(
        "IP address is required.",
      );
      return;
    }

    if (
      !isValidIpAddress(
        normalizedIpAddress,
      )
    ) {
      setValidationError(
        "Please enter a valid IPv4 or IPv6 address.",
      );
      return;
    }

    /*
     * ------------------------------------------------------------------------
     * MAC Address
     * ------------------------------------------------------------------------
     */

    const normalizedMacAddress =
      macAddress.trim();

    if (
      normalizedMacAddress &&
      !isValidMacAddress(
        normalizedMacAddress,
      )
    ) {
      setValidationError(
        "Please enter a valid MAC address.",
      );
      return;
    }

    /*
     * ------------------------------------------------------------------------
     * Tags
     * ------------------------------------------------------------------------
     */

    const parsedTags =
      parseTags(tags);

    /*
     * ------------------------------------------------------------------------
     * Metadata
     * ------------------------------------------------------------------------
     */

    let parsedMetadata:
      | Record<string, unknown>
      | undefined;

    const normalizedMetadata =
      metadata.trim();

    if (normalizedMetadata) {
      try {
        const parsed =
          JSON.parse(
            normalizedMetadata,
          ) as unknown;

        if (
          typeof parsed !==
            "object" ||
          parsed === null ||
          Array.isArray(parsed)
        ) {
          setValidationError(
            "Metadata must be a JSON object.",
          );
          return;
        }

        parsedMetadata =
          parsed as Record<
            string,
            unknown
          >;
      } catch {
        setValidationError(
          "Metadata contains invalid JSON.",
        );
        return;
      }
    }

    /*
     * ------------------------------------------------------------------------
     * Common Payload
     * ------------------------------------------------------------------------
     *
     * IMPORTANT:
     *
     * lifecycle_status is intentionally excluded.
     *
     * Create:
     *   Backend creates the asset as ENABLED.
     *
     * Edit:
     *   Lifecycle changes use:
     *   PATCH /assets/{asset_id}/status
     */

    const commonFields = {
      name: normalizedName,

      asset_type: assetType,

      hostname:
        optionalValue(hostname),

      ip_address:
        normalizedIpAddress,

      mac_address:
        optionalValue(
          normalizedMacAddress,
        ),

      operating_system:
        operatingSystem || undefined,

      environment:
        environment || undefined,

      risk,

      owner:
        optionalValue(owner),

      location:
        optionalValue(location),

      tags: parsedTags,

      description:
        optionalValue(description),

      ...(parsedMetadata !==
      undefined
        ? {
            metadata:
              parsedMetadata,
          }
        : {}),
    };

    /*
     * ------------------------------------------------------------------------
     * Edit
     * ------------------------------------------------------------------------
     */

    if (isEditMode) {
      const payload: AssetUpdateRequest = {
        ...commonFields,
      };

      await onSubmit(payload);
      return;
    }

    /*
     * ------------------------------------------------------------------------
     * Create
     * ------------------------------------------------------------------------
     */

    const payload: AssetCreateRequest = {
      ...commonFields,
    };

    await onSubmit(payload);
  };

  /*
   * ==========================================================================
   * Render
   * ==========================================================================
   */

  return (
    <form
      onSubmit={handleSubmit}
      noValidate
      aria-label={
        isEditMode
          ? "Edit asset form"
          : "Create asset form"
      }
      className="w-full overflow-hidden rounded-2xl border border-slate-800 bg-slate-900 shadow-2xl shadow-black/30"
    >
      {/* ======================================================================
          Header
          ==================================================================== */}

      <div className="border-b border-slate-800 bg-slate-900/80 px-5 py-5 sm:px-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span
                aria-hidden="true"
                className="h-2 w-2 rounded-full bg-cyan-400 shadow-lg shadow-cyan-400/40"
              />

              <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-cyan-400">
                Asset Management
              </span>
            </div>

            <h2 className="mt-2 text-xl font-semibold tracking-tight text-slate-100">
              {isEditMode
                ? "Edit Asset"
                : "Create Asset"}
            </h2>

            <p className="mt-1 text-sm text-slate-500">
              {isEditMode
                ? "Update the managed asset information."
                : "Register a new asset in SentinelSIEM."}
            </p>
          </div>

          {isEditMode && (
            <div className="hidden rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-right sm:block">
              <p className="text-[10px] uppercase tracking-wider text-slate-600">
                Mode
              </p>

              <p className="mt-0.5 text-xs font-medium text-cyan-400">
                EDIT
              </p>
            </div>
          )}
        </div>
      </div>

      {/* ======================================================================
          Body
          ==================================================================== */}

      <div className="space-y-6 p-5 sm:p-6">

        {/* ====================================================================
            Error
            ==================================================================== */}

        {(validationError ||
          error) && (
          <div
            role="alert"
            className="flex items-start gap-3 rounded-xl border border-red-500/20 bg-red-500/5 px-4 py-3"
          >
            <span
              aria-hidden="true"
              className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-red-500/10 text-xs font-bold text-red-400"
            >
              !
            </span>

            <div className="min-w-0">
              <p className="text-sm font-medium text-red-300">
                Unable to save asset
              </p>

              <p className="mt-0.5 text-xs leading-5 text-red-400/80">
                {validationError ??
                  error}
              </p>
            </div>
          </div>
        )}

        {/* ====================================================================
            Asset Identity
            ==================================================================== */}

        <section>
          <div className="mb-4">
            <h3 className="text-sm font-semibold text-slate-200">
              Asset Identity
            </h3>

            <p className="mt-1 text-xs text-slate-600">
              Basic information used to identify the managed asset.
            </p>
          </div>

          <div className="grid grid-cols-1 gap-5 md:grid-cols-2">

            {/* Asset Name */}

            <Field>
              <FieldLabel
                htmlFor="asset-name"
                required
              >
                Asset Name
              </FieldLabel>

              <input
                id="asset-name"
                type="text"
                value={name}
                onChange={(event) =>
                  setName(
                    event.target.value,
                  )
                }
                placeholder="Production Web Server"
                disabled={loading}
                required
                maxLength={255}
                autoComplete="off"
                className={inputClassName}
              />
            </Field>

            {/* Asset Type */}

            <Field>
              <FieldLabel
                htmlFor="asset-type"
                required
              >
                Asset Type
              </FieldLabel>

              <SelectField
                id="asset-type"
                value={assetType}
                onChange={(event) =>
                  setAssetType(
                    event.target
                      .value as AssetType,
                  )
                }
                disabled={loading}
              >
                <option value="">
                  Select asset type
                </option>

                {ASSET_TYPE_OPTIONS.map(
                  (option) => (
                    <option
                      key={option}
                      value={option}
                    >
                      {formatOptionLabel(
                        option,
                      )}
                    </option>
                  ),
                )}
              </SelectField>
            </Field>

            {/* Hostname */}

            <Field>
              <FieldLabel htmlFor="asset-hostname">
                Hostname
              </FieldLabel>

              <input
                id="asset-hostname"
                type="text"
                value={hostname}
                onChange={(event) =>
                  setHostname(
                    event.target.value,
                  )
                }
                placeholder="web01.example.local"
                disabled={loading}
                maxLength={255}
                autoComplete="off"
                className={inputClassName}
              />
            </Field>

            {/* IP Address */}

            <Field>
              <FieldLabel
                htmlFor="asset-ip-address"
                required
              >
                IP Address
              </FieldLabel>

              <input
                id="asset-ip-address"
                type="text"
                inputMode="url"
                value={ipAddress}
                onChange={(event) =>
                  setIpAddress(
                    event.target.value,
                  )
                }
                placeholder="192.168.1.10"
                disabled={loading}
                required
                autoComplete="off"
                spellCheck={false}
                className={`${inputClassName} font-mono`}
              />
            </Field>

            {/* MAC Address */}

            <Field>
              <FieldLabel htmlFor="asset-mac-address">
                MAC Address
              </FieldLabel>

              <input
                id="asset-mac-address"
                type="text"
                value={macAddress}
                onChange={(event) =>
                  setMacAddress(
                    event.target.value,
                  )
                }
                placeholder="00:11:22:33:44:55"
                disabled={loading}
                maxLength={17}
                autoComplete="off"
                spellCheck={false}
                className={`${inputClassName} font-mono`}
              />
            </Field>
          </div>
        </section>

        {/* ====================================================================
            Classification
            ==================================================================== */}

        <section className="border-t border-slate-800/70 pt-6">
          <div className="mb-4">
            <h3 className="text-sm font-semibold text-slate-200">
              Classification
            </h3>

            <p className="mt-1 text-xs text-slate-600">
              Operational context and security classification.
            </p>
          </div>

          <div className="grid grid-cols-1 gap-5 md:grid-cols-2">

            {/* Operating System */}

            <Field>
              <FieldLabel htmlFor="asset-operating-system">
                Operating System
              </FieldLabel>

              <SelectField
                id="asset-operating-system"
                value={operatingSystem}
                onChange={(event) =>
                  setOperatingSystem(
                    event.target
                      .value as AssetOperatingSystem,
                  )
                }
                disabled={loading}
              >
                <option value="">
                  Select operating system
                </option>

                {OS_OPTIONS.map(
                  (option) => (
                    <option
                      key={option}
                      value={option}
                    >
                      {formatOptionLabel(
                        option,
                      )}
                    </option>
                  ),
                )}
              </SelectField>
            </Field>

            {/* Environment */}

            <Field>
              <FieldLabel htmlFor="asset-environment">
                Environment
              </FieldLabel>

              <SelectField
                id="asset-environment"
                value={environment}
                onChange={(event) =>
                  setEnvironment(
                    event.target
                      .value as AssetEnvironment,
                  )
                }
                disabled={loading}
              >
                <option value="">
                  Select environment
                </option>

                {ENVIRONMENT_OPTIONS.map(
                  (option) => (
                    <option
                      key={option}
                      value={option}
                    >
                      {formatOptionLabel(
                        option,
                      )}
                    </option>
                  ),
                )}
              </SelectField>
            </Field>

            {/* Risk */}

            <Field>
              <FieldLabel
                htmlFor="asset-risk"
                required
              >
                Risk
              </FieldLabel>

              <SelectField
                id="asset-risk"
                value={risk}
                onChange={(event) =>
                  setRisk(
                    event.target
                      .value as AssetRisk,
                  )
                }
                disabled={loading}
              >
                {RISK_OPTIONS.map(
                  (option) => (
                    <option
                      key={option}
                      value={option}
                    >
                      {formatOptionLabel(
                        option,
                      )}
                    </option>
                  ),
                )}
              </SelectField>
            </Field>

            {/* Owner */}

            <Field>
              <FieldLabel htmlFor="asset-owner">
                Owner
              </FieldLabel>

              <input
                id="asset-owner"
                type="text"
                value={owner}
                onChange={(event) =>
                  setOwner(
                    event.target.value,
                  )
                }
                placeholder="Security Team"
                disabled={loading}
                maxLength={255}
                autoComplete="organization"
                className={inputClassName}
              />
            </Field>

            {/* Location */}

            <Field>
              <FieldLabel htmlFor="asset-location">
                Location
              </FieldLabel>

              <input
                id="asset-location"
                type="text"
                value={location}
                onChange={(event) =>
                  setLocation(
                    event.target.value,
                  )
                }
                placeholder="Primary Data Center"
                disabled={loading}
                maxLength={255}
                autoComplete="off"
                className={inputClassName}
              />
            </Field>

            {/* Tags */}

            <Field>
              <FieldLabel htmlFor="asset-tags">
                Tags
              </FieldLabel>

              <input
                id="asset-tags"
                type="text"
                value={tags}
                onChange={(event) =>
                  setTags(
                    event.target.value,
                  )
                }
                placeholder="web, production, critical"
                disabled={loading}
                autoComplete="off"
                className={inputClassName}
              />

              <p className="mt-1.5 text-[11px] text-slate-600">
                Separate multiple tags with commas.
              </p>
            </Field>
          </div>
        </section>

        {/* ====================================================================
            Lifecycle Information
            ==================================================================== */}

        <section className="border-t border-slate-800/70 pt-6">
          <div className="rounded-xl border border-slate-800 bg-slate-950/50 px-4 py-3">
            <div className="flex items-start gap-3">
              <div className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-cyan-500/10 text-cyan-400">
                <span
                  aria-hidden="true"
                  className="text-xs"
                >
                  ●
                </span>
              </div>

              <div>
                <p className="text-sm font-medium text-slate-300">
                  Lifecycle Status
                </p>

                <p className="mt-1 text-xs leading-5 text-slate-600">
                  {isEditMode
                    ? "Lifecycle status is managed separately. Use Enable or Disable from the asset actions."
                    : "New assets are created as Enabled by default."}
                </p>

                {isEditMode &&
                  asset && (
                    <p className="mt-2 text-xs font-medium text-slate-400">
                      Current status:{" "}
                      <span className="text-cyan-400">
                        {formatOptionLabel(
                          asset.lifecycle_status,
                        )}
                      </span>
                    </p>
                  )}
              </div>
            </div>
          </div>
        </section>

        {/* ====================================================================
            Description
            ==================================================================== */}

        <section className="border-t border-slate-800/70 pt-6">
          <div className="mb-4">
            <h3 className="text-sm font-semibold text-slate-200">
              Description
            </h3>

            <p className="mt-1 text-xs text-slate-600">
              Describe the purpose, role, or operational context of this asset.
            </p>
          </div>

          <textarea
            id="asset-description"
            value={description}
            onChange={(event) =>
              setDescription(
                event.target.value,
              )
            }
            placeholder="Describe the purpose or role of this asset..."
            disabled={loading}
            maxLength={2000}
            rows={4}
            className={`${textareaClassName} min-h-28`}
          />

          <p className="mt-1.5 text-right text-[10px] text-slate-600">
            {description.length}/2000
          </p>
        </section>

        {/* ====================================================================
            Metadata
            ==================================================================== */}

        <section className="border-t border-slate-800/70 pt-6">
          <div className="mb-4 flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">
                Metadata
              </h3>

              <p className="mt-1 text-xs text-slate-600">
                Optional structured information associated with the asset.
              </p>
            </div>

            <span className="text-[10px] uppercase tracking-wider text-slate-600">
              JSON Object
            </span>
          </div>

          <textarea
            id="asset-metadata"
            value={metadata}
            onChange={(event) =>
              setMetadata(
                event.target.value,
              )
            }
            placeholder={`{
  "department": "SOC",
  "criticality": "high"
}`}
            disabled={loading}
            rows={8}
            spellCheck={false}
            className={`${textareaClassName} resize-y font-mono text-xs leading-6`}
          />

          <p className="mt-2 text-xs text-slate-600">
            Metadata must contain a valid JSON object.
          </p>
        </section>
      </div>

      {/* ======================================================================
          Footer Actions
          ==================================================================== */}

      <div className="flex flex-col-reverse gap-3 border-t border-slate-800 bg-slate-950/30 px-5 py-4 sm:flex-row sm:items-center sm:justify-end sm:px-6">
        {onCancel && (
          <button
            type="button"
            onClick={onCancel}
            disabled={loading}
            className="inline-flex h-10 w-full items-center justify-center rounded-lg border border-slate-700 bg-slate-900 px-5 text-sm font-medium text-slate-300 transition hover:border-slate-600 hover:bg-slate-800 hover:text-white focus:outline-none focus:ring-2 focus:ring-slate-500/20 disabled:cursor-not-allowed disabled:opacity-40 sm:w-auto"
          >
            Cancel
          </button>
        )}

        <button
          type="submit"
          disabled={loading}
          className="inline-flex h-10 w-full min-w-[150px] items-center justify-center gap-2 rounded-lg border border-cyan-400/30 bg-cyan-500/10 px-5 text-sm font-semibold text-cyan-300 transition hover:border-cyan-400/50 hover:bg-cyan-500/20 hover:text-cyan-200 focus:outline-none focus:ring-2 focus:ring-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-50 sm:w-auto"
        >
          {loading ? (
            <>
              <span
                aria-hidden="true"
                className="h-4 w-4 animate-spin rounded-full border-2 border-cyan-300/30 border-t-cyan-300"
              />

              Saving...
            </>
          ) : (
            <>
              <span aria-hidden="true">
                {isEditMode
                  ? "✓"
                  : "+"}
              </span>

              {isEditMode
                ? "Save Changes"
                : "Create Asset"}
            </>
          )}
        </button>
      </div>
    </form>
  );
}

/*
 * ============================================================================
 * Reusable UI Helpers
 * ============================================================================
 */

interface FieldProps {
  children: ReactNode;
}

function Field({
  children,
}: FieldProps) {
  return (
    <div className="min-w-0">
      {children}
    </div>
  );
}

interface FieldLabelProps {
  htmlFor: string;

  required?: boolean;

  children: ReactNode;
}

function FieldLabel({
  htmlFor,
  required = false,
  children,
}: FieldLabelProps) {
  return (
    <label
      htmlFor={htmlFor}
      className="mb-1.5 block text-xs font-medium uppercase tracking-wide text-slate-400"
    >
      {children}

      {required && (
        <span
          aria-hidden="true"
          className="ml-1 text-red-400"
        >
          *
        </span>
      )}
    </label>
  );
}

interface SelectFieldProps {
  id: string;

  value: string;

  onChange: (
    event: ChangeEvent<HTMLSelectElement>,
  ) => void;

  disabled?: boolean;

  children: ReactNode;
}

function SelectField({
  id,
  value,
  onChange,
  disabled = false,
  children,
}: SelectFieldProps) {
  return (
    <div className="relative">
      <select
        id={id}
        value={value}
        onChange={onChange}
        disabled={disabled}
        className={`${inputClassName} appearance-none pr-10`}
      >
        {children}
      </select>

      <span
        aria-hidden="true"
        className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-slate-500"
      >
        ▼
      </span>
    </div>
  );
}

/*
 * ============================================================================
 * Shared Styles
 * ============================================================================
 */

const inputClassName =
  "h-11 w-full rounded-lg border border-slate-700/80 bg-slate-950/80 px-3 text-sm text-slate-100 outline-none transition placeholder:text-slate-600 hover:border-slate-600 focus:border-cyan-500/60 focus:ring-2 focus:ring-cyan-500/10 disabled:cursor-not-allowed disabled:opacity-50";

const textareaClassName =
  "w-full rounded-lg border border-slate-700/80 bg-slate-950/80 px-3 py-2.5 text-sm text-slate-100 outline-none transition placeholder:text-slate-600 hover:border-slate-600 focus:border-cyan-500/60 focus:ring-2 focus:ring-cyan-500/10 disabled:cursor-not-allowed disabled:opacity-50";