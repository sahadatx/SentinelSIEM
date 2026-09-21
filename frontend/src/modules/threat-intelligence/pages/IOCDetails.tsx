/**
 * ============================================================================
 * SentinelSIEM — IOC Details
 * ============================================================================
 *
 * Professional Threat Intelligence investigation view.
 *
 * Responsibilities:
 *   - Load IOC details from the backend
 *   - Display IOC identity and classification
 *   - Display severity, reputation, status and confidence
 *   - Display source/feed and timestamps
 *   - Display description and tags
 *   - Display related Events, Alerts, Incidents, Assets and MITRE techniques
 *   - Display backend metadata when available
 *   - Handle loading, empty, error and retry states
 *
 * Notes:
 *   - Backend is the source of truth.
 *   - This page is read-only.
 *   - No IOC mutation is performed here.
 *   - Enable/Disable and Edit belong to the Threat Intelligence workspace.
 *
 * ============================================================================
 */

import {
  useCallback,
  useEffect,
  useState,
} from "react";

import {
  Link,
  useLocation,
  useParams,
} from "react-router-dom";

import {
  Panel,
} from "../../../components/ui/Panel";

import {
  threatIntelligenceApi,
} from "../api";

import type {
  IOCDetail,
} from "../types";

import "../ThreatIntelligence.css";


/* ============================================================================
 * Types
 * ========================================================================== */

interface DetailFieldProps {
  label: string;
  value: string;
}

interface RelationshipCardProps {
  title: string;
  count: number;
  ids: string[];
}

interface IOCDetailsContentProps {
  ioc: IOCDetail;
}


/* ============================================================================
 * IOC Details Page
 * ========================================================================== */

export default function IOCDetails() {

  const {
    iocId,
  } = useParams<{
    iocId: string;
  }>();

  const location = useLocation();

  const [
    ioc,
    setIOC,
  ] = useState<IOCDetail | null>(null);

  const [
    loading,
    setLoading,
  ] = useState<boolean>(true);

  const [
    error,
    setError,
  ] = useState<string | null>(null);


  /* ==========================================================================
   * Load IOC
   * ======================================================================== */

  const loadIOC = useCallback(
    async (): Promise<void> => {

      const id = iocId?.trim();

      if (!id) {

        setIOC(null);

        setError(
          "IOC identifier is missing.",
        );

        setLoading(false);

        return;
      }

      try {

        setLoading(true);
        setError(null);

        const result =
          await threatIntelligenceApi.getDetail(id);

        setIOC(result);

      } catch (err: unknown) {

        setIOC(null);

        setError(
          getErrorMessage(
            err,
            "Failed to load IOC details.",
          ),
        );

      } finally {

        setLoading(false);
      }

    },
    [iocId],
  );


  /* ==========================================================================
   * Initial / Route Change Load
   * ======================================================================== */

  useEffect(() => {

    void loadIOC();

  }, [loadIOC]);


  /* ==========================================================================
   * Render
   * ======================================================================== */

  return (
    <div className="threat-intelligence">

      {/* ======================================================================
       * Page Heading
       * ==================================================================== */}

      <div className="page-heading">

        <div>

          <span
            className="page-eyebrow"
          >
            THREAT INTELLIGENCE
          </span>

          <h2>
            IOC Details
          </h2>

          <p>
            Detailed threat indicator
            investigation context
          </p>

        </div>

        <Link
          className="ioc-details-back-link"
          to={getBackPath(
            location.state as { from?: string } | null,
          )}
        >
          ← Back
        </Link>

      </div>


      {/* ======================================================================
       * Main Content
       * ==================================================================== */}

      <Panel
        title="Indicator"
        subtitle={
          ioc
            ? "Backend-sourced threat intelligence details"
            : "Threat indicator details"
        }
      >

        {loading && (
          <LoadingState />
        )}

        {!loading && error && (
          <ErrorState
            message={error}
            onRetry={() => {
              void loadIOC();
            }}
          />
        )}

        {!loading && !error && !ioc && (
          <EmptyState />
        )}

        {!loading && !error && ioc && (
          <IOCDetailsContent
            ioc={ioc}
          />
        )}

      </Panel>

    </div>
  );
}


/* ============================================================================
 * IOC Details Content
 * ========================================================================== */

function IOCDetailsContent({
  ioc,
}: IOCDetailsContentProps) {

  const relationships =
    getRelationships(ioc);

  const tags =
    Array.isArray(ioc.tags)
      ? ioc.tags.filter(
          (tag): tag is string =>
            typeof tag === "string" &&
            tag.trim().length > 0,
        )
      : [];

  const metadata =
    isRecord(ioc.metadata)
      ? ioc.metadata
      : {};

  const value =
    getIOCValue(ioc);

  const type =
    getIOCType(ioc);

  const severity =
    getIOCSeverity(ioc);

  const status =
    getIOCStatus(ioc);

  const reputation =
    getIOCReputation(ioc);

  const confidence =
    getIOCConfidence(ioc);

  const source =
    getOptionalString(ioc.source);

  const feed =
    getOptionalString(ioc.feed);

  const description =
    getOptionalString(ioc.description);

  const firstSeen =
    formatDateTime(ioc.first_seen);

  const lastSeen =
    formatDateTime(ioc.last_seen);

  const expiration =
    formatDateTime(ioc.expiration);

  const createdAt =
    formatDateTime(
      getOptionalString(
        ioc.created_at,
      ),
    );

  const updatedAt =
    formatDateTime(
      getOptionalString(
        ioc.updated_at,
      ),
    );

  return (
    <div className="ioc-details-content">

      {/* ======================================================================
       * Identity
       * ==================================================================== */}

      <section className="ioc-details-section">

        <SectionHeader
          title="Indicator Identity"
          description="Core identifier information returned by the backend."
        />

        <div className="ioc-details-grid">

          <DetailField
            label="IOC ID"
            value={getIOCId(ioc)}
          />

          <DetailField
            label="IOC Value"
            value={value}
            emphasis
          />

          <DetailField
            label="Type"
            value={formatType(type)}
          />

          <DetailField
            label="Normalized Value"
            value={
              getOptionalString(
                (ioc as unknown as Record<string, unknown>)
                  .normalized_value,
              ) || "—"
            }
          />

        </div>

      </section>


      {/* ======================================================================
       * Classification
       * ==================================================================== */}

      <section className="ioc-details-section">

        <SectionHeader
          title="Classification"
          description="Threat classification and reputation context."
        />

        <div className="ioc-details-classification">

          <ClassificationBadge
            label="Severity"
            value={severity}
            className={getSeverityClass(severity)}
          />

          <ClassificationBadge
            label="Reputation"
            value={reputation}
            className={getReputationClass(reputation)}
          />

          <ClassificationBadge
            label="Status"
            value={status}
            className={getStatusClass(status)}
          />

          <ClassificationBadge
            label="Confidence"
            value={formatConfidence(confidence)}
            className="ioc-details-badge-neutral"
          />

        </div>

      </section>


      {/* ======================================================================
       * Overview
       * ==================================================================== */}

      <section className="ioc-details-section">

        <SectionHeader
          title="Overview"
          description="Source, feed and lifecycle timestamps."
        />

        <div className="ioc-details-grid">

          <DetailField
            label="Source"
            value={source || "—"}
          />

          <DetailField
            label="Feed"
            value={feed || "—"}
          />

          <DetailField
            label="First Seen"
            value={firstSeen}
          />

          <DetailField
            label="Last Seen"
            value={lastSeen}
          />

          <DetailField
            label="Expires At"
            value={expiration}
          />

          <DetailField
            label="Created At"
            value={createdAt}
          />

          <DetailField
            label="Updated At"
            value={updatedAt}
          />

        </div>

      </section>


      {/* ======================================================================
       * Description
       * ==================================================================== */}

      <section className="ioc-details-section">

        <SectionHeader
          title="Description"
          description="Analyst-facing context associated with this indicator."
        />

        <div className="ioc-details-description">

          {description ? (
            <p>
              {description}
            </p>
          ) : (
            <span className="ioc-details-muted">
              No description available.
            </span>
          )}

        </div>

      </section>


      {/* ======================================================================
       * Tags
       * ==================================================================== */}

      <section className="ioc-details-section">

        <SectionHeader
          title="Tags"
          description="Backend-provided indicator tags."
        />

        {tags.length > 0 ? (

          <div className="ioc-details-tags">

            {tags.map((tag) => (
              <span
                key={tag}
                className="ioc-details-tag"
              >
                {tag}
              </span>
            ))}

          </div>

        ) : (

          <span className="ioc-details-muted">
            No tags available.
          </span>

        )}

      </section>


      {/* ======================================================================
       * Relationships
       * ==================================================================== */}

      <section className="ioc-details-section">

        <SectionHeader
          title="Related Objects"
          description="Objects associated with this IOC by the backend."
        />

        <div className="ioc-details-relationships">

          {relationships.map((relationship) => (
            <RelationshipCard
              key={relationship.title}
              title={relationship.title}
              count={relationship.count}
              ids={relationship.ids}
            />
          ))}

        </div>

      </section>


      {/* ======================================================================
       * Metadata
       * ==================================================================== */}

      <section className="ioc-details-section">

        <SectionHeader
          title="Metadata"
          description="Additional backend metadata associated with the indicator."
        />

        <MetadataViewer
          metadata={metadata}
        />

      </section>

    </div>
  );
}


/* ============================================================================
 * Loading State
 * ========================================================================== */

function LoadingState() {

  return (
    <div
      className="ioc-details-state"
      role="status"
      aria-live="polite"
    >

      <div className="ioc-details-state-icon">
        ⟳
      </div>

      <h3>
        Loading IOC details
      </h3>

      <p>
        Fetching the latest indicator information from the backend.
      </p>

    </div>
  );
}


/* ============================================================================
 * Error State
 * ========================================================================== */

interface ErrorStateProps {
  message: string;
  onRetry: () => void;
}

function ErrorState({
  message,
  onRetry,
}: ErrorStateProps) {

  return (
    <div
      className="ioc-details-state ioc-details-state-error"
      role="alert"
    >

      <div className="ioc-details-state-icon">
        !
      </div>

      <h3>
        Unable to load IOC
      </h3>

      <p>
        {message}
      </p>

      <button
        type="button"
        className="ioc-details-retry-button"
        onClick={onRetry}
      >
        Retry
      </button>

    </div>
  );
}


/* ============================================================================
 * Empty State
 * ========================================================================== */

function EmptyState() {

  return (
    <div
      className="ioc-details-state"
      role="status"
    >

      <div className="ioc-details-state-icon">
        ?
      </div>

      <h3>
        IOC not found
      </h3>

      <p>
        The requested threat indicator could not be found.
      </p>

    </div>
  );
}


/* ============================================================================
 * Section Header
 * ========================================================================== */

interface SectionHeaderProps {
  title: string;
  description?: string;
}

function SectionHeader({
  title,
  description,
}: SectionHeaderProps) {

  return (
    <div className="ioc-details-section-header">

      <div>

        <h3>
          {title}
        </h3>

        {description && (
          <p>
            {description}
          </p>
        )}

      </div>

    </div>
  );
}


/* ============================================================================
 * Detail Field
 * ========================================================================== */

interface DetailFieldExtendedProps
  extends DetailFieldProps {
  emphasis?: boolean;
}

function DetailField({
  label,
  value,
  emphasis = false,
}: DetailFieldExtendedProps) {

  return (
    <div className="ioc-details-field">

      <span className="ioc-details-field-label">
        {label}
      </span>

      <span
        className={
          emphasis
            ? "ioc-details-field-value ioc-details-field-value-emphasis"
            : "ioc-details-field-value"
        }
      >
        {value || "—"}
      </span>

    </div>
  );
}


/* ============================================================================
 * Classification Badge
 * ========================================================================== */

interface ClassificationBadgeProps {
  label: string;
  value: string;
  className: string;
}

function ClassificationBadge({
  label,
  value,
  className,
}: ClassificationBadgeProps) {

  return (
    <div className="ioc-details-classification-item">

      <span className="ioc-details-classification-label">
        {label}
      </span>

      <span
        className={`ioc-details-badge ${className}`}
      >
        {formatLabel(value)}
      </span>

    </div>
  );
}


/* ============================================================================
 * Relationship Card
 * ========================================================================== */

function RelationshipCard({
  title,
  count,
  ids,
}: RelationshipCardProps) {

  const safeIds =
    Array.isArray(ids)
      ? ids.filter(
          (id): id is string =>
            typeof id === "string" &&
            id.trim().length > 0,
        )
      : [];

  return (
    <div className="ioc-details-relationship-card">

      <div className="ioc-details-relationship-header">

        <span className="ioc-details-relationship-title">
          {title}
        </span>

        <span className="ioc-details-relationship-count">
          {count}
        </span>

      </div>

      {safeIds.length > 0 ? (

        <div className="ioc-details-relationship-list">

          {safeIds.slice(0, 10).map((id) => (
            <span
              key={id}
              className="ioc-details-relationship-id"
              title={id}
            >
              {id}
            </span>
          ))}

          {safeIds.length > 10 && (
            <span className="ioc-details-muted">
              +{safeIds.length - 10} more
            </span>
          )}

        </div>

      ) : (

        <span className="ioc-details-muted">
          No related objects available.
        </span>

      )}

    </div>
  );
}


/* ============================================================================
 * Metadata Viewer
 * ========================================================================== */

function MetadataViewer({
  metadata,
}: {
  metadata: Record<string, unknown>;
}) {

  const entries =
    Object.entries(metadata);

  if (entries.length === 0) {

    return (
      <span className="ioc-details-muted">
        No additional metadata available.
      </span>
    );
  }

  return (
    <div className="ioc-details-metadata">

      {entries.map(([key, value]) => (

        <div
          key={key}
          className="ioc-details-metadata-row"
        >

          <span className="ioc-details-metadata-key">
            {key}
          </span>

          <span className="ioc-details-metadata-value">
            {formatMetadataValue(value)}
          </span>

        </div>

      ))}

    </div>
  );
}


/* ============================================================================
 * Relationship Normalization
 * ========================================================================== */

interface NormalizedRelationship {
  title: string;
  count: number;
  ids: string[];
}

function getRelationships(
  ioc: IOCDetail,
): NormalizedRelationship[] {

  const relationships =
    isRecord(ioc.relationships)
      ? ioc.relationships
      : {};

  return [
    createRelationship(
      "Events",
      getRelationshipCount(
        ioc,
        relationships,
        [
          "event_count",
          "events_count",
        ],
      ),
      getRelationshipIds(
        ioc,
        relationships,
        [
          "event_ids",
          "events",
        ],
      ),
    ),

    createRelationship(
      "Alerts",
      getRelationshipCount(
        ioc,
        relationships,
        [
          "alert_count",
          "alerts_count",
        ],
      ),
      getRelationshipIds(
        ioc,
        relationships,
        [
          "alert_ids",
          "alerts",
        ],
      ),
    ),

    createRelationship(
      "Incidents",
      getRelationshipCount(
        ioc,
        relationships,
        [
          "incident_count",
          "incidents_count",
        ],
      ),
      getRelationshipIds(
        ioc,
        relationships,
        [
          "incident_ids",
          "incidents",
        ],
      ),
    ),

    createRelationship(
      "Assets",
      getRelationshipCount(
        ioc,
        relationships,
        [
          "asset_count",
          "assets_count",
        ],
      ),
      getRelationshipIds(
        ioc,
        relationships,
        [
          "asset_ids",
          "assets",
        ],
      ),
    ),

    createRelationship(
      "MITRE Techniques",
      getRelationshipCount(
        ioc,
        relationships,
        [
          "mitre_technique_count",
          "mitre_techniques_count",
        ],
      ),
      getRelationshipIds(
        ioc,
        relationships,
        [
          "mitre_technique_ids",
          "mitre_techniques",
        ],
      ),
    ),
  ];
}


/* ============================================================================
 * Relationship Helpers
 * ========================================================================== */

function createRelationship(
  title: string,
  count: number,
  ids: string[],
): NormalizedRelationship {

  return {
    title,
    count: Math.max(
      count,
      ids.length,
    ),
    ids,
  };
}


function getRelationshipCount(
  ioc: IOCDetail,
  relationships: Record<string, unknown>,
  keys: string[],
): number {

  for (const key of keys) {

    const directValue =
      (ioc as unknown as Record<string, unknown>)[key];

    const nestedValue =
      relationships[key];

    const value =
      directValue !== undefined
        ? directValue
        : nestedValue;

    if (
      typeof value === "number" &&
      Number.isFinite(value)
    ) {
      return Math.max(0, value);
    }
  }

  return 0;
}


function getRelationshipIds(
  ioc: IOCDetail,
  relationships: Record<string, unknown>,
  keys: string[],
): string[] {

  for (const key of keys) {

    const directValue =
      (ioc as unknown as Record<string, unknown>)[key];

    const nestedValue =
      relationships[key];

    const value =
      directValue !== undefined
        ? directValue
        : nestedValue;

    const ids =
      normalizeIds(value);

    if (ids.length > 0) {
      return ids;
    }
  }

  return [];
}


function normalizeIds(
  value: unknown,
): string[] {

  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .map((item) => {

      if (
        typeof item === "string"
      ) {
        return item.trim();
      }

      if (
        typeof item === "number"
      ) {
        return String(item);
      }

      if (
        isRecord(item)
      ) {

        const candidate =
          item.id ??
          item.event_id ??
          item.alert_id ??
          item.incident_id ??
          item.asset_id ??
          item.technique_id ??
          item.mitre_id;

        if (
          typeof candidate === "string"
        ) {
          return candidate.trim();
        }

        if (
          typeof candidate === "number"
        ) {
          return String(candidate);
        }
      }

      return "";
    })
    .filter(
      (value): value is string =>
        value.length > 0,
    );
}


/* ============================================================================
 * IOC Field Helpers
 * ========================================================================== */

function getIOCId(
  ioc: IOCDetail,
): string {

  const source =
    ioc as unknown as Record<string, unknown>;

  return (
    getOptionalString(
      source.ioc_id,
    ) ||
    getOptionalString(
      source.id,
    ) ||
    "—"
  );
}


function getIOCValue(
  ioc: IOCDetail,
): string {

  const source =
    ioc as unknown as Record<string, unknown>;

  return (
    getOptionalString(
      source.value,
    ) ||
    getOptionalString(
      source.indicator,
    ) ||
    "—"
  );
}


function getIOCType(
  ioc: IOCDetail,
): string {

  const source =
    ioc as unknown as Record<string, unknown>;

  return (
    getOptionalString(
      source.ioc_type,
    ) ||
    getOptionalString(
      source.type,
    ) ||
    "unknown"
  );
}


function getIOCSeverity(
  ioc: IOCDetail,
): string {

  const source =
    ioc as unknown as Record<string, unknown>;

  return (
    getOptionalString(
      source.severity,
    ) ||
    "unknown"
  );
}


function getIOCStatus(
  ioc: IOCDetail,
): string {

  const source =
    ioc as unknown as Record<string, unknown>;

  return (
    getOptionalString(
      source.status,
    ) ||
    "unknown"
  );
}


function getIOCReputation(
  ioc: IOCDetail,
): string {

  const source =
    ioc as unknown as Record<string, unknown>;

  return (
    getOptionalString(
      source.reputation,
    ) ||
    "unknown"
  );
}


function getIOCConfidence(
  ioc: IOCDetail,
): unknown {

  const source =
    ioc as unknown as Record<string, unknown>;

  return source.confidence;
}


/* ============================================================================
 * Formatting Helpers
 * ========================================================================== */

function formatType(
  value: string,
): string {

  if (
    !value ||
    value === "unknown"
  ) {
    return "Unknown";
  }

  return formatLabel(value);
}


function formatLabel(
  value: string,
): string {

  if (!value) {
    return "—";
  }

  return value
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .split(" ")
    .map(
      (part) =>
        part.length > 0
          ? part.charAt(0).toUpperCase() +
            part.slice(1).toLowerCase()
          : part,
    )
    .join(" ");
}


function formatConfidence(
  value: unknown,
): string {

  if (
    typeof value === "number" &&
    Number.isFinite(value)
  ) {

    const normalized =
      value <= 1
        ? value * 100
        : value;

    return `${Math.round(normalized)}%`;
  }

  if (
    typeof value === "string" &&
    value.trim()
  ) {
    return value;
  }

  return "—";
}


function formatDateTime(
  value: unknown,
): string {

  const raw =
    getOptionalString(value);

  if (!raw) {
    return "—";
  }

  const timestamp =
    Date.parse(raw);

  if (
    Number.isNaN(timestamp)
  ) {
    return raw;
  }

  return new Intl.DateTimeFormat(
    undefined,
    {
      dateStyle: "medium",
      timeStyle: "medium",
    },
  ).format(
    new Date(timestamp),
  );
}


function formatMetadataValue(
  value: unknown,
): string {

  if (
    value === null ||
    value === undefined
  ) {
    return "—";
  }

  if (
    typeof value === "string"
  ) {
    return value;
  }

  if (
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return String(value);
  }

  try {

    return JSON.stringify(
      value,
      null,
      2,
    );

  } catch {

    return String(value);
  }
}


/* ============================================================================
 * CSS Classification Helpers
 * ========================================================================== */

function getSeverityClass(
  value: string,
): string {

  switch (
    value.toLowerCase()
  ) {

    case "critical":
      return "ioc-details-badge-critical";

    case "high":
      return "ioc-details-badge-high";

    case "medium":
      return "ioc-details-badge-medium";

    case "low":
      return "ioc-details-badge-low";

    case "info":
    case "informational":
      return "ioc-details-badge-info";

    default:
      return "ioc-details-badge-neutral";
  }
}


function getReputationClass(
  value: string,
): string {

  switch (
    value.toLowerCase()
  ) {

    case "malicious":
      return "ioc-details-badge-critical";

    case "suspicious":
      return "ioc-details-badge-high";

    case "benign":
      return "ioc-details-badge-low";

    case "unknown":
      return "ioc-details-badge-neutral";

    default:
      return "ioc-details-badge-neutral";
  }
}


function getStatusClass(
  value: string,
): string {

  switch (
    value.toLowerCase()
  ) {

    case "active":
      return "ioc-details-badge-active";

    case "expired":
      return "ioc-details-badge-medium";

    case "revoked":
      return "ioc-details-badge-neutral";

    default:
      return "ioc-details-badge-neutral";
  }
}


/* ============================================================================
 * Generic Helpers
 * ========================================================================== */

function getOptionalString(
  value: unknown,
): string {

  if (
    typeof value !== "string"
  ) {
    return "";
  }

  return value.trim();
}


function isRecord(
  value: unknown,
): value is Record<string, unknown> {

  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}


function getErrorMessage(
  error: unknown,
  fallback: string,
): string {

  if (
    error instanceof Error &&
    error.message.trim()
  ) {
    return error.message;
  }

  if (
    isRecord(error)
  ) {

    const detail =
      error.detail;

    if (
      typeof detail === "string" &&
      detail.trim()
    ) {
      return detail;
    }

    const message =
      error.message;

    if (
      typeof message === "string" &&
      message.trim()
    ) {
      return message;
    }
  }

  return fallback;
}


/* ============================================================================
 * Back Navigation
 * ========================================================================== */

function getBackPath(
  state: { from?: string } | null,
): string {

  const from =
    state?.from;

  if (
    typeof from === "string" &&
    from.startsWith("/")
  ) {
    return from;
  }

  return "/threat-intelligence";
}