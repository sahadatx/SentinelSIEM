/* ==========================================================================
 * SentinelSIEM Resource Pages
 * Shared application-level resource views
 * ========================================================================== */

import {
  useEffect,
  useState,
  type ReactNode,
} from "react";

import { Panel } from "../components/ui/Panel";
import { api } from "../services/api";

import type {
  HealthResponse,
  PaginatedResponse,
  SecurityEvent,
  SystemResponse,
} from "../types/api";

/* ==========================================================================
 * Security Events
 * ========================================================================== */

/**
 * Shared application-level Security Events resource page.
 *
 * Dashboard state is intentionally not used here.
 *
 * Data ownership:
 *
 *   ResourcePage
 *        ↓
 *   services/api.ts
 *        ↓
 *   backend Events API
 *
 * Dashboard-specific state remains inside:
 *
 *   modules/dashboard/
 */
export function EventsPage() {
  const [events, setEvents] =
    useState<
      PaginatedResponse<SecurityEvent> | null
    >(null);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState<string | null>(null);

  useEffect(() => {
    let mounted = true;

    async function loadEvents() {
      setLoading(true);
      setError(null);

      try {
        const response = await api.events();

        if (!mounted) {
          return;
        }

        setEvents(response);
      } catch {
        if (!mounted) {
          return;
        }

        setEvents(null);
        setError(
          "Security event data is currently unavailable.",
        );
      } finally {
        if (mounted) {
          setLoading(false);
        }
      }
    }

    void loadEvents();

    return () => {
      mounted = false;
    };
  }, []);

  const items = events?.items ?? [];

  const total =
    events?.pagination.total ?? 0;

  return (
    <Page
      title="Security Events"
      subtitle="Canonical events delivered by the Phase 15 API"
    >
      <Panel
        title="Event stream"
        subtitle={
          loading
            ? "Loading security events..."
            : events
              ? `${total} records available`
              : "Event repository is unavailable"
        }
      >
        {error && (
          <Unavailable
            message={error}
          />
        )}

        {!error && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Source</th>
                  <th>Source IP</th>
                  <th>User</th>
                  <th>Action</th>
                  <th>Outcome</th>
                </tr>
              </thead>

              <tbody>
                {items.map((event) => (
                  <tr
                    key={event.event_id}
                  >
                    <td>
                      {formatDateTime(
                        event.timestamp,
                      )}
                    </td>

                    <td>
                      {event.source}
                    </td>

                    <td>
                      {event.source_ip ?? "—"}
                    </td>

                    <td>
                      {event.username ?? "—"}
                    </td>

                    <td>
                      {event.action ?? "—"}
                    </td>

                    <td>
                      {event.outcome ?? "—"}
                    </td>
                  </tr>
                ))}

                {!loading &&
                  items.length === 0 && (
                    <Empty
                      cols={6}
                      message="No security events available."
                    />
                  )}

                {loading && (
                  <Empty
                    cols={6}
                    message="Loading security events..."
                  />
                )}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </Page>
  );
}

/* ==========================================================================
 * System Health
 * ========================================================================== */

/**
 * Shared application-level system health page.
 *
 * This page intentionally does not depend on:
 *
 *   store/dashboard.ts
 *
 * Health and system information are loaded directly
 * from the shared API transport.
 */
export function SystemPage() {
  const [health, setHealth] =
    useState<HealthResponse | null>(
      null,
    );

  const [system, setSystem] =
    useState<SystemResponse | null>(
      null,
    );

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState<string | null>(null);

  useEffect(() => {
    let mounted = true;

    async function loadSystemHealth() {
      setLoading(true);
      setError(null);

      const results =
        await Promise.allSettled([
          api.health(),
          api.system(),
        ]);

      if (!mounted) {
        return;
      }

      const [
        healthResult,
        systemResult,
      ] = results;

      if (
        healthResult.status ===
        "fulfilled"
      ) {
        setHealth(
          healthResult.value,
        );
      } else {
        setHealth(null);
      }

      if (
        systemResult.status ===
        "fulfilled"
      ) {
        setSystem(
          systemResult.value,
        );
      } else {
        setSystem(null);
      }

      const failedEndpoints =
        results.filter(
          (result) =>
            result.status ===
            "rejected",
        ).length;

      if (failedEndpoints > 0) {
        setError(
          `${failedEndpoints} system endpoint(s) unavailable.`,
        );
      }

      setLoading(false);
    }

    void loadSystemHealth();

    return () => {
      mounted = false;
    };
  }, []);

  const apiStatus =
    health?.status ?? "offline";

  return (
    <Page
      title="System Health"
      subtitle="Operational status from the Phase 15 system API"
    >
      {error && (
        <div
          role="alert"
          className="mb-4"
        >
          <Unavailable
            message={`${error} Available information is still displayed.`}
          />
        </div>
      )}

      <Panel title="Platform Status">
        {loading ? (
          <Unavailable
            message="Loading platform status..."
          />
        ) : (
          <div className="health-list">
            <HealthRow
              name="API"
              status={apiStatus}
            />

            <HealthRow
              name="Service"
              status={
                health?.service ??
                "unavailable"
              }
            />

            <HealthRow
              name="Version"
              status={
                health?.version ??
                "—"
              }
            />

            <HealthRow
              name="Environment"
              status={
                system?.environment ??
                "—"
              }
            />

            <HealthRow
              name="System Service"
              status={
                system?.service ??
                "—"
              }
            />
          </div>
        )}
      </Panel>

      <Panel title="Capabilities">
        {system?.capabilities?.length ? (
          <div className="capability-list">
            {system.capabilities.map(
              (capability) => (
                <span
                  className="health-pill healthy"
                  key={capability}
                >
                  {capability}
                </span>
              ),
            )}
          </div>
        ) : (
          <Unavailable
            message={
              loading
                ? "Loading system capabilities..."
                : "System capability information is currently unavailable."
            }
          />
        )}
      </Panel>
    </Page>
  );
}

/* ==========================================================================
 * Generic Resource Page
 * ========================================================================== */

/**
 * Generic fallback page for resources whose dedicated
 * feature module has not yet been implemented.
 */
export function GenericPage({
  title,
}: {
  title: string;
}) {
  return (
    <Page
      title={title}
      subtitle="This view is intentionally read-only until the corresponding backend capability is exposed."
    >
      <Panel title="Service-backed view">
        <div className="empty-state">
          <p>
            No frontend business logic is
            implemented here. Connect this
            page to the existing Phase 15 API
            contract when the backend endpoint
            is available.
          </p>
        </div>
      </Panel>
    </Page>
  );
}

/* ==========================================================================
 * Shared Page Layout
 * ========================================================================== */

function Page({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle: string;
  children: ReactNode;
}) {
  return (
    <>
      <div className="page-heading">
        <div>
          <h2>{title}</h2>
          <p>{subtitle}</p>
        </div>
      </div>

      {children}
    </>
  );
}

/* ==========================================================================
 * Shared Empty Table State
 * ========================================================================== */

function Empty({
  cols,
  message = "No data available.",
}: {
  cols: number;
  message?: string;
}) {
  return (
    <tr>
      <td
        colSpan={cols}
        className="empty"
      >
        {message}
      </td>
    </tr>
  );
}

/* ==========================================================================
 * Shared Unavailable State
 * ========================================================================== */

function Unavailable({
  message,
}: {
  message: string;
}) {
  return (
    <div className="empty-state">
      <p>{message}</p>
    </div>
  );
}

/* ==========================================================================
 * Shared Health Row
 * ========================================================================== */

function HealthRow({
  name,
  status,
}: {
  name: string;
  status: string;
}) {
  const normalized =
    status.toLowerCase();

  const healthClass =
    normalized === "ok" ||
    normalized === "healthy" ||
    normalized === "available"
      ? "healthy"
      : normalized === "degraded"
        ? "degraded"
        : normalized === "offline" ||
            normalized === "unavailable"
          ? "offline"
          : "";

  return (
    <div className="health-row">
      <span>{name}</span>

      <span
        className={`health-pill ${healthClass}`}
      >
        {status}
      </span>
    </div>
  );
}

/* ==========================================================================
 * Shared Date Formatter
 * ========================================================================== */

function formatDateTime(
  value: string,
): string {
  const date = new Date(value);

  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    return value;
  }

  return date.toLocaleString();
}