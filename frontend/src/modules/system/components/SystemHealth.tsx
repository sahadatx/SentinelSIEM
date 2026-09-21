/**
 * ============================================================
 * SentinelSIEM — System Health
 * ============================================================
 *
 * Displays the availability state of the System API.
 *
 * Important:
 * The current /api/v1/system response does not expose a
 * dedicated "status" field. Therefore this component does
 * not invent or calculate a health status.
 * ============================================================
 */

import type {
  SystemComponentProps,
} from "../types";

export function SystemHealth({
  system,
}: SystemComponentProps) {
  return (
    <section
      aria-labelledby="system-health-title"
      className="rounded-xl border bg-card p-6 shadow-sm"
    >
      <div className="mb-5">
        <h2
          id="system-health-title"
          className="text-lg font-semibold"
        >
          System Health
        </h2>

        <p className="mt-1 text-sm text-muted-foreground">
          Current availability of the SentinelSIEM
          system endpoint.
        </p>
      </div>

      <div className="flex items-center gap-4 rounded-lg border p-4">
        <div
          aria-hidden="true"
          className="h-3 w-3 rounded-full bg-emerald-500"
        />

        <div>
          <p className="font-medium">
            System API Available
          </p>

          <p className="text-sm text-muted-foreground">
            {system.service} responded successfully.
          </p>
        </div>
      </div>
    </section>
  );
}

export default SystemHealth;
