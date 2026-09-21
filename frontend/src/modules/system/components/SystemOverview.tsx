/**
 * ============================================================
 * SentinelSIEM — System Overview
 * ============================================================
 *
 * Displays the core SentinelSIEM system metadata:
 *   - Service
 *   - Version
 *   - Environment
 * ============================================================
 */

import type { SystemComponentProps } from "../types";

export function SystemOverview({
  system,
}: SystemComponentProps) {
  return (
    <section
      aria-labelledby="system-overview-title"
      className="rounded-xl border bg-card p-6 shadow-sm"
    >
      <div className="mb-5">
        <h2
          id="system-overview-title"
          className="text-lg font-semibold"
        >
          System Overview
        </h2>

        <p className="mt-1 text-sm text-muted-foreground">
          Core SentinelSIEM platform information.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <div className="rounded-lg border p-4">
          <p className="text-sm text-muted-foreground">
            Service
          </p>

          <p className="mt-1 break-words text-base font-medium">
            {system.service}
          </p>
        </div>

        <div className="rounded-lg border p-4">
          <p className="text-sm text-muted-foreground">
            Version
          </p>

          <p className="mt-1 text-base font-medium">
            {system.version}
          </p>
        </div>

        <div className="rounded-lg border p-4">
          <p className="text-sm text-muted-foreground">
            Environment
          </p>

          <p className="mt-1 text-base font-medium capitalize">
            {system.environment}
          </p>
        </div>
      </div>
    </section>
  );
}

export default SystemOverview;
