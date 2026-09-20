/*
 * ============================================================================
 * SentinelSIEM — Shared Panel
 * ============================================================================
 *
 * Reusable presentation component for dashboard and feature panels.
 *
 * Responsibilities:
 * - Render a consistent SentinelSIEM panel container
 * - Render panel title
 * - Render optional subtitle
 * - Render optional header action
 * - Render arbitrary panel content
 *
 * This component intentionally contains no:
 * - business logic
 * - API calls
 * - authentication logic
 * - authorization logic
 * - feature-specific state
 * ============================================================================
 */

import type { ReactNode } from "react";

/* ============================================================================
   Props
   ========================================================================== */

export interface PanelProps {
  title: string;
  subtitle?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}

/* ============================================================================
   Panel
   ========================================================================== */

export function Panel({
  title,
  subtitle,
  action,
  children,
  className = "",
}: PanelProps) {
  const panelClassName = [
    "panel",
    className.trim(),
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <section className={panelClassName}>
      {/* ====================================================================
         Header
         ================================================================== */}

      <div className="panel-header">
        <div>
          <h2>{title}</h2>

          {subtitle ? (
            <p>{subtitle}</p>
          ) : null}
        </div>

        {action ? (
          <div className="panel-header-action">
            {action}
          </div>
        ) : null}
      </div>

      {/* ====================================================================
         Content
         ================================================================== */}

      {children}
    </section>
  );
}

/* ============================================================================
   Default Export
   ========================================================================== */

export default Panel;