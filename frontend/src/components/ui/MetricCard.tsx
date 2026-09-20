import type { ReactNode } from "react";

export interface MetricCardProps {
  label: string;
  value: string | number;
  detail?: string;
  icon: ReactNode;
  tone?: "default" | "danger" | "warning" | "success" | "info";
}

export function MetricCard({
  label,
  value,
  detail,
  icon,
  tone = "default",
}: MetricCardProps) {
  return (
    <article className={`metric-card ${tone}`}>
      <div className="metric-icon">
        {icon}
      </div>

      <div className="metric-content">
        <span className="metric-card-label">
          {label}
        </span>

        <strong className="metric-card-value">
          {value}
        </strong>

        {detail && (
          <small className="metric-card-meta">
            {detail}
          </small>
        )}
      </div>
    </article>
  );
}