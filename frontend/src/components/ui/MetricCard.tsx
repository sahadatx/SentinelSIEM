import type { ReactNode } from "react";

export function MetricCard({ label, value, detail, icon, tone = "default" }: {
  label: string; value: string | number; detail?: string; icon: ReactNode; tone?: "default" | "danger" | "warning" | "success";
}) {
  return (
    <article className={`metric-card ${tone}`}>
      <div className="metric-icon">{icon}</div>
      <div><span>{label}</span><strong>{value}</strong>{detail && <small>{detail}</small>}</div>
    </article>
  );
}
