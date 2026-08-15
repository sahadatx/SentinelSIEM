import type { Severity } from "../../types/api";

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  return <span className={`severity severity-${severity.toLowerCase()}`}>{severity}</span>;
}
