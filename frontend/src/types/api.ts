export type Severity =
  | "info"
  | "low"
  | "medium"
  | "high"
  | "critical";

export type HealthState =
  | "healthy"
  | "degraded"
  | "offline"
  | "unknown";

export interface SecurityEvent {
  event_id: string;
  timestamp: string;
  source: string;
  source_type: string;
  source_ip?: string;
  destination_ip?: string;
  username?: string;
  action?: string;
  outcome?: string;
  severity?: Severity;
  category?: string;
}

export interface Alert {
  alert_id: string;
  title: string;
  severity: Severity;
  priority: string;
  status: string;
  source_id: string;
  created_at: string;
  risk_score: number;
}

export interface Incident {
  incident_id: string;
  title: string;
  severity: Severity;
  status: string;
  created_at: string;
  assigned_to?: string;
}

export interface IOC {
  ioc_id: string;
  type: string;
  value: string;
  reputation: string;
  confidence: number;
  source: string;
}

export interface MitreCoverage {
  total_techniques: number;
  covered_techniques: number;
  coverage_percent: number;
}

export interface Pagination {
  page: number;
  page_size: number;
  total: number;
}

export interface PaginatedResponse<T> {
  items: T[];
  pagination: Pagination;
}

/*
 * Actual Phase 15 /api/v1/health response.
 *
 * This endpoint currently exposes API health only.
 * It does not expose database, Redis, OpenSearch,
 * queue, worker, or ingestion telemetry.
 */
export interface HealthResponse {
  status: string;
  service: string;
  version: string;
}

/*
 * Actual Phase 15 /api/v1/system response.
 */
export interface SystemResponse {
  service: string;
  version: string;
  environment: string;
  capabilities: string[];
}

export interface DashboardSnapshot {
  events: PaginatedResponse<SecurityEvent> | null;
  alerts: PaginatedResponse<Alert> | null;
  incidents: PaginatedResponse<Incident> | null;
  iocs: PaginatedResponse<IOC> | null;
  mitre: MitreCoverage | null;
  health: HealthResponse | null;
  system: SystemResponse | null;
}