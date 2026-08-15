import type {
  Alert,
  HealthResponse,
  Incident,
  IOC,
  MitreCoverage,
  PaginatedResponse,
  SecurityEvent,
  SystemResponse,
} from "../types/api";

/*
 * Keep the API client relative to the frontend origin.
 *
 * In development:
 *   Browser -> Vite :5173 -> proxy -> FastAPI :8000
 *
 * In production/preview:
 *   The same relative /api path can be handled by the
 *   configured reverse proxy.
 */
const API_BASE_URL = "";

export class ApiError extends Error {
  status: number;
  detail: string;

  constructor(
    status: number,
    detail: string,
  ) {
    super(detail);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

async function request<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const response = await fetch(
    `${API_BASE_URL}${path}`,
    {
      ...init,
      headers: {
        Accept: "application/json",
        ...(init?.headers ?? {}),
      },
    },
  );

  if (!response.ok) {
    let detail = `Request failed with status ${response.status}`;

    try {
      const body = (await response.json()) as {
        detail?: string;
        message?: string;
      };

      detail =
        body.detail ??
        body.message ??
        detail;
    } catch {
      // Keep the default HTTP error message.
    }

    throw new ApiError(
      response.status,
      detail,
    );
  }

  return (await response.json()) as T;
}

function paginatedPath(
  resource: string,
  page = 1,
  pageSize = 100,
): string {
  const params = new URLSearchParams({
    page: String(page),
    page_size: String(pageSize),
  });

  return `/api/v1/${resource}?${params.toString()}`;
}

/**
 * Phase 15 API
 */
export const api = {
  /**
   * GET /api/v1/health
   */
  health(): Promise<HealthResponse> {
    return request<HealthResponse>(
      "/api/v1/health",
    );
  },

  /**
   * GET /api/v1/system
   */
  system(): Promise<SystemResponse> {
    return request<SystemResponse>(
      "/api/v1/system",
    );
  },

  /**
   * GET /api/v1/events
   */
  events(
    page = 1,
    pageSize = 100,
  ): Promise<PaginatedResponse<SecurityEvent>> {
    return request<
      PaginatedResponse<SecurityEvent>
    >(
      paginatedPath(
        "events",
        page,
        pageSize,
      ),
    );
  },

  /**
   * GET /api/v1/alerts
   */
  alerts(
    page = 1,
    pageSize = 100,
  ): Promise<PaginatedResponse<Alert>> {
    return request<
      PaginatedResponse<Alert>
    >(
      paginatedPath(
        "alerts",
        page,
        pageSize,
      ),
    );
  },

  /**
   * GET /api/v1/incidents
   */
  incidents(
    page = 1,
    pageSize = 100,
  ): Promise<PaginatedResponse<Incident>> {
    return request<
      PaginatedResponse<Incident>
    >(
      paginatedPath(
        "incidents",
        page,
        pageSize,
      ),
    );
  },

  /**
   * GET /api/v1/iocs
   */
  iocs(
    page = 1,
    pageSize = 100,
  ): Promise<PaginatedResponse<IOC>> {
    return request<
      PaginatedResponse<IOC>
    >(
      paginatedPath(
        "iocs",
        page,
        pageSize,
      ),
    );
  },

  /**
   * GET /api/v1/mitre/coverage
   */
  mitre(): Promise<MitreCoverage> {
    return request<MitreCoverage>(
      "/api/v1/mitre/coverage",
    );
  },
};