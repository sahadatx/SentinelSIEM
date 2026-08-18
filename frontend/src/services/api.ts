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
import { useAuthStore } from "../store/auth";

/*
 * Keep the API client relative to the frontend origin.
 *
 * Development:
 *   Browser -> Vite :5173 -> proxy -> FastAPI :8000
 *
 * Production:
 *   Browser -> Nginx/frontend origin -> /api -> backend
 */
const API_BASE_URL = "";

export interface AuthUser {
  user_id: string;
  username: string;
  roles: string[];
  permissions: string[];
  session_id: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  user: AuthUser;
}

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
  const token =
    useAuthStore.getState().accessToken;

  const headers = new Headers(
    init?.headers,
  );

  headers.set(
    "Accept",
    "application/json",
  );

  if (token) {
    headers.set(
      "Authorization",
      `Bearer ${token}`,
    );
  }

  const response = await fetch(
    `${API_BASE_URL}${path}`,
    {
      ...init,
      headers,
    },
  );

  if (!response.ok) {
    let detail =
      `Request failed with status ${response.status}`;

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

    /*
     * Authentication state is no longer valid.
     *
     * Do not automatically clear the session for every
     * 403 response because a 403 can also mean that the
     * authenticated user simply lacks a permission.
     */
    if (response.status === 401) {
      useAuthStore
        .getState()
        .clearAuthentication();
    }

    throw new ApiError(
      response.status,
      detail,
    );
  }

  /*
   * Support endpoints such as logout that may return
   * HTTP 204 No Content.
   */
  if (response.status === 204) {
    return undefined as T;
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
 * Phase 15 / Phase 17 API
 */
export const api = {
  /**
   * POST /api/v1/auth/login
   */
  async login(
    login: string,
    password: string,
  ): Promise<LoginResponse> {
    const response =
      await request<LoginResponse>(
        "/api/v1/auth/login",
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/json",
          },
          body: JSON.stringify({
            login,
            password,
          }),
        },
      );

    useAuthStore
      .getState()
      .setAuthentication(
        response.access_token,
        response.user,
      );

    return response;
  },

  /**
   * GET /api/v1/auth/me
   */
  me(): Promise<AuthUser> {
    return request<AuthUser>(
      "/api/v1/auth/me",
    );
  },

  /**
   * POST /api/v1/auth/logout
   */
  async logout(): Promise<void> {
    try {
      await request<void>(
        "/api/v1/auth/logout",
        {
          method: "POST",
        },
      );
    } finally {
      /*
       * Always clear local authentication state after
       * logout attempt.
       */
      useAuthStore
        .getState()
        .clearAuthentication();
    }
  },

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
  ): Promise<
    PaginatedResponse<SecurityEvent>
  > {
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
  ): Promise<
    PaginatedResponse<Alert>
  > {
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
  ): Promise<
    PaginatedResponse<Incident>
  > {
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
  ): Promise<
    PaginatedResponse<IOC>
  > {
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