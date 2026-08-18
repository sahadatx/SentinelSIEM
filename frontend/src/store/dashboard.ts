import { create } from "zustand";

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

interface DashboardState {
  events: PaginatedResponse<SecurityEvent> | null;
  alerts: PaginatedResponse<Alert> | null;
  incidents: PaginatedResponse<Incident> | null;
  iocs: PaginatedResponse<IOC> | null;

  mitre: MitreCoverage | null;
  health: HealthResponse | null;
  system: SystemResponse | null;

  error: string | null;
  live: boolean;

  setSnapshot: (snapshot: Partial<DashboardState>) => void;
  setError: (error: string | null) => void;
  setLive: (live: boolean) => void;
}

export const useDashboardStore = create<DashboardState>(
  (set) => ({
    events: null,
    alerts: null,
    incidents: null,
    iocs: null,

    mitre: null,
    health: null,
    system: null,

    error: null,
    live: false,

    setSnapshot: (snapshot) => {
      set(snapshot);
    },

    setError: (error) => {
      set({ error });
    },

    setLive: (live) => {
      set({ live });
    },
  }),
);