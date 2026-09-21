/**
 * ============================================================
 * SentinelSIEM — System Module
 * ============================================================
 *
 * Public exports for the System feature module.
 * ============================================================
 */

export {
  default as System,
} from "./pages/System";

export {
  getSystemInfo,
} from "./api";

export type {
  SystemInfo,
  SystemCapability,
  SystemComponentProps,
  SystemLoadingProps,
  SystemErrorProps,
} from "./types";

export {
  default as SystemOverview,
} from "./components/SystemOverview";

export {
  default as SystemHealth,
} from "./components/SystemHealth";

export {
  default as SystemCapabilities,
} from "./components/SystemCapabilities";

export {
  default as SystemRuntime,
} from "./components/SystemRuntime";
