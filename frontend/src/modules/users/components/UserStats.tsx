/**
 * ============================================================================
 * SentinelSIEM — User Statistics
 * ============================================================================
 *
 * Users-module statistics presentation layer.
 *
 * Responsibilities:
 * - Display total users
 * - Display active users
 * - Display disabled users
 * - Display locked users
 *
 * The component is intentionally presentation-only.
 * Data loading and business logic remain in the Users page/API layer.
 *
 * The shared MetricCard component owns the actual metric-card UI.
 * ============================================================================
 */

import {
  Lock,
  UserCheck,
  UserPlus,
  Users,
} from "lucide-react";

import { MetricCard } from "../../../components/ui/MetricCard";

import type { UserStatistics } from "../types";

/**
 * ============================================================================
 * Props
 * ============================================================================
 */

export interface UserStatsProps {
  /**
   * Aggregated user-management statistics.
   */
  statistics: UserStatistics;
}

/**
 * ============================================================================
 * User Statistics
 * ============================================================================
 */

export default function UserStats({
  statistics,
}: UserStatsProps) {
  /**
   * Keep the statistics component free of
   * API calls, state, and business logic.
   *
   * The Users page is responsible for obtaining
   * and providing the statistics.
   */

  return (
    <section
      className="metrics-grid"
      aria-label="User statistics"
    >
      {/* ================================================================== */}
      {/* Total Users                                                        */}
      {/* ================================================================== */}

      <MetricCard
        label="Total Users"
        value={statistics.total}
        detail="Registered user accounts"
        icon={
          <Users
            size={17}
            aria-hidden="true"
          />
        }
      />

      {/* ================================================================== */}
      {/* Active Users                                                       */}
      {/* ================================================================== */}

      <MetricCard
        label="Active Users"
        value={statistics.active}
        detail="Accounts currently enabled"
        icon={
          <UserCheck
            size={17}
            aria-hidden="true"
          />
        }
        tone="success"
      />

      {/* ================================================================== */}
      {/* Disabled Users                                                     */}
      {/* ================================================================== */}

      <MetricCard
        label="Disabled Users"
        value={statistics.disabled}
        detail="Accounts currently disabled"
        icon={
          <UserPlus
            size={17}
            aria-hidden="true"
          />
        }
        tone={
          statistics.disabled > 0
            ? "warning"
            : "default"
        }
      />

      {/* ================================================================== */}
      {/* Locked Users                                                        */}
      {/* ================================================================== */}

      <MetricCard
        label="Locked Users"
        value={statistics.locked}
        detail="Accounts currently locked"
        icon={
          <Lock
            size={17}
            aria-hidden="true"
          />
        }
        tone={
          statistics.locked > 0
            ? "danger"
            : "default"
        }
      />
    </section>
  );
}