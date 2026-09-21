import type { LucideIcon } from "lucide-react";
import {
  Users as UsersIcon,
} from "lucide-react";

import {
  USERS_READ,
} from "./permissions";

/* ==========================================================================
   Navigation Contract
   ========================================================================== */

export interface UsersNavigationItem {
  label: string;
  path: string;
  icon: LucideIcon;
  permission: string;
  description: string;
}

/* ==========================================================================
   Users Navigation
   ========================================================================== */

export const usersNavigation: UsersNavigationItem = {
  label: "Users",
  path: "/users",
  icon: UsersIcon,
  permission: USERS_READ,
  description:
    "Manage SentinelSIEM user accounts and access.",
};

export default usersNavigation;
