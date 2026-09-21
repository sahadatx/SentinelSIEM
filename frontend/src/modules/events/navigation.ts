import {
  Activity,
} from "lucide-react";

import { PERMISSIONS } from "../../auth/rbac";

export interface EventsNavigationItem {
  to: string;
  label: string;
  permission: string;
  icon: typeof Activity;
  end?: boolean;
}

export const eventsNavigation: EventsNavigationItem = {
  to: "/events",
  label: "Events",
  permission: PERMISSIONS.EVENTS_READ,
  icon: Activity,
  end: true,
};