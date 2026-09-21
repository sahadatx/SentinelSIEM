import { Route } from "react-router-dom";

import { PermissionRoute } from "../../components/auth/PermissionRoute";
import Events from "./pages/Events";
import EventDetails from "./pages/EventDetails";
import { EVENTS_READ } from "./permissions";

/**
 * Events module route registry.
 *
 * This file intentionally does not modify App.tsx.
 * The central application router can import this route
 * definition later during the routing migration.
 */
export function EventsRoutes() {
  return (
    <Route
      element={
        <PermissionRoute
          permission={EVENTS_READ}
        />
      }
    >
      <Route
        path="/events"
        element={<Events />}
      />

      <Route
        path="/events/:eventId"
        element={<EventDetails />}
      />
    </Route>
  );
}