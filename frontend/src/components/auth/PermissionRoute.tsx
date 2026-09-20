import {
  Navigate,
  Outlet,
  useLocation,
} from "react-router-dom";

import { useAuthStore } from "../../store/auth";

interface PermissionRouteProps {
  permission: string;
  fallbackPath?: string;
}

export function PermissionRoute({
  permission,
  fallbackPath = "/",
}: PermissionRouteProps) {
  const location = useLocation();

  const authReady = useAuthStore(
    (state) => state.authReady,
  );

  const authenticated = useAuthStore(
    (state) => state.authenticated,
  );

  const hasPermission = useAuthStore(
    (state) => state.hasPermission,
  );

  if (!authReady) {
    return (
      <main className="auth-page">
        <section className="auth-card auth-loading">
          <div className="auth-brand">
            <div className="auth-brand-mark">
              <span className="auth-loading-dot" />
            </div>

            <div>
              <strong>
                SentinelSIEM
              </strong>

              <span>
                SOC Platform
              </span>
            </div>
          </div>

          <div className="auth-heading">
            <h1>
              Verifying session
            </h1>

            <p>
              Validating your authentication
              session. Please wait.
            </p>
          </div>
        </section>
      </main>
    );
  }

  if (!authenticated) {
    return (
      <Navigate
        to="/login"
        replace
        state={{
          from: location.pathname,
        }}
      />
    );
  }

  if (!hasPermission(permission)) {
    return (
      <Navigate
        to={fallbackPath}
        replace
      />
    );
  }

  return <Outlet />;
}