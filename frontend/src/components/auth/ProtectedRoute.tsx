import {
  Navigate,
  Outlet,
  useLocation,
} from "react-router-dom";

import { useAuthStore } from "../../store/auth";

export function ProtectedRoute() {
  const location = useLocation();

  const authenticated = useAuthStore(
    (state) => state.authenticated,
  );

  const authReady = useAuthStore(
    (state) => state.authReady,
  );

  /*
   * Authentication bootstrap is still running.
   *
   * Do not redirect to /login until the stored token,
   * if any, has been validated against the backend.
   */
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

  return <Outlet />;
}