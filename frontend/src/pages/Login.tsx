import { useState } from "react";
import type { FormEvent } from "react";
import {
  CircleGauge,
  Eye,
  EyeOff,
  LockKeyhole,
  LogIn,
  ShieldCheck,
} from "lucide-react";
import {
  useLocation,
  useNavigate,
} from "react-router-dom";

import { ApiError, api } from "../services/api";

interface LoginLocationState {
  from?: string;
}

export default function Login() {
  const navigate = useNavigate();
  const location = useLocation();

  const [login, setLogin] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const locationState =
    location.state as LoginLocationState | null;

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    if (submitting) {
      return;
    }

    setError("");
    setSubmitting(true);

    try {
      await api.login(
        login.trim(),
        password,
      );

      /*
       * Return the user to the protected route that
       * originally triggered authentication.
       *
       * Fall back to the main dashboard.
       */
      const destination =
        locationState?.from || "/";

      navigate(destination, {
        replace: true,
      });
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 401) {
          setError(
            "Invalid username or password.",
          );
        } else {
          setError(err.detail);
        }
      } else {
        setError(
          "Unable to sign in. Please try again.",
        );
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main
      className="auth-page"
      aria-label="SentinelSIEM authentication"
    >
      <div
        className="auth-background-grid"
        aria-hidden="true"
      />

      <div
        className="auth-background-glow auth-background-glow-primary"
        aria-hidden="true"
      />

      <div
        className="auth-background-glow auth-background-glow-secondary"
        aria-hidden="true"
      />

      <section className="auth-card">
        <div className="auth-card-header">
          <div className="auth-brand">
            <div
              className="auth-brand-mark"
              aria-hidden="true"
            >
              <CircleGauge size={25} strokeWidth={1.8} />
            </div>

            <div className="auth-brand-copy">
              <strong>SentinelSIEM</strong>
              <span>Security Operations Platform</span>
            </div>
          </div>

          <div
            className="auth-security-status"
            aria-label="Secure authentication"
          >
            <ShieldCheck
              size={14}
              aria-hidden="true"
            />
            <span>Secure Access</span>
          </div>
        </div>

        <div className="auth-heading">
          <span className="auth-eyebrow">
            SECURITY OPERATIONS CENTER
          </span>

          <h1>Sign in</h1>

          <p>
            Sign in to access your SentinelSIEM
            security operations console.
          </p>
        </div>

        {error && (
          <div
            className="auth-error"
            role="alert"
            aria-live="assertive"
          >
            <div
              className="auth-error-indicator"
              aria-hidden="true"
            />

            <div className="auth-error-content">
              <strong>
                Authentication failed
              </strong>

              <span>{error}</span>
            </div>
          </div>
        )}

        <form
          className="auth-form"
          onSubmit={handleSubmit}
        >
          <div className="auth-field">
            <label htmlFor="login">
              Username or email
            </label>

            <div className="auth-input-wrapper">
              <CircleGauge
                className="auth-input-icon"
                size={17}
                aria-hidden="true"
              />

              <input
                id="login"
                name="login"
                type="text"
                autoComplete="username"
                autoCapitalize="none"
                spellCheck={false}
                value={login}
                onChange={(event) =>
                  setLogin(event.target.value)
                }
                disabled={submitting}
                required
                placeholder="Enter your username or email"
              />
            </div>
          </div>

          <div className="auth-field">
            <label htmlFor="password">
              Password
            </label>

            <div className="auth-input-wrapper">
              <LockKeyhole
                className="auth-input-icon"
                size={17}
                aria-hidden="true"
              />

              <input
                id="password"
                name="password"
                type={
                  showPassword
                    ? "text"
                    : "password"
                }
                autoComplete="current-password"
                value={password}
                onChange={(event) =>
                  setPassword(event.target.value)
                }
                disabled={submitting}
                required
                placeholder="Enter your password"
              />

              <button
                type="button"
                className="auth-password-toggle"
                onClick={() =>
                  setShowPassword(
                    (visible) => !visible,
                  )
                }
                disabled={submitting}
                aria-label={
                  showPassword
                    ? "Hide password"
                    : "Show password"
                }
                aria-pressed={showPassword}
              >
                {showPassword ? (
                  <EyeOff
                    size={17}
                    aria-hidden="true"
                  />
                ) : (
                  <Eye
                    size={17}
                    aria-hidden="true"
                  />
                )}
              </button>
            </div>
          </div>

          <button
            className="auth-submit"
            type="submit"
            disabled={
              submitting ||
              !login.trim() ||
              !password
            }
          >
            {submitting ? (
              <span
                className="auth-submit-spinner"
                aria-hidden="true"
              />
            ) : (
              <LogIn
                size={17}
                aria-hidden="true"
              />
            )}

            <span>
              {submitting
                ? "Signing in..."
                : "Sign in"}
            </span>
          </button>
        </form>

        <div className="auth-card-footer">
          <span>
            Protected SentinelSIEM environment
          </span>

          <span
            className="auth-footer-separator"
            aria-hidden="true"
          >
            •
          </span>

          <span>
            Authorized access only
          </span>
        </div>
      </section>

      <footer className="auth-page-footer">
        <span>SentinelSIEM</span>
        <span
          className="auth-footer-separator"
          aria-hidden="true"
        >
          •
        </span>
        <span>
          Security Operations Center
        </span>
      </footer>
    </main>
  );
}