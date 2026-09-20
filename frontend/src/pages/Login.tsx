import { useState } from "react";
import type { FormEvent } from "react";
import {
  CircleGauge,
  LockKeyhole,
  LogIn,
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
    <main className="auth-page">
      <section className="auth-card">
        <div className="auth-brand">
          <div className="auth-brand-mark">
            <CircleGauge size={24} />
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
          <h1>Sign in</h1>

          <p>
            Authenticate to access the Security
            Operations Center.
          </p>
        </div>

        {error && (
          <div
            className="notice warning auth-error"
            role="alert"
          >
            {error}
          </div>
        )}

        <form
          className="auth-form"
          onSubmit={handleSubmit}
        >
          <label htmlFor="login">
            Username or email
          </label>

          <input
            id="login"
            name="login"
            type="text"
            autoComplete="username"
            value={login}
            onChange={(event) =>
              setLogin(event.target.value)
            }
            disabled={submitting}
            required
          />

          <label htmlFor="password">
            Password
          </label>

          <div className="auth-password">
            <LockKeyhole
              size={16}
              aria-hidden="true"
            />

            <input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) =>
                setPassword(event.target.value)
              }
              disabled={submitting}
              required
            />
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
            <LogIn size={16} />

            {submitting
              ? "Signing in..."
              : "Sign in"}
          </button>
        </form>
      </section>
    </main>
  );
}