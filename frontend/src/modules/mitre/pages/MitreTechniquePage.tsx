/**
 * ============================================================================
 * SentinelSIEM — MITRE ATT&CK Technique Detail Page
 * ============================================================================
 *
 * Route
 * -----
 *   /mitre/techniques/:techniqueId
 *
 * Purpose
 * -------
 * Present the complete read-only detail view for one MITRE ATT&CK
 * technique/sub-technique.
 *
 * Workflow
 * --------
 *
 *   MITRE Technique
 *          │
 *          ▼
 *   Technique Detail
 *          │
 *   ┌──────┼──────────┬──────────┬────────┬──────────┬────────┐
 *   ▼      ▼          ▼          ▼        ▼          ▼        ▼
 * Overview Sub-techniques Detections Events Alerts Incidents IOCs
 *                                                               │
 *                                                               ▼
 *                                                            Assets
 *
 * Data ownership
 * --------------
 *
 * MITRE ATT&CK Knowledge
 * ├── technique metadata
 * ├── tactics
 * ├── platforms
 * ├── descriptions
 * ├── references
 * ├── mitigations
 * └── detection guidance
 *
 * SentinelSIEM Intelligence
 * ├── detection mappings
 * ├── detections
 * ├── events
 * ├── alerts
 * ├── incidents
 * ├── IOCs
 * ├── assets
 * └── coverage
 *
 * Architecture
 * ------------
 * - Read-only page.
 * - No MITRE knowledge CRUD.
 * - No coverage calculation.
 * - No authentication/RBAC access.
 * - No client-side reconstruction of backend intelligence.
 * - Technique detail API is authoritative.
 * - Detail data is loaded lazily for the requested technique.
 * - Refresh reloads the current technique from the backend.
 *
 * Important
 * ---------
 * The page does not derive a technique's coverage state.
 *
 * Coverage is supplied by:
 *
 *   MitreTechniqueDetail.coverage
 *
 * The page simply passes the authoritative response to TechniqueDetails.
 *
 * ============================================================================
 */

import {
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import "../Mitre.css";

import {
  TechniqueDetails,
} from "../components/TechniqueDetails";

import {
  mitreApi,
} from "../api";

import type {
  MitreTechniqueDetail,
} from "../types";

/* ============================================================================
 * Props
 * ========================================================================== */

export interface MitreTechniquePageProps {
  /**
   * Canonical ATT&CK identifier from the route.
   *
   * Examples:
   *
   *   T1059
   *   T1059.001
   */
  techniqueId: string;
}

/* ============================================================================
 * Helpers
 * ========================================================================== */

/**
 * Convert an unknown request failure into a safe UI message.
 */
function getErrorMessage(
  error: unknown,
): string {
  if (
    error instanceof Error
  ) {
    const message =
      error.message.trim();

    if (message) {
      return message;
    }
  }

  if (
    typeof error === "string"
  ) {
    const message =
      error.trim();

    if (message) {
      return message;
    }
  }

  return "Unable to load MITRE ATT&CK technique.";
}

/**
 * Normalize the route parameter.
 *
 * This only removes accidental surrounding whitespace.
 *
 * It does not transform or reconstruct ATT&CK IDs.
 */
function normalizeTechniqueId(
  value: string,
): string {
  return value.trim();
}

/* ============================================================================
 * Component
 * ========================================================================== */

export function MitreTechniquePage({
  techniqueId,
}: MitreTechniquePageProps) {
  /* ==========================================================================
   * Technique Detail
   * ======================================================================== */

  const [
    technique,
    setTechnique,
  ] = useState<MitreTechniqueDetail | null>(
    null,
  );

  /* ==========================================================================
   * Request State
   * ======================================================================== */

  const [
    loading,
    setLoading,
  ] = useState(true);

  const [
    error,
    setError,
  ] = useState<string | null>(
    null,
  );

  /* ==========================================================================
   * Request Identity
   *
   * Prevent stale asynchronous responses from overwriting a newer request.
   *
   * Example:
   *
   *   T1059 request starts
   *          ↓
   *   T1059.001 request starts
   *          ↓
   *   T1059 response arrives late
   *
   * The old T1059 response is ignored.
   * ======================================================================== */

  const requestSequence =
    useRef(0);

  /* ==========================================================================
   * Load Technique Detail
   * ======================================================================== */

  const loadTechnique =
    useCallback(
      async () => {
        const normalizedId =
          normalizeTechniqueId(
            techniqueId,
          );

        const requestId =
          ++requestSequence.current;

        /* --------------------------------------------------------------------
         * Invalid route parameter
         * ------------------------------------------------------------------ */

        if (!normalizedId) {
          setTechnique(
            null,
          );

          setError(
            "MITRE technique ID is required.",
          );

          setLoading(
            false,
          );

          return;
        }

        /* --------------------------------------------------------------------
         * Request state
         * ------------------------------------------------------------------ */

        setLoading(
          true,
        );

        setError(
          null,
        );

        /*
         * Clear previous detail immediately when the route changes.
         *
         * This prevents the previous technique from being displayed while
         * the new technique is loading.
         */
        setTechnique(
          null,
        );

        /* --------------------------------------------------------------------
         * API request
         * ------------------------------------------------------------------ */

        try {
          const detail =
            await mitreApi.getTechniqueDetail(
              normalizedId,
            );

          /*
           * Ignore stale responses.
           */
          if (
            requestSequence.current !==
            requestId
          ) {
            return;
          }

          setTechnique(
            detail,
          );

          setError(
            null,
          );
        } catch (
          requestError
        ) {
          /*
           * Ignore stale errors.
           */
          if (
            requestSequence.current !==
            requestId
          ) {
            return;
          }

          setTechnique(
            null,
          );

          setError(
            getErrorMessage(
              requestError,
            ),
          );
        } finally {
          /*
           * Only the active request may update loading state.
           */
          if (
            requestSequence.current ===
            requestId
          ) {
            setLoading(
              false,
            );
          }
        }
      },
      [
        techniqueId,
      ],
    );

  /* ==========================================================================
   * Route Parameter Changes
   *
   * Supports navigation between:
   *
   *   /mitre/techniques/T1059
   *
   * and:
   *
   *   /mitre/techniques/T1059.001
   *
   * without requiring this page component to be remounted.
   * ======================================================================== */

  useEffect(() => {
    void loadTechnique();
  }, [
    loadTechnique,
  ]);

  /* ==========================================================================
   * Render
   * ======================================================================== */

  return (
    <main
      className="page mitre-technique-page"
      aria-labelledby="mitre-technique-page-title"
    >
      {/* ====================================================================
       * Page Header
       * ================================================================== */}

      <header className="page__header">
        <div>
          <h1 id="mitre-technique-page-title">
            MITRE ATT&amp;CK Technique
          </h1>

          <p className="page__description">
            Detailed MITRE ATT&amp;CK information and
            SentinelSIEM security intelligence for the
            selected technique.
          </p>
        </div>

        {/* ------------------------------------------------------------------
         * Refresh
         * ---------------------------------------------------------------- */}

        <button
          type="button"
          className="mitre-technique-page__refresh"
          onClick={() => {
            void loadTechnique();
          }}
          disabled={
            loading
          }
          aria-label="Refresh MITRE ATT&CK technique details"
        >
          {loading
            ? "Refreshing..."
            : "Refresh"}
        </button>
      </header>

      {/* ====================================================================
       * Page-Level Error
       *
       * The detailed component also receives the same error so it can render
       * its contextual error state.
       * ================================================================== */}

      {error && (
        <div
          className="resource-card__error"
          role="alert"
          aria-live="assertive"
        >
          {error}
        </div>
      )}

      {/* ====================================================================
       * Technique Details
       * ================================================================== */}

      <section
        className="mitre-technique-page__details"
        aria-label="MITRE ATT&CK Technique Details"
      >
        <TechniqueDetails
          technique={
            technique
          }
          loading={
            loading
          }
          error={
            error
          }
        />
      </section>
    </main>
  );
}

/* ============================================================================
 * Default Export
 * ========================================================================== */

export default MitreTechniquePage;

/* ============================================================================
 * End of File
 * ============================================================================
 */