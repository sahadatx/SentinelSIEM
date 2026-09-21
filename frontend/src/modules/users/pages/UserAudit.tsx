/**
 * ============================================================================
 * SentinelSIEM — User Audit Page
 * ============================================================================
 *
 * User Management audit-history page boundary.
 *
 * Responsibilities:
 * - Enforce users:read permission
 * - Validate the requested user ID
 * - Provide page-level navigation
 * - Provide audit-page context
 * - Delegate audit data/rendering to UserAuditPanel
 *
 * This page does NOT:
 * - Fetch audit data directly
 * - Implement audit filtering
 * - Implement audit statistics
 * - Implement audit table rendering
 * - Implement audit event details
 *
 * Backend remains the authoritative security boundary.
 *
 * ============================================================================
 */

import {
  ArrowLeft,
  FileSearch,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";

import "../Users.css";

import { useAuthStore } from "../../../store/auth";
import { USERS_READ } from "../permissions";

import UserAuditPanel from "../components/UserAuditPanel";

/* ============================================================================
 * Props
 * ========================================================================== */

export interface UserAuditPageProps {
  /**
   * ID of the user whose audit history should be displayed.
   */
  userId: string;

  /**
   * Optional callback used to return to the previous page.
   */
  onBack?: () => void;
}

/* ============================================================================
 * User Audit Page
 * ========================================================================== */

export default function UserAudit({
  userId,
  onBack,
}: UserAuditPageProps) {
  /* --------------------------------------------------------------------------
   * RBAC
   * ------------------------------------------------------------------------ */

  const hasPermission = useAuthStore(
    (state) => state.hasPermission,
  );

  const canReadUsers = hasPermission(
    USERS_READ,
  );

  /* --------------------------------------------------------------------------
   * Normalize User ID
   * ------------------------------------------------------------------------ */

  const normalizedUserId = userId.trim();

  /* ==========================================================================
   * Permission Gate
   * ======================================================================== */

  if (!canReadUsers) {
    return (
      <section
        className="user-audit-page"
        aria-labelledby="user-audit-access-title"
      >
        <PageHeader
          onBack={onBack}
          restricted
        />

        <div className="user-audit-page-body">
          <section
            className="user-audit-permission-card"
            role="alert"
          >
            <div
              className="user-audit-permission-icon"
              aria-hidden="true"
            >
              <ShieldAlert size={20} />
            </div>

            <div className="user-audit-permission-content">
              <strong id="user-audit-access-title">
                Audit access restricted
              </strong>

              <p>
                Your account does not have
                permission to view user audit
                activity.
              </p>

              <span>
                Required permission:{" "}
                <code>{USERS_READ}</code>
              </span>
            </div>
          </section>
        </div>
      </section>
    );
  }

  /* ==========================================================================
   * Invalid User ID
   * ======================================================================== */

  if (!normalizedUserId) {
    return (
      <section
        className="user-audit-page"
        aria-labelledby="user-audit-invalid-title"
      >
        <PageHeader
          onBack={onBack}
        />

        <div className="user-audit-page-body">
          <div
            className="user-audit-alert user-audit-alert-error"
            role="alert"
          >
            <div
              className="user-audit-alert-icon"
              aria-hidden="true"
            >
              <ShieldAlert size={17} />
            </div>

            <div>
              <strong id="user-audit-invalid-title">
                Invalid user
              </strong>

              <span>
                A valid user ID is required
                to view audit activity.
              </span>
            </div>
          </div>
        </div>
      </section>
    );
  }

  /* ==========================================================================
   * Render
   * ======================================================================== */

  return (
    <section
      className="user-audit-page"
      aria-labelledby="user-audit-page-title"
    >
      {/* ======================================================================
       * Page Header
       * ==================================================================== */}

      <PageHeader
        onBack={onBack}
      />

      {/* ======================================================================
       * Audit Context
       * ==================================================================== */}

      <div
        className="user-audit-context"
        role="note"
      >
        <div
          className="user-audit-context-icon"
          aria-hidden="true"
        >
          <FileSearch size={16} />
        </div>

        <div className="user-audit-context-content">
          <span>
            Reviewing security audit
            activity for user
          </span>

          <strong className="mono">
            {normalizedUserId}
          </strong>
        </div>
      </div>

      {/* ======================================================================
       * Audit Panel
       *
       * UserAuditPanel owns:
       * - API loading
       * - Audit state
       * - Audit statistics
       * - Audit filters
       * - Audit activity table
       * - Event selection
       * - Event details
       * - Pagination
       * - Refresh handling
       * ==================================================================== */}

      <UserAuditPanel
        userId={normalizedUserId}
      />
    </section>
  );
}

/* ============================================================================
 * Page Header
 * ========================================================================== */

function PageHeader({
  onBack,
  restricted = false,
}: {
  onBack?: () => void;
  restricted?: boolean;
}) {
  return (
    <header
      className="page-heading user-audit-page-heading"
    >
      <div className="user-audit-page-title">
        <div
          className={
            restricted
              ? "user-audit-page-icon danger"
              : "user-audit-page-icon"
          }
          aria-hidden="true"
        >
          {restricted ? (
            <ShieldAlert size={19} />
          ) : (
            <ShieldCheck size={19} />
          )}
        </div>

        <div>
          <span className="user-audit-page-eyebrow">
            SECURITY &amp; COMPLIANCE
          </span>

          <h2 id="user-audit-page-title">
            User Audit
          </h2>

          <p>
            Review security events, account
            changes, and audit activity for
            this user.
          </p>
        </div>
      </div>

      {onBack && (
        <div className="users-toolbar">
          <button
            type="button"
            className="secondary-button user-audit-back-button"
            onClick={onBack}
            aria-label="Return to previous page"
          >
            <ArrowLeft
              size={14}
              aria-hidden="true"
            />

            Back
          </button>
        </div>
      )}
    </header>
  );
}