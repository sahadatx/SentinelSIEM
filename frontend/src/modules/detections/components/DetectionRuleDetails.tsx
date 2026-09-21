/* ==========================================================================
 * Detection Rule Details Drawer
 * SentinelSIEM SOC Dashboard
 *
 * Responsibility:
 *   - Display complete information for one Detection rule
 *   - Display rule statistics
 *   - Display detection conditions
 *   - Display tags
 *   - Provide rule actions
 *   - Render as a right-side drawer
 *
 * Locked workflow:
 *
 *   Detection Rules
 *        ↓
 *   Rule Details Drawer
 *        ├── Overview
 *        ├── Detection
 *        ├── Statistics
 *        ├── Tags
 *        └── Actions
 *
 * API communication remains outside this component.
 * ========================================================================== */

import type {
  DetectionRule,
} from "../types";


/* ==========================================================================
 * Props
 * ========================================================================== */

interface DetectionRuleDetailsProps {
  rule: DetectionRule | null;

  loading?: boolean;

  error?: string | null;

  onClose?: () => void;

  /**
   * Open the rule in the existing create/edit form.
   */
  onEdit?: (
    rule: DetectionRule,
  ) => void;

  /**
   * Enable / disable the rule.
   */
  onToggle?: (
    rule: DetectionRule,
  ) => void;

  /**
   * Navigate to Alerts filtered by rule_id.
   */
  onViewAlerts?: (
    rule: DetectionRule,
  ) => void;
}


/* ==========================================================================
 * Helpers
 * ========================================================================== */

/**
 * Format condition operator.
 */
function formatOperator(
  operator:
    DetectionRule["conditions"][number]["operator"],
): string {
  switch (operator) {
    case "equals":
      return "Equals";

    case "not_equals":
      return "Not Equals";

    case "in":
      return "In";

    case "not_in":
      return "Not In";

    case "contains":
      return "Contains";

    case "exists":
      return "Exists";

    default:
      return operator;
  }
}


/**
 * Safely render an arbitrary condition value.
 */
function formatValue(
  value: unknown,
): string {
  if (
    value === null ||
    value === undefined
  ) {
    return "—";
  }

  if (
    typeof value === "string"
  ) {
    return value || "—";
  }

  if (
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return String(value);
  }

  try {
    const serialized =
      JSON.stringify(value);

    return serialized || "—";
  } catch {
    return String(value);
  }
}


/**
 * Format severity.
 */
function formatSeverity(
  severity: string,
): string {
  const value =
    severity.trim();

  if (!value) {
    return "Unknown";
  }

  return (
    value.charAt(0).toUpperCase() +
    value.slice(1)
  );
}


/**
 * Build a safe severity CSS class.
 */
function getSeverityClass(
  severity: string,
): string {
  const normalized =
    severity
      .trim()
      .toLowerCase()
      .replace(
        /[^a-z0-9_-]/g,
        "-",
      );

  return normalized || "unknown";
}


/**
 * Format statistics.
 */
function formatNumber(
  value: number,
): string {
  if (
    !Number.isFinite(value)
  ) {
    return "—";
  }

  return Math.max(
    0,
    value,
  ).toLocaleString();
}


/**
 * Format the last-match timestamp.
 */
function formatLastMatch(
  value: string | null,
): string {
  if (!value) {
    return "No recorded match";
  }

  const date =
    new Date(value);

  if (
    Number.isNaN(
      date.getTime(),
    )
  ) {
    return "Invalid timestamp";
  }

  return date.toLocaleString(
    undefined,
    {
      dateStyle: "medium",
      timeStyle: "short",
    },
  );
}


/**
 * Extract rule statistics while supporting both the nested
 * and direct response shapes.
 */
function getStatistics(
  rule: DetectionRule,
) {
  return {
    matches:
      rule.statistics?.matches ??
      rule.matches ??
      0,

    alerts:
      rule.statistics?.alerts ??
      rule.alerts ??
      0,

    suppressed:
      rule.statistics?.suppressed ??
      rule.suppressed ??
      0,

    lastMatchAt:
      rule.statistics?.last_match_at ??
      rule.last_match_at ??
      null,
  };
}


/* ==========================================================================
 * Detail Field
 * ========================================================================== */

interface DetailFieldProps {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}


function DetailField({
  label,
  value,
  mono = false,
}: DetailFieldProps) {
  return (
    <div className="detection-detail-field">

      <span className="detection-detail-field-label">
        {label}
      </span>

      <strong
        className={
          mono
            ? "detection-detail-field-value detection-detail-field-value-mono"
            : "detection-detail-field-value"
        }
      >
        {value}
      </strong>

    </div>
  );
}


/* ==========================================================================
 * Component
 * ========================================================================== */

export function DetectionRuleDetails({
  rule,
  loading = false,
  error = null,
  onClose,
  onEdit,
  onToggle,
  onViewAlerts,
}: DetectionRuleDetailsProps) {

  /* ------------------------------------------------------------------------
   * Nothing selected
   * ---------------------------------------------------------------------- */

  if (
    !rule &&
    !loading &&
    !error
  ) {
    return null;
  }


  /* ------------------------------------------------------------------------
   * Drawer
   * ---------------------------------------------------------------------- */

  return (
    <>

      {/* ------------------------------------------------------------------
       * Backdrop
       * ---------------------------------------------------------------- */}

      <div
        className="detection-rule-drawer-backdrop"
        aria-hidden="true"
        onClick={onClose}
      />


      {/* ------------------------------------------------------------------
       * Drawer
       * ---------------------------------------------------------------- */}

      <aside
        className="detection-rule-drawer"
        aria-label={
          rule
            ? `Detection rule details for ${rule.name}`
            : "Detection rule details"
        }
        aria-busy={loading}
      >

        {/* --------------------------------------------------------------
         * Drawer Header
         * ------------------------------------------------------------ */}

        <header className="detection-rule-drawer-header">

          <div className="detection-rule-drawer-heading">

            <span className="detection-rule-drawer-eyebrow">
              Detection Rule
            </span>

            <h2>
              {rule?.name ??
                "Rule Details"}
            </h2>

            {rule ? (
              <span className="detection-rule-drawer-id">
                {rule.id}
              </span>
            ) : null}

          </div>


          <button
            type="button"
            className="detection-rule-drawer-close"
            onClick={onClose}
            aria-label="Close rule details"
          >
            ×
          </button>

        </header>


        {/* --------------------------------------------------------------
         * Body
         * ------------------------------------------------------------ */}

        <div className="detection-rule-drawer-body">

          {/* ------------------------------------------------------------
           * Loading
           * ---------------------------------------------------------- */}

          {loading ? (
            <div
              className="detection-rule-drawer-loading"
              aria-live="polite"
            >

              <div className="detection-rule-drawer-loading-block" />

              <div className="detection-rule-drawer-loading-block" />

              <div className="detection-rule-drawer-loading-block" />

              <span>
                Loading rule information...
              </span>

            </div>
          ) : null}


          {/* ------------------------------------------------------------
           * Error
           * ---------------------------------------------------------- */}

          {!loading && error ? (
            <div
              className="detection-rule-drawer-error"
              role="alert"
            >

              <strong>
                Unable to load rule
              </strong>

              <p>
                {error}
              </p>

            </div>
          ) : null}


          {/* ------------------------------------------------------------
           * Rule Content
           * ---------------------------------------------------------- */}

          {!loading &&
          !error &&
          rule ? (
            <>
              {(() => {
                const statistics =
                  getStatistics(
                    rule,
                  );

                return (
                  <>
                    {/* --------------------------------------------------
                     * Status / Severity
                     * ------------------------------------------------ */}

                    <div className="detection-rule-drawer-status-row">

                      <span
                        className={
                          rule.enabled
                            ? "detection-rule-status detection-rule-status-enabled"
                            : "detection-rule-status detection-rule-status-disabled"
                        }
                      >

                        <span
                          className="detection-rule-status-dot"
                          aria-hidden="true"
                        />

                        {rule.enabled
                          ? "Enabled"
                          : "Disabled"}

                      </span>


                      <span
                        className={`detection-severity detection-severity-${getSeverityClass(
                          rule.severity,
                        )}`}
                      >
                        {formatSeverity(
                          rule.severity,
                        )}
                      </span>

                    </div>


                    {/* --------------------------------------------------
                     * Overview
                     * ------------------------------------------------ */}

                    <section className="detection-rule-drawer-section">

                      <div className="detection-rule-drawer-section-heading">
                        <h3>
                          Overview
                        </h3>
                      </div>


                      <div className="detection-rule-drawer-description">

                        <span>
                          Description
                        </span>

                        <p>
                          {rule.description ||
                            "No description provided."}
                        </p>

                      </div>


                      <div className="detection-rule-details-grid">

                        <DetailField
                          label="Rule ID"
                          value={rule.id}
                          mono
                        />

                        <DetailField
                          label="Category"
                          value={
                            rule.category ||
                            "Unknown"
                          }
                        />

                        <DetailField
                          label="Match Mode"
                          value={
                            rule.match ===
                            "all"
                              ? "All conditions"
                              : "Any condition"
                          }
                        />

                        <DetailField
                          label="Conditions"
                          value={
                            rule.conditions.length.toLocaleString()
                          }
                        />

                      </div>

                    </section>


                    {/* --------------------------------------------------
                     * Detection Statistics
                     * ------------------------------------------------ */}

                    <section className="detection-rule-drawer-section">

                      <div className="detection-rule-drawer-section-heading">

                        <h3>
                          Statistics
                        </h3>

                      </div>


                      <div className="detection-rule-statistics">

                        <article className="detection-rule-statistic">

                          <span>
                            Matches
                          </span>

                          <strong>
                            {formatNumber(
                              Number(
                                statistics.matches,
                              ),
                            )}
                          </strong>

                        </article>


                        <article className="detection-rule-statistic">

                          <span>
                            Alerts
                          </span>

                          <strong>
                            {formatNumber(
                              Number(
                                statistics.alerts,
                              ),
                            )}
                          </strong>

                        </article>


                        <article className="detection-rule-statistic">

                          <span>
                            Suppressed
                          </span>

                          <strong>
                            {formatNumber(
                              Number(
                                statistics.suppressed,
                              ),
                            )}
                          </strong>

                        </article>

                      </div>


                      <div className="detection-rule-last-match">

                        <span>
                          Last Match
                        </span>

                        <strong>
                          {formatLastMatch(
                            statistics.lastMatchAt,
                          )}
                        </strong>

                      </div>

                    </section>


                    {/* --------------------------------------------------
                     * Detection Condition
                     * ------------------------------------------------ */}

                    <section className="detection-rule-drawer-section">

                      <div className="detection-rule-drawer-section-heading">

                        <h3>
                          Detection Condition
                        </h3>

                        <span>
                          {rule.match ===
                          "all"
                            ? "All"
                            : "Any"}
                        </span>

                      </div>


                      {rule.conditions.length > 0 ? (
                        <div className="detection-rule-conditions">

                          {rule.conditions.map(
                            (
                              condition,
                              index,
                            ) => (
                              <article
                                key={`${condition.field}-${condition.operator}-${index}`}
                                className="detection-rule-condition"
                              >

                                <div>

                                  <span>
                                    Field
                                  </span>

                                  <strong>
                                    {condition.field}
                                  </strong>

                                </div>


                                <div>

                                  <span>
                                    Operator
                                  </span>

                                  <strong>
                                    {formatOperator(
                                      condition.operator,
                                    )}
                                  </strong>

                                </div>


                                <div>

                                  <span>
                                    Value
                                  </span>

                                  <strong className="detection-rule-condition-value">
                                    {formatValue(
                                      condition.value,
                                    )}
                                  </strong>

                                </div>

                              </article>
                            ),
                          )}

                        </div>
                      ) : (
                        <div className="detection-rule-empty-inline">
                          No conditions configured.
                        </div>
                      )}

                    </section>


                    {/* --------------------------------------------------
                     * Tags
                     * ------------------------------------------------ */}

                    <section className="detection-rule-drawer-section">

                      <div className="detection-rule-drawer-section-heading">

                        <h3>
                          Tags
                        </h3>

                        <span>
                          {rule.tags.length}
                        </span>

                      </div>


                      {rule.tags.length > 0 ? (
                        <div className="detection-rule-tags">

                          {rule.tags.map(
                            (tag) => (
                              <span
                                key={tag}
                              >
                                {tag}
                              </span>
                            ),
                          )}

                        </div>
                      ) : (
                        <div className="detection-rule-empty-inline">
                          No tags configured.
                        </div>
                      )}

                    </section>


                    {/* --------------------------------------------------
                     * Actions
                     * ------------------------------------------------ */}

                    <section className="detection-rule-drawer-section detection-rule-drawer-actions-section">

                      <div className="detection-rule-drawer-section-heading">

                        <h3>
                          Actions
                        </h3>

                      </div>


                      <div className="detection-rule-drawer-actions">

                        {onViewAlerts ? (
                          <button
                            type="button"
                            className="detection-rule-drawer-action detection-rule-drawer-action-primary"
                            onClick={() =>
                              onViewAlerts(
                                rule,
                              )
                            }
                          >
                            View Alerts
                          </button>
                        ) : null}


                        {onEdit ? (
                          <button
                            type="button"
                            className="detection-rule-drawer-action"
                            onClick={() =>
                              onEdit(
                                rule,
                              )
                            }
                          >
                            Edit Rule
                          </button>
                        ) : null}


                        {onToggle ? (
                          <button
                            type="button"
                            className="detection-rule-drawer-action"
                            onClick={() =>
                              onToggle(
                                rule,
                              )
                            }
                          >
                            {rule.enabled
                              ? "Disable Rule"
                              : "Enable Rule"}
                          </button>
                        ) : null}

                      </div>

                    </section>

                  </>
                );
              })()}
            </>
          ) : null}

        </div>


        {/* --------------------------------------------------------------
         * Footer
         * ------------------------------------------------------------ */}

        <footer className="detection-rule-drawer-footer">

          {rule ? (
            <span>
              Rule ID:
              <strong>
                {rule.id}
              </strong>
            </span>
          ) : null}

          <button
            type="button"
            className="detection-rule-drawer-footer-close"
            onClick={onClose}
          >
            Close
          </button>

        </footer>

      </aside>

    </>
  );
}


/* ==========================================================================
 * Default Export
 * ========================================================================== */

export default DetectionRuleDetails;