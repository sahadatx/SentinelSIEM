/* ==========================================================================
 * Detection Rule Form
 * SentinelSIEM SOC Dashboard
 *
 * Backend contract:
 *
 *   POST  /api/v1/detections/rules
 *   PATCH /api/v1/detections/rules/{rule_id}
 *
 * Responsibility:
 *   - Create Detection rules
 *   - Edit Detection rules
 *   - Validate rule input
 *   - Build backend-compatible payloads
 *   - Handle loading / submitting / error states
 *   - Maintain reusable Create / Edit workflow
 *
 * Locked DetectionRule schema:
 *
 *   id
 *   name
 *   description
 *   enabled
 *   severity
 *   category
 *   conditions
 *   match
 *   tags
 *
 * Severity:
 *   - Create/Edit uses backend-provided severity options.
 *   - No frontend severity catalogue is hardcoded here.
 *   - Severity options are supplied by the parent page from:
 *
 *       GET /api/v1/detections/filter-options
 *
 *   - The backend remains authoritative.
 *   - Any severity already used by an existing rule is preserved by
 *     the backend filter-options endpoint.
 *
 * API communication remains outside this component.
 * ========================================================================== */

import {
  useEffect,
  useMemo,
  useState,
  type ChangeEvent,
  type FormEvent,
} from "react";

import type {
  ConditionOperator,
  DetectionRule,
  DetectionRuleCondition,
  DetectionRuleCreateRequest,
  DetectionRuleFormState,
  DetectionRuleUpdateRequest,
} from "../types";

import {
  createEmptyDetectionCondition,
  createEmptyDetectionRuleForm,
  detectionRuleToFormState,
} from "../types";


/* ==========================================================================
 * Props
 * ========================================================================== */

interface DetectionRuleFormProps {
  /**
   * Existing rule when editing.
   *
   * null / undefined means Create mode.
   */
  rule?: DetectionRule | null;

  /**
   * Loading state while existing rule information is being prepared.
   */
  loading?: boolean;

  /**
   * Submission state.
   */
  submitting?: boolean;

  /**
   * External API error.
   */
  error?: string | null;

  /**
   * Backend-owned severity catalogue.
   *
   * Parent page should provide:
   *
   *   filterOptions?.severity ?? []
   *
   * from:
   *
   *   GET /api/v1/detections/filter-options
   */
  severityOptions?: string[];

  /**
   * Parent owns API submission.
   */
  onSubmit: (
    payload:
      | DetectionRuleCreateRequest
      | DetectionRuleUpdateRequest,
  ) => void | Promise<void>;

  /**
   * Close/cancel the form.
   */
  onCancel?: () => void;
}


/* ==========================================================================
 * Constants
 * ========================================================================== */

const CONDITION_OPERATORS: Array<{
  value: ConditionOperator;
  label: string;
}> = [
  {
    value: "equals",
    label: "Equals",
  },
  {
    value: "not_equals",
    label: "Not Equals",
  },
  {
    value: "in",
    label: "In",
  },
  {
    value: "not_in",
    label: "Not In",
  },
  {
    value: "contains",
    label: "Contains",
  },
  {
    value: "exists",
    label: "Exists",
  },
];

const MAX_CONDITIONS = 50;
const MAX_TAGS = 50;

const MAX_RULE_ID_LENGTH = 128;
const MAX_NAME_LENGTH = 200;
const MAX_DESCRIPTION_LENGTH = 2000;
const MAX_SEVERITY_LENGTH = 32;
const MAX_CATEGORY_LENGTH = 64;
const MAX_FIELD_LENGTH = 128;
const MAX_TAG_LENGTH = 128;

const RULE_ID_PATTERN =
  /^[a-z0-9][a-z0-9_-]{2,127}$/;


/* ==========================================================================
 * Helpers
 * ========================================================================== */

/**
 * Convert an option value into a human-readable label.
 *
 * Examples:
 *
 *   critical      -> Critical
 *   high          -> High
 *   informational -> Informational
 *   account_lock  -> Account Lock
 *   brute-force   -> Brute Force
 */
function formatOptionLabel(
  value: string,
): string {
  return value
    .trim()
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .replace(
      /\b\w/g,
      (character) =>
        character.toUpperCase(),
    );
}


/**
 * Normalize and deduplicate backend-provided severity values.
 *
 * Backend remains the source of truth.
 *
 * This helper does NOT create or invent severity values.
 * It only cleans the values received from the backend.
 */
function normalizeSeverityOptions(
  options: string[],
): string[] {
  const values = new Map<string, string>();

  for (const option of options) {
    const normalized = option.trim();

    if (!normalized) {
      continue;
    }

    const key = normalized.toLowerCase();

    if (!values.has(key)) {
      values.set(key, normalized);
    }
  }

  return Array.from(values.values()).sort(
    (a, b) =>
      a.localeCompare(
        b,
        undefined,
        {
          sensitivity: "base",
        },
      ),
  );
}


/**
 * Convert a condition value into an input-safe string.
 */
function conditionValueToInput(
  value: unknown,
): string {
  if (
    value === null ||
    value === undefined
  ) {
    return "";
  }

  if (
    typeof value === "string"
  ) {
    return value;
  }

  if (
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return String(value);
  }

  try {
    return JSON.stringify(
      value,
    );
  } catch {
    return String(value);
  }
}


/**
 * Convert text input into a JSON-compatible value.
 *
 * The Detection backend accepts arbitrary condition values.
 */
function parseConditionValue(
  value: string,
): unknown {
  const trimmed =
    value.trim();

  if (!trimmed) {
    return "";
  }

  if (
    trimmed === "true"
  ) {
    return true;
  }

  if (
    trimmed === "false"
  ) {
    return false;
  }

  if (
    trimmed === "null"
  ) {
    return null;
  }

  if (
    /^-?\d+(?:\.\d+)?$/.test(
      trimmed,
    )
  ) {
    const numberValue =
      Number(trimmed);

    if (
      Number.isFinite(
        numberValue,
      )
    ) {
      return numberValue;
    }
  }

  /**
   * Support JSON arrays and objects.
   */
  if (
    (
      trimmed.startsWith("[") &&
      trimmed.endsWith("]")
    ) ||
    (
      trimmed.startsWith("{") &&
      trimmed.endsWith("}")
    )
  ) {
    try {
      return JSON.parse(
        trimmed,
      );
    } catch {
      /**
       * Preserve invalid/incomplete JSON as text.
       *
       * Final validation is intentionally left to the backend
       * because condition values are arbitrary JSON-compatible data.
       */
      return trimmed;
    }
  }

  return trimmed;
}


/**
 * Normalize one Detection condition.
 */
function normalizeCondition(
  condition: DetectionRuleCondition,
): DetectionRuleCondition {
  return {
    field:
      condition.field.trim(),

    operator:
      condition.operator,

    value:
      condition.value,
  };
}


/**
 * Normalize tags.
 */
function normalizeTags(
  tags: string[],
): string[] {
  return tags
    .map(
      (tag) =>
        tag.trim(),
    )
    .filter(Boolean);
}


/**
 * Build Create payload.
 *
 * Only backend-supported DetectionRuleCreateRequest fields are included.
 */
function buildCreatePayload(
  form: DetectionRuleFormState,
): DetectionRuleCreateRequest {
  return {
    id:
      form.id.trim(),

    name:
      form.name.trim(),

    description:
      form.description.trim(),

    enabled:
      form.enabled,

    severity:
      form.severity.trim(),

    category:
      form.category.trim(),

    conditions:
      form.conditions.map(
        normalizeCondition,
      ),

    match:
      form.match,

    tags:
      normalizeTags(
        form.tags,
      ),
  };
}


/**
 * Build Update payload.
 *
 * Rule ID is immutable during editing, therefore it is intentionally
 * excluded from the PATCH payload.
 */
function buildUpdatePayload(
  form: DetectionRuleFormState,
): DetectionRuleUpdateRequest {
  return {
    name:
      form.name.trim(),

    description:
      form.description.trim(),

    enabled:
      form.enabled,

    severity:
      form.severity.trim(),

    category:
      form.category.trim(),

    conditions:
      form.conditions.map(
        normalizeCondition,
      ),

    match:
      form.match,

    tags:
      normalizeTags(
        form.tags,
      ),
  };
}


/* ==========================================================================
 * Component
 * ========================================================================== */

export function DetectionRuleForm({
  rule = null,
  loading = false,
  submitting = false,
  error = null,
  severityOptions = [],
  onSubmit,
  onCancel,
}: DetectionRuleFormProps) {

  const editing =
    Boolean(rule);


  /* ==========================================================================
   * Backend Severity Options
   * ========================================================================== */

  const normalizedSeverityOptions =
    useMemo(
      () =>
        normalizeSeverityOptions(
          severityOptions,
        ),
      [severityOptions],
    );


  /**
   * During Edit, an existing rule may contain a severity that is not
   * currently present in the filter-options response.
   *
   * We must not lose that value or make the existing rule impossible
   * to edit.
   *
   * Therefore:
   *
   *   Backend options
   *          +
   *   current rule severity
   *          ↓
   *   Select options
   *
   * The current value is NOT invented; it comes from the existing rule.
   */
  const availableSeverityOptions =
    useMemo(() => {
      const values = [
        ...normalizedSeverityOptions,
      ];

      const currentSeverity =
        rule?.severity?.trim() ?? "";

      if (
        currentSeverity &&
        !values.some(
          (value) =>
            value.toLowerCase() ===
            currentSeverity.toLowerCase(),
        )
      ) {
        values.push(
          currentSeverity,
        );
      }

      return values.sort(
        (a, b) =>
          a.localeCompare(
            b,
            undefined,
            {
              sensitivity: "base",
            },
          ),
      );
    }, [
      normalizedSeverityOptions,
      rule?.severity,
    ]);


  /* ==========================================================================
   * State
   * ========================================================================== */

  const [
    form,
    setForm,
  ] = useState<DetectionRuleFormState>(
    () =>
      rule
        ? detectionRuleToFormState(
            rule,
          )
        : createEmptyDetectionRuleForm(),
  );


  const [
    validationError,
    setValidationError,
  ] = useState<string | null>(
    null,
  );


  /* ==========================================================================
   * Sync Form
   * ========================================================================== */

  useEffect(() => {
    setValidationError(
      null,
    );

    setForm(
      rule
        ? detectionRuleToFormState(
            rule,
          )
        : createEmptyDetectionRuleForm(),
    );
  }, [rule]);


  /* ==========================================================================
   * Generic Field Update
   * ========================================================================== */

  function updateField<
    K extends keyof DetectionRuleFormState,
  >(
    field: K,
    value: DetectionRuleFormState[K],
  ): void {
    setForm(
      (current) => ({
        ...current,
        [field]: value,
      }),
    );

    setValidationError(
      null,
    );
  }


  /* ==========================================================================
   * Condition Updates
   * ========================================================================== */

  function updateCondition(
    index: number,
    updates: Partial<DetectionRuleCondition>,
  ): void {
    setForm(
      (current) => ({
        ...current,

        conditions:
          current.conditions.map(
            (
              condition,
              conditionIndex,
            ) =>
              conditionIndex ===
              index
                ? {
                    ...condition,
                    ...updates,
                  }
                : condition,
          ),
      }),
    );

    setValidationError(
      null,
    );
  }


  /**
   * Add a new condition.
   */
  function addCondition(): void {
    if (
      form.conditions.length >=
      MAX_CONDITIONS
    ) {
      setValidationError(
        `A Detection rule can contain at most ${MAX_CONDITIONS} conditions.`,
      );

      return;
    }

    setForm(
      (current) => ({
        ...current,

        conditions: [
          ...current.conditions,
          createEmptyDetectionCondition(),
        ],
      }),
    );

    setValidationError(
      null,
    );
  }


  /**
   * Remove condition.
   *
   * Backend requires at least one condition.
   */
  function removeCondition(
    index: number,
  ): void {
    if (
      form.conditions.length <=
      1
    ) {
      setValidationError(
        "At least one Detection rule condition is required.",
      );

      return;
    }

    setForm(
      (current) => ({
        ...current,

        conditions:
          current.conditions.filter(
            (
              _condition,
              conditionIndex,
            ) =>
              conditionIndex !==
              index,
          ),
      }),
    );

    setValidationError(
      null,
    );
  }


  /* ==========================================================================
   * Tag Updates
   * ========================================================================== */

  function addTag(): void {
    if (
      form.tags.length >=
      MAX_TAGS
    ) {
      setValidationError(
        `A Detection rule can contain at most ${MAX_TAGS} tags.`,
      );

      return;
    }

    setForm(
      (current) => ({
        ...current,

        tags: [
          ...current.tags,
          "",
        ],
      }),
    );

    setValidationError(
      null,
    );
  }


  function updateTag(
    index: number,
    value: string,
  ): void {
    setForm(
      (current) => ({
        ...current,

        tags:
          current.tags.map(
            (
              tag,
              tagIndex,
            ) =>
              tagIndex === index
                ? value
                : tag,
          ),
      }),
    );

    setValidationError(
      null,
    );
  }


  function removeTag(
    index: number,
  ): void {
    setForm(
      (current) => ({
        ...current,

        tags:
          current.tags.filter(
            (
              _tag,
              tagIndex,
            ) =>
              tagIndex !==
              index,
          ),
      }),
    );

    setValidationError(
      null,
    );
  }


  /* ==========================================================================
   * Validation
   * ========================================================================== */

  function validateForm(): string | null {
    const id =
      form.id.trim();

    const name =
      form.name.trim();

    const description =
      form.description.trim();

    const severity =
      form.severity.trim();

    const category =
      form.category.trim();


    /* ------------------------------------------------------------------------
     * Rule ID
     * ---------------------------------------------------------------------- */

    /**
     * ID is required only during Create.
     *
     * During Edit it is immutable.
     */
    if (!editing) {
      if (!id) {
        return "Rule ID is required.";
      }

      if (
        id.length >
        MAX_RULE_ID_LENGTH
      ) {
        return (
          "Rule ID cannot exceed 128 characters."
        );
      }

      if (
        !RULE_ID_PATTERN.test(
          id,
        )
      ) {
        return (
          "Rule ID must contain 3-128 lowercase letters, numbers, underscores, or hyphens."
        );
      }
    }


    /* ------------------------------------------------------------------------
     * Name
     * ---------------------------------------------------------------------- */

    if (!name) {
      return "Rule name is required.";
    }

    if (
      name.length >
      MAX_NAME_LENGTH
    ) {
      return (
        "Rule name cannot exceed 200 characters."
      );
    }


    /* ------------------------------------------------------------------------
     * Description
     * ---------------------------------------------------------------------- */

    if (!description) {
      return "Rule description is required.";
    }

    if (
      description.length >
      MAX_DESCRIPTION_LENGTH
    ) {
      return (
        "Rule description cannot exceed 2000 characters."
      );
    }


    /* ------------------------------------------------------------------------
     * Severity
     * ---------------------------------------------------------------------- */

    if (!severity) {
      return "Severity is required.";
    }

    if (
      severity.length >
      MAX_SEVERITY_LENGTH
    ) {
      return (
        "Severity cannot exceed 32 characters."
      );
    }


    /**
     * Create/Edit severity must come from the backend-provided catalogue.
     *
     * Exception:
     *
     * During Edit, the existing rule's severity is allowed if it is not
     * currently present in the backend filter-options response.
     *
     * This prevents an existing rule from becoming uneditable because
     * the catalogue changed.
     */
    const severityExists =
      availableSeverityOptions.some(
        (option) =>
          option.toLowerCase() ===
          severity.toLowerCase(),
      );

    if (
      availableSeverityOptions.length ===
        0 &&
      !editing
    ) {
      return (
        "Severity options are still loading from the Detection backend."
      );
    }

    if (
      availableSeverityOptions.length > 0 &&
      !severityExists
    ) {
      return (
        "Please select a severity provided by the Detection backend."
      );
    }


    /* ------------------------------------------------------------------------
     * Category
     * ---------------------------------------------------------------------- */

    if (!category) {
      return "Category is required.";
    }

    if (
      category.length >
      MAX_CATEGORY_LENGTH
    ) {
      return (
        "Category cannot exceed 64 characters."
      );
    }


    /* ------------------------------------------------------------------------
     * Match Mode
     * ---------------------------------------------------------------------- */

    if (
      form.match !== "all" &&
      form.match !== "any"
    ) {
      return (
        "Match mode must be All or Any."
      );
    }


    /* ------------------------------------------------------------------------
     * Conditions
     * ---------------------------------------------------------------------- */

    if (
      form.conditions.length <
      1
    ) {
      return (
        "At least one Detection rule condition is required."
      );
    }

    if (
      form.conditions.length >
      MAX_CONDITIONS
    ) {
      return (
        `A maximum of ${MAX_CONDITIONS} conditions is allowed.`
      );
    }


    for (
      const [
        index,
        condition,
      ] of form.conditions.entries()
    ) {
      const position =
        index + 1;

      if (!condition) {
        return (
          `Condition ${position} is invalid.`
        );
      }


      const field =
        condition.field.trim();


      if (!field) {
        return (
          `Condition ${position} requires a field.`
        );
      }


      if (
        field.length >
        MAX_FIELD_LENGTH
      ) {
        return (
          `Condition ${position} field cannot exceed 128 characters.`
        );
      }


      if (
        !CONDITION_OPERATORS.some(
          (operator) =>
            operator.value ===
            condition.operator,
        )
      ) {
        return (
          `Condition ${position} has an invalid operator.`
        );
      }


      /**
       * `exists` intentionally does not require a value.
       */
      if (
        condition.operator !==
          "exists" &&
        (
          condition.value ===
            null ||
          condition.value ===
            undefined ||
          (
            typeof condition.value ===
              "string" &&
            condition.value.trim() ===
              ""
          )
        )
      ) {
        return (
          `Condition ${position} requires a value.`
        );
      }
    }


    /* ------------------------------------------------------------------------
     * Tags
     * ---------------------------------------------------------------------- */

    if (
      form.tags.length >
      MAX_TAGS
    ) {
      return (
        `A maximum of ${MAX_TAGS} tags is allowed.`
      );
    }


    for (
      const [
        index,
        tag,
      ] of form.tags.entries()
    ) {
      if (
        tag.trim().length >
        MAX_TAG_LENGTH
      ) {
        return (
          `Tag ${index + 1} cannot exceed 128 characters.`
        );
      }
    }


    return null;
  }


  /* ==========================================================================
   * Submit
   * ========================================================================== */

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();

    if (submitting) {
      return;
    }


    const validation =
      validateForm();


    if (validation) {
      setValidationError(
        validation,
      );

      return;
    }


    setValidationError(
      null,
    );


    if (editing) {
      await onSubmit(
        buildUpdatePayload(
          form,
        ),
      );

      return;
    }


    await onSubmit(
      buildCreatePayload(
        form,
      ),
    );
  }


  /* ==========================================================================
   * Loading State
   * ========================================================================== */

  if (loading) {
    return (
      <section
        className="detection-rule-form"
        aria-label="Detection rule form"
        aria-busy="true"
      >

        <div className="detection-rule-form-header">

          <div>

            <span className="detection-form-eyebrow">
              Detection
            </span>

            <strong>
              {editing
                ? "Edit Detection Rule"
                : "Create Detection Rule"}
            </strong>

            <p>
              Loading rule information...
            </p>

          </div>


          <span className="detection-form-status detection-form-status-loading">
            Loading
          </span>

        </div>


        <div
          className="detection-form-loading"
          aria-hidden="true"
        >
          <span />
          <span />
          <span />
        </div>

      </section>
    );
  }


  /* ==========================================================================
   * Render
   * ========================================================================== */

  return (
    <section
      className="detection-rule-form"
      aria-label={
        editing
          ? "Edit detection rule"
          : "Create detection rule"
      }
    >

      {/* ====================================================================
       * HEADER
       * ================================================================== */}

      <div className="detection-rule-form-header">

        <div>

          <span className="detection-form-eyebrow">
            Detection
          </span>

          <strong>
            {editing
              ? "Edit Detection Rule"
              : "Create Detection Rule"}
          </strong>

          <p>
            {editing
              ? "Update the selected Detection rule."
              : "Create and register a new Detection rule."}
          </p>

        </div>


        <span
          className={
            editing
              ? "detection-form-status detection-form-status-edit"
              : "detection-form-status detection-form-status-new"
          }
        >
          {editing
            ? "Edit"
            : "New"}
        </span>

      </div>


      {/* ====================================================================
       * ERROR
       * ================================================================== */}

      {validationError ||
      error ? (
        <div
          className="detection-rule-form-error"
          role="alert"
        >

          <strong>
            Unable to save rule
          </strong>

          <span>
            {validationError ||
              error}
          </span>

        </div>
      ) : null}


      {/* ====================================================================
       * FORM
       * ================================================================== */}

      <form
        onSubmit={
          handleSubmit
        }
        noValidate
      >

        {/* ==================================================================
         * RULE INFORMATION
         * ================================================================ */}

        <fieldset
          disabled={
            submitting
          }
        >

          <legend>
            Rule Information
          </legend>


          <div className="detection-form-grid">

            {/* ==============================================================
             * RULE ID
             * ============================================================ */}

            <div className="detection-form-field detection-form-field-full">

              <label
                htmlFor="detection-rule-id"
              >
                Rule ID
              </label>

              <input
                id="detection-rule-id"
                name="rule-id"
                type="text"
                value={
                  form.id
                }
                disabled={
                  editing ||
                  submitting
                }
                readOnly={
                  editing
                }
                onChange={(
                  event: ChangeEvent<HTMLInputElement>,
                ) =>
                  updateField(
                    "id",
                    event.target.value,
                  )
                }
                placeholder="brute-force"
                maxLength={
                  MAX_RULE_ID_LENGTH
                }
                autoComplete="off"
                spellCheck={false}
                required
              />

              <small>
                {editing
                  ? "Rule ID cannot be changed."
                  : "3-128 lowercase letters, numbers, underscores, or hyphens."}
              </small>

            </div>


            {/* ==============================================================
             * NAME
             * ============================================================ */}

            <div className="detection-form-field">

              <label
                htmlFor="detection-rule-name"
              >
                Name
              </label>

              <input
                id="detection-rule-name"
                name="name"
                type="text"
                value={
                  form.name
                }
                onChange={(
                  event: ChangeEvent<HTMLInputElement>,
                ) =>
                  updateField(
                    "name",
                    event.target.value,
                  )
                }
                placeholder="Brute Force Detection"
                maxLength={
                  MAX_NAME_LENGTH
                }
                autoComplete="off"
                required
              />

            </div>


            {/* ==============================================================
             * SEVERITY
             * ============================================================ */}

            <div className="detection-form-field">

              <label
                htmlFor="detection-rule-severity"
              >
                Severity
              </label>

              <select
                id="detection-rule-severity"
                name="severity"
                value={
                  form.severity
                }
                onChange={(
                  event: ChangeEvent<HTMLSelectElement>,
                ) =>
                  updateField(
                    "severity",
                    event.target.value,
                  )
                }
                disabled={
                  submitting ||
                  (
                    availableSeverityOptions.length ===
                    0 &&
                    !editing
                  )
                }
                required
              >

                <option value="">
                  {availableSeverityOptions.length ===
                  0
                    ? "Loading severity..."
                    : "Select severity"}
                </option>


                {availableSeverityOptions.map(
                  (
                    severity,
                  ) => (
                    <option
                      key={
                        severity
                      }
                      value={
                        severity
                      }
                    >
                      {
                        formatOptionLabel(
                          severity,
                        )
                      }
                    </option>
                  ),
                )}

              </select>


              <small>
                {availableSeverityOptions.length ===
                0
                  ? "Severity options are being loaded from the Detection backend."
                  : "Severity options are provided by the Detection backend."}
              </small>

            </div>


            {/* ==============================================================
             * CATEGORY
             * ============================================================ */}

            <div className="detection-form-field">

              <label
                htmlFor="detection-rule-category"
              >
                Category
              </label>

              <input
                id="detection-rule-category"
                name="category"
                type="text"
                value={
                  form.category
                }
                onChange={(
                  event: ChangeEvent<HTMLInputElement>,
                ) =>
                  updateField(
                    "category",
                    event.target.value,
                  )
                }
                placeholder="authentication"
                maxLength={
                  MAX_CATEGORY_LENGTH
                }
                autoComplete="off"
                required
              />

            </div>


            {/* ==============================================================
             * ENABLED
             * ============================================================ */}

            <div className="detection-form-field detection-form-field-toggle">

              <label
                htmlFor="detection-rule-enabled"
              >
                Rule Status
              </label>


              <label
                className="detection-form-switch"
              >

                <input
                  id="detection-rule-enabled"
                  name="enabled"
                  type="checkbox"
                  checked={
                    form.enabled
                  }
                  onChange={(
                    event,
                  ) =>
                    updateField(
                      "enabled",
                      event.target.checked,
                    )
                  }
                />

                <span
                  className="detection-form-switch-track"
                  aria-hidden="true"
                />

                <span className="detection-form-switch-label">
                  {form.enabled
                    ? "Enabled"
                    : "Disabled"}
                </span>

              </label>

            </div>


            {/* ==============================================================
             * DESCRIPTION
             * ============================================================ */}

            <div className="detection-form-field detection-form-field-full">

              <label
                htmlFor="detection-rule-description"
              >
                Description
              </label>

              <textarea
                id="detection-rule-description"
                name="description"
                value={
                  form.description
                }
                onChange={(
                  event: ChangeEvent<HTMLTextAreaElement>,
                ) =>
                  updateField(
                    "description",
                    event.target.value,
                  )
                }
                placeholder="Describe what this rule detects."
                maxLength={
                  MAX_DESCRIPTION_LENGTH
                }
                rows={4}
                required
              />

              <small>
                {form.description.length}
                /
                {MAX_DESCRIPTION_LENGTH}
              </small>

            </div>

          </div>

        </fieldset>


        {/* ==================================================================
         * DETECTION CONDITIONS
         * ================================================================ */}

        <fieldset
          disabled={
            submitting
          }
        >

          <legend>
            Detection Condition
          </legend>


          <div className="detection-rule-form-section-header">

            <div>

              <strong>
                Rule Conditions
              </strong>

              <p>
                Define the conditions evaluated
                by the Detection engine.
              </p>

            </div>


            <button
              type="button"
              className="detection-form-secondary-button"
              onClick={
                addCondition
              }
              disabled={
                form.conditions.length >=
                MAX_CONDITIONS
              }
            >
              + Add Condition
            </button>

          </div>


          {/* ================================================================
           * MATCH MODE
           * ============================================================== */}

          <div className="detection-form-field detection-form-match-field">

            <label
              htmlFor="detection-rule-match"
            >
              Match Mode
            </label>

            <select
              id="detection-rule-match"
              name="match"
              value={
                form.match
              }
              onChange={(
                event,
              ) =>
                updateField(
                  "match",
                  event.target
                    .value as DetectionRuleFormState["match"],
                )
              }
            >

              <option value="all">
                All conditions
              </option>

              <option value="any">
                Any condition
              </option>

            </select>


            <small>
              {form.match ===
              "all"
                ? "Every condition must match."
                : "At least one condition must match."}
            </small>

          </div>


          {/* ================================================================
           * CONDITION LIST
           * ============================================================== */}

          <div className="detection-rule-condition-list">

            {form.conditions.map(
              (
                condition,
                index,
              ) => (

                <article
                  key={`condition-${index}`}
                  className="detection-rule-condition-editor"
                >

                  <div className="detection-rule-condition-editor-header">

                    <strong>
                      Condition {index + 1}
                    </strong>


                    <button
                      type="button"
                      className="detection-form-remove-button"
                      onClick={() =>
                        removeCondition(
                          index,
                        )
                      }
                      disabled={
                        form.conditions.length <=
                        1
                      }
                    >
                      Remove
                    </button>

                  </div>


                  <div className="detection-form-grid">

                    {/* ------------------------------------------------------
                     * FIELD
                     * ---------------------------------------------------- */}

                    <div className="detection-form-field">

                      <label
                        htmlFor={`detection-condition-field-${index}`}
                      >
                        Field
                      </label>

                      <input
                        id={`detection-condition-field-${index}`}
                        name={`condition-${index}-field`}
                        type="text"
                        value={
                          condition.field
                        }
                        onChange={(
                          event,
                        ) =>
                          updateCondition(
                            index,
                            {
                              field:
                                event.target.value,
                            },
                          )
                        }
                        placeholder="source_ip"
                        maxLength={
                          MAX_FIELD_LENGTH
                        }
                        autoComplete="off"
                        spellCheck={false}
                        required
                      />

                    </div>


                    {/* ------------------------------------------------------
                     * OPERATOR
                     * ---------------------------------------------------- */}

                    <div className="detection-form-field">

                      <label
                        htmlFor={`detection-condition-operator-${index}`}
                      >
                        Operator
                      </label>

                      <select
                        id={`detection-condition-operator-${index}`}
                        name={`condition-${index}-operator`}
                        value={
                          condition.operator
                        }
                        onChange={(
                          event,
                        ) =>
                          updateCondition(
                            index,
                            {
                              operator:
                                event.target.value as ConditionOperator,
                            },
                          )
                        }
                      >

                        {CONDITION_OPERATORS.map(
                          (
                            operator,
                          ) => (
                            <option
                              key={
                                operator.value
                              }
                              value={
                                operator.value
                              }
                            >
                              {
                                operator.label
                              }
                            </option>
                          ),
                        )}

                      </select>

                    </div>


                    {/* ------------------------------------------------------
                     * VALUE
                     * ---------------------------------------------------- */}

                    <div className="detection-form-field detection-form-field-full">

                      <label
                        htmlFor={`detection-condition-value-${index}`}
                      >
                        Value
                      </label>

                      <input
                        id={`detection-condition-value-${index}`}
                        name={`condition-${index}-value`}
                        type="text"
                        value={
                          conditionValueToInput(
                            condition.value,
                          )
                        }
                        disabled={
                          condition.operator ===
                          "exists"
                        }
                        onChange={(
                          event,
                        ) =>
                          updateCondition(
                            index,
                            {
                              value:
                                parseConditionValue(
                                  event.target.value,
                                ),
                            },
                          )
                        }
                        placeholder={
                          condition.operator ===
                          "exists"
                            ? "Not required"
                            : "10.0.0.10"
                        }
                        autoComplete="off"
                      />

                      <small>
                        {condition.operator ===
                        "exists"
                          ? "The exists operator does not require a value."
                          : "Strings, numbers, booleans, arrays, and JSON objects are supported."}
                      </small>

                    </div>

                  </div>

                </article>

              ),
            )}

          </div>

        </fieldset>


        {/* ==================================================================
         * TAGS
         * ================================================================ */}

        <fieldset
          disabled={
            submitting
          }
        >

          <legend>
            Tags
          </legend>


          <div className="detection-rule-form-section-header">

            <div>

              <strong>
                Rule Tags
              </strong>

              <p>
                Add optional tags for classification
                and investigation.
              </p>

            </div>


            <button
              type="button"
              className="detection-form-secondary-button"
              onClick={
                addTag
              }
              disabled={
                form.tags.length >=
                MAX_TAGS
              }
            >
              + Add Tag
            </button>

          </div>


          {form.tags.length ===
          0 ? (

            <div className="detection-rule-tags-empty">
              No tags configured.
            </div>

          ) : (

            <div className="detection-rule-tag-editor">

              {form.tags.map(
                (
                  tag,
                  index,
                ) => (

                  <div
                    key={`tag-${index}`}
                    className="detection-rule-tag-field"
                  >

                    <label
                      htmlFor={`detection-rule-tag-${index}`}
                    >
                      Tag {index + 1}
                    </label>


                    <div>

                      <input
                        id={`detection-rule-tag-${index}`}
                        name={`tag-${index}`}
                        type="text"
                        value={
                          tag
                        }
                        onChange={(
                          event,
                        ) =>
                          updateTag(
                            index,
                            event.target.value,
                          )
                        }
                        placeholder="authentication"
                        maxLength={
                          MAX_TAG_LENGTH
                        }
                        autoComplete="off"
                      />


                      <button
                        type="button"
                        className="detection-form-remove-button"
                        onClick={() =>
                          removeTag(
                            index,
                          )
                        }
                      >
                        Remove
                      </button>

                    </div>

                  </div>

                ),
              )}

            </div>

          )}

        </fieldset>


        {/* ==================================================================
         * FORM ACTIONS
         * ================================================================ */}

        <div className="detection-rule-form-actions">

          {onCancel ? (
            <button
              type="button"
              className="detection-form-cancel-button"
              onClick={
                onCancel
              }
              disabled={
                submitting
              }
            >
              Cancel
            </button>
          ) : null}


          <button
            type="submit"
            className="detection-form-submit-button"
            disabled={
              submitting ||
              (
                availableSeverityOptions.length ===
                0 &&
                !editing
              )
            }
          >

            {submitting ? (
              <>
                <span
                  className="detection-form-submit-spinner"
                  aria-hidden="true"
                />

                Saving...
              </>
            ) : (
              editing
                ? "Update Rule"
                : "Create Rule"
            )}

          </button>

        </div>

      </form>

    </section>
  );
}


/* ==========================================================================
 * Default Export
 * ========================================================================== */

export default DetectionRuleForm;