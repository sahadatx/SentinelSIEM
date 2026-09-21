/* ==========================================================================
 * SentinelSIEM
 * Detection Operations Page
 *
 * LOCKED UI CONTRACT
 * ----------------------------------------------------------------------------
 *
 * Header:
 *   Detection
 *   Detection rules and runtime detection activity
 *   Refresh
 *   Create Rule
 *
 * KPI:
 *   Active Rules
 *   Detection Matches
 *   Enabled Plugins
 *   Total Evaluations
 *
 * Engine Health:
 *   Engine Status
 *   Rule Registry
 *   Rules Loaded
 *   Plugin Registry
 *   Plugins Enabled
 *   Evaluation Errors
 *
 * Rule Filters:
 *   Search
 *   Status
 *   Severity
 *   Category
 *   Tags
 *
 * Filter UX:
 *   - No Apply Filters button.
 *   - Dropdown filters apply automatically.
 *   - Search applies automatically with a short debounce.
 *   - Active filter count is displayed on the left.
 *   - Reset Filters is displayed on the right.
 *
 * Rule Table:
 *   Rule
 *   Severity
 *   Category
 *   Status
 *   Conditions
 *   Matches
 *   Suppressed
 *   Last Match
 *   Actions
 *
 * Pagination:
 *   - Backend authoritative.
 *   - No local slicing.
 *   - No local pagination calculation from items.
 *   - Page changes request the backend again.
 *
 * Rule Details:
 *   Basic Information
 *   Conditions
 *   Match Mode
 *   Runtime Statistics
 *   Matched Detection Results
 *
 * IMPORTANT
 * ----------------------------------------------------------------------------
 * Backend is the source of truth.
 *
 * This page does NOT:
 *   - calculate authoritative Detection metrics
 *   - invent timestamps
 *   - invent backend fields
 *   - derive Generated Alerts
 *   - derive Last Evaluation
 *   - derive Alert Pipeline
 *   - hardcode Severity / Category / Tags options
 *   - locally filter authoritative rule data
 *   - locally paginate authoritative rule data
 *
 * Filter options:
 *
 *   GET /api/v1/detections/filter-options
 *
 * Filtered/paginated rules:
 *
 *   GET /api/v1/detections
 *
 * Backend RBAC remains authoritative.
 * ========================================================================== */

import {
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import "../Detections.css";

import { detectionApi } from "../api";

import { DetectionRuleDetails } from "../components/DetectionRuleDetails";
import { DetectionRuleForm } from "../components/DetectionRuleForm";
import { DetectionRuleTable } from "../components/DetectionRuleTable";
import { DetectionStatusCard } from "../components/DetectionStatusCard";
import { DetectionSummary } from "../components/DetectionSummary";

import type {
  DetectionCapability,
  DetectionFilterOptions,
  DetectionRule,
  DetectionRuleCreateRequest,
  DetectionRuleUpdateRequest,
  DetectionStatistics,
  DetectionSummary as DetectionSummaryType,
} from "../types";


/* ==========================================================================
 * Types
 * ========================================================================== */

interface DetectionRuleFilters {
  search: string;
  status: string;
  severity: string;
  category: string;
  tag: string;
}

interface DetectionRuleQuery {
  query?: string;
  enabled?: boolean;
  severity?: string;
  category?: string;
  tag?: string;
  page: number;
  page_size: number;
}


/* ==========================================================================
 * Constants
 * ========================================================================== */

const EMPTY_RULE_FILTERS: DetectionRuleFilters = {
  search: "",
  status: "",
  severity: "",
  category: "",
  tag: "",
};

const EMPTY_FILTER_OPTIONS: DetectionFilterOptions = {
  status: [],
  severity: [],
  category: [],
  tags: [],
};

const DEFAULT_RULE_PAGE = 1;
const DEFAULT_RULE_PAGE_SIZE = 30;

const SEARCH_DEBOUNCE_MS = 350;


/* ==========================================================================
 * Component
 * ========================================================================== */

export default function Detections() {
  /* ========================================================================
   * BACKEND DATA
   * ====================================================================== */

  const [capability, setCapability] =
    useState<DetectionCapability | null>(
      null,
    );

  const [statistics, setStatistics] =
    useState<DetectionStatistics | null>(
      null,
    );

  const [summary, setSummary] =
    useState<DetectionSummaryType | null>(
      null,
    );

  const [rules, setRules] =
    useState<DetectionRule[]>(
      [],
    );

  const [filterOptions, setFilterOptions] =
    useState<DetectionFilterOptions>(
      EMPTY_FILTER_OPTIONS,
    );


  /* ========================================================================
   * BACKEND PAGINATION STATE
   *
   * These values come from the Detection list response.
   *
   * No local pagination is performed.
   * ====================================================================== */

  const [currentPage, setCurrentPage] =
    useState(
      DEFAULT_RULE_PAGE,
    );

  const [pageSize, setPageSize] =
    useState(
      DEFAULT_RULE_PAGE_SIZE,
    );

  const [totalRules, setTotalRules] =
    useState(0);

  const [totalPages, setTotalPages] =
    useState(0);


  /* ========================================================================
   * PAGE STATE
   * ====================================================================== */

  const [loading, setLoading] =
    useState(true);

  const [refreshing, setRefreshing] =
    useState(false);

  const [error, setError] =
    useState<string | null>(
      null,
    );

  const [statisticsError, setStatisticsError] =
    useState<string | null>(
      null,
    );

  const [summaryError, setSummaryError] =
    useState<string | null>(
      null,
    );

  const [rulesError, setRulesError] =
    useState<string | null>(
      null,
    );

  const [filterOptionsError, setFilterOptionsError] =
    useState<string | null>(
      null,
    );


  /* ========================================================================
   * FILTER STATE
   *
   * Selected values are the active values.
   *
   * There is intentionally no separate "applied filters" state.
   * ====================================================================== */

  const [filters, setFilters] =
    useState<DetectionRuleFilters>(
      EMPTY_RULE_FILTERS,
    );


  /* ========================================================================
   * RULE DETAILS
   * ====================================================================== */

  const [selectedRule, setSelectedRule] =
    useState<DetectionRule | null>(
      null,
    );


  /* ========================================================================
   * RULE FORM
   * ====================================================================== */

  const [formOpen, setFormOpen] =
    useState(false);

  const [editingRule, setEditingRule] =
    useState<DetectionRule | null>(
      null,
    );


  /* ========================================================================
   * MUTATION STATE
   * ====================================================================== */

  const [mutationRuleId, setMutationRuleId] =
    useState<string | null>(
      null,
    );


  /* ========================================================================
   * DERIVED PAGE STATE
   *
   * IMPORTANT:
   * pageBusy is declared before callbacks that depend on it.
   * ====================================================================== */

  const pageBusy =
    loading ||
    refreshing ||
    mutationRuleId !== null;

  const rulesLoading =
    loading &&
    rules.length === 0;


  /* ========================================================================
   * REQUEST / LIFECYCLE GUARDS
   * ====================================================================== */

  const mountedRef =
    useRef(true);

  const rulesRequestIdRef =
    useRef(0);

  const searchDebounceRef =
    useRef<ReturnType<typeof setTimeout> | null>(
      null,
    );


  /* ========================================================================
   * MOUNT / UNMOUNT
   * ====================================================================== */

  useEffect(() => {
    mountedRef.current = true;

    return () => {
      mountedRef.current = false;

      if (
        searchDebounceRef.current !== null
      ) {
        clearTimeout(
          searchDebounceRef.current,
        );

        searchDebounceRef.current = null;
      }
    };
  }, []);


  /* ========================================================================
   * ERROR NORMALIZATION
   * ====================================================================== */

  const getErrorMessage =
    useCallback(
      (
        reason: unknown,
        fallback: string,
      ): string => {
        if (
          reason instanceof Error &&
          reason.message.trim()
        ) {
          return reason.message;
        }

        if (
          typeof reason === "string" &&
          reason.trim()
        ) {
          return reason.trim();
        }

        if (
          typeof reason === "object" &&
          reason !== null &&
          "message" in reason
        ) {
          const message =
            (
              reason as {
                message?: unknown;
              }
            ).message;

          if (
            typeof message === "string" &&
            message.trim()
          ) {
            return message.trim();
          }
        }

        return fallback;
      },
      [],
    );


  /* ========================================================================
   * FILTER OPTION NORMALIZATION
   * ====================================================================== */

  const normalizeFilterOptions =
    useCallback(
      (
        value:
          | DetectionFilterOptions
          | null
          | undefined,
      ): DetectionFilterOptions => {
        if (!value) {
          return {
            ...EMPTY_FILTER_OPTIONS,
          };
        }

        return {
          status: Array.isArray(
            value.status,
          )
            ? value.status
            : [],

          severity: Array.isArray(
            value.severity,
          )
            ? value.severity
            : [],

          category: Array.isArray(
            value.category,
          )
            ? value.category
            : [],

          tags: Array.isArray(
            value.tags,
          )
            ? value.tags
            : [],
        };
      },
      [],
    );


  /* ========================================================================
   * BUILD BACKEND RULE QUERY
   *
   * Backend owns filtering and pagination.
   *
   * No local filtering occurs.
   * ====================================================================== */

  const buildRuleQuery =
    useCallback(
      (
        currentFilters: DetectionRuleFilters,
        page: number,
        requestedPageSize: number,
      ): DetectionRuleQuery => {
        const params: DetectionRuleQuery = {
          page,
          page_size: requestedPageSize,
        };


        /* ------------------------------------------------------------------
         * Search
         * ---------------------------------------------------------------- */

        const search =
          currentFilters.search.trim();

        if (search) {
          params.query = search;
        }


        /* ------------------------------------------------------------------
         * Status
         * ---------------------------------------------------------------- */

        const status =
          currentFilters.status
            .trim()
            .toLowerCase();

        if (
          status === "enabled"
        ) {
          params.enabled = true;
        } else if (
          status === "disabled"
        ) {
          params.enabled = false;
        }


        /* ------------------------------------------------------------------
         * Severity
         * ---------------------------------------------------------------- */

        const severity =
          currentFilters.severity.trim();

        if (severity) {
          params.severity =
            severity;
        }


        /* ------------------------------------------------------------------
         * Category
         * ---------------------------------------------------------------- */

        const category =
          currentFilters.category.trim();

        if (category) {
          params.category =
            category;
        }


        /* ------------------------------------------------------------------
         * Tag
         * ---------------------------------------------------------------- */

        const tag =
          currentFilters.tag.trim();

        if (tag) {
          params.tag =
            tag;
        }

        return params;
      },
      [],
    );


  /* ========================================================================
   * SYNCHRONIZE SELECTED RULE
   * ====================================================================== */

  const synchronizeSelectedRule =
    useCallback(
      (
        items: DetectionRule[],
      ): void => {
        setSelectedRule(
          (current) => {
            if (!current) {
              return null;
            }

            return (
              items.find(
                (item) =>
                  item.id ===
                  current.id,
              ) ?? null
            );
          },
        );
      },
      [],
    );


  /* ========================================================================
   * SYNCHRONIZE EDITING RULE
   * ====================================================================== */

  const synchronizeEditingRule =
    useCallback(
      (
        items: DetectionRule[],
      ): void => {
        setEditingRule(
          (current) => {
            if (!current) {
              return null;
            }

            return (
              items.find(
                (item) =>
                  item.id ===
                  current.id,
              ) ?? null
            );
          },
        );
      },
      [],
    );


  /* ========================================================================
   * APPLY RULE RESPONSE
   *
   * The response is authoritative.
   *
   * IMPORTANT:
   * - items are rendered as returned
   * - total is taken from backend
   * - page is taken from backend
   * - page_size is taken from backend
   * - total_pages is taken from backend
   *
   * No local pagination math is performed.
   * ====================================================================== */

  const applyRulesResponse =
    useCallback(
      (
        response: {
          items: DetectionRule[];
          total: number;
          page: number;
          page_size: number;
          total_pages: number;
        },
      ): void => {
        const items =
          Array.isArray(
            response.items,
          )
            ? response.items
            : [];

        setRules(
          items,
        );

        setTotalRules(
          response.total,
        );

        setCurrentPage(
          response.page,
        );

        setPageSize(
          response.page_size,
        );

        setTotalPages(
          response.total_pages,
        );

        synchronizeSelectedRule(
          items,
        );

        synchronizeEditingRule(
          items,
        );
      },
      [
        synchronizeEditingRule,
        synchronizeSelectedRule,
      ],
    );


  /* ========================================================================
   * LOAD PAGE DATA
   *
   * Loads:
   *   - capability
   *   - statistics
   *   - summary
   *   - filtered + paginated rules
   *   - filter options
   *
   * Used for:
   *   - initial page load
   *   - refresh
   *   - successful mutations
   *   - pagination refresh
   * ====================================================================== */

  const loadPageData =
    useCallback(
      async (
        currentFilters: DetectionRuleFilters,
        requestedPage: number,
        requestedPageSize: number,
        options?: {
          showLoading?: boolean;
          showRefreshing?: boolean;
        },
      ): Promise<void> => {
        const showLoading =
          options?.showLoading ??
          false;

        const showRefreshing =
          options?.showRefreshing ??
          false;

        if (showLoading) {
          setLoading(true);
        }

        if (showRefreshing) {
          setRefreshing(true);
        }

        setError(null);
        setStatisticsError(null);
        setSummaryError(null);
        setRulesError(null);
        setFilterOptionsError(null);

        const ruleQuery =
          buildRuleQuery(
            currentFilters,
            requestedPage,
            requestedPageSize,
          );

        try {
          const [
            capabilityResult,
            statisticsResult,
            summaryResult,
            rulesResult,
            filterOptionsResult,
          ] = await Promise.allSettled([
            detectionApi.getCapability(),

            detectionApi.getStatistics(),

            detectionApi.getSummary(),

            detectionApi.listRules(
              ruleQuery,
            ),

            detectionApi.getFilterOptions(),
          ]);

          if (!mountedRef.current) {
            return;
          }

          let firstError:
            | string
            | null = null;


          /* ================================================================
           * CAPABILITY
           * ============================================================ */

          if (
            capabilityResult.status ===
            "fulfilled"
          ) {
            setCapability(
              capabilityResult.value,
            );
          } else {
            setCapability(
              null,
            );

            firstError =
              getErrorMessage(
                capabilityResult.reason,
                "Failed to load detection capability.",
              );
          }


          /* ================================================================
           * STATISTICS
           * ============================================================ */

          if (
            statisticsResult.status ===
            "fulfilled"
          ) {
            setStatistics(
              statisticsResult.value,
            );

            setStatisticsError(
              null,
            );
          } else {
            setStatistics(
              null,
            );

            const message =
              getErrorMessage(
                statisticsResult.reason,
                "Failed to load detection statistics.",
              );

            setStatisticsError(
              message,
            );

            if (!firstError) {
              firstError =
                message;
            }
          }


          /* ================================================================
           * SUMMARY
           * ============================================================ */

          if (
            summaryResult.status ===
            "fulfilled"
          ) {
            setSummary(
              summaryResult.value,
            );

            setSummaryError(
              null,
            );
          } else {
            setSummary(
              null,
            );

            const message =
              getErrorMessage(
                summaryResult.reason,
                "Failed to load detection summary.",
              );

            setSummaryError(
              message,
            );

            if (!firstError) {
              firstError =
                message;
            }
          }


          /* ================================================================
           * RULES
           * ============================================================ */

          if (
            rulesResult.status ===
            "fulfilled"
          ) {
            applyRulesResponse(
              rulesResult.value,
            );

            setRulesError(
              null,
            );
          } else {
            setRules(
              [],
            );

            setTotalRules(
              0,
            );

            setTotalPages(
              0,
            );

            const message =
              getErrorMessage(
                rulesResult.reason,
                "Failed to load detection rules.",
              );

            setRulesError(
              message,
            );

            if (!firstError) {
              firstError =
                message;
            }
          }


          /* ================================================================
           * FILTER OPTIONS
           * ============================================================ */

          if (
            filterOptionsResult.status ===
            "fulfilled"
          ) {
            setFilterOptions(
              normalizeFilterOptions(
                filterOptionsResult.value,
              ),
            );

            setFilterOptionsError(
              null,
            );
          } else {
            /*
             * Never use hardcoded frontend fallback options.
             */
            setFilterOptions(
              {
                ...EMPTY_FILTER_OPTIONS,
              },
            );

            const message =
              getErrorMessage(
                filterOptionsResult.reason,
                "Failed to load detection filter options.",
              );

            setFilterOptionsError(
              message,
            );

            if (!firstError) {
              firstError =
                message;
            }
          }

          setError(
            firstError,
          );
        } finally {
          if (!mountedRef.current) {
            return;
          }

          if (showLoading) {
            setLoading(false);
          }

          if (showRefreshing) {
            setRefreshing(false);
          }
        }
      },
      [
        applyRulesResponse,
        buildRuleQuery,
        getErrorMessage,
        normalizeFilterOptions,
      ],
    );


  /* ========================================================================
   * LOAD FILTERED RULES ONLY
   *
   * Used when:
   *   - search changes
   *   - status changes
   *   - severity changes
   *   - category changes
   *   - tag changes
   *
   * Every filter request starts from page 1.
   *
   * Backend owns the actual filtering.
   * ====================================================================== */

  const loadFilteredRules =
    useCallback(
      async (
        currentFilters: DetectionRuleFilters,
      ): Promise<void> => {
        const requestId =
          ++rulesRequestIdRef.current;

        setRulesError(
          null,
        );

        try {
          const response =
            await detectionApi.listRules(
              buildRuleQuery(
                currentFilters,
                DEFAULT_RULE_PAGE,
                pageSize,
              ),
            );

          if (
            !mountedRef.current ||
            requestId !==
              rulesRequestIdRef.current
          ) {
            return;
          }

          applyRulesResponse(
            response,
          );
        } catch (
          err: unknown
        ) {
          if (
            !mountedRef.current ||
            requestId !==
              rulesRequestIdRef.current
          ) {
            return;
          }

          setRules(
            [],
          );

          setTotalRules(
            0,
          );

          setTotalPages(
            0,
          );

          setRulesError(
            getErrorMessage(
              err,
              "Failed to load detection rules.",
            ),
          );
        }
      },
      [
        applyRulesResponse,
        buildRuleQuery,
        getErrorMessage,
        pageSize,
      ],
    );


  /* ========================================================================
   * INITIAL LOAD
   *
   * Starts from:
   *   page 1
   *   backend default/locked page size 30
   * ====================================================================== */

  useEffect(() => {
    void loadPageData(
      EMPTY_RULE_FILTERS,
      DEFAULT_RULE_PAGE,
      DEFAULT_RULE_PAGE_SIZE,
      {
        showLoading: true,
      },
    );
  }, [loadPageData]);


  /* ========================================================================
   * AUTO APPLY FILTERS
   *
   * Search:
   *   350ms debounce.
   *
   * Dropdown:
   *   immediate request.
   *
   * No Apply button.
   * ====================================================================== */

  useEffect(() => {
    if (loading) {
      return;
    }

    if (
      searchDebounceRef.current !==
      null
    ) {
      clearTimeout(
        searchDebounceRef.current,
      );

      searchDebounceRef.current =
        null;
    }

    const currentFilters = {
      ...filters,
    };

    const hasSearch =
      currentFilters.search.trim()
        .length > 0;

    const delay =
      hasSearch
        ? SEARCH_DEBOUNCE_MS
        : 0;

    searchDebounceRef.current =
      setTimeout(
        () => {
          searchDebounceRef.current =
            null;

          /*
           * Every filter change resets backend pagination to page 1.
           */
          setCurrentPage(
            DEFAULT_RULE_PAGE,
          );

          void loadFilteredRules(
            currentFilters,
          );
        },
        delay,
      );

    return () => {
      if (
        searchDebounceRef.current !==
        null
      ) {
        clearTimeout(
          searchDebounceRef.current,
        );

        searchDebounceRef.current =
          null;
      }
    };
  }, [
    filters,
    loading,
    loadFilteredRules,
  ]);


  /* ========================================================================
   * REFRESH
   *
   * Keeps the currently selected filters and current backend page.
   * ====================================================================== */

  const handleRefresh =
    useCallback(
      async (): Promise<void> => {
        if (pageBusy) {
          return;
        }

        await loadPageData(
          filters,
          currentPage,
          pageSize,
          {
            showRefreshing: true,
          },
        );
      },
      [
        currentPage,
        filters,
        loadPageData,
        pageBusy,
        pageSize,
      ]);


  /* ========================================================================
   * PAGE CHANGE
   *
   * Backend owns the page contents.
   *
   * No local array slicing occurs.
   * ====================================================================== */

  const handlePageChange =
    useCallback(
      async (
        requestedPage: number,
      ): Promise<void> => {
        if (
          pageBusy
        ) {
          return;
        }

        if (
          requestedPage < 1
        ) {
          return;
        }

        if (
          totalPages > 0 &&
          requestedPage >
            totalPages
        ) {
          return;
        }

        const requestId =
          ++rulesRequestIdRef.current;

        setRulesError(
          null,
        );

        try {
          const response =
            await detectionApi.listRules(
              buildRuleQuery(
                filters,
                requestedPage,
                pageSize,
              ),
            );

          if (
            !mountedRef.current ||
            requestId !==
              rulesRequestIdRef.current
          ) {
            return;
          }

          applyRulesResponse(
            response,
          );
        } catch (
          err: unknown
        ) {
          if (
            !mountedRef.current ||
            requestId !==
              rulesRequestIdRef.current
          ) {
            return;
          }

          setRulesError(
            getErrorMessage(
              err,
              "Failed to load detection rules.",
            ),
          );
        }
      },
      [
        applyRulesResponse,
        buildRuleQuery,
        filters,
        getErrorMessage,
        pageBusy,
        pageSize,
        totalPages,
      ]);


  /* ========================================================================
   * PREVIOUS PAGE
   * ====================================================================== */

  const handlePreviousPage =
    useCallback(
      (): void => {
        if (
          pageBusy ||
          currentPage <= 1
        ) {
          return;
        }

        void handlePageChange(
          currentPage - 1,
        );
      },
      [
        currentPage,
        handlePageChange,
        pageBusy,
      ]);


  /* ========================================================================
   * NEXT PAGE
   * ====================================================================== */

  const handleNextPage =
    useCallback(
      (): void => {
        if (
          pageBusy ||
          totalPages <= 0 ||
          currentPage >=
            totalPages
        ) {
          return;
        }

        void handlePageChange(
          currentPage + 1,
        );
      },
      [
        currentPage,
        handlePageChange,
        pageBusy,
        totalPages,
      ]);


  /* ========================================================================
   * FILTER HANDLERS
   * ====================================================================== */

  const handleSearchChange =
    useCallback(
      (
        value: string,
      ): void => {
        setFilters(
          (current) => ({
            ...current,
            search: value,
          }),
        );
      },
      [],
    );


  const handleStatusChange =
    useCallback(
      (
        value: string,
      ): void => {
        setFilters(
          (current) => ({
            ...current,
            status: value,
          }),
        );
      },
      [],
    );


  const handleSeverityChange =
    useCallback(
      (
        value: string,
      ): void => {
        setFilters(
          (current) => ({
            ...current,
            severity: value,
          }),
        );
      },
      [],
    );


  const handleCategoryChange =
    useCallback(
      (
        value: string,
      ): void => {
        setFilters(
          (current) => ({
            ...current,
            category: value,
          }),
        );
      },
      [],
    );


  const handleTagChange =
    useCallback(
      (
        value: string,
      ): void => {
        setFilters(
          (current) => ({
            ...current,
            tag: value,
          }),
        );
      },
      [],
    );


  /* ========================================================================
   * RESET FILTERS
   * ====================================================================== */

  const handleResetFilters =
    useCallback(
      (): void => {
        if (pageBusy) {
          return;
        }

        setCurrentPage(
          DEFAULT_RULE_PAGE,
        );

        setFilters(
          {
            ...EMPTY_RULE_FILTERS,
          },
        );
      },
      [
        pageBusy,
      ]);


  /* ========================================================================
   * ACTIVE FILTER COUNT
   *
   * UI-only count.
   *
   * One selected filter control = one active filter.
   * ====================================================================== */

  const activeFilterCount =
    [
      filters.search.trim(),
      filters.status,
      filters.severity,
      filters.category,
      filters.tag,
    ].filter(
      Boolean,
    ).length;


  /* ========================================================================
   * SELECT RULE
   * ====================================================================== */

  const handleSelectRule =
    useCallback(
      (
        rule: DetectionRule,
      ): void => {
        if (
          mutationRuleId !== null
        ) {
          return;
        }

        setSelectedRule(
          rule,
        );
      },
      [
        mutationRuleId,
      ]);


  /* ========================================================================
   * CLOSE DETAILS
   * ====================================================================== */

  const handleCloseDetails =
    useCallback(
      (): void => {
        if (
          mutationRuleId !== null
        ) {
          return;
        }

        setSelectedRule(
          null,
        );
      },
      [
        mutationRuleId,
      ]);


  /* ========================================================================
   * CREATE RULE
   * ====================================================================== */

  const handleCreateRule =
    useCallback(
      (): void => {
        if (pageBusy) {
          return;
        }

        setSelectedRule(
          null,
        );

        setEditingRule(
          null,
        );

        setFormOpen(
          true,
        );
      },
      [
        pageBusy,
      ]);


  /* ========================================================================
   * EDIT RULE
   * ====================================================================== */

  const handleEditRule =
    useCallback(
      (
        rule: DetectionRule,
      ): void => {
        if (pageBusy) {
          return;
        }

        setSelectedRule(
          null,
        );

        setEditingRule(
          rule,
        );

        setFormOpen(
          true,
        );
      },
      [
        pageBusy,
      ]);


  /* ========================================================================
   * CLOSE FORM
   * ====================================================================== */

  const handleCloseForm =
    useCallback(
      (): void => {
        if (
          mutationRuleId !== null
        ) {
          return;
        }

        setFormOpen(
          false,
        );

        setEditingRule(
          null,
        );
      },
      [
        mutationRuleId,
      ]);


  /* ==========================================================================
  * RULE SAVED
  *
  * Create:
  *   POST /api/v1/detections/rules
  *
  * Edit:
  *   PATCH /api/v1/detections/rules/{rule_id}
  *
  * Backend remains authoritative.
  * After successful mutation the page reloads:
  *   - rules
  *   - statistics
  *   - summary
  *   - filter-options
  * ========================================================================== */

  const handleRuleSaved =
    useCallback(
      async (
        payload:
          | DetectionRuleCreateRequest
          | DetectionRuleUpdateRequest,
      ): Promise<void> => {
        if (
          !mountedRef.current ||
          mutationRuleId !== null
        ) {
          return;
        }

        const ruleBeingEdited =
          editingRule;

        /*
        * Use the rule ID as mutation state during Edit.
        * Use a stable temporary marker during Create.
        */
        setMutationRuleId(
          ruleBeingEdited?.id ??
            "__creating__",
        );

        setRulesError(
          null,
        );

        try {
          /* ================================================================
          * EDIT
          * ================================================================ */

          if (
            ruleBeingEdited
          ) {
            await detectionApi.updateRule(
              ruleBeingEdited.id,
              payload as DetectionRuleUpdateRequest,
            );
          }

          /* ================================================================
          * CREATE
          * ================================================================ */

          else {
            await detectionApi.createRule(
              payload as DetectionRuleCreateRequest,
            );
          }

          if (
            !mountedRef.current
          ) {
            return;
          }

          /*
          * Close the form only after the backend mutation succeeds.
          */
          setFormOpen(
            false,
          );

          setEditingRule(
            null,
          );

          /*
          * Reload authoritative backend state.
          *
          * This also refreshes filter-options, so a newly introduced
          * backend-supported severity/category/tag becomes available
          * to the table filters.
          */
          await loadPageData(
            filters,
            currentPage,
            pageSize,
          );
        } catch (
          err: unknown
        ) {
          if (
            !mountedRef.current
          ) {
            return;
          }

          /*
          * Keep the drawer open so the user can see the error and
          * correct/retry the rule.
          */
          setRulesError(
            getErrorMessage(
              err,
              ruleBeingEdited
                ? "Failed to update detection rule."
                : "Failed to create detection rule.",
            ),
          );
        } finally {
          if (
            mountedRef.current
          ) {
            setMutationRuleId(
              null,
            );
          }
        }
      },
      [
        currentPage,
        editingRule,
        filters,
        getErrorMessage,
        loadPageData,
        mutationRuleId,
        pageSize,
      ],
    );

  /* ========================================================================
   * DELETE RULE
   * ====================================================================== */

  const handleDeleteRule =
    useCallback(
      async (
        rule: DetectionRule,
      ): Promise<void> => {
        if (
          mutationRuleId !== null
        ) {
          return;
        }

        const ruleId =
          rule.id;

        setRulesError(
          null,
        );

        setMutationRuleId(
          ruleId,
        );

        try {
          await detectionApi.deleteRule(
            ruleId,
          );

          if (
            !mountedRef.current
          ) {
            return;
          }

          setSelectedRule(
            (current) =>
              current?.id ===
              ruleId
                ? null
                : current,
          );

          setEditingRule(
            (current) =>
              current?.id ===
              ruleId
                ? null
                : current,
          );

          if (
            editingRule?.id ===
            ruleId
          ) {
            setFormOpen(
              false,
            );
          }

          /*
           * Reload the same backend page.
           *
           * Backend remains authoritative. If deletion changes the
           * available page count, the backend response determines the
           * resulting page and total_pages.
           */
          await loadPageData(
            filters,
            currentPage,
            pageSize,
          );
        } catch (
          err: unknown
        ) {
          if (
            !mountedRef.current
          ) {
            return;
          }

          setRulesError(
            getErrorMessage(
              err,
              "Failed to delete detection rule.",
            ),
          );
        } finally {
          if (
            mountedRef.current
          ) {
            setMutationRuleId(
              null,
            );
          }
        }
      },
      [
        currentPage,
        editingRule,
        filters,
        getErrorMessage,
        loadPageData,
        mutationRuleId,
        pageSize,
      ]);


  /* ========================================================================
   * ENABLE / DISABLE RULE
   * ====================================================================== */

  const handleToggleRule =
    useCallback(
      async (
        rule: DetectionRule,
      ): Promise<void> => {
        if (
          mutationRuleId !== null
        ) {
          return;
        }

        const ruleId =
          rule.id;

        const nextEnabled =
          !rule.enabled;

        setRulesError(
          null,
        );

        setMutationRuleId(
          ruleId,
        );

        try {
          await detectionApi.setRuleEnabled(
            ruleId,
            nextEnabled,
          );

          if (
            !mountedRef.current
          ) {
            return;
          }

          await loadPageData(
            filters,
            currentPage,
            pageSize,
          );
        } catch (
          err: unknown
        ) {
          if (
            !mountedRef.current
          ) {
            return;
          }

          setRulesError(
            getErrorMessage(
              err,
              nextEnabled
                ? "Failed to enable detection rule."
                : "Failed to disable detection rule.",
            ),
          );
        } finally {
          if (
            mountedRef.current
          ) {
            setMutationRuleId(
              null,
            );
          }
        }
      },
      [
        currentPage,
        filters,
        getErrorMessage,
        loadPageData,
        mutationRuleId,
        pageSize,
      ]);


  /* ========================================================================
   * FILTER OPTIONS
   * ====================================================================== */

  const statusOptions =
    filterOptions.status;

  const severityOptions =
    filterOptions.severity;

  const categoryOptions =
    filterOptions.category;

  const tagOptions =
    filterOptions.tags;


  /* ========================================================================
   * PAGINATION DISPLAY
   *
   * Uses backend-provided total/page/page_size/total_pages.
   *
   * The range below is display formatting only; it does not slice data.
   * ====================================================================== */

  const rangeStart =
    totalRules === 0
      ? 0
      : (
          (currentPage - 1) *
            pageSize
        ) + 1;

  const rangeEnd =
    totalRules === 0
      ? 0
      : Math.min(
          currentPage *
            pageSize,
          totalRules,
        );


  /* ========================================================================
   * RENDER
   * ====================================================================== */

  return (
    <div className="detection-page">

      {/* ==================================================================
       * HEADER
       * ================================================================== */}

      <header className="page-heading">
        <div>
          <h2>
            Detection
          </h2>

          <p>
            Detection rules and runtime detection activity
          </p>
        </div>

        <div className="page-heading-actions">
          <button
            type="button"
            className="detection-page-refresh-button"
            onClick={() => {
              void handleRefresh();
            }}
            disabled={
              pageBusy
            }
            aria-label="Refresh detection data"
          >
            {refreshing
              ? "Refreshing..."
              : "Refresh"}
          </button>

          <button
            type="button"
            className="detection-page-create-button"
            onClick={
              handleCreateRule
            }
            disabled={
              pageBusy
            }
          >
            + Create Rule
          </button>
        </div>
      </header>


      {/* ==================================================================
       * PAGE ERROR
       * ================================================================== */}

      {error ? (
        <div
          className="detection-page-error"
          role="alert"
        >
          <strong>
            Detection partially unavailable
          </strong>

          <span>
            {error}
          </span>
        </div>
      ) : null}


      {/* ==================================================================
       * KPI
       * ================================================================== */}

      <DetectionSummary
        summary={
          summary
        }
        engineStatus={
          capability?.status ??
          "unknown"
        }
        loading={
          loading
        }
        error={
          summaryError ??
          statisticsError
        }
      />


      {/* ==================================================================
       * ENGINE HEALTH
       * ================================================================== */}

      <DetectionStatusCard
        capability={
          capability
        }
        statistics={
          statistics
        }
        loading={
          loading
        }
        error={
          statisticsError ??
          error
        }
      />


      {/* ==================================================================
       * DETECTION RULE FILTERS
       *
       * NO APPLY BUTTON.
       * ================================================================== */}

      <section
        className="detection-rule-filters"
        aria-label="Detection rule filters"
      >

        {/* ================================================================
         * SEARCH
         * ================================================================ */}

        <div className="detection-rule-filter-search">
          <label
            htmlFor="detection-rule-search"
          >
            Search
          </label>

          <input
            id="detection-rule-search"
            type="search"
            value={
              filters.search
            }
            onChange={(event) => {
              handleSearchChange(
                event.target.value,
              );
            }}
            placeholder="Search rule, ID or description..."
            disabled={
              pageBusy
            }
            autoComplete="off"
          />
        </div>


        {/* ================================================================
         * DROPDOWNS
         * ================================================================ */}

        <div className="detection-rule-filter-grid">

          {/* --------------------------------------------------------------
           * STATUS
           * ------------------------------------------------------------ */}

          <div className="detection-rule-filter-field">
            <label
              htmlFor="detection-rule-status"
            >
              Status
            </label>

            <select
              id="detection-rule-status"
              value={
                filters.status
              }
              onChange={(event) => {
                handleStatusChange(
                  event.target.value,
                );
              }}
              disabled={
                pageBusy ||
                !!filterOptionsError
              }
            >
              <option value="">
                All
              </option>

              {statusOptions.map(
                (option) => (
                  <option
                    key={option}
                    value={option}
                  >
                    {option}
                  </option>
                ),
              )}
            </select>
          </div>


          {/* --------------------------------------------------------------
           * SEVERITY
           * ------------------------------------------------------------ */}

          <div className="detection-rule-filter-field">
            <label
              htmlFor="detection-rule-severity"
            >
              Severity
            </label>

            <select
              id="detection-rule-severity"
              value={
                filters.severity
              }
              onChange={(event) => {
                handleSeverityChange(
                  event.target.value,
                );
              }}
              disabled={
                pageBusy ||
                !!filterOptionsError
              }
            >
              <option value="">
                All
              </option>

              {severityOptions.map(
                (option) => (
                  <option
                    key={option}
                    value={option}
                  >
                    {option}
                  </option>
                ),
              )}
            </select>
          </div>


          {/* --------------------------------------------------------------
           * CATEGORY
           * ------------------------------------------------------------ */}

          <div className="detection-rule-filter-field">
            <label
              htmlFor="detection-rule-category"
            >
              Category
            </label>

            <select
              id="detection-rule-category"
              value={
                filters.category
              }
              onChange={(event) => {
                handleCategoryChange(
                  event.target.value,
                );
              }}
              disabled={
                pageBusy ||
                !!filterOptionsError
              }
            >
              <option value="">
                All
              </option>

              {categoryOptions.map(
                (option) => (
                  <option
                    key={option}
                    value={option}
                  >
                    {option}
                  </option>
                ),
              )}
            </select>
          </div>


          {/* --------------------------------------------------------------
           * TAG
           * ------------------------------------------------------------ */}

          <div className="detection-rule-filter-field">
            <label
              htmlFor="detection-rule-tag"
            >
              Tags
            </label>

            <select
              id="detection-rule-tag"
              value={
                filters.tag
              }
              onChange={(event) => {
                handleTagChange(
                  event.target.value,
                );
              }}
              disabled={
                pageBusy ||
                !!filterOptionsError
              }
            >
              <option value="">
                All
              </option>

              {tagOptions.map(
                (option) => (
                  <option
                    key={option}
                    value={option}
                  >
                    {option}
                  </option>
                ),
              )}
            </select>
          </div>

        </div>


        {/* ================================================================
         * FILTER STATUS
         * ================================================================ */}

        <div className="detection-rule-filter-status">
          <span
            className="detection-filter-applied"
            aria-live="polite"
          >
            Filter Applied (
            {activeFilterCount}
            )
          </span>

          <button
            type="button"
            className="detection-filter-reset-button"
            onClick={
              handleResetFilters
            }
            disabled={
              pageBusy ||
              activeFilterCount ===
                0
            }
          >
            Reset Filters
          </button>
        </div>


        {/* ================================================================
         * FILTER OPTION ERROR
         * ================================================================ */}

        {filterOptionsError ? (
          <div
            className="detection-filter-options-error"
            role="alert"
          >
            <strong>
              Filter options unavailable
            </strong>

            <span>
              {filterOptionsError}
            </span>
          </div>
        ) : null}

      </section>


      {/* ==================================================================
       * RULE TABLE
       * ================================================================== */}

      <DetectionRuleTable
        rules={
          rules
        }
        loading={
          rulesLoading
        }
        error={
          rulesError
        }
        onSelectRule={
          handleSelectRule
        }
        onEditRule={
          handleEditRule
        }
        onDeleteRule={
          handleDeleteRule
        }
        onToggleRule={
          handleToggleRule
        }
      />


      {/* ==================================================================
       * BACKEND PAGINATION
       *
       * IMPORTANT:
       * This controls backend page requests.
       * DetectionRuleTable itself does not paginate.
       * ================================================================== */}

{/* ==================================================================
 * BACKEND PAGINATION
 * ================================================================== */}

      {!rulesLoading &&
      !rulesError &&
      totalRules > 0 ? (
        <section
          className="detection-rule-pagination"
          aria-label="Detection rule pagination"
        >
          <div className="detection-rule-pagination-bar">

            <span
              className="detection-rule-pagination-info"
              aria-live="polite"
            >
              {rangeStart.toLocaleString()}
              –
              {rangeEnd.toLocaleString()}
              {" "}
              Rules
              {" "}
              •
              {" "}
              Total{" "}
              {totalRules.toLocaleString()}
              {" "}
              •
              {" "}
              Page{" "}
              {currentPage.toLocaleString()}
              {" "}
              of{" "}
              {totalPages.toLocaleString()}
            </span>


            <div className="detection-rule-pagination-controls">

              <button
                type="button"
                className="detection-rule-pagination-button"
                onClick={
                  handlePreviousPage
                }
                disabled={
                  pageBusy ||
                  currentPage <= 1
                }
                aria-label="Previous page"
              >
                Previous
              </button>


              <button
                type="button"
                className="detection-rule-pagination-button"
                onClick={
                  handleNextPage
                }
                disabled={
                  pageBusy ||
                  totalPages <= 0 ||
                  currentPage >= totalPages
                }
                aria-label="Next page"
              >
                Next
              </button>

            </div>

          </div>
        </section>
      ) : null}


      {/* ==================================================================
       * RULE DETAILS
       * ================================================================== */}

      {selectedRule ? (
        <DetectionRuleDetails
          rule={
            selectedRule
          }
          onClose={
            handleCloseDetails
          }
          onEdit={
            handleEditRule
          }
          onToggle={
            handleToggleRule
          }
        />
      ) : null}


      {/* ==================================================================
       * CREATE / EDIT DRAWER
       * ================================================================== */}

      {formOpen ? (
  <div
    className="detection-rule-form-overlay"
    role="presentation"
    onMouseDown={(event) => {
      if (event.target === event.currentTarget) {
        handleCloseForm();
      }
    }}
  >
    <div
      className="detection-rule-form-drawer"
      role="dialog"
      aria-modal="true"
      aria-label={
        editingRule
          ? "Edit Detection Rule"
          : "Create Detection Rule"
      }
      onMouseDown={(event) => {
        event.stopPropagation();
      }}
    >
      <DetectionRuleForm
        rule={editingRule}
        loading={mutationRuleId !== null}
        severityOptions={filterOptions?.severity ?? []}
        onSubmit={handleRuleSaved}
        onCancel={handleCloseForm}
      />
    </div>
  </div>
) : null}

    </div>
  );
}