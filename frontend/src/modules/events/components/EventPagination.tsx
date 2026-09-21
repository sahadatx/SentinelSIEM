import {
  ChevronLeft,
  ChevronRight,
} from "lucide-react";

/* ==========================================================================
 * Props
 * ========================================================================== */

export interface EventPaginationProps {
  page: number;

  pageSize: number;

  total: number;

  loading?: boolean;

  onPageChange: (
    page: number,
  ) => void;
}

/* ==========================================================================
 * Component
 * ========================================================================== */

export default function EventPagination({
  page,
  pageSize,
  total,
  loading = false,
  onPageChange,
}: EventPaginationProps) {
  /* ------------------------------------------------------------------------
   * Safe Pagination Values
   * ------------------------------------------------------------------------ */

  const safePage = Math.max(
    1,
    page,
  );

  const safePageSize = Math.max(
    1,
    pageSize,
  );

  const safeTotal = Math.max(
    0,
    total,
  );

  /* ------------------------------------------------------------------------
   * Page Calculations
   * ------------------------------------------------------------------------ */

  const totalPages = Math.max(
    1,
    Math.ceil(
      safeTotal / safePageSize,
    ),
  );

  const hasPreviousPage =
    safePage > 1;

  const hasNextPage =
    safePage < totalPages;

  /* ------------------------------------------------------------------------
   * Display Range
   * ------------------------------------------------------------------------ */

  const firstItem =
    safeTotal === 0
      ? 0
      : (safePage - 1) *
          safePageSize +
        1;

  const lastItem =
    safeTotal === 0
      ? 0
      : Math.min(
          safePage * safePageSize,
          safeTotal,
        );

  /* ------------------------------------------------------------------------
   * Handlers
   * ------------------------------------------------------------------------ */

  function handlePrevious() {
    if (
      loading ||
      !hasPreviousPage
    ) {
      return;
    }

    onPageChange(
      Math.max(
        1,
        safePage - 1,
      ),
    );
  }

  function handleNext() {
    if (
      loading ||
      !hasNextPage
    ) {
      return;
    }

    onPageChange(
      Math.min(
        totalPages,
        safePage + 1,
      ),
    );
  }

  /* ------------------------------------------------------------------------
   * Render
   * ------------------------------------------------------------------------ */

  return (
    <nav
      className="events-pagination"
      aria-label="Event pagination"
    >
      {/* ====================================================================
       * Pagination Information
       * ==================================================================== */}

      <div className="events-pagination-info">
        <div className="events-pagination-page">
          <span className="events-pagination-label">
            Page
          </span>

          <strong>
            {safePage}
          </strong>

          <span className="events-pagination-separator">
            /
          </span>

          <span>
            {totalPages}
          </span>
        </div>

        <span className="events-pagination-range">
          {safeTotal === 0
            ? "0 events"
            : `${firstItem}–${lastItem} of ${safeTotal}`}
        </span>
      </div>

      {/* ====================================================================
       * Pagination Actions
       * ==================================================================== */}

      <div className="events-pagination-actions">
        <button
          type="button"
          className="events-pagination-button"
          onClick={handlePrevious}
          disabled={
            loading ||
            !hasPreviousPage
          }
          aria-label="Previous events page"
          title="Previous page"
        >
          <ChevronLeft
            size={15}
            aria-hidden="true"
          />

          <span>
            Previous
          </span>
        </button>

        <button
          type="button"
          className="events-pagination-button"
          onClick={handleNext}
          disabled={
            loading ||
            !hasNextPage
          }
          aria-label="Next events page"
          title="Next page"
        >
          <span>
            Next
          </span>

          <ChevronRight
            size={15}
            aria-hidden="true"
          />
        </button>
      </div>
    </nav>
  );
}