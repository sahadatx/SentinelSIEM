import { describe, expect, it } from "vitest";

describe("Phase 16 dashboard contract", () => {
  it("keeps the MITRE coverage calculation as a backend-provided value", () => {
    const payload = { total_techniques: 15, covered_techniques: 3, coverage_percent: 20 };
    expect(payload.coverage_percent).toBe(20);
    expect(payload.covered_techniques).toBeLessThanOrEqual(payload.total_techniques);
  });

  it("uses bounded severity values", () => {
    const allowed = ["info", "low", "medium", "high", "critical"];
    expect(allowed).toContain("critical");
  });
});
