import { describe, it, expect } from 'vitest';
import { computeExitCode, computeDetailedExitCode,
  EXIT_IDENTICAL, EXIT_DIFFERENCES, EXIT_ERROR,
  EXIT_DETAILED_IDENTICAL, EXIT_DETAILED_ERROR,
  EXIT_DETAILED_FIXES_ONLY, EXIT_DETAILED_REGRESSIONS_ONLY,
  EXIT_DETAILED_MIXED, EXIT_DETAILED_BASELINE_CHANGED,
  EXIT_DETAILED_DRIFT_ONLY,
} from '../src/exit-codes.js';
import type { ComparisonSummary } from '../src/types.js';

/**
 * Build a ComparisonSummary with sensible defaults (all unchanged).
 * Override individual fields as needed for each test scenario.
 */
function makeSummary(overrides: Partial<ComparisonSummary> = {}): ComparisonSummary {
  return {
    total: 10,
    fixed: 0,
    regressed: 0,
    new: 0,
    absent: 0,
    unchanged: 10,
    updated: 0,
    matchedCount: 10,
    unmatchedOldCount: 0,
    unmatchedNewCount: 0,
    ...overrides,
  };
}

// ── Constants ───────────────────────────────────────────────────────────

describe('exit code constants', () => {
  it('should export GNU diff compatible constants', () => {
    expect(EXIT_IDENTICAL).toBe(0);
    expect(EXIT_DIFFERENCES).toBe(1);
    expect(EXIT_ERROR).toBe(2);
  });

  it('should export detailed exit code constants', () => {
    expect(EXIT_DETAILED_IDENTICAL).toBe(0);
    expect(EXIT_DETAILED_ERROR).toBe(1);
    expect(EXIT_DETAILED_FIXES_ONLY).toBe(10);
    expect(EXIT_DETAILED_REGRESSIONS_ONLY).toBe(11);
    expect(EXIT_DETAILED_MIXED).toBe(12);
    expect(EXIT_DETAILED_BASELINE_CHANGED).toBe(13);
    expect(EXIT_DETAILED_DRIFT_ONLY).toBe(14);
  });
});

// ── computeExitCode (basic/GNU diff mode) ───────────────────────────────

describe('computeExitCode', () => {
  it('should return 0 when all requirements are unchanged (identical)', () => {
    const summary = makeSummary();
    expect(computeExitCode(summary)).toBe(0);
  });

  it('should return 1 when fixes exist', () => {
    const summary = makeSummary({ fixed: 3, unchanged: 7 });
    expect(computeExitCode(summary)).toBe(1);
  });

  it('should return 1 when regressions exist', () => {
    const summary = makeSummary({ regressed: 2, unchanged: 8 });
    expect(computeExitCode(summary)).toBe(1);
  });

  it('should return 1 when mixed fixes and regressions exist', () => {
    const summary = makeSummary({ fixed: 2, regressed: 1, unchanged: 7 });
    expect(computeExitCode(summary)).toBe(1);
  });

  it('should return 1 when only new controls exist', () => {
    const summary = makeSummary({
      new: 2, unchanged: 10, total: 12,
      unmatchedNewCount: 2, matchedCount: 10,
    });
    expect(computeExitCode(summary)).toBe(1);
  });

  it('should return 1 when only absent controls exist', () => {
    const summary = makeSummary({
      absent: 3, unchanged: 7, total: 10,
      unmatchedOldCount: 3, matchedCount: 7,
    });
    expect(computeExitCode(summary)).toBe(1);
  });

  it('should return 1 when new AND absent controls exist', () => {
    const summary = makeSummary({
      new: 1, absent: 1, unchanged: 8, total: 10,
      unmatchedNewCount: 1, unmatchedOldCount: 1, matchedCount: 8,
    });
    expect(computeExitCode(summary)).toBe(1);
  });

  it('should return 1 when only metadata drift (updated) exists', () => {
    const summary = makeSummary({ updated: 1, unchanged: 9 });
    expect(computeExitCode(summary)).toBe(1);
  });

  it('should return 0 for an empty comparison (total=0)', () => {
    const summary = makeSummary({
      total: 0, unchanged: 0, matchedCount: 0,
    });
    expect(computeExitCode(summary)).toBe(0);
  });
});

// ── computeDetailedExitCode ─────────────────────────────────────────────

describe('computeDetailedExitCode', () => {
  // Scenario 1: All unchanged → 0
  it('should return 0 when all requirements are unchanged (identical)', () => {
    const summary = makeSummary();
    expect(computeDetailedExitCode(summary)).toBe(0);
  });

  // Scenario 2: Fixes only → 10
  it('should return 10 when only fixes are present', () => {
    const summary = makeSummary({ fixed: 3, unchanged: 7 });
    expect(computeDetailedExitCode(summary)).toBe(10);
  });

  // Scenario 3: Regressions only → 11
  it('should return 11 when only regressions are present', () => {
    const summary = makeSummary({ regressed: 2, unchanged: 8 });
    expect(computeDetailedExitCode(summary)).toBe(11);
  });

  // Scenario 4: Mixed fixes and regressions → 12
  it('should return 12 when both fixes and regressions are present', () => {
    const summary = makeSummary({ fixed: 2, regressed: 1, unchanged: 7 });
    expect(computeDetailedExitCode(summary)).toBe(12);
  });

  // Scenario 5: Only new controls → 13
  it('should return 13 when only new controls are present', () => {
    const summary = makeSummary({
      new: 2, unchanged: 10, total: 12,
      unmatchedNewCount: 2, matchedCount: 10,
    });
    expect(computeDetailedExitCode(summary)).toBe(13);
  });

  // Scenario 6: Only absent controls → 13
  it('should return 13 when only absent controls are present', () => {
    const summary = makeSummary({
      absent: 3, unchanged: 7, total: 10,
      unmatchedOldCount: 3, matchedCount: 7,
    });
    expect(computeDetailedExitCode(summary)).toBe(13);
  });

  // Scenario 7: New AND absent (but no fixes/regressions) → 13
  it('should return 13 when both new and absent controls are present but no status changes', () => {
    const summary = makeSummary({
      new: 1, absent: 1, unchanged: 8, total: 10,
      unmatchedNewCount: 1, unmatchedOldCount: 1, matchedCount: 8,
    });
    expect(computeDetailedExitCode(summary)).toBe(13);
  });

  // Scenario 8: Only metadata drift (updated but no fixes/regressions/new/absent) → 14
  it('should return 14 when only metadata drift (updated) is present', () => {
    const summary = makeSummary({ updated: 1, unchanged: 9 });
    expect(computeDetailedExitCode(summary)).toBe(14);
  });

  // Scenario 9: Fixes + new controls → 10 (fixes take priority over baseline changes)
  it('should return 10 when fixes and new controls are present (fixes take priority)', () => {
    const summary = makeSummary({
      fixed: 2, new: 1, unchanged: 7, total: 10,
      unmatchedNewCount: 1, matchedCount: 9,
    });
    expect(computeDetailedExitCode(summary)).toBe(10);
  });

  // Scenario 10: Regressions + absent controls → 11 (regressions take priority)
  it('should return 11 when regressions and absent controls are present (regressions take priority)', () => {
    const summary = makeSummary({
      regressed: 1, absent: 2, unchanged: 7, total: 10,
      unmatchedOldCount: 2, matchedCount: 8,
    });
    expect(computeDetailedExitCode(summary)).toBe(11);
  });

  // Edge: empty comparison → 0
  it('should return 0 for an empty comparison (total=0)', () => {
    const summary = makeSummary({
      total: 0, unchanged: 0, matchedCount: 0,
    });
    expect(computeDetailedExitCode(summary)).toBe(0);
  });

  // Edge: fixes + regressions + new + absent → 12 (mixed takes priority)
  it('should return 12 when fixes, regressions, new, and absent all present', () => {
    const summary = makeSummary({
      fixed: 1, regressed: 1, new: 1, absent: 1, unchanged: 6, total: 10,
      unmatchedNewCount: 1, unmatchedOldCount: 1, matchedCount: 8,
    });
    expect(computeDetailedExitCode(summary)).toBe(12);
  });

  // Edge: updated + new → 13 (baseline changes take priority over drift)
  it('should return 13 when updated and new controls present but no status changes', () => {
    const summary = makeSummary({
      updated: 1, new: 1, unchanged: 8, total: 10,
      unmatchedNewCount: 1, matchedCount: 9,
    });
    expect(computeDetailedExitCode(summary)).toBe(13);
  });
});
