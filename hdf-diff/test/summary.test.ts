import { describe, it, expect } from 'vitest';
import { computeSummary } from '../src/summary.js';
import type { RequirementDiff, ComparisonSummary } from '../src/types.js';

/**
 * Build a minimal RequirementDiff with only the fields computeSummary needs.
 */
function makeReq(
  id: string,
  state: RequirementDiff['state'],
): RequirementDiff {
  return {
    id,
    state,
    changeReasons: [],
    fieldChanges: [],
    before: state === 'new' ? null : {},
    after: state === 'absent' ? null : {},
  };
}

describe('computeSummary', () => {
  // ── 1. Empty array → all zeros ────────────────────────────────────
  it('should return all zeros for an empty requirements array', () => {
    const summary = computeSummary([]);

    expect(summary).toEqual<ComparisonSummary>({
      fixed: 0,
      regressed: 0,
      new: 0,
      absent: 0,
      unchanged: 0,
      updated: 0,
      total: 0,
      matchedCount: 0,
      unmatchedOldCount: 0,
      unmatchedNewCount: 0,
    });
  });

  // ── 2. All fixed ──────────────────────────────────────────────────
  it('should count all requirements as fixed when all have fixed state', () => {
    const reqs: RequirementDiff[] = [
      makeReq('SV-001', 'fixed'),
      makeReq('SV-002', 'fixed'),
      makeReq('SV-003', 'fixed'),
    ];

    const summary = computeSummary(reqs);

    expect(summary.fixed).toBe(3);
    expect(summary.regressed).toBe(0);
    expect(summary.new).toBe(0);
    expect(summary.absent).toBe(0);
    expect(summary.unchanged).toBe(0);
    expect(summary.updated).toBe(0);
    expect(summary.total).toBe(3);
    expect(summary.matchedCount).toBe(3);
    expect(summary.unmatchedOldCount).toBe(0);
    expect(summary.unmatchedNewCount).toBe(0);
  });

  // ── 3. All regressed ─────────────────────────────────────────────
  it('should count all requirements as regressed when all have regressed state', () => {
    const reqs: RequirementDiff[] = [
      makeReq('SV-001', 'regressed'),
      makeReq('SV-002', 'regressed'),
      makeReq('SV-003', 'regressed'),
      makeReq('SV-004', 'regressed'),
    ];

    const summary = computeSummary(reqs);

    expect(summary.regressed).toBe(4);
    expect(summary.fixed).toBe(0);
    expect(summary.new).toBe(0);
    expect(summary.absent).toBe(0);
    expect(summary.unchanged).toBe(0);
    expect(summary.updated).toBe(0);
    expect(summary.total).toBe(4);
    expect(summary.matchedCount).toBe(4);
    expect(summary.unmatchedOldCount).toBe(0);
    expect(summary.unmatchedNewCount).toBe(0);
  });

  // ── 4. Mixed states ────────────────────────────────────────────
  it('should correctly count a mix of all state types', () => {
    const reqs: RequirementDiff[] = [
      makeReq('SV-001', 'fixed'),
      makeReq('SV-002', 'fixed'),
      makeReq('SV-003', 'regressed'),
      makeReq('SV-004', 'unchanged'),
      makeReq('SV-005', 'unchanged'),
      makeReq('SV-006', 'unchanged'),
      makeReq('SV-007', 'new'),
      makeReq('SV-008', 'absent'),
      makeReq('SV-009', 'updated'),
    ];

    const summary = computeSummary(reqs);

    expect(summary.fixed).toBe(2);
    expect(summary.regressed).toBe(1);
    expect(summary.unchanged).toBe(3);
    expect(summary.new).toBe(1);
    expect(summary.absent).toBe(1);
    expect(summary.updated).toBe(1);
    expect(summary.total).toBe(9);
    // matched = fixed(2) + regressed(1) + unchanged(3) + updated(1) = 7
    expect(summary.matchedCount).toBe(7);
    // unmatchedOld = absent(1)
    expect(summary.unmatchedOldCount).toBe(1);
    // unmatchedNew = new(1)
    expect(summary.unmatchedNewCount).toBe(1);
  });

  // ── 5. Single unchanged ──────────────────────────────────────────
  it('should handle a single unchanged requirement', () => {
    const reqs: RequirementDiff[] = [makeReq('SV-001', 'unchanged')];

    const summary = computeSummary(reqs);

    expect(summary.unchanged).toBe(1);
    expect(summary.total).toBe(1);
    expect(summary.fixed).toBe(0);
    expect(summary.regressed).toBe(0);
    expect(summary.new).toBe(0);
    expect(summary.absent).toBe(0);
    expect(summary.updated).toBe(0);
    expect(summary.matchedCount).toBe(1);
    expect(summary.unmatchedOldCount).toBe(0);
    expect(summary.unmatchedNewCount).toBe(0);
  });

  // ── 6. All new ─────────────────────────────────────────────────
  it('should count all requirements as new when all have new state', () => {
    const reqs: RequirementDiff[] = [
      makeReq('SV-001', 'new'),
      makeReq('SV-002', 'new'),
      makeReq('SV-003', 'new'),
      makeReq('SV-004', 'new'),
      makeReq('SV-005', 'new'),
    ];

    const summary = computeSummary(reqs);

    expect(summary.new).toBe(5);
    expect(summary.fixed).toBe(0);
    expect(summary.regressed).toBe(0);
    expect(summary.absent).toBe(0);
    expect(summary.unchanged).toBe(0);
    expect(summary.updated).toBe(0);
    expect(summary.total).toBe(5);
    expect(summary.matchedCount).toBe(0);
    expect(summary.unmatchedOldCount).toBe(0);
    expect(summary.unmatchedNewCount).toBe(5);
  });
});
