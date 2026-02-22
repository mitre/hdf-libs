import { describe, it, expect } from 'vitest';
import { computeEffectiveStatus } from '../src/helpers.js';

/**
 * Minimal requirement stub with only the fields computeEffectiveStatus inspects.
 */
function req(
  impact: number,
  results: Array<{ status: string }>,
  effectiveStatus?: string
) {
  return { impact, results, effectiveStatus } as Parameters<
    typeof computeEffectiveStatus
  >[0];
}

describe('computeEffectiveStatus', () => {
  // --- effectiveStatus already set ---

  it('should return effectiveStatus when already set', () => {
    expect(
      computeEffectiveStatus(req(0.5, [{ status: 'failed' }], 'passed'))
    ).toBe('passed');
  });

  it('should return effectiveStatus even if impact is 0', () => {
    expect(
      computeEffectiveStatus(req(0, [{ status: 'passed' }], 'failed'))
    ).toBe('failed');
  });

  // --- impact === 0 ---

  it('should return notApplicable when impact is 0 and no effectiveStatus', () => {
    expect(computeEffectiveStatus(req(0, [{ status: 'passed' }]))).toBe(
      'notApplicable'
    );
  });

  it('should return notApplicable when impact is 0 with no results', () => {
    expect(computeEffectiveStatus(req(0, []))).toBe('notApplicable');
  });

  // --- no results ---

  it('should return notReviewed when no results and impact > 0', () => {
    expect(computeEffectiveStatus(req(0.5, []))).toBe('notReviewed');
  });

  it('should return notReviewed when results is undefined', () => {
    expect(
      computeEffectiveStatus({ impact: 0.5 } as Parameters<
        typeof computeEffectiveStatus
      >[0])
    ).toBe('notReviewed');
  });

  // --- single result statuses ---

  it('should return passed when all results passed', () => {
    expect(
      computeEffectiveStatus(
        req(0.5, [{ status: 'passed' }, { status: 'passed' }])
      )
    ).toBe('passed');
  });

  it('should return failed when any result failed', () => {
    expect(
      computeEffectiveStatus(
        req(0.5, [{ status: 'passed' }, { status: 'failed' }])
      )
    ).toBe('failed');
  });

  it('should return error when any result is error', () => {
    expect(
      computeEffectiveStatus(
        req(0.5, [{ status: 'passed' }, { status: 'error' }])
      )
    ).toBe('error');
  });

  // --- precedence ---

  it('should return error over failed', () => {
    expect(
      computeEffectiveStatus(
        req(0.5, [{ status: 'failed' }, { status: 'error' }])
      )
    ).toBe('error');
  });

  it('should return failed over passed', () => {
    expect(
      computeEffectiveStatus(
        req(0.5, [
          { status: 'passed' },
          { status: 'passed' },
          { status: 'failed' },
        ])
      )
    ).toBe('failed');
  });

  it('should return error over failed and passed', () => {
    expect(
      computeEffectiveStatus(
        req(0.5, [
          { status: 'passed' },
          { status: 'failed' },
          { status: 'error' },
        ])
      )
    ).toBe('error');
  });

  // --- notReviewed/skipped results ---

  it('should return notReviewed when all results are notReviewed', () => {
    expect(
      computeEffectiveStatus(
        req(0.5, [{ status: 'notReviewed' }, { status: 'notReviewed' }])
      )
    ).toBe('notReviewed');
  });

  it('should return passed when mixed passed and notReviewed', () => {
    expect(
      computeEffectiveStatus(
        req(0.5, [{ status: 'passed' }, { status: 'notReviewed' }])
      )
    ).toBe('passed');
  });

  // --- edge cases ---

  it('should return notReviewed for single result with unknown status', () => {
    expect(
      computeEffectiveStatus(req(0.5, [{ status: 'something_else' }]))
    ).toBe('notReviewed');
  });

  it('should handle impact exactly at boundary (0.0)', () => {
    expect(computeEffectiveStatus(req(0.0, [{ status: 'failed' }]))).toBe(
      'notApplicable'
    );
  });

  it('should handle very small positive impact', () => {
    expect(computeEffectiveStatus(req(0.1, [{ status: 'passed' }]))).toBe(
      'passed'
    );
  });
});
