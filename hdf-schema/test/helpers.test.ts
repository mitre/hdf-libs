import { describe, it, expect } from 'vitest';
import { computeEffectiveStatus, severityToImpact, impactToSeverity } from '../src/helpers.js';

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

describe('severityToImpact', () => {
  // CVSS bands normalized to 0-1:
  // critical=0.9, high=0.7, medium=0.5, low=0.3, informational=0.0

  it('should map critical to 0.9 (floor of critical band 0.9-1.0)', () => {
    expect(severityToImpact('critical')).toBe(0.9);
  });

  it('should map high to 0.7 (floor of high band 0.7-0.8)', () => {
    expect(severityToImpact('high')).toBe(0.7);
  });

  it('should map medium to 0.5 (floor of medium band 0.4-0.6)', () => {
    expect(severityToImpact('medium')).toBe(0.5);
  });

  it('should map low to 0.3 (floor of low band 0.1-0.3)', () => {
    expect(severityToImpact('low')).toBe(0.3);
  });

  it('should map informational to 0.0 (not applicable)', () => {
    expect(severityToImpact('informational')).toBe(0.0);
  });

  it('should map info shorthand to 0.0', () => {
    expect(severityToImpact('info')).toBe(0.0);
  });

  it('should be case-insensitive', () => {
    expect(severityToImpact('CRITICAL')).toBe(0.9);
    expect(severityToImpact('High')).toBe(0.7);
    expect(severityToImpact('MEDIUM')).toBe(0.5);
    expect(severityToImpact('LOW')).toBe(0.3);
  });

  it('should default to 0.5 (medium) for unknown severity', () => {
    expect(severityToImpact('unknown')).toBe(0.5);
    expect(severityToImpact('')).toBe(0.5);
  });
});

describe('impactToSeverity', () => {
  // Band boundaries: 0.0=informational, 0.1-0.3=low, 0.4-0.6=medium, 0.7-0.8=high, 0.9-1.0=critical

  it('should map 1.0 to critical', () => {
    expect(impactToSeverity(1.0)).toBe('critical');
  });

  it('should map 0.9 to critical (lower bound)', () => {
    expect(impactToSeverity(0.9)).toBe('critical');
  });

  it('should map 0.8 to high (upper bound)', () => {
    expect(impactToSeverity(0.8)).toBe('high');
  });

  it('should map 0.7 to high (lower bound)', () => {
    expect(impactToSeverity(0.7)).toBe('high');
  });

  it('should map 0.6 to medium (upper bound)', () => {
    expect(impactToSeverity(0.6)).toBe('medium');
  });

  it('should map 0.5 to medium (midpoint)', () => {
    expect(impactToSeverity(0.5)).toBe('medium');
  });

  it('should map 0.4 to medium (lower bound)', () => {
    expect(impactToSeverity(0.4)).toBe('medium');
  });

  it('should map 0.3 to low (upper bound)', () => {
    expect(impactToSeverity(0.3)).toBe('low');
  });

  it('should map 0.1 to low (lower bound)', () => {
    expect(impactToSeverity(0.1)).toBe('low');
  });

  it('should map 0.0 to informational', () => {
    expect(impactToSeverity(0.0)).toBe('informational');
  });

  // Sub-band precision: values within a band should all map to the same severity
  it('should map all values in critical band (0.9-1.0) to critical', () => {
    expect(impactToSeverity(0.91)).toBe('critical');
    expect(impactToSeverity(0.95)).toBe('critical');
    expect(impactToSeverity(0.99)).toBe('critical');
  });

  it('should map all values in high band (0.7-0.89) to high', () => {
    expect(impactToSeverity(0.71)).toBe('high');
    expect(impactToSeverity(0.75)).toBe('high');
    expect(impactToSeverity(0.89)).toBe('high');
  });

  // Round-trip: severity → impact → severity should be stable
  it('should round-trip through severityToImpact', () => {
    expect(impactToSeverity(severityToImpact('critical'))).toBe('critical');
    expect(impactToSeverity(severityToImpact('high'))).toBe('high');
    expect(impactToSeverity(severityToImpact('medium'))).toBe('medium');
    expect(impactToSeverity(severityToImpact('low'))).toBe('low');
    expect(impactToSeverity(severityToImpact('informational'))).toBe('informational');
  });
});

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
