import { describe, it, expect } from 'vitest';
import {
  STATUS_SEVERITY_ORDER,
  statusRank,
  worstStatus,
  governingStatusOverride,
  governingOverrideIndex,
  computeEffectiveStatus,
} from '../src/status/index.js';

const REF = '2026-01-01T00:00:00Z';
const FAR_FUTURE = '2099-12-31T00:00:00Z';
const LONG_AGO = '2020-01-01T00:00:00Z';
const APPLIED_OLD = '2025-01-01T00:00:00Z';
const APPLIED_NEW = '2025-06-01T00:00:00Z';

describe('statusRank / STATUS_SEVERITY_ORDER', () => {
  it('ranks the canonical ordering, higher = worse', () => {
    expect(STATUS_SEVERITY_ORDER).toEqual([
      'error',
      'failed',
      'passed',
      'notApplicable',
      'notReviewed',
    ]);
    expect(statusRank('error')).toBe(4);
    expect(statusRank('failed')).toBe(3);
    expect(statusRank('passed')).toBe(2);
    expect(statusRank('notApplicable')).toBe(1);
    expect(statusRank('notReviewed')).toBe(0);
    expect(statusRank('bogus')).toBe(-1);
  });
});

describe('worstStatus', () => {
  it('rolls up worst-wins per the canonical ordering', () => {
    expect(worstStatus([])).toBe('notReviewed');
    expect(worstStatus(['passed'])).toBe('passed');
    expect(worstStatus(['passed', 'failed'])).toBe('failed');
    expect(worstStatus(['failed', 'error', 'passed'])).toBe('error');
    expect(worstStatus(['notReviewed', 'passed'])).toBe('passed');
    expect(worstStatus(['notReviewed', 'notApplicable'])).toBe('notApplicable');
    expect(worstStatus(['bogus', 'passed'])).toBe('passed');
    expect(worstStatus(['bogus'])).toBe('notReviewed');
  });
});

describe('governingOverrideIndex', () => {
  const all = () => true;

  it('selects the most recently applied eligible non-expired override', () => {
    const overrides = [
      { appliedAt: APPLIED_OLD, expiresAt: FAR_FUTURE },
      { appliedAt: APPLIED_NEW, expiresAt: FAR_FUTURE },
    ];
    expect(governingOverrideIndex(overrides, all, REF)).toBe(1);
  });

  it('skips ineligible overrides', () => {
    const overrides = [
      { appliedAt: APPLIED_OLD, expiresAt: FAR_FUTURE },
      { appliedAt: APPLIED_NEW, expiresAt: FAR_FUTURE },
    ];
    expect(governingOverrideIndex(overrides, (i) => i === 0, REF)).toBe(0);
  });

  it('skips expired overrides', () => {
    const overrides = [
      { appliedAt: APPLIED_NEW, expiresAt: LONG_AGO },
      { appliedAt: APPLIED_OLD, expiresAt: FAR_FUTURE },
    ];
    expect(governingOverrideIndex(overrides, all, REF)).toBe(1);
  });

  it('treats a missing expiresAt as never expiring', () => {
    expect(governingOverrideIndex([{ appliedAt: APPLIED_OLD }], all, REF)).toBe(0);
  });

  it('returns -1 when none are eligible', () => {
    const overrides = [{ appliedAt: APPLIED_OLD, expiresAt: FAR_FUTURE }];
    expect(governingOverrideIndex(overrides, () => false, REF)).toBe(-1);
  });
});

describe('governingStatusOverride', () => {
  it('selects the most recently applied non-expired override', () => {
    const governing = governingStatusOverride(
      [
        { status: 'notApplicable', appliedAt: APPLIED_OLD, expiresAt: FAR_FUTURE },
        { status: 'failed', appliedAt: APPLIED_NEW, expiresAt: FAR_FUTURE },
      ],
      REF
    );
    expect(governing?.status).toBe('failed');
  });

  it('skips expired overrides', () => {
    const governing = governingStatusOverride(
      [
        { status: 'failed', appliedAt: APPLIED_NEW, expiresAt: LONG_AGO },
        { status: 'notApplicable', appliedAt: APPLIED_OLD, expiresAt: FAR_FUTURE },
      ],
      REF
    );
    expect(governing?.status).toBe('notApplicable');
  });

  it('treats a missing expiresAt as never expiring', () => {
    const governing = governingStatusOverride([{ status: 'passed', appliedAt: APPLIED_OLD }], REF);
    expect(governing?.status).toBe('passed');
  });

  it('returns undefined when all overrides are expired or statusless', () => {
    expect(
      governingStatusOverride([{ status: 'passed', appliedAt: APPLIED_OLD, expiresAt: LONG_AGO }], REF)
    ).toBeUndefined();
    expect(
      governingStatusOverride([{ appliedAt: APPLIED_NEW, expiresAt: FAR_FUTURE }], REF)
    ).toBeUndefined();
  });
});

describe('computeEffectiveStatus', () => {
  it('forces notApplicable at impact zero regardless of results', () => {
    expect(computeEffectiveStatus({ impact: 0, resultStatuses: ['failed'] }, REF)).toBe(
      'notApplicable'
    );
  });

  it('lets the governing override win over results and effectiveStatus', () => {
    expect(
      computeEffectiveStatus(
        {
          impact: 0.7,
          effectiveStatus: 'failed',
          resultStatuses: ['failed'],
          overrides: [{ status: 'notApplicable', appliedAt: APPLIED_OLD, expiresAt: FAR_FUTURE }],
        },
        REF
      )
    ).toBe('notApplicable');
  });

  it('honors effectiveStatus only when no overrides are present', () => {
    expect(
      computeEffectiveStatus(
        { impact: 0.7, effectiveStatus: 'passed', resultStatuses: ['failed'] },
        REF
      )
    ).toBe('passed');
  });

  it('recomputes from results when every override has expired', () => {
    expect(
      computeEffectiveStatus(
        {
          impact: 0.7,
          effectiveStatus: 'passed',
          resultStatuses: ['failed'],
          overrides: [{ status: 'notApplicable', appliedAt: APPLIED_OLD, expiresAt: LONG_AGO }],
        },
        REF
      )
    ).toBe('failed');
  });

  it('rolls results up worst-wins and defaults empty results to notReviewed', () => {
    expect(
      computeEffectiveStatus({ impact: 0.5, resultStatuses: ['passed', 'error', 'failed'] }, REF)
    ).toBe('error');
    expect(computeEffectiveStatus({ impact: 0.5 }, REF)).toBe('notReviewed');
  });

  it('falls back to the wall clock when no reference timestamp is given', () => {
    expect(
      computeEffectiveStatus({
        impact: 0.7,
        resultStatuses: ['failed'],
        overrides: [{ status: 'notApplicable', appliedAt: APPLIED_OLD, expiresAt: FAR_FUTURE }],
      })
    ).toBe('notApplicable');
  });
});
