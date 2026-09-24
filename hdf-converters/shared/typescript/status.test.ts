import { describe, it, expect } from 'vitest';
import type { EvaluatedRequirement } from '@mitre/hdf-schema';
import { requirementEffectiveStatus, requirementEffectiveImpact, governingOverride } from './status.js';

// These two are the schema-typed wrappers an external consumer reaches for, so
// they are tested directly rather than only through whichever converter happens
// to call them. Parity: shared/go/status_test.go.

const req = (r: Record<string, unknown>) => r as unknown as EvaluatedRequirement;

const adjustment = (value: number, appliedAt: string, expiresAt?: string) => ({
  type: 'riskAdjustment',
  reason: 'environmental context',
  appliedAt,
  ...(expiresAt ? { expiresAt } : {}),
  impact: { value },
});

describe('requirementEffectiveStatus', () => {
  it('walks the ladder: override, error roll-up, impact-0, worst-wins', () => {
    expect(requirementEffectiveStatus(req({ impact: 0.5, results: [{ status: 'passed' }, { status: 'failed' }] }))).toBe('failed');
    expect(requirementEffectiveStatus(req({ impact: 0.5 }))).toBe('notReviewed');
    expect(requirementEffectiveStatus(req({ impact: 0, results: [{ status: 'failed' }] }))).toBe('notApplicable');
    expect(requirementEffectiveStatus(req({ impact: 0, results: [{ status: 'error' }] }))).toBe('error');
    expect(
      requirementEffectiveStatus(
        req({
          impact: 0.5,
          results: [{ status: 'failed' }],
          statusOverrides: [{ type: 'waiver', status: 'passed', appliedAt: '2025-01-01T00:00:00Z', expiresAt: '2099-12-31T00:00:00Z' }],
        })
      )
    ).toBe('passed');
  });
});

describe('requirementEffectiveImpact', () => {
  const cases: { name: string; req: EvaluatedRequirement; want: number }[] = [
    { name: "no overrides falls back to the requirement's own impact", req: req({ impact: 0.9 }), want: 0.9 },
    {
      name: 'a governing adjustment wins',
      req: req({ impact: 0.9, statusOverrides: [adjustment(0.3, '2025-01-01T00:00:00Z', '2099-12-31T00:00:00Z')] }),
      want: 0.3,
    },
    {
      name: 'an expired adjustment does not',
      req: req({ impact: 0.9, statusOverrides: [adjustment(0.3, '2019-01-01T00:00:00Z', '2020-01-01T00:00:00Z')] }),
      want: 0.9,
    },
    {
      // Eligibility is per field: a waiver adjudicates status and says nothing
      // about impact, so it cannot displace an older re-score.
      name: 'a newer status-only override does not displace an older re-score',
      req: req({
        impact: 0.9,
        statusOverrides: [
          adjustment(0.3, '2025-01-01T00:00:00Z', '2099-12-31T00:00:00Z'),
          { type: 'waiver', status: 'passed', appliedAt: '2025-06-01T00:00:00Z', expiresAt: '2099-12-31T00:00:00Z' },
        ],
      }),
      want: 0.3,
    },
    {
      name: 'an adjustment to zero is honoured, not read as absent',
      req: req({ impact: 0.9, statusOverrides: [adjustment(0, '2025-01-01T00:00:00Z', '2099-12-31T00:00:00Z')] }),
      want: 0,
    },
    {
      // The stored field is an output cache; a consumer that trusted it would
      // report a number nothing in the document accounts for.
      name: 'the stored effectiveImpact cache is never read',
      req: req({ impact: 0.9, effectiveImpact: 0.99 }),
      want: 0.9,
    },
  ];

  for (const c of cases) {
    it(c.name, () => {
      expect(requirementEffectiveImpact(c.req)).toBeCloseTo(c.want, 9);
    });
  }
});

// Parity: TestGoverningOverrideIndex_IsByAppliedAtNotPosition in shared/go.
// Array position is not recency. The schema says order is not significant and
// this repo's own writers append, so on a document amended twice the newest
// override is LAST; a reader taking statusOverrides[0] gets the oldest.
describe('governingOverride', () => {
  const older = {
    type: 'waiver', status: 'passed', reason: 'older',
    appliedAt: '2024-06-01T00:00:00Z', expiresAt: '2099-12-31T00:00:00Z',
  };
  const newer = {
    type: 'riskAdjustment', reason: 'newer',
    appliedAt: '2025-01-01T00:00:00Z', expiresAt: '2099-12-31T00:00:00Z',
    impact: { value: 0.3 },
  };
  const expired = {
    type: 'riskAdjustment', reason: 'expired',
    appliedAt: '2026-01-01T00:00:00Z', expiresAt: '2020-01-01T00:00:00Z',
    impact: { value: 0.1 },
  };
  const NOW = '2026-06-01T00:00:00Z';
  const of = (overrides: unknown[]) => req({ statusOverrides: overrides });

  it('takes the newest even when append put it last', () => {
    expect(governingOverride(of([older, newer]), NOW)?.reason).toBe('newer');
  });

  it('gives the same answer in the order the schema used to ask for', () => {
    expect(governingOverride(of([newer, older]), NOW)?.reason).toBe('newer');
  });

  it('never lets an expired override govern, however recently applied', () => {
    expect(governingOverride(of([older, newer, expired]), NOW)?.reason).toBe('newer');
  });

  it('returns undefined when nothing governs', () => {
    expect(governingOverride(of([]), NOW)).toBeUndefined();
    expect(governingOverride(req({}), NOW)).toBeUndefined();
  });
});
