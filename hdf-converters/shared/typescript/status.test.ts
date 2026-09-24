import { describe, it, expect } from 'vitest';
import type { EvaluatedRequirement } from '@mitre/hdf-schema';
import { requirementEffectiveStatus, requirementEffectiveImpact } from './status.js';

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
