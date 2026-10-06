import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import type { EvaluatedRequirement } from '@mitre/hdf-schema';
import {
  requirementEffectiveStatus,
  requirementEffectiveImpact,
  governingOverride,
  requirementDisposition,
  requirementStatusInput,
} from './status.js';

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

// Parity: TestRequirementDisposition in shared/go/status_test.go.
describe('requirementDisposition', () => {
  const waiver = {
    type: 'waiver', status: 'passed',
    appliedAt: '2024-06-01T00:00:00Z', expiresAt: '2099-12-31T00:00:00Z',
  };
  const adjustment = {
    type: 'riskAdjustment',
    appliedAt: '2025-01-01T00:00:00Z', expiresAt: '2099-12-31T00:00:00Z',
    impact: { value: 0.3 },
  };
  const expiredWaiver = {
    type: 'waiver', status: 'passed',
    appliedAt: '2024-06-01T00:00:00Z', expiresAt: '2020-01-01T00:00:00Z',
  };
  const NOW = '2026-06-01T00:00:00Z';

  it('is the governing override type, whatever the array order', () => {
    expect(requirementDisposition(req({ statusOverrides: [waiver, adjustment] }), NOW)).toBe('riskAdjustment');
    expect(requirementDisposition(req({ statusOverrides: [adjustment, waiver] }), NOW)).toBe('riskAdjustment');
  });

  it('is empty when nothing governs', () => {
    expect(requirementDisposition(req({}), NOW)).toBe('');
    expect(requirementDisposition(req({ statusOverrides: [expiredWaiver] }), NOW)).toBe('');
  });

  it('never reads the stored cache when overrides are present', () => {
    expect(requirementDisposition(req({ disposition: 'waiver', statusOverrides: [adjustment] }), NOW)).toBe('riskAdjustment');
    // An EXPIRED override still counts as the document carrying overrides, so
    // the fallback stays suppressed.
    expect(requirementDisposition(req({ disposition: 'waiver', statusOverrides: [expiredWaiver] }), NOW)).toBe('');
  });

  it('falls back to the stored field only when there are no overrides at all', () => {
    expect(requirementDisposition(req({ disposition: 'waiver' }), NOW)).toBe('waiver');
  });

  // Schema-invalid, but the converters structurally check their input rather
  // than schema-validate it, so this shape reaches the exporters. It must yield
  // the empty string in both languages, never the literal "undefined".
  it('yields empty, not "undefined", for an override carrying no type', () => {
    const typeless = { reason: 'r', appliedAt: '2025-01-01T00:00:00Z', expiresAt: '2099-12-31T00:00:00Z' };
    expect(requirementDisposition(req({ statusOverrides: [typeless] }), NOW)).toBe('');
  });
});

const __dirname = dirname(fileURLToPath(import.meta.url));

interface StatusExpiryCase {
  name: string;
  note: string;
  want: string;
  requirement: EvaluatedRequirement;
}

const expiryCases = (
  JSON.parse(readFileSync(join(__dirname, '..', 'status-expiry-cases.json'), 'utf-8')) as {
    cases: StatusExpiryCase[];
  }
).cases;

describe('requirementEffectiveStatus: shared Go/TypeScript expiry case table', () => {
  it.each(expiryCases.map((c) => [c.name, c] as const))('%s', (_name, c) => {
    expect(requirementEffectiveStatus(c.requirement), c.note).toBe(c.want);
  });
});

// quicktype types expiresAt as Date, so a consumer that hands the bridge a
// decoded document gives it a Date instance rather than the raw string.
describe('requirementStatusInput: Go zero time as a Date instance', () => {
  const zeroTimeOverride = (expiresAt: Date): EvaluatedRequirement =>
    ({
      id: 'SV-230221',
      impact: 0.7,
      results: [{ status: 'failed', startTime: '2025-03-14T09:12:44Z' }],
      statusOverrides: [
        {
          type: 'waiver',
          status: 'passed',
          reason: 'Vendor support contract renewed; waiver recorded in the SSP.',
          appliedBy: { type: 'simple', identifier: 'isso@example.test' },
          appliedAt: new Date('2025-03-20T00:00:00Z'),
          expiresAt,
        },
      ],
    }) as unknown as EvaluatedRequirement;

  it('drops expiresAt when the Date carries the Go zero instant', () => {
    const req = zeroTimeOverride(new Date('0001-01-01T00:00:00Z'));
    expect(requirementStatusInput(req).overrides).toEqual([
      { status: 'passed', appliedAt: '2025-03-20T00:00:00.000Z', expiresAt: undefined },
    ]);
    expect(requirementEffectiveStatus(req)).toBe('passed');
  });

  it('keeps expiresAt when the Date carries a real far-future instant', () => {
    const req = zeroTimeOverride(new Date('2099-12-31T00:00:00Z'));
    expect(requirementStatusInput(req).overrides).toEqual([
      {
        status: 'passed',
        appliedAt: '2025-03-20T00:00:00.000Z',
        expiresAt: '2099-12-31T00:00:00.000Z',
      },
    ]);
    expect(requirementEffectiveStatus(req)).toBe('passed');
  });
});

// Parity: TestRequirementDisposition_DoesNotReadPoams in shared/go. A plan
// governs status in hdf-engine and hdf-diff, but an export carries the plan
// separately, so a POA&M alone yields no disposition here and the stored
// fallback still applies.
describe('requirementDisposition: does not read poams', () => {
  const plan = { appliedAt: '2020-01-01T00:00:00Z', expiresAt: '2099-12-31T00:00:00Z', status: 'passed' };

  it('a plan alone governs no export disposition', () => {
    expect(requirementDisposition(req({ id: 'V-1', impact: 0.5, poams: [plan] }), '2026-06-01T00:00:00Z')).toBe('');
  });

  it('with no overrides the stored field is still the fallback, plan or not', () => {
    expect(requirementDisposition(req({ id: 'V-1', impact: 0.5, poams: [plan], disposition: 'waiver' }), '2026-06-01T00:00:00Z')).toBe('waiver');
  });
});
