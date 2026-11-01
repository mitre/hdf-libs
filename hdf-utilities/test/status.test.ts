import { describe, it, expect } from 'vitest';
import {
  STATUS_SEVERITY_ORDER,
  statusRank,
  worstStatus,
  governingStatusOverride,
  governingOverrideIndex,
  computeEffectiveStatus,
  computeEffectiveImpact,
  type EffectiveStatusInput,
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
  it('never lets impact reach the status', () => {
    // Not-applicable is a claim about scope, which belongs in results[] or in
    // an override. Impact is a severity band. The same results therefore roll
    // up to the same status at every impact, including 0 — a source whose
    // convention conflates the two translates it at import.
    const cases: Array<[string[] | undefined, string]> = [
      [['notReviewed'], 'notReviewed'],
      [undefined, 'notReviewed'],
      [['failed'], 'failed'],
      [['passed'], 'passed'],
      [['notApplicable'], 'notApplicable'],
    ];
    for (const [resultStatuses, want] of cases) {
      for (const impact of [0, 0.3, 0.5, 1]) {
        expect(computeEffectiveStatus({ impact, resultStatuses }, REF)).toBe(want);
      }
    }
  });

  it('reports error at impact 0 when a result errored', () => {
    // error outranks every other status in the worst-wins order, so this holds
    // without a dedicated rung. Kept because it is the case a reader expects to
    // find: an execution error means the check never ran, which matches InSpec
    // EnhancedOutcomes and Heimdall inspecjs.
    expect(computeEffectiveStatus({ impact: 0, resultStatuses: ['error'] }, REF)).toBe('error');
    expect(computeEffectiveStatus({ impact: 0, resultStatuses: ['passed', 'error'] }, REF)).toBe(
      'error'
    );
  });

  it('still lets a governing override adjudicate an errored impact-0 requirement', () => {
    // Overrides rank above the raw roll-up everywhere else; an explicit
    // non-expired override on a crashed impact-0 check governs the same way.
    // 'passed' (a falsePositive adjudication) distinguishes the override
    // branch from the error roll-up.
    expect(
      computeEffectiveStatus(
        {
          impact: 0,
          resultStatuses: ['error'],
          overrides: [{ status: 'passed', appliedAt: APPLIED_OLD, expiresAt: FAR_FUTURE }],
        },
        REF
      )
    ).toBe('passed');
  });

  it('lets the governing override win over results', () => {
    expect(
      computeEffectiveStatus(
        {
          impact: 0.7,
          resultStatuses: ['failed'],
          overrides: [{ status: 'notApplicable', appliedAt: APPLIED_OLD, expiresAt: FAR_FUTURE }],
        },
        REF
      )
    ).toBe('notApplicable');
  });

  it('lets a governing override adjudicate an impact-0 requirement regardless of termination', () => {
    // The override sits at the top of the ladder: whether the check failed,
    // passed, or errored, a signed non-expired override governs uniformly —
    // impact 0 does not silence it.
    for (const resultStatuses of [['failed'], ['passed'], ['error']]) {
      expect(
        computeEffectiveStatus(
          {
            impact: 0,
            resultStatuses,
            overrides: [{ status: 'passed', appliedAt: APPLIED_OLD, expiresAt: FAR_FUTURE }],
          },
          REF
        )
      ).toBe('passed');
    }
  });

  it('lets an error roll-up win when no overrides govern', () => {
    // An execution error means the check never ran; absent a governing
    // override the ladder reports it at any impact.
    expect(computeEffectiveStatus({ impact: 0, resultStatuses: ['error'] }, REF)).toBe('error');
    expect(computeEffectiveStatus({ impact: 0.7, resultStatuses: ['error'] }, REF)).toBe('error');
  });

  it('recomputes from results when every override has expired', () => {
    expect(
      computeEffectiveStatus(
        {
          impact: 0.7,
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

// The impact twin of the status ladder. The schema has always defined
// effectiveImpact as "the most recent non-expired override with an impact
// field", and governingOverrideIndex was generalized for exactly that, but
// nothing computed it — so a riskAdjustment was invisible to every consumer
// asking about impact. Parity: TestComputeEffectiveImpact in go/status_test.go.
describe('computeEffectiveImpact', () => {
  const adjustment = (impact: number, appliedAt: string, expiresAt?: string) => ({
    impact,
    appliedAt,
    ...(expiresAt ? { expiresAt } : {}),
  });

  const cases: { name: string; input: EffectiveStatusInput; want: number }[] = [
    { name: 'no overrides falls back to the raw impact', input: { impact: 0.9 }, want: 0.9 },
    {
      name: 'a governing adjustment wins',
      input: { impact: 0.9, overrides: [adjustment(0.3, APPLIED_OLD, FAR_FUTURE)] },
      want: 0.3,
    },
    {
      name: 'an expired adjustment does not',
      input: { impact: 0.9, overrides: [adjustment(0.3, APPLIED_OLD, LONG_AGO)] },
      want: 0.9,
    },
    {
      name: 'the most recently applied of several wins',
      input: { impact: 0.9, overrides: [adjustment(0.3, APPLIED_OLD), adjustment(0.5, APPLIED_NEW)] },
      want: 0.5,
    },
    {
      name: 'an override carrying no impact is not eligible',
      input: { impact: 0.9, overrides: [{ status: 'passed', appliedAt: APPLIED_NEW }] },
      want: 0.9,
    },
    {
      // Eligibility is per-field: a waiver adjudicates status and says nothing
      // about impact, so the older adjustment still governs impact.
      name: 'a status override newer than the impact one does not displace it',
      input: {
        impact: 0.9,
        overrides: [adjustment(0.3, APPLIED_OLD), { status: 'passed', appliedAt: APPLIED_NEW }],
      },
      want: 0.3,
    },
    {
      // Why impact is optional rather than defaulted: 0 is a legitimate re-score
      // meaning "no longer applicable", and a default could not tell it from
      // "this override carries no impact".
      name: 'an adjustment to zero is honoured, not treated as absent',
      input: { impact: 0.9, overrides: [adjustment(0, APPLIED_OLD)] },
      want: 0,
    },
  ];

  for (const c of cases) {
    it(c.name, () => {
      expect(computeEffectiveImpact(c.input, REF)).toBeCloseTo(c.want, 5);
    });
  }
});

// Parity: TestComputeEffectiveStatus_ImpactNeverReachesStatus in go/.
// Status answers "what did the assessment establish" and impact answers "how
// much risk if it is realized". Neither an authored impact nor an impact
// override reaches the status, so the two can never disagree: a riskAdjustment
// re-scoring a finding to 0.0 leaves it failed, and an adjustment away from 0
// cannot bring a control into scope. Only an override carrying a status makes a
// scope claim, and it governs through the ladder's first rung. See
// status-determination.md, "Settled — impact never reaches the status".
describe('computeEffectiveStatus — impact never reaches the status', () => {
  const adjust = (impact: number) => ({
    impact,
    appliedAt: APPLIED_OLD,
    expiresAt: FAR_FUTURE,
  });
  const waived = { status: 'notApplicable', appliedAt: APPLIED_OLD, expiresAt: FAR_FUTURE };

  const cases: { name: string; input: EffectiveStatusInput; want: string }[] = [
    {
      // An impact of 0 is a severity band, not a scope claim. A source whose
      // convention says otherwise — InSpec supplies no pass/fail for an
      // impact-0 control — states the claim in results[] at import instead,
      // where every consumer can see it.
      name: 'an authored impact of 0 with no results is notReviewed, not notApplicable',
      input: { impact: 0 },
      want: 'notReviewed',
    },
    {
      name: 'an adjustment to 0 leaves a real finding failing — it is re-scored, not closed',
      input: { impact: 0.7, resultStatuses: ['failed'], overrides: [adjust(0)] },
      want: 'failed',
    },
    {
      name: 'an adjustment away from 0 does not change the status either',
      input: { impact: 0, overrides: [adjust(0.9)] },
      want: 'notReviewed',
    },
    {
      // An override that DOES carry a status is making a scope claim, and rung 1
      // lets it win — that is the sanctioned way to say this.
      name: 'a status-carrying override outranks the roll-up',
      input: { impact: 0.7, resultStatuses: ['failed'], overrides: [waived] },
      want: 'notApplicable',
    },
    {
      // The translated shape the InSpec importer now emits: the scope claim is a
      // result, so it survives without help from the ladder.
      name: 'an explicit notApplicable result reports notApplicable at impact 0',
      input: { impact: 0, resultStatuses: ['notReviewed', 'notApplicable'] },
      want: 'notApplicable',
    },
  ];

  for (const c of cases) {
    it(c.name, () => {
      expect(computeEffectiveStatus(c.input, REF)).toBe(c.want);
    });
  }
});
