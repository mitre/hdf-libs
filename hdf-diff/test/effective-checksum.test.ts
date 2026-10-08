import { describe, it, expect } from 'vitest';
import {
  computeEffectiveChecksum,
  computeEffectiveImpact,
  computeDisposition,
} from '../src/effective-checksum.js';

const REF_TIME = '2026-07-01T00:00:00Z';

// Pinned cross-language vectors: sha256 of the canonical JSON
// {"status":<resolved>,"impact":<resolved>,"disposition":<type|null>}.
// The Go suite (effective_checksum_test.go) pins the same hex values.
const VECTOR_FAILED_HALF = '704f62b2d0803438ad6b7b9bab45e2c4f350b7344135a2a7f8ef986d98669021';
const VECTOR_WAIVED_NA = '40f165574efcca5a6bf5ff2c113e6d1bc2aea56e4251b70b68bdb2e05d1fef3b';
const VECTOR_ZERO_IMPACT = 'de78ada7d86293d722efc2c30b0bac553303183ec9e784839c3c9a7745472ffc';
const VECTOR_PASSED_HALF = '73908440a3b44d76de559753babfea36987a618b80ee9d26adcf29cb5c7a5217';

function makeResult(status: string, codeDesc = 'test', startTime = '2025-01-01T00:00:00Z') {
  return { status, codeDesc, startTime };
}

function makeOverride(opts: {
  type?: string;
  status?: string;
  impact?: number;
  appliedAt?: string;
  expiresAt?: string;
}) {
  return {
    type: opts.type ?? 'waiver',
    ...(opts.status !== undefined ? { status: opts.status } : {}),
    ...(opts.impact !== undefined ? { impact: { value: opts.impact } } : {}),
    reason: 'approved by team lead',
    appliedBy: { identifier: 'admin' },
    appliedAt: opts.appliedAt ?? '2025-01-01T00:00:00Z',
    expiresAt: opts.expiresAt ?? '2099-12-31T23:59:59Z',
  };
}

function failingReq(): Record<string, unknown> {
  return {
    id: 'SV-100001',
    impact: 0.5,
    tags: {},
    descriptions: [],
    results: [makeResult('failed')],
  };
}

describe('computeEffectiveChecksum', () => {
  it('matches the pinned vector for a failing requirement with no overrides', async () => {
    const cs = await computeEffectiveChecksum(failingReq(), REF_TIME);
    expect(cs.algorithm).toBe('sha256');
    expect(cs.value).toBe(VECTOR_FAILED_HALF);
  });

  it('matches the pinned vector for a waived requirement (disposition present)', async () => {
    const req = {
      ...failingReq(),
      impact: 0.7,
      statusOverrides: [makeOverride({ type: 'waiver', status: 'notApplicable' })],
    };
    const cs = await computeEffectiveChecksum(req, REF_TIME);
    expect(cs.value).toBe(VECTOR_WAIVED_NA);
  });

  it('matches the pinned vector when impact zero forces notApplicable', async () => {
    const req = { ...failingReq(), impact: 0, results: [makeResult('passed')] };
    const cs = await computeEffectiveChecksum(req, REF_TIME);
    expect(cs.value).toBe(VECTOR_ZERO_IMPACT);
  });

  it('is deterministic', async () => {
    const a = await computeEffectiveChecksum(failingReq(), REF_TIME);
    const b = await computeEffectiveChecksum(failingReq(), REF_TIME);
    expect(a.value).toBe(b.value);
  });

  it('flips on status change', async () => {
    const req = { ...failingReq(), results: [makeResult('passed')] };
    const cs = await computeEffectiveChecksum(req, REF_TIME);
    expect(cs.value).toBe(VECTOR_PASSED_HALF);
    expect(cs.value).not.toBe(VECTOR_FAILED_HALF);
  });

  it('flips on impact override', async () => {
    const req = {
      ...failingReq(),
      statusOverrides: [makeOverride({ type: 'riskAdjustment', impact: 0.2 })],
    };
    const cs = await computeEffectiveChecksum(req, REF_TIME);
    expect(cs.value).not.toBe(VECTOR_FAILED_HALF);
  });

  it('flips on disposition even when status is unchanged', async () => {
    const req = {
      ...failingReq(),
      statusOverrides: [makeOverride({ type: 'waiver', status: 'failed' })],
    };
    const cs = await computeEffectiveChecksum(req, REF_TIME);
    expect(cs.value).not.toBe(VECTOR_FAILED_HALF);
  });

  it('is stable under volatile non-effective fields', async () => {
    const req = failingReq();
    req['results'] = [
      makeResult('failed', 'entirely different check description', '2026-06-30T12:00:00Z'),
    ];
    req['tags'] = { severity: 'high', nist: ['AC-6'] };
    req['title'] = 'Some new title';
    const cs = await computeEffectiveChecksum(req, REF_TIME);
    expect(cs.value).toBe(VECTOR_FAILED_HALF);
  });

  it('falls back past expired overrides (status from results, disposition null)', async () => {
    const req = {
      ...failingReq(),
      statusOverrides: [
        makeOverride({ type: 'waiver', status: 'notApplicable', expiresAt: '2020-01-01T00:00:00Z' }),
      ],
    };
    const cs = await computeEffectiveChecksum(req, REF_TIME);
    expect(cs.value).toBe(VECTOR_FAILED_HALF);
  });
});

describe('computeEffectiveImpact', () => {
  it('returns base impact when no overrides', () => {
    expect(computeEffectiveImpact(failingReq(), REF_TIME)).toBe(0.5);
  });

  it('honors a non-expired impact override', () => {
    const req = {
      ...failingReq(),
      statusOverrides: [makeOverride({ type: 'riskAdjustment', impact: 0.2 })],
    };
    expect(computeEffectiveImpact(req, REF_TIME)).toBe(0.2);
  });

  it('ignores an expired impact override', () => {
    const req = {
      ...failingReq(),
      statusOverrides: [
        makeOverride({ type: 'riskAdjustment', impact: 0.2, expiresAt: '2020-01-01T00:00:00Z' }),
      ],
    };
    expect(computeEffectiveImpact(req, REF_TIME)).toBe(0.5);
  });

  it('honors a stored effectiveImpact when no overrides', () => {
    const req = { ...failingReq(), effectiveImpact: 0.3 };
    expect(computeEffectiveImpact(req, REF_TIME)).toBe(0.3);
  });

  it('lets the most recently applied impact override win regardless of array order', () => {
    const req = {
      ...failingReq(),
      statusOverrides: [
        makeOverride({ type: 'riskAdjustment', impact: 0.4, appliedAt: '2025-01-01T00:00:00Z' }),
        makeOverride({ type: 'riskAdjustment', impact: 0.1, appliedAt: '2025-06-01T00:00:00Z' }),
      ],
    };
    expect(computeEffectiveImpact(req, REF_TIME)).toBe(0.1);
  });

  it('does not let an impact-less newer override mask an older impact-bearing one', () => {
    const req = {
      ...failingReq(),
      statusOverrides: [
        makeOverride({ type: 'riskAdjustment', impact: 0.2, appliedAt: '2025-01-01T00:00:00Z' }),
        makeOverride({ type: 'waiver', status: 'notApplicable', appliedAt: '2025-06-01T00:00:00Z' }),
      ],
    };
    expect(computeEffectiveImpact(req, REF_TIME)).toBe(0.2);
  });
});

describe('computeDisposition', () => {
  it('returns null when no overrides', () => {
    expect(computeDisposition(failingReq(), REF_TIME)).toBeNull();
  });

  it('returns the governing non-expired override type', () => {
    const req = {
      ...failingReq(),
      statusOverrides: [makeOverride({ type: 'waiver', status: 'notApplicable' })],
    };
    expect(computeDisposition(req, REF_TIME)).toBe('waiver');
  });

  // A POA&M governs disposition too — the schema has always defined the field as
  // 'the most recent non-expired override or POAM', and only the override half
  // was implemented. Parity: TestComputeDisposition in go/effective_checksum_test.go.
  const plan = (appliedAt: string, expiresAt: string) => [
    { type: 'remediation', explanation: 'scheduled', appliedAt, expiresAt },
  ];
  const waiver = (appliedAt: string, expiresAt: string) => [
    { type: 'waiver', status: 'notApplicable', reason: 'r', appliedAt, expiresAt },
  ];
  const LIVE = '2099-12-31T00:00:00Z';
  const LAPSED = '2020-01-01T00:00:00Z';
  const OLDER = '2024-06-01T00:00:00Z';
  const NEWER = '2025-01-01T00:00:00Z';

  it('a live POA&M governs when no override does', () => {
    const req = { ...failingReq(), poams: plan(OLDER, LIVE) };
    expect(computeDisposition(req, REF_TIME)).toBe('poam');
  });

  it('a lapsed POA&M governs nothing, as a lapsed override does', () => {
    const req = { ...failingReq(), poams: plan(OLDER, LAPSED) };
    expect(computeDisposition(req, REF_TIME)).toBeNull();
  });

  it('the more recent live entry governs, whichever kind it is', () => {
    const byPoam = { ...failingReq(), statusOverrides: waiver(OLDER, LIVE), poams: plan(NEWER, LIVE) };
    expect(computeDisposition(byPoam, REF_TIME), 'the newer plan governs the older waiver').toBe('poam');

    const byWaiver = { ...failingReq(), statusOverrides: waiver(NEWER, LIVE), poams: plan(OLDER, LIVE) };
    expect(computeDisposition(byWaiver, REF_TIME), 'the newer waiver governs the older plan').toBe('waiver');

    // Expiry outranks recency: the waiver is newer by appliedAt but lapsed.
    const byLive = { ...failingReq(), statusOverrides: waiver(NEWER, LAPSED), poams: plan(OLDER, LIVE) };
    expect(computeDisposition(byLive, REF_TIME), 'a lapsed newer waiver cannot displace a live older plan').toBe('poam');
  });

  // The stored-field fallback is now reached in fewer cases: a requirement with
  // no overrides but a LAPSED plan used to fall through to the cached
  // disposition and now resolves to none. Correct — a lapsed entry governs
  // nothing, and a stored effective* field is an output cache, not an input —
  // but it moves the checksum, so it is pinned rather than left silent.
  // Parity: the same subtest in go/effective_checksum_test.go.
  it('a lapsed plan suppresses the stored-disposition fallback', () => {
    const withLapsedPlan = { ...failingReq(), disposition: 'falsePositive', poams: plan(OLDER, LAPSED) };
    expect(
      computeDisposition(withLapsedPlan, REF_TIME),
      'a lapsed plan governs nothing, and the cached value is not an input',
    ).toBeNull();

    // With no plan at all the cache is still honoured, so the narrowing is
    // specific rather than a removal of the fallback.
    const bare = { ...failingReq(), disposition: 'falsePositive' };
    expect(computeDisposition(bare, REF_TIME)).toBe('falsePositive');
  });

  it('honors a stored disposition when no overrides', () => {
    const req = { ...failingReq(), disposition: 'falsePositive' };
    expect(computeDisposition(req, REF_TIME)).toBe('falsePositive');
  });

  it('defaults to wall clock when no reference timestamp is given', () => {
    // far-future (2099) override is non-expired against any real wall clock
    const req = {
      ...failingReq(),
      statusOverrides: [makeOverride({ type: 'waiver', status: 'notApplicable' })],
    };
    expect(computeDisposition(req)).toBe('waiver');
  });

  it('returns null when all overrides are expired', () => {
    const req = {
      ...failingReq(),
      statusOverrides: [
        makeOverride({ type: 'waiver', status: 'notApplicable', expiresAt: '2020-01-01T00:00:00Z' }),
      ],
    };
    expect(computeDisposition(req, REF_TIME)).toBeNull();
  });

  it('lets the most recently applied override type win regardless of array order', () => {
    const req = {
      ...failingReq(),
      statusOverrides: [
        makeOverride({ type: 'waiver', status: 'notApplicable', appliedAt: '2025-01-01T00:00:00Z' }),
        makeOverride({ type: 'riskAdjustment', impact: 0.2, appliedAt: '2025-06-01T00:00:00Z' }),
      ],
    };
    expect(computeDisposition(req, REF_TIME)).toBe('riskAdjustment');
  });
});

// Parity: TestComputeEffectiveImpact_StoredFallbackOnlyWithoutOverrides in go.
// The stored effectiveImpact is a fallback for the no-overrides case only; the
// moment any override exists it is unread, matching the shared ladder.
describe('computeEffectiveImpact: the stored fallback', () => {
  const base = { id: 'V-1', impact: 0.9, effectiveImpact: 0.2 };

  it('is honoured only when the requirement carries no overrides', () => {
    expect(computeEffectiveImpact(base, REF_TIME)).toBeCloseTo(0.2, 9);
  });

  it('is unread the moment any override exists, even one carrying no impact', () => {
    const withWaiver = {
      ...base,
      statusOverrides: [{ type: 'waiver', status: 'passed', appliedAt: '2020-01-01T00:00:00Z', expiresAt: '2099-12-31T00:00:00Z' }],
    };
    expect(computeEffectiveImpact(withWaiver, REF_TIME)).toBeCloseTo(0.9, 9);
  });
});
