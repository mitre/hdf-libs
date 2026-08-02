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
