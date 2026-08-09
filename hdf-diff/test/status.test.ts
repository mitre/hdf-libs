import { describe, it, expect } from 'vitest';
import {
  computeEffectiveStatus,
  classifyChangeReasons,
  classifyDiffStatus,
} from '../src/status.js';

// ---------------------------------------------------------------------------
// Helpers to build minimal HDF requirement structures
// ---------------------------------------------------------------------------

function makeResult(status: string, codeDesc = 'test', startTime = '2025-01-01T00:00:00Z') {
  return { status, codeDesc, startTime };
}

function makeOverride(opts: {
  type?: string;
  status?: string;
  reason?: string;
  appliedAt?: string;
  expiresAt?: string;
}) {
  return {
    type: opts.type ?? 'waiver',
    status: opts.status ?? 'passed',
    reason: opts.reason ?? 'approved by team lead',
    appliedBy: { name: 'admin', email: 'admin@example.com' },
    appliedAt: opts.appliedAt ?? '2025-01-01T00:00:00Z',
    expiresAt: opts.expiresAt ?? '2099-12-31T23:59:59Z',
  };
}

function makeRequirement(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'SV-100001',
    impact: 0.7,
    results: [],
    tags: {},
    descriptions: [],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// computeEffectiveStatus
// ---------------------------------------------------------------------------

describe('computeEffectiveStatus', () => {
  it('returns "passed" for a single passing result with no overrides', () => {
    const req = makeRequirement({
      results: [makeResult('passed')],
    });
    expect(computeEffectiveStatus(req)).toBe('passed');
  });

  it('returns "failed" for a single failing result with no overrides', () => {
    const req = makeRequirement({
      results: [makeResult('failed')],
    });
    expect(computeEffectiveStatus(req)).toBe('failed');
  });

  it('returns "error" for a single error result with no overrides', () => {
    const req = makeRequirement({
      results: [makeResult('error')],
    });
    expect(computeEffectiveStatus(req)).toBe('error');
  });

  it('returns "failed" when results contain one passed and one failed (worst wins)', () => {
    const req = makeRequirement({
      results: [makeResult('passed'), makeResult('failed')],
    });
    expect(computeEffectiveStatus(req)).toBe('failed');
  });

  it('returns "error" when results contain one error and one failed (worst wins)', () => {
    const req = makeRequirement({
      results: [makeResult('error'), makeResult('failed')],
    });
    expect(computeEffectiveStatus(req)).toBe('error');
  });

  it('returns "notReviewed" for an empty results array', () => {
    const req = makeRequirement({
      results: [],
    });
    expect(computeEffectiveStatus(req)).toBe('notReviewed');
  });

  it('returns "notApplicable" when impact is 0 and there are no results', () => {
    const req = makeRequirement({
      impact: 0,
      results: [],
    });
    expect(computeEffectiveStatus(req)).toBe('notApplicable');
  });

  it('uses non-expired waiver override status instead of result status', () => {
    const req = makeRequirement({
      results: [makeResult('failed')],
      statusOverrides: [
        makeOverride({
          status: 'passed',
          expiresAt: '2099-12-31T23:59:59Z',
        }),
      ],
    });
    expect(computeEffectiveStatus(req, '2025-06-01T00:00:00Z')).toBe('passed');
  });

  it('falls back to results when waiver override is expired', () => {
    const req = makeRequirement({
      results: [makeResult('failed')],
      statusOverrides: [
        makeOverride({
          status: 'passed',
          expiresAt: '2025-01-15T00:00:00Z',
        }),
      ],
    });
    // Reference timestamp is after expiration
    expect(computeEffectiveStatus(req, '2025-06-01T00:00:00Z')).toBe('failed');
  });

  it('uses the governing (most recently applied) override regardless of array order', () => {
    const req = makeRequirement({
      results: [makeResult('failed')],
      statusOverrides: [
        // Listed first but applied later: governs per the schema's
        // "most recent non-expired override" definition of disposition.
        makeOverride({
          status: 'passed',
          appliedAt: '2025-06-01T00:00:00Z',
          expiresAt: '2099-12-31T00:00:00Z',
        }),
        makeOverride({
          status: 'notApplicable',
          appliedAt: '2025-01-01T00:00:00Z',
          expiresAt: '2099-12-31T00:00:00Z',
        }),
      ],
    });
    expect(computeEffectiveStatus(req, '2026-01-01T00:00:00Z')).toBe('passed');
  });

  it('uses the governing non-expired override when multiple overrides exist', () => {
    const req = makeRequirement({
      results: [makeResult('failed')],
      statusOverrides: [
        // First override: expired
        makeOverride({
          status: 'passed',
          appliedAt: '2025-01-01T00:00:00Z',
          expiresAt: '2025-03-01T00:00:00Z',
        }),
        // Second override: still valid
        makeOverride({
          type: 'attestation',
          status: 'notReviewed',
          appliedAt: '2025-04-01T00:00:00Z',
          expiresAt: '2099-12-31T23:59:59Z',
        }),
      ],
    });
    expect(computeEffectiveStatus(req, '2025-06-01T00:00:00Z')).toBe('notReviewed');
  });

  it('uses effectiveStatus field directly when present and no overrides exist', () => {
    const req = makeRequirement({
      results: [makeResult('failed')],
      effectiveStatus: 'passed',
    });
    expect(computeEffectiveStatus(req)).toBe('passed');
  });

  it('returns "notApplicable" when impact is 0 regardless of results', () => {
    const req = makeRequirement({
      impact: 0,
      results: [makeResult('passed'), makeResult('failed')],
    });
    expect(computeEffectiveStatus(req)).toBe('notApplicable');
  });

  it('uses Date.now() when overrides exist but no referenceTimestamp provided', () => {
    const req = makeRequirement({
      results: [makeResult('failed')],
      statusOverrides: [
        makeOverride({
          status: 'passed',
          expiresAt: '2099-12-31T23:59:59Z',
        }),
      ],
    });
    // No referenceTimestamp — should use Date.now() and the override is far in the future
    expect(computeEffectiveStatus(req)).toBe('passed');
  });

  it('skips impact-only override (no status) and falls through to results', () => {
    const req = makeRequirement({
      results: [makeResult('failed')],
      statusOverrides: [
        {
          type: 'riskAdjustment',
          impact: { value: 0.3 },
          reason: 'Dead code path',
          appliedBy: { name: 'admin', email: 'admin@example.com' },
          appliedAt: '2025-01-01T00:00:00Z',
          expiresAt: '2099-12-31T23:59:59Z',
        },
      ],
    });
    expect(computeEffectiveStatus(req, '2025-06-01T00:00:00Z')).toBe('failed');
  });

  it('uses status override after skipping impact-only override', () => {
    const req = makeRequirement({
      results: [makeResult('failed')],
      statusOverrides: [
        {
          type: 'riskAdjustment',
          impact: { value: 0.3 },
          reason: 'Dead code path',
          appliedBy: { name: 'admin', email: 'admin@example.com' },
          appliedAt: '2025-01-01T00:00:00Z',
          expiresAt: '2099-12-31T23:59:59Z',
        },
        makeOverride({
          type: 'waiver',
          status: 'passed',
          expiresAt: '2099-12-31T23:59:59Z',
        }),
      ],
    });
    expect(computeEffectiveStatus(req, '2025-06-01T00:00:00Z')).toBe('passed');
  });

  it('uses effectiveStatus when overrides array is empty', () => {
    const req = makeRequirement({
      results: [makeResult('failed')],
      effectiveStatus: 'passed',
      statusOverrides: [],
    });
    expect(computeEffectiveStatus(req)).toBe('passed');
  });

  it('returns "notReviewed" when results field is undefined', () => {
    const req = makeRequirement();
    delete (req as Record<string, unknown>)['results'];
    expect(computeEffectiveStatus(req)).toBe('notReviewed');
  });
});

// ---------------------------------------------------------------------------
// classifyChangeReasons
// ---------------------------------------------------------------------------

describe('classifyChangeReasons', () => {
  it('returns empty array when old and new requirements are identical', () => {
    const req = makeRequirement({
      results: [makeResult('passed')],
    });
    // Deep copy to ensure we have distinct objects
    const oldReq = JSON.parse(JSON.stringify(req)) as Record<string, unknown>;
    const newReq = JSON.parse(JSON.stringify(req)) as Record<string, unknown>;
    expect(classifyChangeReasons(oldReq, newReq)).toEqual([]);
  });

  it('returns ["resultChanged"] when result statuses differ', () => {
    const oldReq = makeRequirement({
      results: [makeResult('passed')],
    });
    const newReq = makeRequirement({
      results: [makeResult('failed')],
    });
    expect(classifyChangeReasons(oldReq, newReq)).toEqual(['resultChanged']);
  });

  it('returns ["overrideAdded"] when an override is added in the new requirement', () => {
    const oldReq = makeRequirement({
      results: [makeResult('failed')],
    });
    const newReq = makeRequirement({
      results: [makeResult('failed')],
      statusOverrides: [
        makeOverride({ status: 'passed' }),
      ],
    });
    expect(classifyChangeReasons(oldReq, newReq)).toContain('overrideAdded');
  });

  it('returns ["overrideExpired"] when an override expires between scans', () => {
    const override = makeOverride({
      status: 'passed',
      expiresAt: '2025-06-01T00:00:00Z',
    });
    const oldReq = makeRequirement({
      results: [makeResult('failed')],
      statusOverrides: [override],
    });
    const newReq = makeRequirement({
      results: [makeResult('failed')],
      statusOverrides: [override],
    });
    // Old scan: before expiry; New scan: after expiry
    const reasons = classifyChangeReasons(
      oldReq,
      newReq,
      '2025-05-01T00:00:00Z',
      '2025-07-01T00:00:00Z',
    );
    expect(reasons).toContain('overrideExpired');
  });

  it('skips the overrideExpired check when a scan timestamp is unparseable', () => {
    const override = makeOverride({ status: 'passed', expiresAt: '2025-06-01T00:00:00Z' });
    const oldReq = makeRequirement({ results: [makeResult('failed')], statusOverrides: [override] });
    const newReq = makeRequirement({ results: [makeResult('failed')], statusOverrides: [override] });
    // Garbage old timestamp → parseTimestamp returns null → the window check is
    // skipped rather than misfiring, so overrideExpired is not reported.
    const reasons = classifyChangeReasons(oldReq, newReq, 'not-a-date', '2025-07-01T00:00:00Z');
    expect(reasons).not.toContain('overrideExpired');
  });

  it('detects overrideExpired with zone-less scan timestamps (read as UTC, host-independent)', () => {
    const override = makeOverride({
      status: 'passed',
      // Expires three hours after the old scan's UTC midnight: a host-local
      // reading of the zone-less old timestamp on any western-hemisphere
      // host would push the scan past the expiry and lose the reason.
      expiresAt: '2025-06-01T03:00:00Z',
    });
    const oldReq = makeRequirement({
      results: [makeResult('failed')],
      statusOverrides: [override],
    });
    const newReq = makeRequirement({
      results: [makeResult('failed')],
      statusOverrides: [override],
    });
    const reasons = classifyChangeReasons(
      oldReq,
      newReq,
      '2025-06-01T00:00:00',
      '2025-07-01T00:00:00',
    );
    expect(reasons).toContain('overrideExpired');
  });

  it('returns ["overrideRemoved"] when an override is removed in the new requirement', () => {
    const oldReq = makeRequirement({
      results: [makeResult('failed')],
      statusOverrides: [
        makeOverride({ status: 'passed' }),
      ],
    });
    const newReq = makeRequirement({
      results: [makeResult('failed')],
    });
    expect(classifyChangeReasons(oldReq, newReq)).toContain('overrideRemoved');
  });

  it('returns ["impactChanged"] when impact differs', () => {
    const oldReq = makeRequirement({
      impact: 0.7,
      results: [makeResult('passed')],
    });
    const newReq = makeRequirement({
      impact: 0.0,
      results: [makeResult('passed')],
    });
    expect(classifyChangeReasons(oldReq, newReq)).toContain('impactChanged');
  });

  it('returns ["metadataChanged"] when tags differ', () => {
    const oldReq = makeRequirement({
      results: [makeResult('passed')],
      tags: { cci: ['CCI-000001'] },
    });
    const newReq = makeRequirement({
      results: [makeResult('passed')],
      tags: { cci: ['CCI-000002'] },
    });
    expect(classifyChangeReasons(oldReq, newReq)).toContain('metadataChanged');
  });

  it('returns multiple reasons when result changed AND impact changed', () => {
    const oldReq = makeRequirement({
      impact: 0.7,
      results: [makeResult('passed')],
    });
    const newReq = makeRequirement({
      impact: 0.3,
      results: [makeResult('failed')],
    });
    const reasons = classifyChangeReasons(oldReq, newReq);
    expect(reasons).toContain('resultChanged');
    expect(reasons).toContain('impactChanged');
    expect(reasons.length).toBeGreaterThanOrEqual(2);
  });

  it('returns multiple reasons when override added AND result changed', () => {
    const oldReq = makeRequirement({
      results: [makeResult('passed')],
    });
    const newReq = makeRequirement({
      results: [makeResult('failed')],
      statusOverrides: [
        makeOverride({ status: 'passed' }),
      ],
    });
    const reasons = classifyChangeReasons(oldReq, newReq);
    expect(reasons).toContain('overrideAdded');
    expect(reasons).toContain('resultChanged');
    expect(reasons.length).toBeGreaterThanOrEqual(2);
  });

  it('handles undefined results gracefully (uses empty fallback)', () => {
    const oldReq = makeRequirement();
    delete (oldReq as Record<string, unknown>)['results'];
    const newReq = makeRequirement({
      results: [makeResult('failed')],
    });
    const reasons = classifyChangeReasons(oldReq, newReq);
    expect(reasons).toContain('resultChanged');
  });

  it('handles undefined results on new requirement (newResults ?? [] fallback)', () => {
    const oldReq = makeRequirement({ results: [makeResult('passed')] });
    const newReq = makeRequirement();
    delete (newReq as Record<string, unknown>)['results'];
    const reasons = classifyChangeReasons(oldReq, newReq);
    expect(reasons).toContain('resultChanged');
  });

  it('handles undefined tags and descriptions gracefully', () => {
    const oldReq = makeRequirement({
      results: [makeResult('passed')],
    });
    delete (oldReq as Record<string, unknown>)['tags'];
    delete (oldReq as Record<string, unknown>)['descriptions'];
    const newReq = makeRequirement({
      results: [makeResult('passed')],
    });
    delete (newReq as Record<string, unknown>)['tags'];
    delete (newReq as Record<string, unknown>)['descriptions'];
    // Both missing — should return empty array (no change)
    expect(classifyChangeReasons(oldReq, newReq)).toEqual([]);
  });

  it('detects metadataChanged when descriptions differ', () => {
    const oldReq = makeRequirement({
      results: [makeResult('passed')],
      descriptions: [{ label: 'default', data: 'old description' }],
    });
    const newReq = makeRequirement({
      results: [makeResult('passed')],
      descriptions: [{ label: 'default', data: 'new description' }],
    });
    expect(classifyChangeReasons(oldReq, newReq)).toContain('metadataChanged');
  });

  it('detects metadataChanged when title differs', () => {
    const oldReq = makeRequirement({
      results: [makeResult('passed')],
      title: 'Old Title',
    });
    const newReq = makeRequirement({
      results: [makeResult('passed')],
      title: 'New Title',
    });
    expect(classifyChangeReasons(oldReq, newReq)).toContain('metadataChanged');
  });

  it('returns ["dispositionChanged"] when disposition differs', () => {
    const oldReq = makeRequirement({
      results: [makeResult('failed')],
      disposition: 'waiver',
    });
    const newReq = makeRequirement({
      results: [makeResult('failed')],
      disposition: 'riskAdjustment',
    });
    expect(classifyChangeReasons(oldReq, newReq)).toContain('dispositionChanged');
  });

  it('returns ["dispositionChanged"] when disposition added', () => {
    const oldReq = makeRequirement({
      results: [makeResult('failed')],
    });
    const newReq = makeRequirement({
      results: [makeResult('failed')],
      disposition: 'falsePositive',
    });
    expect(classifyChangeReasons(oldReq, newReq)).toContain('dispositionChanged');
  });

  it('returns ["dispositionChanged"] when disposition removed', () => {
    const oldReq = makeRequirement({
      results: [makeResult('failed')],
      disposition: 'waiver',
    });
    const newReq = makeRequirement({
      results: [makeResult('failed')],
    });
    expect(classifyChangeReasons(oldReq, newReq)).toContain('dispositionChanged');
  });

  it('does not return "dispositionChanged" when disposition is the same', () => {
    const oldReq = makeRequirement({
      results: [makeResult('failed')],
      disposition: 'waiver',
    });
    const newReq = makeRequirement({
      results: [makeResult('failed')],
      disposition: 'waiver',
    });
    expect(classifyChangeReasons(oldReq, newReq)).not.toContain('dispositionChanged');
  });

  it('returns ["effectiveImpactChanged"] when effectiveImpact differs', () => {
    const oldReq = makeRequirement({
      results: [makeResult('failed')],
      effectiveImpact: 0.7,
    });
    const newReq = makeRequirement({
      results: [makeResult('failed')],
      effectiveImpact: 0.3,
    });
    expect(classifyChangeReasons(oldReq, newReq)).toContain('effectiveImpactChanged');
  });

  it('returns ["effectiveImpactChanged"] when effectiveImpact added', () => {
    const oldReq = makeRequirement({
      results: [makeResult('failed')],
    });
    const newReq = makeRequirement({
      results: [makeResult('failed')],
      effectiveImpact: 0.3,
    });
    expect(classifyChangeReasons(oldReq, newReq)).toContain('effectiveImpactChanged');
  });

  it('does not return "effectiveImpactChanged" when effectiveImpact is the same', () => {
    const oldReq = makeRequirement({
      results: [makeResult('failed')],
      effectiveImpact: 0.3,
    });
    const newReq = makeRequirement({
      results: [makeResult('failed')],
      effectiveImpact: 0.3,
    });
    expect(classifyChangeReasons(oldReq, newReq)).not.toContain('effectiveImpactChanged');
  });
});

// ---------------------------------------------------------------------------
// classifyDiffStatus
// ---------------------------------------------------------------------------

describe('classifyDiffStatus', () => {
  it('returns "fixed" when failed -> passed', () => {
    expect(classifyDiffStatus('failed', 'passed')).toBe('fixed');
  });

  it('returns "fixed" when error -> passed', () => {
    expect(classifyDiffStatus('error', 'passed')).toBe('fixed');
  });

  it('returns "regressed" when passed -> failed', () => {
    expect(classifyDiffStatus('passed', 'failed')).toBe('regressed');
  });

  it('returns "regressed" when passed -> error', () => {
    expect(classifyDiffStatus('passed', 'error')).toBe('regressed');
  });

  it('returns "unchanged" when passed -> passed', () => {
    expect(classifyDiffStatus('passed', 'passed')).toBe('unchanged');
  });

  it('returns "unchanged" when failed -> failed', () => {
    expect(classifyDiffStatus('failed', 'failed')).toBe('unchanged');
  });

  it('returns "updated" when notReviewed -> notApplicable', () => {
    expect(classifyDiffStatus('notReviewed', 'notApplicable')).toBe('updated');
  });

  it('returns "updated" when failed -> notApplicable', () => {
    expect(classifyDiffStatus('failed', 'notApplicable')).toBe('updated');
  });

  it('returns "fixed" when notReviewed -> passed (notReviewed is non-passing)', () => {
    expect(classifyDiffStatus('notReviewed', 'passed')).toBe('fixed');
  });

  it('returns "regressed" when passed -> notReviewed', () => {
    expect(classifyDiffStatus('passed', 'notReviewed')).toBe('regressed');
  });
});
