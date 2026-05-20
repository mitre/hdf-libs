import { describe, it, expect } from 'vitest';
import { createSrgCciTiebreakStrategy } from '../../src/matching/srg-cci-tiebreak.js';

/** Helper to build a requirement with gtitle, CCI tags, and title. */
function reqWithSRG(id: string, gtitle: string, ccis: string[] = [], title?: string) {
  return {
    id,
    impact: 0.7,
    title: title ?? `Control ${id}`,
    tags: {
      gtitle,
      ...(ccis.length > 0 ? { cci: ccis } : {}),
    },
  };
}

describe('SrgCciTiebreakStrategy', () => {
  const strategy = createSrgCciTiebreakStrategy();

  it('should have name "srgCciTiebreak"', () => {
    expect(strategy.name).toBe('srgCciTiebreak');
  });

  it('should match when multiple old reqs share a gtitle with one new req using CCI scoring', () => {
    const oldReqs = [
      reqWithSRG('V-001', 'SRG-OS-000001', ['CCI-000366', 'CCI-000777'], 'Enable audit logging'),
      reqWithSRG('V-002', 'SRG-OS-000001', ['CCI-000888'], 'Enable remote logging'),
    ];
    const newReqs = [
      reqWithSRG('RHEL-001', 'SRG-OS-000001', ['CCI-000366', 'CCI-000777'], 'Enable audit logging'),
    ];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(1);
    expect(result.matched[0]!.oldReq['id']).toBe('V-001');
    expect(result.matched[0]!.newReq['id']).toBe('RHEL-001');
    expect(result.matched[0]!.strategy).toBe('srgCciTiebreak');
    expect(result.matched[0]!.confidence).toBeGreaterThan(0);
    expect(result.matched[0]!.relationship).toBe('primary');
    // Loser goes to unmatched
    expect(result.unmatchedOld).toHaveLength(1);
    expect((result.unmatchedOld[0] as Record<string, unknown>)['id']).toBe('V-002');
    expect(result.unmatchedNew).toHaveLength(0);
  });

  it('should match when multiple new reqs share a gtitle with one old req', () => {
    const oldReqs = [
      reqWithSRG('V-001', 'SRG-OS-000001', ['CCI-000366'], 'Enable audit logging'),
    ];
    const newReqs = [
      reqWithSRG('RHEL-001', 'SRG-OS-000001', ['CCI-000366'], 'Enable audit logging'),
      reqWithSRG('RHEL-002', 'SRG-OS-000001', ['CCI-000888'], 'Enable remote logging'),
    ];

    const result = strategy.match(oldReqs, newReqs);

    // 2 new + 1 old → both get matched (greedy), best first is primary
    expect(result.matched).toHaveLength(2);
    expect(result.matched[0]!.oldReq['id']).toBe('V-001');
    expect(result.matched[0]!.newReq['id']).toBe('RHEL-001');
    expect(result.matched[0]!.relationship).toBe('primary');
    // Second match is related (same old claimed)
    expect(result.matched[1]!.relationship).toBe('related');
    expect(result.unmatchedNew).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(0);
  });

  it('should prefer unclaimed old candidates', () => {
    const oldReqs = [
      reqWithSRG('V-001', 'SRG-OS-000001', ['CCI-000366'], 'Enable audit logging'),
      reqWithSRG('V-002', 'SRG-OS-000001', ['CCI-000366'], 'Enable audit logging'),
    ];
    const newReqs = [
      reqWithSRG('RHEL-001', 'SRG-OS-000001', ['CCI-000366'], 'Enable audit logging'),
      reqWithSRG('RHEL-002', 'SRG-OS-000001', ['CCI-000366'], 'Enable audit logging'),
    ];

    const result = strategy.match(oldReqs, newReqs);

    // Both new → both old; should distribute across distinct olds
    expect(result.matched).toHaveLength(2);
    const matchedOldIds = result.matched.map((m) => m.oldReq['id']);
    expect(matchedOldIds).toContain('V-001');
    expect(matchedOldIds).toContain('V-002');
    expect(result.unmatchedOld).toHaveLength(0);
    expect(result.unmatchedNew).toHaveLength(0);
  });

  it('should handle no CCI tags (title-only fallback)', () => {
    const oldReqs = [
      reqWithSRG('V-001', 'SRG-OS-000001', [], 'Enable audit logging'),
      reqWithSRG('V-002', 'SRG-OS-000001', [], 'Enable remote logging'),
    ];
    const newReqs = [
      reqWithSRG('RHEL-001', 'SRG-OS-000001', [], 'Enable audit logging'),
    ];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(1);
    // Should match V-001 via title similarity
    expect(result.matched[0]!.oldReq['id']).toBe('V-001');
    expect(result.matched[0]!.newReq['id']).toBe('RHEL-001');
  });

  it('should skip requirements without gtitle', () => {
    const oldReqs = [{ id: 'V-001', impact: 0.7, tags: { nist: ['AC-1'] } }];
    const newReqs = [{ id: 'RHEL-001', impact: 0.7, tags: { nist: ['AC-1'] } }];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(1);
  });

  it('should skip 1:1 gtitle matches (those belong to srgDeterministic)', () => {
    const oldReqs = [
      reqWithSRG('V-001', 'SRG-OS-000001', ['CCI-000366'], 'Enable audit'),
    ];
    const newReqs = [
      reqWithSRG('RHEL-001', 'SRG-OS-000001', ['CCI-000366'], 'Enable audit'),
    ];

    const result = strategy.match(oldReqs, newReqs);

    // 1:1 is handled by srgDeterministic, so srgCciTiebreak should skip
    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(1);
  });

  it('should handle empty inputs', () => {
    const result = strategy.match([], []);
    expect(result.matched).toHaveLength(0);
  });
});
