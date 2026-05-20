import { describe, it, expect } from 'vitest';
import { createSrgDeterministicStrategy } from '../../src/matching/srg-deterministic.js';

/** Helper to create a requirement with gtitle tag. */
function reqWithGtitle(id: string, gtitle: string, title?: string) {
  return {
    id,
    impact: 0.7,
    title: title ?? `Control ${id}`,
    tags: { gtitle },
  };
}

describe('SrgDeterministicStrategy', () => {
  const strategy = createSrgDeterministicStrategy();

  it('should have name "srgDeterministic"', () => {
    expect(strategy.name).toBe('srgDeterministic');
  });

  it('should match 1:1 by gtitle with confidence 1.0 and relationship "primary"', () => {
    const oldReqs = [reqWithGtitle('V-001', 'SRG-OS-000185-GPOS-00079')];
    const newReqs = [reqWithGtitle('RHEL-001', 'SRG-OS-000185-GPOS-00079')];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(1);
    expect(result.matched[0]!.oldReq['id']).toBe('V-001');
    expect(result.matched[0]!.newReq['id']).toBe('RHEL-001');
    expect(result.matched[0]!.strategy).toBe('srgDeterministic');
    expect(result.matched[0]!.confidence).toBe(1.0);
    expect(result.matched[0]!.relationship).toBe('primary');
    expect(result.unmatchedOld).toHaveLength(0);
    expect(result.unmatchedNew).toHaveLength(0);
  });

  it('should handle N new + 1 old (1:N split) — first primary, rest related', () => {
    const oldReqs = [reqWithGtitle('V-001', 'SRG-OS-000185-GPOS-00079')];
    const newReqs = [
      reqWithGtitle('RHEL-001', 'SRG-OS-000185-GPOS-00079'),
      reqWithGtitle('RHEL-002', 'SRG-OS-000185-GPOS-00079'),
      reqWithGtitle('RHEL-003', 'SRG-OS-000185-GPOS-00079'),
    ];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(3);
    expect(result.unmatchedOld).toHaveLength(0);
    expect(result.unmatchedNew).toHaveLength(0);

    // First new gets primary
    expect(result.matched[0]!.newReq['id']).toBe('RHEL-001');
    expect(result.matched[0]!.relationship).toBe('primary');

    // Rest get related
    expect(result.matched[1]!.newReq['id']).toBe('RHEL-002');
    expect(result.matched[1]!.relationship).toBe('related');
    expect(result.matched[2]!.newReq['id']).toBe('RHEL-003');
    expect(result.matched[2]!.relationship).toBe('related');

    // All reference the same old req
    for (const m of result.matched) {
      expect(m.oldReq['id']).toBe('V-001');
      expect(m.confidence).toBe(1.0);
    }
  });

  it('should handle 1 new + N old — first old primary, rest related', () => {
    const oldReqs = [
      reqWithGtitle('V-001', 'SRG-OS-000185-GPOS-00079'),
      reqWithGtitle('V-002', 'SRG-OS-000185-GPOS-00079'),
    ];
    const newReqs = [reqWithGtitle('RHEL-001', 'SRG-OS-000185-GPOS-00079')];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(2);
    expect(result.unmatchedOld).toHaveLength(0);
    expect(result.unmatchedNew).toHaveLength(0);

    // First old gets primary
    expect(result.matched[0]!.oldReq['id']).toBe('V-001');
    expect(result.matched[0]!.relationship).toBe('primary');

    // Second old gets related
    expect(result.matched[1]!.oldReq['id']).toBe('V-002');
    expect(result.matched[1]!.relationship).toBe('related');

    // Both reference the same new req
    for (const m of result.matched) {
      expect(m.newReq['id']).toBe('RHEL-001');
    }
  });

  it('should skip N:M ambiguous (multiple old and multiple new)', () => {
    const oldReqs = [
      reqWithGtitle('V-001', 'SRG-OS-000185-GPOS-00079'),
      reqWithGtitle('V-002', 'SRG-OS-000185-GPOS-00079'),
    ];
    const newReqs = [
      reqWithGtitle('RHEL-001', 'SRG-OS-000185-GPOS-00079'),
      reqWithGtitle('RHEL-002', 'SRG-OS-000185-GPOS-00079'),
    ];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(2);
    expect(result.unmatchedNew).toHaveLength(2);
  });

  it('should pass through requirements with no gtitle', () => {
    const oldReqs = [{ id: 'V-001', impact: 0.7, tags: { nist: ['AC-1'] } }];
    const newReqs = [{ id: 'RHEL-001', impact: 0.7, tags: { nist: ['AC-1'] } }];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(1);
  });

  it('should pass through requirements with no tags', () => {
    const oldReqs = [{ id: 'V-001', impact: 0.7 }];
    const newReqs = [{ id: 'RHEL-001', impact: 0.7 }];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(1);
  });

  it('should handle mixed: some gtitles match, some do not', () => {
    const oldReqs = [
      reqWithGtitle('V-001', 'SRG-OS-000001'),
      reqWithGtitle('V-002', 'SRG-OS-000002'),
      { id: 'V-003', impact: 0.3 }, // no gtitle
    ];
    const newReqs = [
      reqWithGtitle('RHEL-001', 'SRG-OS-000001'),
      reqWithGtitle('RHEL-002', 'SRG-OS-000999'), // no match
      { id: 'RHEL-003', impact: 0.3 }, // no gtitle
    ];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(1);
    expect(result.matched[0]!.oldReq['id']).toBe('V-001');
    expect(result.matched[0]!.newReq['id']).toBe('RHEL-001');
    expect(result.matched[0]!.relationship).toBe('primary');

    // V-002 unmatched (no new has SRG-OS-000002), V-003 unmatched (no gtitle)
    expect(result.unmatchedOld).toHaveLength(2);
    // RHEL-002 unmatched (no old has SRG-OS-000999), RHEL-003 unmatched (no gtitle)
    expect(result.unmatchedNew).toHaveLength(2);
  });

  it('should handle multiple distinct gtitles independently', () => {
    const oldReqs = [
      reqWithGtitle('V-001', 'SRG-OS-000001'),
      reqWithGtitle('V-002', 'SRG-OS-000002'),
    ];
    const newReqs = [
      reqWithGtitle('RHEL-001', 'SRG-OS-000001'),
      reqWithGtitle('RHEL-002', 'SRG-OS-000002'),
    ];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(2);
    expect(result.matched[0]!.oldReq['id']).toBe('V-001');
    expect(result.matched[0]!.newReq['id']).toBe('RHEL-001');
    expect(result.matched[1]!.oldReq['id']).toBe('V-002');
    expect(result.matched[1]!.newReq['id']).toBe('RHEL-002');
    expect(result.unmatchedOld).toHaveLength(0);
    expect(result.unmatchedNew).toHaveLength(0);
  });

  it('should handle empty inputs', () => {
    expect(strategy.match([], []).matched).toHaveLength(0);
    expect(strategy.match([], []).unmatchedOld).toHaveLength(0);
    expect(strategy.match([], []).unmatchedNew).toHaveLength(0);
  });

  it('should handle gtitle present only in old (no new match)', () => {
    const oldReqs = [reqWithGtitle('V-001', 'SRG-OS-000001')];
    const newReqs = [reqWithGtitle('RHEL-001', 'SRG-OS-000999')];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(1);
  });

  it('should handle empty string gtitle as missing', () => {
    const oldReqs = [{ id: 'V-001', impact: 0.7, tags: { gtitle: '' } }];
    const newReqs = [{ id: 'RHEL-001', impact: 0.7, tags: { gtitle: '' } }];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(1);
  });
});
