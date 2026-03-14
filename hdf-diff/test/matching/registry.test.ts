import { describe, it, expect } from 'vitest';
import { matchRequirements } from '../../src/matching/index.js';

describe('matchRequirements (registry + fallback chain)', () => {
  it('should default to exactId strategy', () => {
    const oldReqs = [{ id: 'SV-001', impact: 0.7 }];
    const newReqs = [{ id: 'SV-001', impact: 0.7 }];

    const result = matchRequirements(oldReqs, newReqs);

    expect(result.matched).toHaveLength(1);
    expect(result.matched[0]!.strategy).toBe('exactId');
    expect(result.matched[0]!.confidence).toBe(1.0);
  });

  it('should use specified strategy', () => {
    const mapping = { 'V-001-old': 'V-001-new' };
    const oldReqs = [{ id: 'V-001-old', impact: 0.7 }];
    const newReqs = [{ id: 'V-001-new', impact: 0.7 }];

    const result = matchRequirements(oldReqs, newReqs, {
      strategy: 'mappedId',
      mappingTable: mapping,
    });

    expect(result.matched).toHaveLength(1);
    expect(result.matched[0]!.strategy).toBe('mappedId');
    expect(result.matched[0]!.confidence).toBe(0.95);
  });

  it('should handle mappedId strategy with no mapping table (triggers ?? {} fallback)', () => {
    const oldReqs = [{ id: 'V-001', impact: 0.7, tags: {} }];
    const newReqs = [{ id: 'V-002', impact: 0.7, tags: {} }];
    const result = matchRequirements(
      oldReqs as unknown as Record<string, unknown>[],
      newReqs as unknown as Record<string, unknown>[],
      { strategy: 'mappedId' },
    );
    // Empty mapping = nothing maps, so nothing matches
    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(1);
  });

  it('should apply fallback strategies to unmatched requirements', () => {
    const oldReqs = [
      { id: 'SV-001', title: 'Ensure SSH root login is disabled', impact: 0.7 },
      { id: 'V-002-old', title: 'Configure NTP time synchronization', impact: 0.5 },
    ];
    const newReqs = [
      { id: 'SV-001', title: 'Ensure SSH root login is disabled', impact: 0.7 },
      { id: 'RHEL-002', title: 'Configure NTP time synchronization', impact: 0.5 },
    ];

    const result = matchRequirements(oldReqs, newReqs, {
      strategy: 'exactId',
      fallbackStrategies: ['fuzzyTitle'],
    });

    // SV-001 matched by exactId
    // V-002-old -> RHEL-002 matched by fuzzyTitle (identical titles)
    expect(result.matched).toHaveLength(2);

    const exactMatch = result.matched.find((m) => m.strategy === 'exactId');
    expect(exactMatch).toBeDefined();
    expect(exactMatch!.oldReq['id']).toBe('SV-001');

    const fuzzyMatch = result.matched.find((m) => m.strategy === 'fuzzyTitle');
    expect(fuzzyMatch).toBeDefined();
    expect(fuzzyMatch!.oldReq['id']).toBe('V-002-old');
    expect(fuzzyMatch!.newReq['id']).toBe('RHEL-002');
  });

  it('should chain multiple fallback strategies', () => {
    const mapping = { 'V-002-old': 'V-002-new' };
    const oldReqs = [
      { id: 'SV-001', title: 'SSH check', impact: 0.7 },
      { id: 'V-002-old', title: 'NTP check', impact: 0.5 },
      { id: 'V-003', title: 'Ensure audit logging is enabled', tags: { cci: ['CCI-000366'] }, impact: 0.3 },
    ];
    const newReqs = [
      { id: 'SV-001', title: 'SSH check', impact: 0.7 },
      { id: 'V-002-new', title: 'NTP check', impact: 0.5 },
      { id: 'RHEL-003', title: 'Audit logging configuration', tags: { cci: ['CCI-000366'] }, impact: 0.3 },
    ];

    const result = matchRequirements(oldReqs, newReqs, {
      strategy: 'exactId',
      fallbackStrategies: ['mappedId', 'cciMatch'],
      mappingTable: mapping,
    });

    expect(result.matched).toHaveLength(3);
    expect(result.unmatchedOld).toHaveLength(0);
    expect(result.unmatchedNew).toHaveLength(0);

    const strategies = result.matched.map((m) => m.strategy).sort();
    expect(strategies).toContain('exactId');
    expect(strategies).toContain('mappedId');
    expect(strategies).toContain('cciMatch');
  });

  it('should respect minConfidence for fuzzy matching', () => {
    const oldReqs = [
      { id: 'V-001', title: 'Ensure SSH root login is disabled', impact: 0.7 },
    ];
    const newReqs = [
      { id: 'RHEL-001', title: 'SSH root login must be disabled', impact: 0.7 },
    ];

    const result = matchRequirements(oldReqs, newReqs, {
      strategy: 'fuzzyTitle',
      minConfidence: 0.95,
    });

    // Similarity is around 0.7-0.8, below 0.95
    expect(result.matched).toHaveLength(0);
  });

  it('should handle unknown strategy name gracefully', () => {
    expect(() =>
      matchRequirements([], [], { strategy: 'nonexistent' })
    ).toThrow();
  });

  it('should handle unknown fallback strategy name gracefully', () => {
    expect(() =>
      matchRequirements([], [], {
        strategy: 'exactId',
        fallbackStrategies: ['nonexistent'],
      })
    ).toThrow();
  });

  it('should pass through unmatched after all strategies are exhausted', () => {
    const oldReqs = [
      { id: 'V-001', title: 'Totally unique old requirement', impact: 0.7 },
    ];
    const newReqs = [
      { id: 'RHEL-001', title: 'Completely different new check', impact: 0.5 },
    ];

    const result = matchRequirements(oldReqs, newReqs, {
      strategy: 'exactId',
      fallbackStrategies: ['fuzzyTitle'],
    });

    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(1);
  });

  it('should work with empty inputs', () => {
    const result = matchRequirements([], []);

    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(0);
    expect(result.unmatchedNew).toHaveLength(0);
  });

  it('should accumulate matched from all strategy layers', () => {
    const oldReqs = [
      { id: 'SV-001', impact: 0.7 },
      { id: 'SV-002', tags: { cci: ['CCI-000366'] }, impact: 0.5 },
    ];
    const newReqs = [
      { id: 'SV-001', impact: 0.7 },
      { id: 'RHEL-002', tags: { cci: ['CCI-000366'] }, impact: 0.5 },
    ];

    const result = matchRequirements(oldReqs, newReqs, {
      strategy: 'exactId',
      fallbackStrategies: ['cciMatch'],
    });

    expect(result.matched).toHaveLength(2);
    // All matched, nothing unmatched
    expect(result.unmatchedOld).toHaveLength(0);
    expect(result.unmatchedNew).toHaveLength(0);
  });
});
