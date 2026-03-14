import { describe, it, expect } from 'vitest';
import { createExactIdStrategy } from '../../src/matching/exact-id.js';

describe('ExactIdStrategy', () => {
  const strategy = createExactIdStrategy();

  it('should have name "exactId"', () => {
    expect(strategy.name).toBe('exactId');
  });

  it('should match requirements with the same id', () => {
    const oldReqs = [
      { id: 'SV-001', title: 'Test 1', impact: 0.7 },
      { id: 'SV-002', title: 'Test 2', impact: 0.5 },
    ];
    const newReqs = [
      { id: 'SV-001', title: 'Test 1 updated', impact: 0.7 },
      { id: 'SV-002', title: 'Test 2', impact: 0.5 },
    ];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(2);
    expect(result.unmatchedOld).toHaveLength(0);
    expect(result.unmatchedNew).toHaveLength(0);
  });

  it('should report confidence 1.0 for all matches', () => {
    const oldReqs = [{ id: 'SV-001', impact: 0.7 }];
    const newReqs = [{ id: 'SV-001', impact: 0.7 }];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched[0]!.confidence).toBe(1.0);
    expect(result.matched[0]!.strategy).toBe('exactId');
  });

  it('should put old-only requirements in unmatchedOld', () => {
    const oldReqs = [
      { id: 'SV-001', impact: 0.7 },
      { id: 'SV-002', impact: 0.5 },
    ];
    const newReqs = [{ id: 'SV-001', impact: 0.7 }];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(1);
    expect(result.unmatchedOld).toHaveLength(1);
    expect((result.unmatchedOld[0] as any).id).toBe('SV-002');
    expect(result.unmatchedNew).toHaveLength(0);
  });

  it('should put new-only requirements in unmatchedNew', () => {
    const oldReqs = [{ id: 'SV-001', impact: 0.7 }];
    const newReqs = [
      { id: 'SV-001', impact: 0.7 },
      { id: 'SV-003', impact: 0.3 },
    ];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(1);
    expect(result.unmatchedOld).toHaveLength(0);
    expect(result.unmatchedNew).toHaveLength(1);
    expect((result.unmatchedNew[0] as any).id).toBe('SV-003');
  });

  it('should handle empty old requirements', () => {
    const oldReqs: Record<string, unknown>[] = [];
    const newReqs = [{ id: 'SV-001', impact: 0.7 }];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(0);
    expect(result.unmatchedNew).toHaveLength(1);
  });

  it('should handle empty new requirements', () => {
    const oldReqs = [{ id: 'SV-001', impact: 0.7 }];
    const newReqs: Record<string, unknown>[] = [];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(0);
  });

  it('should handle both empty', () => {
    const result = strategy.match([], []);

    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(0);
    expect(result.unmatchedNew).toHaveLength(0);
  });

  it('should handle requirements without id field', () => {
    const oldReqs = [{ title: 'No ID', impact: 0.7 }];
    const newReqs = [{ title: 'No ID', impact: 0.7 }];

    const result = strategy.match(oldReqs, newReqs);

    // Requirements without id cannot be matched by exact id
    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(1);
  });

  it('should correctly pair old and new in matched results', () => {
    const oldReqs = [{ id: 'SV-001', impact: 0.7, title: 'Old Title' }];
    const newReqs = [{ id: 'SV-001', impact: 0.5, title: 'New Title' }];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(1);
    expect(result.matched[0]!.oldReq['title']).toBe('Old Title');
    expect(result.matched[0]!.newReq['title']).toBe('New Title');
  });

  it('should treat duplicate new IDs as unresolvable — both go to unmatchedNew', () => {
    const oldReqs = [{ id: 'SV-001', impact: 0.7, title: 'Old' }];
    const newReqs = [
      { id: 'SV-001', impact: 0.7, title: 'New A' },
      { id: 'SV-001', impact: 0.5, title: 'New B' },
    ];

    const result = strategy.match(oldReqs, newReqs);

    // Ambiguous: two new reqs share the same ID → neither can be matched
    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(2);
  });

  it('should treat duplicate old IDs as unresolvable — both go to unmatchedOld', () => {
    const oldReqs = [
      { id: 'SV-001', impact: 0.7, title: 'Old A' },
      { id: 'SV-001', impact: 0.5, title: 'Old B' },
    ];
    const newReqs = [{ id: 'SV-001', impact: 0.7, title: 'New' }];

    const result = strategy.match(oldReqs, newReqs);

    // Ambiguous: two old reqs share the same ID → neither can be matched
    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(2);
    expect(result.unmatchedNew).toHaveLength(1);
  });
});
