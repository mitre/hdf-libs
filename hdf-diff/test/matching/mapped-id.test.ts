import { describe, it, expect } from 'vitest';
import { createMappedIdStrategy } from '../../src/matching/mapped-id.js';

describe('MappedIdStrategy', () => {
  it('should have name "mappedId"', () => {
    const strategy = createMappedIdStrategy({});
    expect(strategy.name).toBe('mappedId');
  });

  it('should match using mapping table to translate old IDs to new IDs', () => {
    const mapping = { 'V-001-old': 'V-001-new' };
    const strategy = createMappedIdStrategy(mapping);

    const oldReqs = [{ id: 'V-001-old', title: 'Test 1', impact: 0.7 }];
    const newReqs = [{ id: 'V-001-new', title: 'Test 1', impact: 0.7 }];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(1);
    expect(result.matched[0]!.oldReq['id']).toBe('V-001-old');
    expect(result.matched[0]!.newReq['id']).toBe('V-001-new');
    expect(result.unmatchedOld).toHaveLength(0);
    expect(result.unmatchedNew).toHaveLength(0);
  });

  it('should report confidence 0.95 for mapped matches', () => {
    const mapping = { 'V-001-old': 'V-001-new' };
    const strategy = createMappedIdStrategy(mapping);

    const oldReqs = [{ id: 'V-001-old', impact: 0.7 }];
    const newReqs = [{ id: 'V-001-new', impact: 0.7 }];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched[0]!.confidence).toBe(0.95);
    expect(result.matched[0]!.strategy).toBe('mappedId');
  });

  it('should leave unmapped old IDs as unmatched', () => {
    const mapping = { 'V-001-old': 'V-001-new' };
    const strategy = createMappedIdStrategy(mapping);

    const oldReqs = [
      { id: 'V-001-old', impact: 0.7 },
      { id: 'V-002-unmapped', impact: 0.5 },
    ];
    const newReqs = [{ id: 'V-001-new', impact: 0.7 }];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(1);
    expect(result.unmatchedOld).toHaveLength(1);
    expect((result.unmatchedOld[0] as any).id).toBe('V-002-unmapped');
  });

  it('should leave new reqs not targeted by any mapping as unmatched', () => {
    const mapping = { 'V-001-old': 'V-001-new' };
    const strategy = createMappedIdStrategy(mapping);

    const oldReqs = [{ id: 'V-001-old', impact: 0.7 }];
    const newReqs = [
      { id: 'V-001-new', impact: 0.7 },
      { id: 'V-003-extra', impact: 0.3 },
    ];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(1);
    expect((result.unmatchedNew[0] as any).id).toBe('V-003-extra');
  });

  it('should handle empty mapping table', () => {
    const strategy = createMappedIdStrategy({});

    const oldReqs = [{ id: 'V-001', impact: 0.7 }];
    const newReqs = [{ id: 'V-001', impact: 0.7 }];

    const result = strategy.match(oldReqs, newReqs);

    // No mappings means nothing is translated, so exact matches on translated IDs
    // With empty mapping, old ID "V-001" is not translated so not matched to new "V-001"
    // because mappedId only uses the mapping table, not exact matching
    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(1);
  });

  it('should handle multiple mappings', () => {
    const mapping = {
      'V-001-old': 'V-001-new',
      'V-002-old': 'V-002-new',
      'V-003-old': 'V-003-new',
    };
    const strategy = createMappedIdStrategy(mapping);

    const oldReqs = [
      { id: 'V-001-old', impact: 0.7 },
      { id: 'V-002-old', impact: 0.5 },
      { id: 'V-003-old', impact: 0.3 },
    ];
    const newReqs = [
      { id: 'V-001-new', impact: 0.7 },
      { id: 'V-002-new', impact: 0.5 },
      { id: 'V-003-new', impact: 0.3 },
    ];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(3);
    expect(result.unmatchedOld).toHaveLength(0);
    expect(result.unmatchedNew).toHaveLength(0);
  });

  it('should handle mapping to a new ID that does not exist in new reqs', () => {
    const mapping = { 'V-001-old': 'V-001-nonexistent' };
    const strategy = createMappedIdStrategy(mapping);

    const oldReqs = [{ id: 'V-001-old', impact: 0.7 }];
    const newReqs = [{ id: 'V-001-actual', impact: 0.7 }];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(1);
  });

  it('should handle requirements without id field', () => {
    const mapping = { 'V-001': 'V-002' };
    const strategy = createMappedIdStrategy(mapping);

    const oldReqs = [{ title: 'No ID', impact: 0.7 }];
    const newReqs = [{ title: 'No ID', impact: 0.7 }];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(1);
  });

  it('should treat duplicate new IDs as unresolvable — both go to unmatchedNew', () => {
    const mapping = { 'V-001-old': 'V-001-new' };
    const strategy = createMappedIdStrategy(mapping);

    const oldReqs = [{ id: 'V-001-old', impact: 0.7 }];
    const newReqs = [
      { id: 'V-001-new', impact: 0.7, title: 'New A' },
      { id: 'V-001-new', impact: 0.5, title: 'New B' },
    ];

    const result = strategy.match(oldReqs, newReqs);

    // Ambiguous: two new reqs share the mapped target ID → neither can be matched
    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(2);
  });

  it('should treat duplicate old IDs as unresolvable — both go to unmatchedOld', () => {
    const mapping = { 'V-001-old': 'V-001-new' };
    const strategy = createMappedIdStrategy(mapping);

    const oldReqs = [
      { id: 'V-001-old', impact: 0.7, title: 'Old A' },
      { id: 'V-001-old', impact: 0.5, title: 'Old B' },
    ];
    const newReqs = [{ id: 'V-001-new', impact: 0.7 }];

    const result = strategy.match(oldReqs, newReqs);

    // Ambiguous: two old reqs share the same ID → neither can be matched
    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(2);
    expect(result.unmatchedNew).toHaveLength(1);
  });
});
