import { describe, it, expect } from 'vitest';
import { createCciMatchStrategy } from '../../src/matching/cci-match.js';

describe('CciMatchStrategy', () => {
  const strategy = createCciMatchStrategy();

  it('should have name "cciMatch"', () => {
    expect(strategy.name).toBe('cciMatch');
  });

  it('should match requirements that share the same CCI identifier', () => {
    const oldReqs = [
      { id: 'V-001', tags: { cci: ['CCI-000366'] }, impact: 0.7 },
    ];
    const newReqs = [
      { id: 'RHEL-001', tags: { cci: ['CCI-000366'] }, impact: 0.7 },
    ];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(1);
    expect(result.matched[0]!.oldReq['id']).toBe('V-001');
    expect(result.matched[0]!.newReq['id']).toBe('RHEL-001');
    expect(result.matched[0]!.confidence).toBe(0.8);
    expect(result.matched[0]!.strategy).toBe('cciMatch');
    expect(result.unmatchedOld).toHaveLength(0);
    expect(result.unmatchedNew).toHaveLength(0);
  });

  it('should skip ambiguous CCI matches (multiple old reqs share same CCI)', () => {
    const oldReqs = [
      { id: 'V-001', tags: { cci: ['CCI-000366'] }, impact: 0.7 },
      { id: 'V-002', tags: { cci: ['CCI-000366'] }, impact: 0.5 },
    ];
    const newReqs = [
      { id: 'RHEL-001', tags: { cci: ['CCI-000366'] }, impact: 0.7 },
    ];

    const result = strategy.match(oldReqs, newReqs);

    // Ambiguous: two old reqs share the same CCI
    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(2);
    expect(result.unmatchedNew).toHaveLength(1);
  });

  it('should skip ambiguous CCI matches (multiple new reqs share same CCI)', () => {
    const oldReqs = [
      { id: 'V-001', tags: { cci: ['CCI-000366'] }, impact: 0.7 },
    ];
    const newReqs = [
      { id: 'RHEL-001', tags: { cci: ['CCI-000366'] }, impact: 0.7 },
      { id: 'RHEL-002', tags: { cci: ['CCI-000366'] }, impact: 0.5 },
    ];

    const result = strategy.match(oldReqs, newReqs);

    // Ambiguous: two new reqs share the same CCI
    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(2);
  });

  it('should match multiple unambiguous CCIs independently', () => {
    const oldReqs = [
      { id: 'V-001', tags: { cci: ['CCI-000366'] }, impact: 0.7 },
      { id: 'V-002', tags: { cci: ['CCI-000777'] }, impact: 0.5 },
    ];
    const newReqs = [
      { id: 'RHEL-001', tags: { cci: ['CCI-000366'] }, impact: 0.7 },
      { id: 'RHEL-002', tags: { cci: ['CCI-000777'] }, impact: 0.5 },
    ];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(2);
    expect(result.unmatchedOld).toHaveLength(0);
    expect(result.unmatchedNew).toHaveLength(0);
  });

  it('should handle requirements with multiple CCIs', () => {
    const oldReqs = [
      { id: 'V-001', tags: { cci: ['CCI-000366', 'CCI-000777'] }, impact: 0.7 },
    ];
    const newReqs = [
      { id: 'RHEL-001', tags: { cci: ['CCI-000366', 'CCI-000777'] }, impact: 0.7 },
    ];

    const result = strategy.match(oldReqs, newReqs);

    // Should match on the first unambiguous CCI found
    expect(result.matched).toHaveLength(1);
    expect(result.unmatchedOld).toHaveLength(0);
    expect(result.unmatchedNew).toHaveLength(0);
  });

  it('should handle requirements without tags', () => {
    const oldReqs = [{ id: 'V-001', impact: 0.7 }];
    const newReqs = [{ id: 'RHEL-001', impact: 0.7 }];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(1);
  });

  it('should handle requirements with empty cci array', () => {
    const oldReqs = [{ id: 'V-001', tags: { cci: [] }, impact: 0.7 }];
    const newReqs = [{ id: 'RHEL-001', tags: { cci: [] }, impact: 0.7 }];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(1);
  });

  it('should handle requirements with tags but no cci field', () => {
    const oldReqs = [{ id: 'V-001', tags: { nist: ['AC-1'] }, impact: 0.7 }];
    const newReqs = [{ id: 'RHEL-001', tags: { nist: ['AC-1'] }, impact: 0.7 }];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(1);
  });

  // Documents conservative ambiguity behavior for multi-CCI requirements.
  // When a CCI appears on multiple old requirements, it is marked ambiguous
  // and cannot be used for matching — even if only one new requirement has it.
  // This is intentional: the CCI matcher treats each CCI independently and
  // requires exactly 1 old + 1 new per CCI for a match. A CCI shared across
  // multiple old reqs (even if one also has a unique CCI) makes that shared
  // CCI ambiguous. The unique CCI can still match, but the shared one cannot.
  it('should demonstrate conservative multi-CCI ambiguity behavior', () => {
    const oldReqs = [
      { id: 'V-A', tags: { cci: ['CCI-001', 'CCI-002'] }, impact: 0.7 },
      { id: 'V-B', tags: { cci: ['CCI-002'] }, impact: 0.5 },
    ];
    const newReqs = [
      { id: 'RHEL-X', tags: { cci: ['CCI-001'] }, impact: 0.7 },
      { id: 'RHEL-Y', tags: { cci: ['CCI-002'] }, impact: 0.5 },
    ];

    const result = strategy.match(oldReqs, newReqs);

    // CCI-001: unambiguous (1 old V-A, 1 new RHEL-X) → matched
    // CCI-002: ambiguous (2 old V-A+V-B, 1 new RHEL-Y) → skipped
    // Result: A matches X via CCI-001, B is unmatched (CCI-002 is ambiguous
    // because A also has it), Y is unmatched for the same reason.
    expect(result.matched).toHaveLength(1);
    expect(result.matched[0]!.oldReq['id']).toBe('V-A');
    expect(result.matched[0]!.newReq['id']).toBe('RHEL-X');
    expect(result.unmatchedOld).toHaveLength(1);
    expect((result.unmatchedOld[0] as Record<string, unknown>)['id']).toBe('V-B');
    expect(result.unmatchedNew).toHaveLength(1);
    expect((result.unmatchedNew[0] as Record<string, unknown>)['id']).toBe('RHEL-Y');
  });

  it('should handle CCI present only in old requirements (triggers ?? [] fallback on newCciMap)', () => {
    const strategy = createCciMatchStrategy();
    const oldReqs = [
      { id: 'V-001', impact: 0.7, tags: { cci: ['CCI-999'] } },
    ];
    const newReqs = [
      { id: 'V-002', impact: 0.7, tags: { cci: ['CCI-888'] } },
    ];
    const result = strategy.match(
      oldReqs as unknown as Record<string, unknown>[],
      newReqs as unknown as Record<string, unknown>[],
    );
    // No shared CCIs, so nothing matches
    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(1);
    expect(result.unmatchedNew).toHaveLength(1);
  });

  it('should handle mix of matchable and ambiguous CCIs', () => {
    const oldReqs = [
      { id: 'V-001', tags: { cci: ['CCI-000366'] }, impact: 0.7 },
      { id: 'V-002', tags: { cci: ['CCI-000777'] }, impact: 0.5 },
      { id: 'V-003', tags: { cci: ['CCI-000777'] }, impact: 0.3 },
    ];
    const newReqs = [
      { id: 'RHEL-001', tags: { cci: ['CCI-000366'] }, impact: 0.7 },
      { id: 'RHEL-002', tags: { cci: ['CCI-000777'] }, impact: 0.5 },
    ];

    const result = strategy.match(oldReqs, newReqs);

    // CCI-000366: unambiguous (1 old, 1 new) -> matched
    // CCI-000777: ambiguous (2 old, 1 new) -> unmatched
    expect(result.matched).toHaveLength(1);
    expect(result.matched[0]!.oldReq['id']).toBe('V-001');
    expect(result.unmatchedOld).toHaveLength(2);
    expect(result.unmatchedNew).toHaveLength(1);
  });
});
