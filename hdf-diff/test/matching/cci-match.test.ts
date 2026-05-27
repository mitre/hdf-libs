import { describe, it, expect } from 'vitest';
import { createCciMatchStrategy, extractCwes } from '../../src/matching/cci-match.js';

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

  // ── CWE fallback (structured req.cwe[] preferred over tags.cwe) ────────

  it('should match requirements sharing a CWE when no CCI match exists', () => {
    const oldReqs = [
      { id: 'OLD-1', cwe: ['CWE-79'], impact: 0.7 },
    ];
    const newReqs = [
      { id: 'NEW-1', cwe: ['CWE-79'], impact: 0.7 },
    ];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(1);
    expect(result.matched[0]!.oldReq['id']).toBe('OLD-1');
    expect(result.matched[0]!.newReq['id']).toBe('NEW-1');
  });

  it('should prefer CCI matches over CWE matches when both are available', () => {
    // V-001/RHEL-001 share CCI-000366 (unambiguous) AND CWE-79
    // V-002/RHEL-002 share only CWE-89
    // CCI is the primary signal; CWE is the fallback.
    const oldReqs = [
      { id: 'V-001', tags: { cci: ['CCI-000366'] }, cwe: ['CWE-79'], impact: 0.7 },
      { id: 'V-002', cwe: ['CWE-89'], impact: 0.5 },
    ];
    const newReqs = [
      { id: 'RHEL-001', tags: { cci: ['CCI-000366'] }, cwe: ['CWE-79'], impact: 0.7 },
      { id: 'RHEL-002', cwe: ['CWE-89'], impact: 0.5 },
    ];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(2);
    const byOldId = Object.fromEntries(
      result.matched.map((m) => [m.oldReq['id'], m.newReq['id']]),
    );
    expect(byOldId).toEqual({ 'V-001': 'RHEL-001', 'V-002': 'RHEL-002' });
    // CCI matches should have higher confidence than CWE matches.
    const v001Match = result.matched.find((m) => m.oldReq['id'] === 'V-001')!;
    const v002Match = result.matched.find((m) => m.oldReq['id'] === 'V-002')!;
    expect(v001Match.confidence).toBeGreaterThan(v002Match.confidence);
  });

  it('should skip ambiguous CWE matches the same way as CCI', () => {
    const oldReqs = [
      { id: 'OLD-A', cwe: ['CWE-79'], impact: 0.7 },
      { id: 'OLD-B', cwe: ['CWE-79'], impact: 0.5 },
    ];
    const newReqs = [
      { id: 'NEW-X', cwe: ['CWE-79'], impact: 0.7 },
    ];

    const result = strategy.match(oldReqs, newReqs);

    // Two old reqs share CWE-79 — ambiguous, skipped.
    expect(result.matched).toHaveLength(0);
    expect(result.unmatchedOld).toHaveLength(2);
    expect(result.unmatchedNew).toHaveLength(1);
  });

  it('should not double-match: a CCI-matched req should not also CWE-match', () => {
    // V-001 matches RHEL-001 via CCI. V-001 ALSO shares CWE-79 with RHEL-002.
    // We should not re-pair already-claimed reqs.
    const oldReqs = [
      { id: 'V-001', tags: { cci: ['CCI-000366'] }, cwe: ['CWE-79'], impact: 0.7 },
    ];
    const newReqs = [
      { id: 'RHEL-001', tags: { cci: ['CCI-000366'] }, impact: 0.7 },
      { id: 'RHEL-002', cwe: ['CWE-79'], impact: 0.5 },
    ];

    const result = strategy.match(oldReqs, newReqs);

    expect(result.matched).toHaveLength(1);
    expect(result.matched[0]!.oldReq['id']).toBe('V-001');
    expect(result.matched[0]!.newReq['id']).toBe('RHEL-001');
    expect(result.unmatchedNew).toHaveLength(1);
    expect(result.unmatchedNew[0]!['id']).toBe('RHEL-002');
  });
});

describe('extractCwes', () => {
  it('prefers structured req.cwe[] over tags.cwe when present', () => {
    const req = {
      cwe: ['CWE-79', 'CWE-89'],
      tags: { cwe: ['CWE-999'] },
    };
    expect(extractCwes(req)).toEqual(['CWE-79', 'CWE-89']);
  });

  it('falls back to tags.cwe when req.cwe[] is absent', () => {
    const req = { tags: { cwe: ['CWE-79'] } };
    expect(extractCwes(req)).toEqual(['CWE-79']);
  });

  it('falls back to tags.cwe when req.cwe[] is empty (length 0)', () => {
    const req = { cwe: [], tags: { cwe: ['CWE-79'] } };
    expect(extractCwes(req)).toEqual(['CWE-79']);
  });

  it('tolerates string tags.cwe (single-value form)', () => {
    const req = { tags: { cwe: 'CWE-79' } };
    expect(extractCwes(req)).toEqual(['CWE-79']);
  });

  it('returns empty array when no CWE data is available', () => {
    expect(extractCwes({})).toEqual([]);
    expect(extractCwes({ tags: {} })).toEqual([]);
    expect(extractCwes({ cwe: 'not-an-array' as unknown as string[] })).toEqual([]);
  });

  it('filters non-string entries from arrays', () => {
    const req = { cwe: ['CWE-79', 42, null, 'CWE-89'] as unknown as string[] };
    expect(extractCwes(req)).toEqual(['CWE-79', 'CWE-89']);
  });
});
