import { describe, expect, it } from 'vitest';
import { UNMAPPED_CODES, loadProblemDocs, problemTypes } from '../src/problems.js';

// The mapping's one home is src/problems.yaml. ADR-0010 §6 records the decision and cites
// that file; nothing here reads the ADR, because a decision record is revised and
// eventually superseded while these invariants have to keep holding against the code.
//
// Completeness against the MCP taxonomy — every code that reaches HTTP is mapped — is not
// checkable from this package: the taxonomy is Go. hdf-libs-hp0vg carries that.

const TAXONOMY_NAME = /^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$/;

describe('the derived problem-type mapping', () => {
  const docs = loadProblemDocs();
  const mapping = problemTypes(docs);
  const codes = Object.keys(mapping);

  // Also the duplicate-code check: two entries naming one code collapse to a single
  // mapping key, so the counts diverge.
  it('maps every coded entry, so the per-code checks cannot pass vacuously', () => {
    const coded = Object.values(docs).filter((entry) => entry.code !== undefined);
    expect(codes).toHaveLength(coded.length);
    expect(codes.length).toBeGreaterThan(5);
  });

  it.each(codes)('%s points at the entry that declares it', (code) => {
    expect(docs[mapping[code]!.type]?.code).toBe(code);
  });
});

describe('codes recorded as never reaching HTTP', () => {
  const mapping = problemTypes();

  it('is a non-empty list of well-formed taxonomy names', () => {
    expect(UNMAPPED_CODES.length).toBeGreaterThan(0);
    for (const code of UNMAPPED_CODES) expect(code).toMatch(TAXONOMY_NAME);
  });

  // A code either reaches HTTP or is recorded as never doing so. Both would mean the table
  // and the list disagree about the same code, with nothing to say which is right.
  it('shares no code with the mapping', () => {
    const both = UNMAPPED_CODES.filter((code) => code in mapping);
    expect(both).toEqual([]);
  });
});
