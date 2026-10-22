import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { decodeReference } from '../src/evidence.js';

// The SHARED table, read rather than restated: Go reads the same file, so a divergence
// between the two languages fails on one side or the other instead of going unnoticed.
// What a reference means is language-independent even where only Go resolves one today.
const vectors = JSON.parse(
  readFileSync(join(import.meta.dirname, '..', 'testdata', 'reference-decode-vectors.json'), 'utf8'),
) as { vectors: { why: string; uri: string; decoded?: string; malformed?: boolean }[] };

describe('decodeReference', () => {
  it('has vectors to check, so a pass cannot mean an empty table', () => {
    expect(vectors.vectors.length).toBeGreaterThan(5);
  });

  for (const v of vectors.vectors) {
    it(v.why, () => {
      if (v.malformed) {
        expect(() => decodeReference(v.uri)).toThrow(/not a valid uri-reference/);
      } else {
        expect(decodeReference(v.uri)).toBe(v.decoded);
      }
    });
  }
});
