import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalChecksum, canonicalJson } from '../src/json/index.js';

interface CanonicalVector {
  name: string;
  input: unknown;
  canonical: string;
  checksum: string;
}

const vectors: CanonicalVector[] = JSON.parse(
  readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'canonical-json-vectors.json'),
    'utf8',
  ),
).vectors;

// The expected values in these vectors were produced by the Go implementation.
// Both languages asserting against the same bytes is what makes the
// cross-language checksum contract real rather than aspirational: an amendment
// chain written by one must verify under the other.
describe('canonical JSON — cross-language vectors', () => {
  it('has vectors to check', () => {
    expect(vectors.length).toBeGreaterThan(0);
  });

  for (const vector of vectors) {
    it(`matches Go: ${vector.name}`, async () => {
      expect(canonicalJson(vector.input)).toBe(vector.canonical);
      await expect(canonicalChecksum(vector.input)).resolves.toBe(vector.checksum);
    });
  }
});

describe('canonicalJson', () => {
  it('sorts keys regardless of insertion order', () => {
    expect(canonicalJson({ b: 1, a: 2 })).toBe(canonicalJson({ a: 2, b: 1 }));
  });

  it('hashes an explicit null the same as an omitted key', async () => {
    await expect(canonicalChecksum({ a: 1, b: null })).resolves.toBe(
      await canonicalChecksum({ a: 1 }),
    );
  });

  it('keeps array order significant', async () => {
    await expect(canonicalChecksum(['a', 'b'])).resolves.not.toBe(
      await canonicalChecksum(['b', 'a']),
    );
  });

  it('escapes the characters Go escapes', () => {
    expect(canonicalJson({ s: 'a & b < c > d' })).toBe(
      '{"s":"a \\u0026 b \\u003c c \\u003e d"}',
    );
  });

  it('emits non-ASCII as UTF-8 rather than escaping it', () => {
    expect(canonicalJson({ s: 'café 你好' })).toBe('{"s":"café 你好"}');
  });
});
