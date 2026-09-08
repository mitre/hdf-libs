import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { normalizeXmlForGolden } from './xml-golden.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

interface XmlGoldenCase {
  name: string;
  a: string;
  b: string;
  expectedA: string;
  expectedB: string;
  equal: boolean;
  why: string;
}

const CASES = (
  JSON.parse(readFileSync(join(__dirname, '..', 'xml-golden-cases.json'), 'utf-8')) as {
    cases: XmlGoldenCase[];
  }
).cases;

// The normalizer is implemented twice, and it is the yardstick every XML parity
// assertion in this repo is measured with, so the two copies are held to one
// shared table rather than to each other's behaviour.
describe('normalizeXmlForGolden', () => {
  it('has a populated shared table', () => {
    expect(CASES.length, 'an empty table would pass vacuously').toBeGreaterThan(0);
  });

  it.each(CASES.map((c) => [c.name, c] as const))('%s', (_name, c) => {
    const a = normalizeXmlForGolden(c.a);
    const b = normalizeXmlForGolden(c.b);
    // Against the table's literal, not merely against each other: two
    // implementations returning the same wrong string would satisfy a
    // relation-only assertion, so the peer would be pinned to nothing.
    expect(a, c.why).toBe(c.expectedA);
    expect(b, c.why).toBe(c.expectedB);
    expect(a === b, c.why).toBe(c.equal);
  });

  // The property the masking bug violated, stated directly: normalization may
  // drop formatting, but it must never turn content into nothing. The members
  // beyond XML's S production: NBSP and U+3000 reach only this language's \s,
  // form feed reaches both, and none has an encoder entry.
  it.each([' ', '\t', '\n', '\r', '  ', '\t\n', '\u00a0', '\u3000', '\u000c', '\u2003'])(
    'keeps %j as element content',
    (ws) => {
      expect(
        normalizeXmlForGolden(`<r><k>${ws}</k></r>`),
        'whitespace content was erased, so an empty element compares equal to one carrying it',
      ).not.toBe(normalizeXmlForGolden('<r><k></k></r>'));
    },
  );
});
