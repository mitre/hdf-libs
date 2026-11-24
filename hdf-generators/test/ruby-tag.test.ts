import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { formatTag, rubyValue } from '../src/ruby-value.js';
import { generateControlStub } from '../src/control-stub.js';
import { makeRequirement } from './helpers.js';

interface RubyTagCase {
  key: string;
  value: unknown;
  line: string;
  why: string;
}

// The Go peer (formatTag) asserts against this same table and has Ruby read
// every line back.
const { cases } = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'ruby-tag-cases.json'), 'utf-8'),
) as { cases: RubyTagCase[] };

describe('formatTag', () => {
  it('reads a non-empty shared table', () => {
    expect(cases.length).toBeGreaterThan(0);
  });

  it.each(cases)('$why', ({ key, value, line }) => {
    expect(formatTag(key, value)).toBe(line);
  });
});

describe('generateControlStub tag order', () => {
  it('writes tags sorted by key, as the Go generator does', () => {
    const ruby = generateControlStub(makeRequirement({ id: 'SV-1', tags: { stig_id: 'X', cci: ['CCI-1'], gid: 'V-1' } }));
    const tags = ruby.split('\n').filter((l) => l.startsWith('  tag ')).map((l) => l.slice(6, l.indexOf(':')));
    expect(tags).toEqual(['cci', 'gid', 'stig_id']);
  });
});

// JSON cannot carry NaN or infinity, but a caller filling tags can; Ruby spells
// them as Float constants. Same cases as the Go TestRubyValue_NonFinite.
describe('rubyValue non-finite numbers', () => {
  it.each([
    [Number.NaN, 'Float::NAN'],
    [Number.POSITIVE_INFINITY, 'Float::INFINITY'],
    [Number.NEGATIVE_INFINITY, '-Float::INFINITY'],
  ])('%s', (n, want) => {
    expect(rubyValue(n)).toBe(want);
  });
});
