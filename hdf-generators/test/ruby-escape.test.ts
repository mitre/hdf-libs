import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { escapeQuotes } from '../src/ruby-escape.js';

interface RubyLiteralCase {
  input: string;
  literal: string;
  why: string;
}

// The Go peer (EscapeQuotes) asserts against this same table and has Ruby read
// every literal back.
const { cases } = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'ruby-literal-cases.json'), 'utf-8'),
) as { cases: RubyLiteralCase[] };

describe('escapeQuotes', () => {
  it('reads a non-empty shared table', () => {
    expect(cases.length).toBeGreaterThan(0);
  });

  it.each(cases)('$why', ({ input, literal }) => {
    expect(escapeQuotes(input)).toBe(literal);
  });
});
