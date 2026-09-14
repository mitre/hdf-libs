import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { canonicalize, stringifyLine, floatNumber } from './exportmap.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// The Go peer asserts this same table against encoding/json, which is the
// rendering contract for every NDJSON number these exporters emit. Reading one
// table from both languages is what stops them drifting on a value no fixture
// happens to carry.
interface NumberCase {
  json: string;
  token: string;
  why: string;
}

const table = JSON.parse(
  readFileSync(join(__dirname, '..', 'export-number-cases.json'), 'utf-8'),
) as { cases: NumberCase[]; floatTokenCases: NumberCase[] };

// JSON.parse, not a JS literal: a literal -0 written in source survives, but the
// point is that the value arrives by parsing converter input, which is also the
// only way the sign reaches the serializer at all.
const parse = (text: string): number => JSON.parse(text) as number;

describe('raw JSON number rendering matches the Go encoder', () => {
  it.each(table.cases.map((c) => [c.json, c.token, c.why] as const))(
    'renders %s as %s',
    (json, token, why) => {
      expect(stringifyLine(canonicalize({ v: parse(json) })), why).toBe(`{"v":${token}}`);
    },
  );
});

describe('floatNumber matches Go FloatToken', () => {
  it.each(table.floatTokenCases.map((c) => [c.json, c.token, c.why] as const))(
    'renders %s as %s',
    (json, token, why) => {
      expect(floatNumber(parse(json)).token, why).toBe(token);
    },
  );
});
