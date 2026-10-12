import { describe, expect, it } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';
import { STRIPPED_OUTPUT_FIELDS } from '../src/generate-api.js';
import { CLOSED_KEYS } from '../src/bindings.js';

const ADR = join(
  new URL('.', import.meta.url).pathname,
  '..',
  '..',
  'dev-docs',
  'adr-0008-openapi-schema-and-reference-api.md',
);

/**
 * Names the outputs clause mentions that are not sources to strip: `id` and `next` are
 * rewrite TARGETS and `total` is carried through by name.
 */
const NOT_STRIPPED = new Set(['id', 'next', 'total']);

/**
 * Parses §2's fixed rewrite map rather than restating it, so a revision to the ADR moves
 * this test instead of leaving it agreeing with a stale copy of itself.
 */
function outputNamesInAdr(): Set<string> {
  const map = /A \*\*fixed rewrite map\*\*.*?(?=\n)/s.exec(readFileSync(ADR, 'utf-8'));
  if (!map) throw new Error('ADR-0008 §2 no longer states a fixed rewrite map');
  const clause = map[0].slice(map[0].indexOf('outputs '), map[0].indexOf('; the table'));
  if (clause === '') throw new Error('the rewrite map no longer has an outputs clause');
  return new Set([...clause.matchAll(/`([A-Za-z][A-Za-z0-9]*)`/g)].map((m) => m[1]!));
}

describe("the strip list agrees with ADR-0008 §2's rewrite map", () => {
  const adr = outputNamesInAdr();

  it('parsed the clause, so the comparisons below cannot pass vacuously', () => {
    expect(adr.size).toBeGreaterThan(5);
    expect(adr.has('outputPath')).toBe(true);
  });

  it.each([...adr].filter((name) => !NOT_STRIPPED.has(name)))(
    '§2 names %s as stripped, so the generator strips it',
    (name) => {
      expect(STRIPPED_OUTPUT_FIELDS.has(name)).toBe(true);
    },
  );

  it.each([...STRIPPED_OUTPUT_FIELDS])('the generator strips %s, so §2 names it', (name) => {
    expect(adr.has(name)).toBe(true);
  });
});

/**
 * The keys §2 enumerates for the binding table. Parsed, for the same reason the rewrite map
 * is: the first attempt at the synthetic status surface widened CLOSED_KEYS and left this
 * list alone, so the code's closed grammar was broader than the document it cites — which is
 * exactly the drift the rewrite-map check above exists to catch, one bullet further up.
 */
function grammarKeysInAdr(): Set<string> {
  const bullet = readFileSync(ADR, 'utf-8')
    .split('\n')
    .find((line) => line.startsWith('- **The binding table**'));
  if (bullet === undefined) throw new Error('ADR-0008 §2 no longer enumerates the binding table grammar');
  return new Set([...bullet.matchAll(/`([a-zA-Z][a-zA-Z0-9]*)/g)].map((m) => m[1]!));
}

// §2 names `tools` and `resources` only in prose ("per tool —", "per resource —"). The other
// four are named, but inside a brace list — `drop: [{name, reason}]`, `absent: [{tool |
// resource | field, reason}]` — and the parse takes only the leading identifier of a
// backticked span, so it never sees them. Measured: these six are exactly what it misses.
const PARSE_MISSES = new Set(['tools', 'resources', 'name', 'reason', 'tool', 'field']);

describe("the binding table's closed keys agree with ADR-0008 §2", () => {
  const adr = grammarKeysInAdr();

  it('parsed the bullet, so the comparisons below cannot pass vacuously', () => {
    expect(adr.size).toBeGreaterThan(8);
    expect(adr.has('summaryRef')).toBe(true);
  });

  it.each([...CLOSED_KEYS].filter((key) => !PARSE_MISSES.has(key)))(
    'the table accepts %s, so §2 names it',
    (key) => {
      expect(adr.has(key)).toBe(true);
    },
  );
});
