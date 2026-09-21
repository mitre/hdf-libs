/**
 * Pins the TypeScript validator to its Go peer on JSON Schema `format`.
 *
 * Both harnesses read ../testdata/format-assertion-cases.json and build the same
 * one-property schema per case in both dialects. The two must agree, because
 * converter tests assert "this input is valid HDF" before converting: a
 * validator that skips `format` lets a test prove nothing while looking green,
 * which is exactly what happened when Go accepted a padded uuid that ajv
 * rejected.
 */
import { readFileSync, writeFileSync, rmSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { ANNOTATION_ONLY_FORMATS, loadSchemaValidator } from './schema-validation.js';

/**
 * A case states `valid` when the libraries agree, or `go` and `ts` when they do
 * not; a format ajv cannot check always spells both, so `valid` never dresses
 * ajv's silence up as agreement. `goDraft07` narrows the Go side only and is
 * irrelevant here, since ajv serves both dialects.
 */
interface FormatCase {
  format: string;
  value: string;
  valid?: boolean;
  go?: boolean;
  ts?: boolean;
  goDraft07?: boolean;
  why?: string;
}

/** The verdict this case records for TypeScript, refusing a half-specified row. */
function expected(tc: FormatCase): boolean {
  if (tc.valid !== undefined) return tc.valid;
  if (tc.ts !== undefined && tc.go !== undefined) return tc.ts;
  throw new Error(`case ${tc.format} ${JSON.stringify(tc.value)} states neither valid nor both of go/ts`);
}

const table = JSON.parse(
  readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), '..', 'testdata', 'format-assertion-cases.json'),
    'utf-8',
  ),
) as {
  formats: string[];
  tsAnnotationOnly: string[];
  cases: FormatCase[];
};

const DIALECTS = [
  'https://json-schema.org/draft/2020-12/schema',
  'http://json-schema.org/draft-07/schema#',
];

function validatorFor(format: string, dialect: string) {
  const dir = mkdtempSync(join(tmpdir(), 'hdf-format-'));
  const path = join(dir, 'format.schema.json');
  writeFileSync(
    path,
    JSON.stringify({
      $schema: dialect,
      type: 'object',
      properties: { v: { type: 'string', format } },
    }),
  );
  try {
    return loadSchemaValidator(path);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('format assertion is pinned across languages', () => {
  it('covers every format the table declares', () => {
    expect(new Set(table.cases.map((c) => c.format))).toEqual(new Set(table.formats));
  });

  // ajv-formats implements none of these, so TypeScript schema tests cannot see
  // a violation of them and Go can. The helper registers them as annotation-only
  // rather than letting ajv ignore them: the set is then a decision this table
  // records, not a warning nobody reads.
  describe('formats ajv-formats does not implement', () => {
    it('are exactly the ones the helper registers as annotation-only', () => {
      expect([...ANNOTATION_ONLY_FORMATS].sort()).toEqual([...table.tsAnnotationOnly].sort());
    });

    it.each(table.tsAnnotationOnly)('%s: ajv accepts every row and Go rejects at least one', (format) => {
      const rows = table.cases.filter((c) => c.format === format);
      expect(rows.length, `${format} has no rows`).toBeGreaterThan(0);
      for (const r of rows) {
        expect(r.ts, `${format} ${JSON.stringify(r.value)} must spell ts: true — ajv never judges it`).toBe(true);
      }
      expect(
        rows.some((r) => r.go === false || r.goDraft07 === false),
        `${format} needs a row Go rejects, or the gap is asserted rather than demonstrated`,
      ).toBe(true);
    });

    // A format neither ajv-formats nor the list above knows must fail loudly:
    // the alternative is what this file exists to prevent — a schema assertion
    // that validates nothing while the suite stays green.
    it.each(DIALECTS)('%s refuses a format not acknowledged here', (dialect) => {
      expect(() => validatorFor('idn-hostname', dialect)).toThrow(/unknown format "idn-hostname"/);
    });
  });

  for (const dialect of DIALECTS) {
    describe(dialect, () => {
      it.each(table.cases.map((c) => [`${c.format} ${JSON.stringify(c.value)}`, c] as const))(
        '%s',
        (_label, tc) => {
          const want = expected(tc);
          const accepted = validatorFor(tc.format, dialect)({ v: tc.value });
          expect(accepted, tc.why ?? `${tc.format} must ${want ? 'accept' : 'reject'} this value`).toBe(
            want,
          );
        },
      );
    });
  }
});
