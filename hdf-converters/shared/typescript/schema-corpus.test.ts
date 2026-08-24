import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { loadSchemaValidator, schemaErrors } from './schema-validation.js';
import {
  resultsCorpus,
  amendmentsCorpus,
  checkCase,
  runSchemaCorpus,
  canonicalJSON,
  toGoldenEntries,
  type CorpusCase,
  type CorpusGoldenEntry,
} from './schema-corpus.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

/** The vendored HDF source schemas the corpus tiers are asserted against. */
function hdfSchema(name: string): string {
  return join(__dirname, '..', '..', '..', 'hdf-validators', 'go', 'schemas', name);
}

const names = (cases: CorpusCase[]): string[] => cases.map((c) => c.name);

describe('adversarial corpus', () => {
  // A case silently disappearing would leave every converter's corpus run green
  // while covering less, so the names are pinned explicitly rather than counted.
  it('covers the documented results cases', () => {
    expect(names(resultsCorpus())).toEqual([
      'zero-baselines',
      'no-timestamp',
      'requirement-without-title',
      'requirement-without-code',
      'requirement-without-severity',
      'baselines-missing',
      'baselines-null',
      'baselines-wrong-type',
      'baseline-empty-requirements',
      'requirement-empty-results',
      'requirement-missing-id',
      'top-level-array',
    ]);
  });

  it('covers the documented amendments cases', () => {
    expect(names(amendmentsCorpus())).toEqual([
      'override-empty-reason',
      'override-no-milestones',
      'evidence-without-description',
      'overrides-missing',
      'overrides-empty',
      'top-level-array',
    ]);
  });

  // The assertion that makes the two-tier split trustworthy: a case claiming to
  // be schema-valid HDF is validated against the real HDF schema, and a case
  // claiming to be degenerate must actually fail it. Without this, a mislabeled
  // case would quietly assert the wrong contract on every converter.
  describe.each([
    ['hdf-results.schema.json', resultsCorpus()],
    ['hdf-amendments.schema.json', amendmentsCorpus()],
  ] as const)('%s tier labels match the HDF schema', (schemaName, cases) => {
    const validate = loadSchemaValidator(hdfSchema(schemaName));

    it.each(cases.map((c) => [c.name, c] as const))('%s', (_name, c) => {
      const errors = schemaErrors(validate, JSON.parse(c.input));
      if (c.hdfValid) {
        expect(errors, `${c.name} is labeled schema-valid HDF but fails ${schemaName}`).toBeNull();
        return;
      }
      expect(
        errors,
        `${c.name} is labeled degenerate but satisfies ${schemaName} — it proves nothing about error handling`,
      ).not.toBeNull();
    });
  });

  // Guards against a refactor that leaves one tier empty, making runs vacuous.
  it.each([
    ['results', resultsCorpus()],
    ['amendments', amendmentsCorpus()],
  ] as const)('%s corpus populates both tiers', (_label, cases) => {
    expect(cases.filter((c) => c.hdfValid).length).toBeGreaterThan(0);
    expect(cases.filter((c) => !c.hdfValid).length).toBeGreaterThan(0);
  });

  // The cross-language contract. Go owns regeneration of the golden
  // (go test ./shared/go/ -update) and TypeScript only verifies it, so neither
  // side can quietly redefine the shared corpus to match itself. Comparing
  // canonicalized inputs — not just case names — means a changed payload, a
  // flipped tier label, or a reordered case all fail here.
  it('matches the Go corpus golden exactly', () => {
    const golden = JSON.parse(
      readFileSync(join(__dirname, '..', 'corpus-golden.json'), 'utf-8'),
    ) as { results: CorpusGoldenEntry[]; amendments: CorpusGoldenEntry[] };

    expect(toGoldenEntries(resultsCorpus()), 'Go and TS results corpora have diverged').toEqual(
      golden.results,
    );
    expect(
      toGoldenEntries(amendmentsCorpus()),
      'Go and TS amendments corpora have diverged',
    ).toEqual(golden.amendments);
  });

  it('canonicalization sorts keys so cross-language comparison is meaningful', () => {
    expect(canonicalJSON('{"b":1,"a":2,"c":{"z":1,"y":2}}')).toBe('{"a":2,"b":1,"c":{"y":2,"z":1}}');
    // JSON.stringify never escapes these; Go's encoder is configured to match.
    expect(canonicalJSON('{"u":"a<b>c&d"}')).toBe('{"u":"a<b>c&d"}');
  });

  // Each of these diverged between the two languages before being normalized, so
  // a regression would silently break the parity guarantee the golden rests on.
  it('canonicalization normalizes the values that diverged across languages', () => {
    // Go preserves -0 on a float64; JSON.stringify renders it 0.
    expect(canonicalJSON('{"n":-0}')).toBe('{"n":0}');
    // Go escapes these line terminators; JSON.stringify emits them literally.
    expect(canonicalJSON('{"u":"a\u2028b"}')).toBe('{"u":"a\\u2028b"}');
    expect(canonicalJSON('{"u":"a\u2029b"}')).toBe('{"u":"a\\u2029b"}');
  });
});

// The contract every converter delegates its conformance assertion to. It is a
// pure function precisely so these tests can assert the FAILING outcomes
// directly — the outcomes that matter most, and that assertions buried in a test
// closure cannot express without failing the test itself.
describe('corpus contract', () => {
  const validate = loadSchemaValidator(hdfSchema('hdf-results.schema.json'));
  const tierA: CorpusCase = { name: 'a', input: '{}', hdfValid: true, why: 'probe' };
  const tierB: CorpusCase = { name: 'b', input: '[]', hdfValid: false, why: 'probe' };

  // JS has no panic/error split, so a crash is identified by what was thrown.
  // Letting any of these satisfy tier B would green-light the defect that tier
  // exists to catch. Raised directly so the tests need no type bypass.
  const CRASHES: Array<[string, unknown]> = [
    ['TypeError', new TypeError("Cannot read properties of undefined (reading 'status')")],
    ['RangeError', new RangeError('Invalid array length')],
    ['ReferenceError', new ReferenceError('x is not defined')],
    ['SyntaxError', new SyntaxError('Unexpected token }')],
    ['a thrown string', 'boom'],
    ['a thrown undefined', undefined],
  ];

  it.each(CRASHES)('%s fails a tier-A case', async (_label, thrown) => {
    const msg = await checkCase(validate, tierA, () => {
      throw thrown;
    });
    expect(msg).toContain('crashed');
  });

  it.each(CRASHES)('%s fails a tier-B case too — a crash is not a rejection', async (_l, thrown) => {
    const msg = await checkCase(validate, tierB, () => {
      throw thrown;
    });
    expect(msg).toContain('crashed');
  });

  it('tier A passes when output satisfies the schema', async () => {
    expect(await checkCase(validate, tierA, () => '{"baselines":[]}')).toBeNull();
  });

  it('tier A fails when output violates the schema', async () => {
    const msg = await checkCase(validate, tierA, () => '{"baselines":"nope"}');
    expect(msg).toContain('does not satisfy the target schema');
  });

  it('tier A fails when a schema-valid input is rejected', async () => {
    const msg = await checkCase(validate, tierA, () => {
      throw new Error('nope');
    });
    expect(msg).toContain('must convert');
  });

  it('tier B passes when the converter rejects', async () => {
    const msg = await checkCase(validate, tierB, () => {
      throw new Error('rejected');
    });
    expect(msg).toBeNull();
  });

  it('tier B fails when the converter accepts invalid HDF', async () => {
    const msg = await checkCase(validate, tierB, () => '{"baselines":[]}');
    expect(msg).toContain('must be rejected, not converted');
  });

  it('runSchemaCorpus reports every failing case, not just the first', async () => {
    const cases: CorpusCase[] = [
      { ...tierB, name: 'first' },
      { ...tierB, name: 'second' },
    ];
    await expect(runSchemaCorpus(validate, cases, () => '{"baselines":[]}')).rejects.toThrow(
      /first[\s\S]*second/,
    );
  });

  it('runSchemaCorpus rejects an empty corpus rather than passing vacuously', async () => {
    await expect(runSchemaCorpus(validate, [], () => '{}')).rejects.toThrow(/corpus is empty/);
  });
});
