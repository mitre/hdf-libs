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
  jsonDocumentValidator,
  canonicalJSON,
  toGoldenEntries,
  type CorpusCase,
  type CorpusGoldenEntry,
} from './schema-corpus.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

/** The vendored HDF source schemas the corpus contracts are asserted against. */
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
      'requirement-with-non-token-id',
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

  // Keeps the classification honest against the real schema: only MustConvert
  // cases may satisfy it. Distinguishing MustReject from MustNotCorrupt needs
  // the shared guard, which the Go peer does; this side inherits that via the
  // Go-owned golden.
  describe.each([
    ['hdf-results.schema.json', resultsCorpus()],
    ['hdf-amendments.schema.json', amendmentsCorpus()],
  ] as const)('%s contracts match the HDF schema', (schemaName, cases) => {
    const validate = loadSchemaValidator(hdfSchema(schemaName));

    it.each(cases.map((c) => [c.name, c] as const))('%s', (_name, c) => {
      const errors = schemaErrors(validate, JSON.parse(c.input));
      if (c.contract === 'MustConvert') {
        expect(errors, `${c.name} is MustConvert but is not schema-valid HDF`).toBeNull();
        return;
      }
      expect(
        errors,
        `${c.name} is not MustConvert but satisfies ${schemaName} — it proves nothing about error handling`,
      ).not.toBeNull();
    });
  });

  // Guards against a refactor that leaves a contract unrepresented, which would
  // make that obligation pass vacuously for every converter.
  it.each([
    ['results', resultsCorpus()],
    ['amendments', amendmentsCorpus()],
  ] as const)('%s corpus populates its contracts', (_label, cases) => {
    expect(cases.filter((c) => c.contract === 'MustConvert').length).toBeGreaterThan(0);
    expect(cases.filter((c) => c.contract === 'MustReject').length).toBeGreaterThan(0);
  });

  // The cross-language contract. Go owns regeneration of the golden
  // (go test ./shared/go/ -update) and TypeScript only verifies it, so neither
  // side can quietly redefine the shared corpus to match itself. Comparing
  // canonicalized inputs — not just case names — means a changed payload, a
  // reclassified case, or a reordered case all fail here.
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
  // Wrapped: the corpus takes a DocumentValidator over raw converter output, so
  // parsing belongs to the validator rather than to the harness.
  const validate = jsonDocumentValidator(loadSchemaValidator(hdfSchema('hdf-results.schema.json')));
  const mustConvert: CorpusCase = { name: 'a', input: '{}', contract: 'MustConvert', why: 'probe' };
  const mustReject: CorpusCase = { name: 'b', input: '[]', contract: 'MustReject', why: 'probe' };
  const mustNotCorrupt: CorpusCase = {
    name: 'nested',
    input: '{"baselines":[{"name":"b","requirements":[]}]}',
    contract: 'MustNotCorrupt',
    why: 'probe',
  };

  // JS has no panic/error split, so a crash is identified by what was thrown.
  // Letting any of these satisfy MustReject would green-light the defect that
  // contract exists to catch. Raised directly so the tests need no type bypass.
  const CRASHES: Array<[string, unknown]> = [
    ['TypeError', new TypeError("Cannot read properties of undefined (reading 'status')")],
    ['RangeError', new RangeError('Invalid array length')],
    ['ReferenceError', new ReferenceError('x is not defined')],
    ['SyntaxError', new SyntaxError('Unexpected token }')],
    ['a thrown string', 'boom'],
    ['a thrown undefined', undefined],
  ];

  it.each(CRASHES)('%s fails a MustConvert case', async (_label, thrown) => {
    const msg = await checkCase(validate, mustConvert, () => {
      throw thrown;
    });
    expect(msg).toContain('crashed');
  });

  it.each(CRASHES)('%s fails a MustReject case too — a crash is not a rejection', async (_l, thrown) => {
    const msg = await checkCase(validate, mustReject, () => {
      throw thrown;
    });
    expect(msg).toContain('crashed');
  });

  it('MustConvert passes when output satisfies the schema', async () => {
    expect(await checkCase(validate, mustConvert, () => '{"baselines":[]}')).toBeNull();
  });

  it('MustConvert fails when output violates the schema', async () => {
    const msg = await checkCase(validate, mustConvert, () => '{"baselines":"nope"}');
    expect(msg).toContain('does not satisfy the target schema');
  });

  it('MustConvert fails when a schema-valid input is rejected', async () => {
    const msg = await checkCase(validate, mustConvert, () => {
      throw new Error('nope');
    });
    expect(msg).toContain('must convert');
  });

  it('MustReject passes when the converter rejects', async () => {
    const msg = await checkCase(validate, mustReject, () => {
      throw new Error('rejected');
    });
    expect(msg).toBeNull();
  });

  it('MustReject fails when the converter accepts invalid HDF', async () => {
    const msg = await checkCase(validate, mustReject, () => '{"baselines":[]}');
    expect(msg).toContain('must not be converted');
  });

  it('runSchemaCorpus reports every failing case, not just the first', async () => {
    const cases: CorpusCase[] = [
      { ...mustReject, name: 'first' },
      { ...mustReject, name: 'second' },
    ];
    await expect(runSchemaCorpus(validate, cases, () => '{"baselines":[]}')).rejects.toThrow(
      /first[\s\S]*second/,
    );
  });

  // The contract that exists precisely because no converter validates nested
  // content: either outcome is acceptable, but converting nested-invalid input
  // into an invalid document is not.
  it('MustNotCorrupt passes when the converter rejects', async () => {
    const msg = await checkCase(validate, mustNotCorrupt, () => {
      throw new Error('strict');
    });
    expect(msg).toBeNull();
  });

  it('MustNotCorrupt passes when the converter tolerates it and emits valid output', async () => {
    expect(await checkCase(validate, mustNotCorrupt, () => '{"baselines":[]}')).toBeNull();
  });

  it('MustNotCorrupt fails when the converter emits an invalid document', async () => {
    const msg = await checkCase(validate, mustNotCorrupt, () => '{"baselines":"nope"}');
    expect(msg).toContain('target schema rejects');
  });

  it('runSchemaCorpus rejects an empty corpus rather than passing vacuously', async () => {
    await expect(runSchemaCorpus(validate, [], () => '{}')).rejects.toThrow(/corpus is empty/);
  });
});
