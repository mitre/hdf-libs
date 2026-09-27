import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { parseXmlWithArrays } from '@mitre/hdf-utilities';
import { loadXsdValidator, assertXsdValid } from '../../../shared/typescript/xsd-validation.js';
import { resultsCorpus, runSchemaCorpus } from '../../../shared/typescript/schema-corpus.js';
import { normalizeXmlForGolden } from '../../../shared/typescript/xml-golden.js';
import { convertHdfToXccdf } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCHEMAS = join(__dirname, '..', 'schemas');

// The XCCDF schema <xsd:import>s these three by relative schemaLocation, so each
// is preloaded under exactly that name and the chain compiles offline. Validating
// against a truncated chain would silently check less, so the suite proves the
// schema really loaded by asserting that a known-invalid document is rejected.
const validateXccdf = loadXsdValidator(join(SCHEMAS, 'xccdf_1.2.xsd'), [
  'xml.xsd',
  'cpe-language_2.3.xsd',
  'cpe-naming_2.3.xsd',
]);

function hdf(body: Record<string, unknown>): string {
  return JSON.stringify(body);
}

const WITH_TIMESTAMP = hdf({
  timestamp: '2020-01-01T00:00:00Z',
  baselines: [
    {
      name: 'b',
      requirements: [
        {
          id: 'V-1',
          impact: 0,
          tags: { gid: 'V-1' },
          descriptions: [{ label: 'default', data: 'd' }],
          results: [{ status: 'passed', codeDesc: 'c', startTime: '2020-01-01T00:00:00Z' }],
        },
      ],
    },
  ],
});

// Until now this converter had no TypeScript XSD gate at all — the TS side got
// XCCDF coverage only transitively, by matching a golden the Go XSD test
// validated. That made every TS-only defect invisible to the schema.
describe('hdf-to-xccdf XSD validation', () => {
  // The same fixture inputs the Go peer's TestConvertHDFToXCCDF_SchemaValid gates.
  it.each(['minimal.json', 'stig-rhel7.json', 'multiline-rhel9.json'])('validates fixture %s', async (name) => {
    const input = readFileSync(join(__dirname, '..', 'fixtures', 'input', name), 'utf-8');
    await assertXsdValid(validateXccdf, name, convertHdfToXccdf(input));
  });

  it('validates a fully-populated document', async () => {
    await assertXsdValid(validateXccdf, 'with timestamp', convertHdfToXccdf(WITH_TIMESTAMP));
  });

  // The defect this card exists for: end-time is use="required" (xccdf_1.2.xsd)
  // while HDF's timestamp is optional, so the window is derived from the results.
  it('validates when the HDF carries no timestamp', async () => {
    const out = convertHdfToXccdf(
      hdf({
        baselines: [
          {
            name: 'b',
            requirements: [
              {
                id: 'V-1',
                impact: 0,
                tags: {},
                descriptions: [{ label: 'default', data: 'd' }],
                results: [
                  { status: 'passed', codeDesc: 'c', startTime: '2020-01-02T09:00:00Z' },
                  { status: 'failed', codeDesc: 'c2', startTime: '2020-01-02T03:04:05Z' },
                ],
              },
            ],
          },
        ],
      }),
    );

    await assertXsdValid(validateXccdf, 'no timestamp', out);
    expect(out).toContain('end-time="2020-01-02T09:00:00Z"');
    expect(out).toContain('start-time="2020-01-02T03:04:05Z"');
  });

  // Proves the schema chain actually loaded: a validator that failed to compile
  // its imports, or one wired to a stub, would call this valid too.
  it('rejects a document missing the required end-time', async () => {
    const stripped = convertHdfToXccdf(WITH_TIMESTAMP).replace(/ end-time="[^"]*"/, '');
    const errors = await validateXccdf(stripped);
    expect(errors, 'the XSD gate is not actually validating').not.toBeNull();
    expect(errors).toContain('end-time');
  });

  // The same adversarial corpus the Go peer runs, against the same XSD. The
  // harness takes any DocumentValidator, so an XSD-backed exporter opts in the
  // same way a JSON-schema one does — with no exemptions here.
  it('satisfies every corpus contract', async () => {
    await runSchemaCorpus(validateXccdf, resultsCorpus(), (input) => convertHdfToXccdf(input));
  });
});

// Running the corpus in each language proves each satisfies the XSD, which is
// not the same as proving they agree: this side once wrote the literal string
// "undefined" into a rule id where Go wrote nothing, and both forms satisfied the
// pattern, so neither XSD gate noticed. Go owns the golden
// (go test ./converters/hdf-to-xccdf/go/ -update); this side only verifies, so
// neither language can quietly redefine parity to match itself.
describe('hdf-to-xccdf corpus output parity', () => {
  const golden = JSON.parse(
    readFileSync(join(__dirname, '..', 'fixtures', 'expected', 'corpus-outputs.json'), 'utf-8'),
  ) as Record<string, string>;

  it('covers every corpus case', () => {
    expect(Object.keys(golden).sort()).toEqual(resultsCorpus().map((c) => c.name).sort());
  });

  it.each(resultsCorpus().map((c) => [c.name, c] as const))(
    'emits what the Go peer emits for %s',
    (name, c) => {
      let actual: string;
      try {
        actual = normalizeXmlForGolden(convertHdfToXccdf(c.input));
      } catch {
        actual = 'REJECTED';
      }
      expect(actual, `TypeScript and Go diverged on corpus case ${name}`).toBe(golden[name]);
    },
  );
});

// multiline-rhel9.json is two requirements trimmed from a real RHEL 9 STIG scan:
// multi-line description, check and fix text, code ending in a newline, and
// result messages that begin and end with one. Mirrors the Go peer: an XSD pass
// cannot show that the text survived, so each value is parsed back out and
// compared byte-exact with its source.
describe('hdf-to-xccdf multi-line content carriage', () => {
  type Text = string | { '#text'?: string };
  interface Rule {
    id: string;
    description?: Text;
    fixtext?: Text;
    check?: Array<{ system: string; 'check-content'?: Text }>;
  }
  interface Requirement {
    id: string;
    code: string;
    descriptions: Array<{ label: string; data: string }>;
    results: Array<{ message?: string }>;
  }

  const text = (v: Text | undefined): string | undefined => (typeof v === 'object' ? v['#text'] : v);
  const hasEdgeWhitespace = (s: string): boolean => s !== s.trim();

  it('preserves description, check, fix, code and messages byte-exact', () => {
    const input = readFileSync(join(__dirname, '..', 'fixtures', 'input', 'multiline-rhel9.json'), 'utf-8');
    const src = JSON.parse(input) as { baselines: Array<{ requirements: Requirement[] }> };
    expect(src.baselines).toHaveLength(1);

    const bench = (
      parseXmlWithArrays(convertHdfToXccdf(input), ['Group', 'Rule', 'check', 'rule-result'], {
        trimValues: false,
        processEntities: true,
        htmlEntities: true,
      }) as {
        Benchmark: {
          Group?: Array<{ Rule?: Rule[] }>;
          Rule?: Rule[];
          TestResult: { 'rule-result': Array<{ message?: Text }> };
        };
      }
    ).Benchmark;
    const rules = [...(bench.Rule ?? []), ...(bench.Group ?? []).flatMap((g) => g.Rule ?? [])];

    const wantMessages: string[] = [];
    let edgeWhitespace = false;
    for (const req of src.baselines[0]!.requirements) {
      const desc = new Map(req.descriptions.map((d) => [d.label, d.data]));
      expect(desc.get('check'), `${req.id}: the fixture must keep its multi-line prose`).toContain('\n');

      const matching = rules.filter((r) => r.id.includes(req.id));
      expect(matching, `${req.id}: exactly one Rule emitted`).toHaveLength(1);
      const rule = matching[0]!;
      const checks = new Map((rule.check ?? []).map((c) => [c.system, text(c['check-content'])]));

      expect(text(rule.description), `${req.id}: description`).toBe(desc.get('default'));
      expect(text(rule.fixtext), `${req.id}: fixtext`).toBe(desc.get('fix'));
      expect(checks.get('http://oval.mitre.org/XMLSchema/oval-definitions-5'), `${req.id}: check text`).toBe(
        desc.get('check'),
      );
      expect(checks.get('http://inspec.io/'), `${req.id}: InSpec code`).toBe(req.code);

      edgeWhitespace ||= hasEdgeWhitespace(req.code);
      for (const res of req.results) {
        wantMessages.push(res.message ?? '');
        edgeWhitespace ||= hasEdgeWhitespace(res.message ?? '');
      }
    }
    expect(edgeWhitespace, 'the fixture must keep its edge-whitespace values').toBe(true);

    expect(bench.TestResult['rule-result'].map((rr) => text(rr.message) ?? ''), 'result messages').toEqual(
      wantMessages,
    );
  });
});
