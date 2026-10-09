import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv, { type ValidateFunction } from 'ajv';
import addFormats from 'ajv-formats';
import { results as sharedResults } from '@mitre/hdf-fixtures';
import { describe, expect, it } from 'vitest';
import {
  jsonDocumentValidator,
  resultsCorpus,
  runSchemaCorpus,
} from '../../../shared/typescript/schema-corpus.js';
import { convertHdfToSarif } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtures = join(__dirname, '..', 'fixtures');

/** Matches the Go peer's testVersion so both languages validate the same bytes. */
const TEST_VERSION = '0.0.0';

// There is one vendored copy of the SARIF schema in the repo and both directions
// validate against it.
const schemaPath = join(__dirname, '..', '..', 'sarif-to-hdf', 'fixtures', 'sarif-schema-2.1.0.json');

const rawSchema = JSON.parse(readFileSync(schemaPath, 'utf-8')) as Record<string, unknown>;

/**
 * Compile the vendored SARIF 2.1.0 schema under ajv.
 *
 * OASIS publishes it as JSON Schema draft-04, a dialect ajv 8 dropped, so the
 * dialect pointer and draft-04's `id` are removed in memory and the document is
 * compiled by the draft-07 class — the same in-memory fix-up the shared helper
 * already applies to the draft-04 CSAF companions. The vendored FILE is never
 * edited, and the equivalence test below asserts the one thing that makes the
 * substitution sound.
 */
function loadSarifValidator(): ValidateFunction {
  const schema = { ...rawSchema };
  delete schema.$schema;
  delete schema.id;
  const ajv = new Ajv({ allErrors: true, strict: false, strictSchema: 'log', logger: false });
  addFormats(ajv);
  return ajv.compile(schema);
}

function schemaErrors(validate: ValidateFunction, doc: unknown): string | null {
  if (validate(doc)) return null;
  return (validate.errors ?? []).map((e) => `  ${e.instancePath || '/'} ${e.message ?? ''}`).join('\n');
}

function expectValidSarif(validate: ValidateFunction, label: string, output: string): void {
  const errors = schemaErrors(validate, JSON.parse(output));
  expect(errors, `${label}: output does not satisfy SARIF 2.1.0:\n${errors}`).toBeNull();
}

/**
 * Compiling a draft-04 schema under the draft-07 class is only sound while the
 * document uses no construct whose meaning differs between the two drafts. The
 * divergences that could silently weaken validation are boolean
 * exclusiveMinimum/exclusiveMaximum (a number in draft-06+, so draft-07 would
 * reject the schema rather than mis-read it — but a boolean value would be
 * ignored under strict:false) and `id` as a base-URI declaration, which draft-07
 * spells `$id` and therefore ignores. This asserts both: no boolean exclusive
 * bound anywhere, and no `id` in a schema POSITION other than the root — the
 * eight remaining ones are SARIF's own `id` PROPERTIES.
 */
describe('the vendored draft-04 SARIF schema is draft-07-equivalent', () => {
  const offenders: string[] = [];
  const walk = (node: unknown, path: string, inProperties: boolean): void => {
    if (Array.isArray(node)) {
      node.forEach((v, i) => walk(v, `${path}/${i}`, false));
      return;
    }
    if (node === null || typeof node !== 'object') return;
    const obj = node as Record<string, unknown>;
    for (const key of ['exclusiveMinimum', 'exclusiveMaximum']) {
      if (typeof obj[key] === 'boolean') offenders.push(`${path}/${key} is a draft-04 boolean`);
    }
    if (!inProperties && 'id' in obj && path !== '') {
      offenders.push(`${path}/id declares a draft-04 base URI`);
    }
    for (const [key, value] of Object.entries(obj)) {
      walk(value, `${path}/${key}`, key === 'properties' || key === 'definitions');
    }
  };

  it('uses no draft-04-only construct', () => {
    walk(rawSchema, '', false);
    expect(offenders).toEqual([]);
  });

  it('is the dialect this test claims it is', () => {
    expect(rawSchema.$schema).toBe('http://json-schema.org/draft-04/schema#');
  });
});

describe('hdf-to-sarif output satisfies SARIF 2.1.0', () => {
  const validate = loadSarifValidator();

  // Exactly the golden inputs, so no frozen golden escapes the schema.
  it.each(['flawfinder', 'grype-cve', 'minimal'])('validates the converted %s input', (name) => {
    const input =
      name === 'minimal'
        ? sharedResults.minimal.read()
        : readFileSync(join(fixtures, 'input', `${name}.hdf.json`), 'utf-8');
    expectValidSarif(validate, name, convertHdfToSarif(input, TEST_VERSION));
  });

  // The big real documents are validated but not frozen: a golden for a
  // 16-baseline Prisma export would be hundreds of kilobytes of review noise,
  // while schema validity and the run count are what they prove.
  it.each([
    ['duplicate-baselines', sharedResults.duplicateBaselines, 16],
    ['merge-grype', sharedResults.mergeGrype, 1],
    ['merge-zap', sharedResults.mergeZap, 4],
  ] as const)('validates the large real document %s', (name, fixture, runs) => {
    const out = convertHdfToSarif(fixture.read(), TEST_VERSION);
    expectValidSarif(validate, name, out);
    expect((JSON.parse(out) as { runs: unknown[] }).runs, 'one run per baseline').toHaveLength(runs);
  });

  // No exemptions: SARIF models a log with no runs, so even the zero-baselines
  // case that a checklist cannot represent converts here.
  it('holds to every adversarial corpus contract', async () => {
    await runSchemaCorpus(jsonDocumentValidator(validate), resultsCorpus(), (input) =>
      convertHdfToSarif(input, TEST_VERSION),
    );
  });
});

describe('hdf-to-sarif re-derives rather than replaying stored bytes', () => {
  // Every SARIF result is re-derived from the mapped HDF fields. The exporter
  // never replays rawSourceRecord, whose bytes are the converter's input: a
  // byte-replay would make a round-trip test pass while proving nothing about the
  // field mapping, and would silently re-emit the pre-amendment finding for any
  // document amended after import.
  it('never emits a rawSourceRecord', () => {
    const input = JSON.stringify({
      baselines: [
        {
          name: 'test',
          requirements: [
            {
              id: 'V-1',
              impact: 0.7,
              tags: {},
              descriptions: [{ label: 'default', data: 'd' }],
              results: [
                {
                  status: 'failed',
                  codeDesc: 'the mapped message',
                  startTime: '2020-01-01T00:00:00Z',
                  rawSourceRecord: {
                    content: '{"ruleId":"STALE","kind":"pass","message":{"text":"stale bytes"}}',
                    encoding: 'utf-8',
                    mediaType: 'application/json',
                  },
                },
              ],
            },
          ],
        },
      ],
    });
    const out = convertHdfToSarif(input, TEST_VERSION);
    expect(out).not.toContain('stale bytes');
    expect(out).not.toContain('rawSourceRecord');

    const result = (JSON.parse(out) as { runs: { results: Record<string, any>[] }[] }).runs[0]
      ?.results[0] as Record<string, any>;
    expect(result.ruleId).toBe('V-1');
    expect(result.kind).toBe('fail');
    expect(result.level).toBe('error');
    expect(result.message.text).toBe('the mapped message');
  });

  // rawSourceArtifacts holds the bytes the document was converted FROM. Echoing
  // a whole source artifact back would multiply the output and invite the same
  // byte-replay shortcut.
  it('never echoes rawSourceArtifacts, but keeps producer passthrough', () => {
    const input = JSON.stringify({
      baselines: [
        {
          name: 'b',
          requirements: [
            {
              id: 'V-1',
              impact: 0.5,
              tags: {},
              descriptions: [{ label: 'default', data: 'd' }],
              results: [{ status: 'failed', codeDesc: 'c', startTime: '2020-01-01T00:00:00Z' }],
            },
          ],
        },
      ],
      extensions: {
        passthrough: { vendor: { keep: 'me' } },
        rawSourceArtifacts: [
          {
            rel: 'raw-source',
            sourceName: 'Flawfinder',
            mediaType: 'application/sarif+json',
            encoding: 'utf-8',
            content: 'SOURCE-ARTIFACT-BYTES',
          },
        ],
      },
    });
    const out = convertHdfToSarif(input, TEST_VERSION);
    expect(out).not.toContain('SOURCE-ARTIFACT-BYTES');
    expect(out).not.toContain('rawSourceArtifacts');

    const log = JSON.parse(out) as Record<string, any>;
    expect(log.properties.hdf.extensions.passthrough.vendor).toEqual({ keep: 'me' });
  });
});
