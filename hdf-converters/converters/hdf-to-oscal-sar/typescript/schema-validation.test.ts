import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { results } from '@mitre/hdf-fixtures';
import * as testhdf from '@mitre/hdf-schema/testhdf';
import { resultsCorpus, runSchemaCorpus } from '../../../shared/typescript/schema-corpus.js';
import { convertHdfToOscalSar } from './converter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// NIST OSCAL v1.1.2 Assessment Results schema. The converter self-declares
// "oscal-version": "1.1.2", so its output must validate against exactly that
// schema. See ../schemas/PROVENANCE.md. Loaded once for all cases.
const arSchema = JSON.parse(
  readFileSync(join(__dirname, '..', 'schemas', 'oscal_assessment-results_schema-v1.1.2.json'), 'utf-8'),
) as object;

// strict:false — validate data against the schema, not lint the (external) schema.
const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
const validateAR = ajv.compile(arSchema);

// Modern HDF crafted to trigger all four #184 defects at once: missing
// reviewed-controls, missing finding.description (empty descriptions), missing
// characterization.origin (impact > 0), and an empty-string prop value (empty code).
const WORST_CASE = JSON.stringify({
  baselines: [
    {
      name: 'worst-case',
      requirements: [
        {
          id: 'AC-3',
          impact: 0.5,
          tags: { nist: ['AC-3'] },
          descriptions: [],
          code: '',
          results: [{ status: 'failed', codeDesc: 'c', startTime: '2026-06-01T00:00:00Z' }],
        },
      ],
    },
  ],
});

const minimal = (status: string): string =>
  JSON.stringify(testhdf.doc(testhdf.baseline('test-baseline',
    testhdf.req('AC-1', {
      impact: 0.5,
      tags: { nist: ['AC-1'] },
      desc: 'Test requirement description',
      status,
    }))));

describe('hdf-to-oscal-sar output validates against NIST OSCAL v1.1.2 AR schema', () => {
  const cases: Array<[string, string]> = [
    ['worst-case (all four defects)', WORST_CASE],
    ['shared minimal fixture', results.minimal.read()],
    ['minimal passed', minimal('passed')],
    ['minimal failed', minimal('failed')],
  ];

  it.each(cases)('%s', async (_label, input) => {
    const out = JSON.parse(await convertHdfToOscalSar(input)) as unknown;
    const valid = validateAR(out);
    if (!valid) {
      const errors = (validateAR.errors ?? [])
        .map((e) => `${e.instancePath || '/'} ${e.message}`)
        .join('\n');
      throw new Error(`output is not valid OSCAL Assessment Results v1.1.2:\n${errors}`);
    }
    expect(valid).toBe(true);
  });
});

// Referential integrity beyond JSON-schema validity (GH #184 follow-up, bead
// d1xo): every characterization.origin.actors[].actor-uuid must resolve to a
// party defined in the same document, and the tool must be a single consistent
// party across the whole document.
interface OriginActor {
  type: string;
  'actor-uuid': string;
}
interface ARDocument {
  'assessment-results': {
    metadata: { parties?: Array<{ uuid: string }> };
    results: Array<{ risks?: Array<{ characterizations?: Array<{ origin?: { actors?: OriginActor[] } }> }> }>;
  };
}

describe('hdf-to-oscal-sar origin actors resolve to a defined party', () => {
  const WITH_TOOL = JSON.stringify({
    tool: { name: 'InSpec', version: '5.22.65', format: 'exec-json' },
    baselines: [
      {
        name: 'b1',
        requirements: [
          { id: 'AC-3', impact: 0.5, tags: { nist: ['AC-3'] }, descriptions: [], results: [{ status: 'failed', codeDesc: 'c', startTime: '2026-06-01T00:00:00Z' }] },
        ],
      },
      {
        name: 'b2',
        requirements: [
          { id: 'AU-2', impact: 0.7, tags: { nist: ['AU-2'] }, descriptions: [], results: [{ status: 'failed', codeDesc: 'c', startTime: '2026-06-01T00:00:00Z' }] },
        ],
      },
    ],
  });

  const cases: Array<[string, string]> = [
    ['tool identity across two baselines', WITH_TOOL],
    ['shared minimal fixture', results.minimal.read()],
  ];

  it.each(cases)('%s', async (_label, input) => {
    const doc = JSON.parse(await convertHdfToOscalSar(input)) as ARDocument;
    const defined = new Set((doc['assessment-results'].metadata.parties ?? []).map((p) => p.uuid));
    const actorUuids = new Set<string>();
    for (const r of doc['assessment-results'].results) {
      for (const risk of r.risks ?? []) {
        for (const c of risk.characterizations ?? []) {
          for (const a of c.origin?.actors ?? []) {
            expect(a['actor-uuid']).toBeTruthy();
            expect(defined.has(a['actor-uuid'])).toBe(true);
            actorUuids.add(a['actor-uuid']);
          }
        }
      }
    }
    expect(actorUuids.size).toBe(1);
  });
});

describe('hdf-to-oscal-sar empty-assessment handling', () => {
  // The converter-specific constraint the shared guard cannot express: the guard
  // checks top-level shape, not the full HDF schema, and it accepts an empty
  // baselines array because hdf-results puts no minItems on it. OSCAL requires
  // results with minItems 1. hdf-libs-wq3u decides whether the HDF schema should
  // carry that constraint too.
  it('rejects an assessment with no evaluated baselines', async () => {
    await expect(convertHdfToOscalSar('{"baselines":[]}')).rejects.toThrow(/at least one result/);
  });

  // Pins the omitempty alignment between the two languages. OSCAL puts minItems 1
  // on a result's findings, observations and risks, so an empty array is invalid
  // where absence is fine. TypeScript emitted [] for all three where Go omits
  // them, which made a baseline whose requirements produce no risks fail the
  // schema on one side only.
  // Unlike the risks case this is NOT reachable from schema-valid HDF —
  // Evaluated_Requirement requires results with minItems 1 — so the input below
  // is deliberately schema-invalid and the branch is defence-in-depth: the shared
  // guard checks top-level shape only, so an upstream producer that skips
  // validation can still reach it. Pinned here because TypeScript is the side
  // that emitted [] for all three fields, and a risks-only test left this path
  // uncovered.
  it('omits observations rather than emitting an empty array', async () => {
    const req = testhdf.req('AC-1', { impact: 0 });
    delete (req as { results?: unknown }).results;
    const out = await convertHdfToOscalSar(JSON.stringify(testhdf.results(req)));

    expect(validateAR(JSON.parse(out)), JSON.stringify(validateAR.errors)).toBe(true);
    expect(out).not.toContain('"observations": []');
  });

  it('omits risks rather than emitting an empty array', async () => {
    // impact 0 produces a finding but no risk.
    const input = JSON.stringify(
      testhdf.results(testhdf.req('AC-1', { impact: 0, status: 'passed' })),
    );
    const out = await convertHdfToOscalSar(input);

    expect(validateAR(JSON.parse(out)), JSON.stringify(validateAR.errors)).toBe(true);
    expect(out).not.toContain('"risks": []');
  });
});

describe('hdf-to-oscal-sar findings without a control id', () => {
  // OSCAL types finding-target.target-id as a token, so an empty one fails the
  // pattern and the whole document with it. The finding is dropped rather than
  // given a derived identifier: an index or a UUID would satisfy the pattern
  // while manufacturing traceability the source never had.
  it('omits the finding and keeps the identified ones', async () => {
    const input = JSON.stringify({
      baselines: [
        {
          name: 'b',
          requirements: [
            {
              impact: 0,
              tags: {},
              descriptions: [{ label: 'default', data: 'd' }],
              results: [{ status: 'passed', codeDesc: 'c', startTime: '2020-01-01T00:00:00Z' }],
            },
            {
              id: 'AC-1',
              impact: 0,
              tags: {},
              descriptions: [{ label: 'default', data: 'd' }],
              results: [{ status: 'passed', codeDesc: 'c', startTime: '2020-01-01T00:00:00Z' }],
            },
          ],
        },
      ],
    });

    const out = await convertHdfToOscalSar(input);
    const doc = JSON.parse(out) as {
      'assessment-results': {
        results: Array<{ findings?: Array<{ target: { 'target-id': string } }> }>;
      };
    };

    expect(validateAR(JSON.parse(out)), JSON.stringify(validateAR.errors)).toBe(true);
    const findings = doc['assessment-results'].results[0].findings ?? [];
    expect(findings).toHaveLength(1);
    expect(findings[0].target['target-id']).toBe('ac-1');
  });
});

// Mirrors the Go corpus run, including the same single exemption. Adding this
// caught a crash Go never saw: req.id arrives undefined here where Go's zero
// value is the empty string.
describe('hdf-to-oscal-sar against the adversarial corpus', () => {
  const CORPUS_EXEMPTIONS: Record<string, string> = {
    'zero-baselines':
      'hdf-libs-wq3u: baselines currently has no minItems, so an empty assessment is legal HDF that OSCAL cannot represent — this converter rejects it deliberately',
  };

  it('satisfies every contract for every non-exempt case', async () => {
    const cases = resultsCorpus().filter((c) => !(c.name in CORPUS_EXEMPTIONS));
    expect(cases.length, 'every case exempted — the run would prove nothing').toBeGreaterThan(0);
    await runSchemaCorpus(validateAR, cases, (input) => convertHdfToOscalSar(input));
  });
});

