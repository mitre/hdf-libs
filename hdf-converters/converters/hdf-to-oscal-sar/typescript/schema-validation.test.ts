import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { results } from '@mitre/hdf-fixtures';
import * as testhdf from '@mitre/hdf-schema/testhdf';
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

// Real RHEL 9 STIG scan (cinc-auditor exec-json run against a UBI9 container,
// converted to HDF, trimmed to two requirements) whose code/check/fix text is
// multi-line with leading/trailing whitespace — the content class OSCAL's
// StringDatatype prop pattern forbids. One requirement has impact > 0 (risk
// emitted) and one has impact 0 (no risk), so fix-text carriage is exercised on
// both paths.
const MULTILINE_FIXTURE = readFileSync(
  join(__dirname, '..', 'fixtures', 'input', 'multiline.hdf.json'),
  'utf-8',
);

describe('hdf-to-oscal-sar output validates against NIST OSCAL v1.1.2 AR schema', () => {
  const cases: Array<[string, string]> = [
    ['worst-case (all four defects)', WORST_CASE],
    ['shared minimal fixture', results.minimal.read()],
    ['minimal passed', minimal('passed')],
    ['minimal failed', minimal('failed')],
    ['real STIG multi-line code/check/fix', MULTILINE_FIXTURE],
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

  // Pins byte-exact carriage: relocating prose out of prop values must never
  // collapse, trim, or truncate it. Schema validity alone cannot catch that
  // (remarks are optional), so this walks every requirement in the real
  // multi-line fixture and compares the moved content back against the HDF source.
  it('preserves multi-line content byte-exact in remarks and back-matter', async () => {
    interface FixtureReq {
      id: string;
      impact: number;
      code?: string;
      descriptions?: Array<{ label: string; data: string }>;
    }
    interface OutFinding {
      props?: Array<{ name: string; value: string; remarks?: string }>;
      links?: Array<{ href: string; rel?: string }>;
    }
    interface OutDoc {
      'assessment-results': {
        results: Array<{ findings: OutFinding[] }>;
        'back-matter': { resources: Array<{ uuid: string; base64: { value: string } }> };
      };
    }

    const hdfDoc = JSON.parse(MULTILINE_FIXTURE) as { baselines: Array<{ requirements: FixtureReq[] }> };
    const doc = (JSON.parse(await convertHdfToOscalSar(MULTILINE_FIXTURE)) as OutDoc)['assessment-results'];
    const resourceByHref = new Map(doc['back-matter'].resources.map((r) => [`#${r.uuid}`, r]));

    const reqs = hdfDoc.baselines[0].requirements;
    const findings = doc.results[0].findings;
    expect(findings).toHaveLength(reqs.length);

    reqs.forEach((req, i) => {
      const finding = findings[i];
      if (!finding) throw new Error(`missing finding for ${req.id}`);
      const prop = (name: string) => finding.props?.find((p) => p.name === name);

      const check = req.descriptions?.find((d) => d.label === 'check')?.data;
      expect(check, `${req.id}: fixture must carry check text`).toBeTruthy();
      expect(prop('check')?.remarks, `${req.id}: check text byte-exact in remarks`).toBe(check);

      if (req.impact <= 0) {
        const fix = req.descriptions?.find((d) => d.label === 'fix')?.data;
        expect(fix, `${req.id}: impact-0 fixture must carry fix text`).toBeTruthy();
        expect(prop('fix')?.remarks, `${req.id}: impact-0 fix text byte-exact in remarks`).toBe(fix);
      }

      const codeLink = finding.links?.find((l) => l.rel === 'code');
      expect(codeLink, `${req.id}: finding must link its code resource`).toBeDefined();
      const resource = resourceByHref.get(codeLink?.href ?? '');
      expect(resource, `${req.id}: code link must resolve to a back-matter resource`).toBeDefined();
      const decoded = Buffer.from(resource?.base64.value ?? '', 'base64').toString('utf-8');
      expect(decoded, `${req.id}: code byte-exact from back-matter`).toBe(req.code);
    });
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
