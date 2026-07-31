import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { validateResults } from '@mitre/hdf-validators';
import { enrichStix } from './enrichStix.js';
import { parseStixBundle, detectStixBundle } from './stix.js';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', 'enrich-fixtures');
const fixture = (name: string): string => readFileSync(join(FIXTURES, name), 'utf-8');

type Doc = Record<string, unknown>;
const results = () => fixture('results-input.json');
const bundle = () => fixture('poison-ivy-stix21.json');

function enriched(): Doc {
  return JSON.parse(enrichStix(results(), bundle())) as Doc;
}
function rootRefs(doc: Doc): Doc[] {
  return (Array.isArray(doc.externalReferences) ? doc.externalReferences : []) as Doc[];
}
function requirementById(doc: Doc, id: string): Doc {
  for (const b of doc.baselines as Doc[]) {
    for (const r of (b.requirements as Doc[]) ?? []) {
      if ((r as Doc).id === id) return r as Doc;
    }
  }
  throw new Error(`requirement ${id} not found`);
}
function reqRefs(req: Doc): Doc[] {
  return (Array.isArray(req.externalReferences) ? req.externalReferences : []) as Doc[];
}
// Independent oracle: locate the raw STIX object carrying a CVE, from the bundle.
function sourceObjectByCVE(cve: string): Doc {
  const b = JSON.parse(bundle()) as { objects: Doc[] };
  for (const o of b.objects) {
    const refs = (o.external_references as Doc[]) ?? [];
    if (refs.some((r) => r.source_name === 'cve' && r.external_id === cve)) return o;
  }
  throw new Error(`no STIX object carries ${cve}`);
}

describe('enrichStix — STIX bundle → results externalReferences[]', () => {
  it('attaches CVE-matched objects to the finding, others to the root', () => {
    const doc = enriched();
    expect(rootRefs(doc)).toHaveLength(7); // unmatched CVE + 6 non-CVE objects

    const refs = reqRefs(requirementById(doc, 'CVE-2012-0158'));
    expect(refs).toHaveLength(1);
    expect(refs[0].sourceName).toBe('stix');
    expect(refs[0].kind).toBe('threat-intel');
    expect(refs[0].externalId).toBe('vulnerability--c7cab3fb-0822-43a5-b1ba-c9bab34361a2');
    expect(refs[0].rel).toBe('investigate');

    expect(reqRefs(requirementById(doc, 'CVE-2009-4324'))).toHaveLength(1);
    expect(reqRefs(requirementById(doc, 'SV-999999'))).toHaveLength(0);
  });

  it('carries the raw STIX object losslessly in document', () => {
    const ref = reqRefs(requirementById(enriched(), 'CVE-2012-0158'))[0];
    expect(ref.document).toEqual(sourceObjectByCVE('CVE-2012-0158'));
  });

  it('routes an unmatched CVE to the root with rel "reference"', () => {
    const found = rootRefs(enriched()).find(
      (r) => (r.document as Doc)?.name === 'CVE-2013-0422',
    );
    expect(found, 'unmatched CVE vulnerability must land on the root').toBeDefined();
    expect(found?.rel).toBe('reference');
    expect(found?.sourceName).toBe('stix');
  });

  it('emits exactly one ref per STIX object (ground-truth anchor)', () => {
    const doc = enriched();
    const objectCount = (JSON.parse(bundle()) as { objects: unknown[] }).objects.length;
    let total = rootRefs(doc).length;
    for (const b of doc.baselines as Doc[]) {
      for (const r of (b.requirements as Doc[]) ?? []) total += reqRefs(r as Doc).length;
    }
    expect(total).toBe(objectCount);
    expect(total).toBe(9);
  });

  it('authors zero overrides and leaves status/impact untouched', () => {
    const doc = enriched();
    let overrides = 0;
    for (const b of doc.baselines as Doc[]) {
      for (const r of (b.requirements as Doc[]) ?? []) {
        const so = (r as Doc).statusOverrides;
        if (Array.isArray(so)) overrides += so.length;
      }
    }
    expect(overrides, 'enrich pass must author zero overrides').toBe(0);

    // A CVE-matched finding's status and impact must be preserved verbatim.
    const matched = requirementById(doc, 'CVE-2012-0158');
    expect(matched.impact).toBe(0.9);
    expect((matched.results as Doc[])[0].status).toBe('failed');
  });

  it('produces schema-valid HDF results', () => {
    const v = validateResults(JSON.parse(enrichStix(results(), bundle())));
    expect(v.valid, v.getErrorMessage()).toBe(true);
  });

  it('matches the shared golden (Go↔TS parity)', () => {
    const golden = JSON.parse(fixture('results-enriched.golden.json'));
    expect(JSON.parse(enrichStix(results(), bundle()))).toEqual(golden);
  });

  it('throws on empty results, invalid bundle, and non-bundle JSON', () => {
    expect(() => enrichStix('', bundle())).toThrow();
    expect(() => enrichStix(results(), 'not json')).toThrow();
    expect(() => enrichStix(results(), '{"type":"something-else","objects":[]}')).toThrow();
  });

  it('emits schema-valid references for id-less STIX objects (anyOf description fallback)', () => {
    const b = JSON.stringify({
      type: 'bundle',
      id: 'bundle--1',
      objects: [
        { type: 'campaign', spec_version: '2.1', name: 'th3bug' }, // no id, has name
        { type: 'note', spec_version: '2.1' }, // no id, no name → type-derived
        { spec_version: '2.1', marker: 'typeless' }, // no id, no name, no type → generic
      ],
    });
    const out = enrichStix(results(), b);
    // Every emitted ref must satisfy External_Reference's anyOf even without an id.
    const v = validateResults(JSON.parse(out));
    expect(v.valid, v.getErrorMessage()).toBe(true);

    const refs = rootRefs(JSON.parse(out) as Doc);
    const campaign = refs.find((r) => (r.document as Doc)?.name === 'th3bug');
    expect(campaign?.externalId).toBeUndefined();
    expect(campaign?.description).toBe('th3bug');
    const note = refs.find((r) => (r.document as Doc)?.type === 'note');
    expect(note?.description).toBe('STIX note object');
    const typeless = refs.find((r) => (r.document as Doc)?.marker === 'typeless');
    expect(typeless?.description).toBe('STIX object');
  });
});

describe('enrichStix — opt-in E:H recompute', () => {
  const recResults = () => fixture('results-with-cvss.json');
  const recBundle = () => fixture('poison-ivy-exploited-stix21.json');
  const asOf = new Date('2099-01-01T00:00:00Z');

  it('authors an inline riskAdjustment for an exploited 3.1 finding', () => {
    const doc = JSON.parse(enrichStix(recResults(), recBundle(), { recomputeCvss: true, asOf })) as Doc;
    const req = requirementById(doc, 'CVE-2012-0158');
    const so = (req.statusOverrides as Doc[]) ?? [];
    expect(so).toHaveLength(1);
    const ov = so[0];
    expect(ov.type).toBe('riskAdjustment');
    expect(ov.appliedAt).toBe('2099-01-01T00:00:00Z');
    expect(ov.expiresAt).toBe('2099-04-01T00:00:00Z');
    expect((ov.impact as Doc).value).toBeCloseTo(0.98, 9);
    const cvss = ov.cvss as Doc;
    expect(cvss.version).toBe('3.1');
    expect(cvss.threatVector).toBe('E:H');
    expect(cvss.computedScore).toBeCloseTo(9.8, 9);
    const refs = ov.externalReferences as Doc[];
    expect(refs).toHaveLength(1);
    expect(refs[0].sourceName).toBe('stix');
  });

  it('skips findings with no base vector or a 4.0 base vector (guardrails)', () => {
    const doc = JSON.parse(enrichStix(recResults(), recBundle(), { recomputeCvss: true, asOf })) as Doc;
    expect((requirementById(doc, 'CVE-2009-4324').statusOverrides as Doc[]) ?? []).toHaveLength(0);
    expect((requirementById(doc, 'CVE-2013-0422').statusOverrides as Doc[]) ?? []).toHaveLength(0);
  });

  it('authors nothing unless recompute is opted in', () => {
    const doc = JSON.parse(enrichStix(recResults(), recBundle())) as Doc;
    for (const id of ['CVE-2012-0158', 'CVE-2009-4324', 'CVE-2013-0422']) {
      expect((requirementById(doc, id).statusOverrides as Doc[]) ?? []).toHaveLength(0);
    }
  });

  it('recompute output is schema-valid HDF results', () => {
    const v = validateResults(JSON.parse(enrichStix(recResults(), recBundle(), { recomputeCvss: true, asOf })));
    expect(v.valid, v.getErrorMessage()).toBe(true);
  });
});

describe('enrichStix — detection + error branch coverage', () => {
  const asOf = new Date('2099-01-01T00:00:00Z');
  const results31 = (cve: string, withBaseVector: boolean): string =>
    JSON.stringify({
      baselines: [
        {
          name: 'B',
          checksum: { algorithm: 'sha256', value: 'abc' },
          requirements: [
            {
              id: cve,
              descriptions: [{ label: 'default', data: 'd' }],
              impact: 0.9,
              tags: {},
              results: [{ status: 'failed', codeDesc: 'x', startTime: '2025-01-01T00:00:00Z' }],
              cvss: withBaseVector
                ? [{ version: '3.1', id: cve, baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', baseScore: 9.8 }]
                : [{ version: '3.1', id: cve }],
            },
          ],
        },
      ],
      components: [],
      statistics: {},
    });
  const bundleWith = (obj: Record<string, unknown>): string =>
    JSON.stringify({
      type: 'bundle',
      id: 'bundle--1',
      objects: [
        {
          type: 'vulnerability',
          spec_version: '2.1',
          id: 'vulnerability--v1',
          name: 'CVE-2021-1',
          external_references: [{ source_name: 'cve', external_id: 'CVE-2021-1' }],
        },
        obj,
      ],
    });
  const overrideCount = (out: string, cve: string): number =>
    ((requirementById(JSON.parse(out) as Doc, cve).statusOverrides as Doc[]) ?? []).length;

  it('detects exploitation via a sighting (sighting_of_ref)', () => {
    const b = bundleWith({ type: 'sighting', spec_version: '2.1', id: 'sighting--1', sighting_of_ref: 'vulnerability--v1' });
    expect(overrideCount(enrichStix(results31('CVE-2021-1', true), b, { recomputeCvss: true, asOf }), 'CVE-2021-1')).toBe(1);
  });

  it('detects exploitation via an indicator (object_refs)', () => {
    const b = bundleWith({ type: 'indicator', spec_version: '2.1', id: 'indicator--1', object_refs: ['vulnerability--v1'] });
    expect(overrideCount(enrichStix(results31('CVE-2021-1', true), b, { recomputeCvss: true, asOf }), 'CVE-2021-1')).toBe(1);
  });

  it('skips recompute when a cvss entry carries no base vector', () => {
    const b = bundleWith({ type: 'sighting', spec_version: '2.1', id: 'sighting--1', sighting_of_ref: 'vulnerability--v1' });
    expect(overrideCount(enrichStix(results31('CVE-2021-1', false), b, { recomputeCvss: true, asOf }), 'CVE-2021-1')).toBe(0);
  });

  it('throws on unparseable results JSON', () => {
    expect(() => enrichStix('not json at all', bundle())).toThrow(/parsing results/);
  });
});

describe('stix helper — parse/detect branches', () => {
  it('parseStixBundle throws when objects[] is missing', () => {
    expect(() => parseStixBundle('{"type":"bundle"}')).toThrow(/no objects/);
  });
  it('parseStixBundle throws on a non-bundle type', () => {
    expect(() => parseStixBundle('{"type":"x","objects":[]}')).toThrow(/not a STIX bundle/);
  });
  it('detectStixBundle returns false on invalid JSON, true on a bundle', () => {
    expect(detectStixBundle('not json')).toBe(false);
    expect(detectStixBundle('{"type":"bundle","objects":[]}')).toBe(true);
  });
});

describe('enrichStix — additional branch coverage', () => {
  const asOf = new Date('2099-01-01T00:00:00Z');
  const resultsFor = (cve: string): string =>
    JSON.stringify({
      baselines: [
        {
          name: 'B',
          checksum: { algorithm: 'sha256', value: 'abc' },
          requirements: [
            {
              id: cve,
              descriptions: [{ label: 'default', data: 'd' }],
              impact: 0.9,
              tags: {},
              results: [{ status: 'failed', codeDesc: 'x', startTime: '2025-01-01T00:00:00Z' }],
              cvss: [{ version: '3.1', id: cve, baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', baseScore: 9.8 }],
            },
          ],
        },
      ],
      components: [],
      statistics: {},
    });

  it('omits externalId for a STIX object with no id and ignores non-targets relationships', () => {
    const b = JSON.stringify({
      type: 'bundle',
      id: 'bundle--1',
      objects: [
        { type: 'campaign', spec_version: '2.1', name: 'no-id-campaign' },
        { type: 'relationship', spec_version: '2.1', id: 'relationship--x', relationship_type: 'uses', source_ref: 'a', target_ref: 'b' },
      ],
    });
    const out = JSON.parse(enrichStix(resultsFor('CVE-2021-1'), b, { recomputeCvss: true, asOf })) as Doc;
    expect((requirementById(out, 'CVE-2021-1').statusOverrides as Doc[]) ?? []).toHaveLength(0);
    const rootRef = (out.externalReferences as Doc[]).find((r) => (r.document as Doc)?.name === 'no-id-campaign');
    expect(rootRef).toBeDefined();
    expect(rootRef?.externalId).toBeUndefined();
  });

  it('tolerates an exploited CVE with no matching finding', () => {
    const b = JSON.stringify({
      type: 'bundle',
      id: 'bundle--1',
      objects: [
        { type: 'vulnerability', spec_version: '2.1', id: 'vulnerability--v1', name: 'CVE-2021-1', external_references: [{ source_name: 'cve', external_id: 'CVE-2021-1' }] },
        { type: 'sighting', spec_version: '2.1', id: 'sighting--1', sighting_of_ref: 'vulnerability--v1' },
      ],
    });
    const out = enrichStix(resultsFor('CVE-9999-9'), b, { recomputeCvss: true, asOf });
    expect((requirementById(JSON.parse(out) as Doc, 'CVE-9999-9').statusOverrides as Doc[]) ?? []).toHaveLength(0);
  });
});

describe('enrichStix — recompute relationship/report/existing-override/horizon branches', () => {
  const asOf = new Date('2099-01-01T00:00:00Z');
  const reqWith = (extra: Record<string, unknown>): string =>
    JSON.stringify({
      baselines: [
        {
          name: 'B',
          checksum: { algorithm: 'sha256', value: 'abc' },
          requirements: [
            {
              id: 'CVE-2021-1',
              descriptions: [{ label: 'default', data: 'd' }],
              impact: 0.9,
              tags: {},
              results: [{ status: 'failed', codeDesc: 'x', startTime: '2025-01-01T00:00:00Z' }],
              cvss: [
                { version: '3.1', id: 'CVE-2021-1', baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', baseScore: 9.8 },
              ],
              ...extra,
            },
          ],
        },
      ],
      components: [],
      statistics: {},
    });
  const vuln = {
    type: 'vulnerability',
    spec_version: '2.1',
    id: 'vulnerability--v1',
    name: 'CVE-2021-1',
    external_references: [{ source_name: 'cve', external_id: 'CVE-2021-1' }],
  };
  const bundleWithSignal = (signal: Record<string, unknown>): string =>
    JSON.stringify({ type: 'bundle', id: 'bundle--1', objects: [vuln, signal] });

  it('detects an "exploits" relationship, appends to a pre-existing override, and honors reviewHorizonMs', () => {
    const results = reqWith({ statusOverrides: [{ type: 'riskAdjustment', reason: 'prior' }] });
    const signal = {
      type: 'relationship',
      spec_version: '2.1',
      id: 'relationship--1',
      relationship_type: 'exploits',
      source_ref: 'campaign--c',
      target_ref: 'vulnerability--v1',
    };
    const out = JSON.parse(
      enrichStix(results, bundleWithSignal(signal), { recomputeCvss: true, asOf, reviewHorizonMs: 60_000 }),
    ) as Doc;
    const so = requirementById(out, 'CVE-2021-1').statusOverrides as Doc[];
    expect(so).toHaveLength(2); // prior override preserved, authored one appended
    expect(so[1].type).toBe('riskAdjustment');
    expect(so[1].appliedAt).toBe('2099-01-01T00:00:00Z');
    expect(so[1].expiresAt).toBe('2099-01-01T00:01:00Z'); // asOf + 60_000ms review horizon
  });

  it('detects a "report" object_refs exploitation signal', () => {
    const signal = { type: 'report', spec_version: '2.1', id: 'report--1', object_refs: ['vulnerability--v1'] };
    const out = JSON.parse(
      enrichStix(reqWith({}), bundleWithSignal(signal), { recomputeCvss: true, asOf }),
    ) as Doc;
    expect(requirementById(out, 'CVE-2021-1').statusOverrides as Doc[]).toHaveLength(1);
  });

  it('recomputes off a version-agnostic cvss entry (baseVector present, no id)', () => {
    const results = reqWith({
      cvss: [{ version: '3.1', baseVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', baseScore: 9.8 }],
    });
    const signal = { type: 'sighting', spec_version: '2.1', id: 'sighting--1', sighting_of_ref: 'vulnerability--v1' };
    const out = JSON.parse(
      enrichStix(results, bundleWithSignal(signal), { recomputeCvss: true, asOf }),
    ) as Doc;
    expect(requirementById(out, 'CVE-2021-1').statusOverrides as Doc[]).toHaveLength(1);
  });

  it('defaults appliedAt to now when asOf is omitted', () => {
    // Exercises the `opts.asOf ?? new Date()` default; asserts only that an
    // override is authored with a string timestamp (no wall-clock value assertion).
    const signal = { type: 'sighting', spec_version: '2.1', id: 'sighting--1', sighting_of_ref: 'vulnerability--v1' };
    const out = JSON.parse(enrichStix(reqWith({}), bundleWithSignal(signal), { recomputeCvss: true })) as Doc;
    const so = requirementById(out, 'CVE-2021-1').statusOverrides as Doc[];
    expect(so).toHaveLength(1);
    expect(typeof so[0].appliedAt).toBe('string');
  });
});
