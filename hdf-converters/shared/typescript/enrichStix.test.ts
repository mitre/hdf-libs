import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from 'vitest';
import { validateResults } from '@mitre/hdf-validators';
import { enrichStix } from './enrichStix.js';

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
});
