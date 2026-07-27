import { validateInputSize } from './converterutil.js';
import { parseStixBundle, stixObjectCVEs, stixObjectId, type StixObject } from './stix.js';

type Doc = Record<string, unknown>;

/**
 * Overlay a STIX 2.1 bundle onto an existing HDF results document, attaching
 * each STIX object as an inert externalReferences[] entry: a CVE-bearing object
 * attaches to the finding whose requirementId is that CVE (fanning out to every
 * match), and everything else — non-CVE objects and CVEs with no matching
 * finding — attaches to the results root. Each entry carries the raw STIX object
 * losslessly in `document`.
 *
 * Informational only: authors no overrides and fabricates no status/impact (the
 * E:A recompute is a separate, opt-in step). The results document is preserved
 * verbatim except for the appended references — manipulated structurally so
 * every pre-existing field, including timestamp strings, round-trips unchanged.
 * TypeScript peer of shared/go/enrich_stix.go (kept at parity).
 */
export function enrichStix(resultsInput: string, bundleInput: string): string {
  validateInputSize(resultsInput, 'enrich-stix');
  validateInputSize(bundleInput, 'enrich-stix');
  if (!resultsInput) throw new Error('enrich-stix: empty results input');

  const bundle = parseStixBundle(bundleInput);

  let doc: Doc;
  try {
    doc = JSON.parse(resultsInput) as Doc;
  } catch (e) {
    throw new Error(`enrich-stix: parsing results: ${(e as Error).message}`);
  }

  const reqById = indexRequirementsById(doc);

  for (const obj of bundle.objects) {
    let matched = false;
    for (const cve of stixObjectCVEs(obj)) {
      for (const req of reqById.get(cve) ?? []) {
        appendExternalReference(req, buildStixRef(obj, 'investigate'));
        matched = true;
      }
    }
    if (!matched) appendExternalReference(doc, buildStixRef(obj, 'reference'));
  }

  return JSON.stringify(doc, null, 2);
}

/** Map each finding id to the requirement objects carrying it (fan-out across baselines). */
function indexRequirementsById(doc: Doc): Map<string, Doc[]> {
  const index = new Map<string, Doc[]>();
  const baselines = Array.isArray(doc.baselines) ? doc.baselines : [];
  for (const b of baselines) {
    const reqs = (b as Doc)?.requirements;
    if (!Array.isArray(reqs)) continue;
    for (const r of reqs) {
      const req = r as Doc;
      if (typeof req.id === 'string' && req.id) {
        const list = index.get(req.id) ?? [];
        list.push(req);
        index.set(req.id, list);
      }
    }
  }
  return index;
}

/** Build an External_Reference envelope carrying the raw STIX object in `document`. */
function buildStixRef(obj: StixObject, rel: 'investigate' | 'reference'): Doc {
  const ref: Doc = {
    sourceName: 'stix',
    kind: 'threat-intel',
    rel,
    document: obj,
  };
  const id = stixObjectId(obj);
  if (id) ref.externalId = id;
  return ref;
}

/** Append a reference to a container's externalReferences[], creating it if absent. */
function appendExternalReference(container: Doc, ref: Doc): void {
  const existing = Array.isArray(container.externalReferences) ? container.externalReferences : [];
  container.externalReferences = [...existing, ref];
}
