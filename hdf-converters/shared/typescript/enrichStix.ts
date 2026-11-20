import { computeCvssScore, parseCvssVector, roundImpact, type CvssScore } from '@mitre/hdf-utilities';
import { limitArrayWithWarning, validateInputSize } from './converterutil.js';
import {
  parseStixBundle,
  stixObjectCVEs,
  stixObjectId,
  type StixBundle,
  type StixObject,
} from './stix.js';

type Doc = Record<string, unknown>;

/** Options for the enrich pass. The empty object is the informational-only pass. */
export interface EnrichOptions {
  /** Enable the opt-in E:H CVSS Threat recompute (Phase 5). Off by default. */
  recomputeCvss?: boolean;
  /** appliedAt for authored overrides; expiresAt = asOf + review horizon. Default: now. */
  asOf?: Date;
  /** Review horizon in ms before an authored riskAdjustment expires. Default: 90 days. */
  reviewHorizonMs?: number;
  /** Cap each input's byte size. Default: the shared DEFAULT_MAX_INPUT_SIZE.
   *  Callers with a user-configurable limit pass it through. */
  maxSize?: number;
}

const DEFAULT_REVIEW_HORIZON_MS = 90 * 24 * 60 * 60 * 1000;

/** Format a Date as canonical trimmed-UTC RFC3339 (seconds precision, matching Go's time.RFC3339). */
function toRfc3339(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * Overlay a STIX 2.1 bundle onto an existing HDF results document, attaching
 * each STIX object as an inert externalReferences[] entry: a CVE-bearing object
 * attaches to the finding whose requirementId is that CVE (fanning out to every
 * match), and everything else — non-CVE objects and CVEs with no matching
 * finding — attaches to the document root. Each entry carries the raw STIX object
 * losslessly in `document`.
 *
 * Informational only: authors no overrides and fabricates no status/impact (the
 * E:A recompute is a separate, opt-in step). The results document is preserved
 * verbatim except for the appended references — manipulated structurally so
 * every pre-existing field, including timestamp strings, round-trips unchanged.
 * TypeScript peer of shared/go/enrich_stix.go (kept at parity).
 */
export function enrichStix(resultsInput: string, bundleInput: string, opts?: EnrichOptions): string {
  // validateInputSize treats a non-positive/undefined limit as the shared
  // default (mirroring Go's ValidateJSONSize + EnrichStix MaxSize contract);
  // a positive opts.maxSize caps the input.
  validateInputSize(resultsInput, 'enrich-stix', opts?.maxSize);
  validateInputSize(bundleInput, 'enrich-stix', opts?.maxSize);
  if (!resultsInput) throw new Error('enrich-stix: empty results input');

  const bundle = parseStixBundle(bundleInput);

  let parsed: unknown;
  try {
    parsed = JSON.parse(resultsInput);
  } catch (e) {
    throw new Error(`enrich-stix: parsing results: ${(e as Error).message}`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('enrich-stix: results input is not a JSON object');
  }
  const doc = parsed as Doc;

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

  // Bound the fan-out. Both dimensions are attacker-controlled from an untrusted
  // threat-intel feed: N bundle objects citing one CVE × M duplicate-id findings
  // that cite it = NxM references, each embedding the full STIX object. Cap the
  // STIX references on every container so output stays linear in the input.
  for (const reqs of reqById.values()) {
    for (const req of reqs) capStixExternalRefs(req, 'finding');
  }
  capStixExternalRefs(doc, 'document root');

  if (opts?.recomputeCvss) recomputeExploitation(bundle, reqById, opts);

  return JSON.stringify(doc, null, 2);
}

/** The CVSS version the exploitation recompute is defined for; E:H is a 3.1 value. */
const RECOMPUTE_CVSS_VERSION = '3.1';

/**
 * Author an inline riskAdjustment on each CVE-matched finding that has a 3.1 base
 * vector and whose CVE carries a structural exploitation signal in the bundle.
 * Applies CVSS Exploit Maturity E:H (the 3.1 analog of 4.0 E:A) and recomputes
 * the Threat score. Skips (no fabrication) when no cvss entry carries a 3.1 base vector.
 * TypeScript peer of recomputeExploitation in enrich_stix.go.
 */
function recomputeExploitation(bundle: StixBundle, reqById: Map<string, Doc[]>, opts: EnrichOptions): void {
  const appliedAt = opts.asOf ?? new Date();
  const expiresAt = new Date(appliedAt.getTime() + (opts.reviewHorizonMs ?? DEFAULT_REVIEW_HORIZON_MS));

  for (const [cve, src] of exploitedCves(bundle)) {
    for (const req of reqById.get(cve) ?? []) {
      const entry = findBaseVectorEntry(req, cve, RECOMPUTE_CVSS_VERSION);
      if (!entry) continue; // no 3.1 base vector → cannot recompute honestly; skip
      const baseVector = entry.baseVector as string;
      let score: CvssScore;
      try {
        score = computeCvssScore(`${baseVector}/E:H`);
      } catch {
        continue; // invalid 3.1 vector → skip, never fabricate
      }
      const ov = buildRiskAdjustment(cve, baseVector, score, src, appliedAt, expiresAt);
      const existing = Array.isArray(req.statusOverrides) ? req.statusOverrides : [];
      req.statusOverrides = [...existing, ov];
    }
  }
}

/**
 * Map each CVE with a structural exploitation signal in the bundle to the STIX
 * object providing it: a sighting (sighting_of_ref), a targets/exploits
 * relationship (target_ref), or an indicator/report (object_refs).
 */
function exploitedCves(bundle: StixBundle): Map<string, Doc> {
  const vulnCves = new Map<string, string[]>();
  for (const o of bundle.objects) {
    // An object without an id cannot be a reference target, so it is not indexed.
    if (o.type === 'vulnerability') {
      const id = stixObjectId(o);
      if (id) vulnCves.set(id, [...(vulnCves.get(id) ?? []), ...stixObjectCVEs(o)]);
    }
  }
  const exploited = new Map<string, Doc>();
  const mark = (vulnId: string, src: Doc): void => {
    for (const cve of vulnCves.get(vulnId) ?? []) {
      if (!exploited.has(cve)) exploited.set(cve, src);
    }
  };
  for (const o of bundle.objects) {
    for (const ref of stixExploitationReferences(o)) mark(ref, o);
  }
  return exploited;
}

const isStixReference = (ref: unknown): ref is string => typeof ref === 'string' && ref !== '';

function stixExploitationReferences(o: Doc): string[] {
  switch (o.type) {
    case 'sighting':
      return isStixReference(o.sighting_of_ref) ? [o.sighting_of_ref] : [];
    case 'relationship':
      if (o.relationship_type !== 'targets' && o.relationship_type !== 'exploits') return [];
      return isStixReference(o.target_ref) ? [o.target_ref] : [];
    case 'indicator':
    case 'report':
      return Array.isArray(o.object_refs) ? o.object_refs.filter(isStixReference) : [];
    default:
      return [];
  }
}

/**
 * The finding's first cvss[] entry whose base vector is of the wanted CVSS
 * version and whose id is the CVE or absent. The version is part of the search
 * because a finding can carry one entry per version: trivy writes its 2.0 entry
 * before its 3.x one.
 */
function findBaseVectorEntry(req: Doc, cve: string, version: string): Doc | undefined {
  const arr = req.cvss;
  if (!Array.isArray(arr)) return undefined;
  for (const e of arr) {
    const m = e as Doc;
    const bv = m.baseVector;
    if (typeof bv !== 'string' || !bv) continue;
    if (parseCvssVector(bv).version !== version) continue;
    const id = m.id;
    if (id === undefined || id === cve) return m;
  }
  return undefined;
}

/** Build the inline riskAdjustment recording the E:H-recomputed Threat score + STIX source. */
function buildRiskAdjustment(
  cve: string,
  baseVector: string,
  score: CvssScore,
  src: Doc,
  appliedAt: Date,
  expiresAt: Date,
): Doc {
  return {
    type: 'riskAdjustment',
    reason: `${cve} actively exploited per STIX threat intelligence (${stixSourceLabel(src)}); CVSS Threat recomputed with Exploit Maturity E:H.`,
    impact: { value: roundImpact(score.temporalScore / 10) },
    appliedBy: { type: 'other', identifier: 'hdf-enrich' },
    appliedAt: toRfc3339(appliedAt),
    expiresAt: toRfc3339(expiresAt),
    cvss: {
      version: score.version,
      baseVector,
      baseScore: score.baseScore,
      threatVector: 'E:H',
      threatScore: score.temporalScore,
      computedScore: score.temporalScore,
    },
    externalReferences: [buildStixRef(src, 'evidence')],
  };
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

/** Build an External_Reference envelope carrying the raw STIX object in `document`. `rel` is an open token. */
function buildStixRef(obj: StixObject, rel: string): Doc {
  const ref: Doc = {
    sourceName: 'stix',
    kind: 'threat-intel',
    rel,
    document: obj,
  };
  const id = stixObjectId(obj);
  if (id) {
    ref.externalId = id;
  } else {
    // No id → satisfy External_Reference's anyOf(externalId/href/description).
    ref.description = stixFallbackDescription(obj);
  }
  return ref;
}

/** Human-readable description for an id-less STIX object: its name, else a
 *  type-derived label, else a generic one — so its reference satisfies anyOf. */
/** Names a STIX object for a reader: its id, or its fallback description. */
function stixSourceLabel(obj: StixObject): string {
  return stixObjectId(obj) || stixFallbackDescription(obj);
}

function stixFallbackDescription(obj: StixObject): string {
  if (typeof obj.name === 'string' && obj.name) return obj.name;
  if (typeof obj.type === 'string' && obj.type) return `STIX ${obj.type} object`;
  return 'STIX object';
}

/** Append a reference to a container's externalReferences[], creating it if absent. */
function appendExternalReference(container: Doc, ref: Doc): void {
  const existing = Array.isArray(container.externalReferences) ? container.externalReferences : [];
  container.externalReferences = [...existing, ref];
}

// Bounds how many STIX externalReferences[] the enrich pass may attach to a
// single container (a finding or the document root). Caps the quadratic fan-out
// from an untrusted bundle without dropping pre-existing (non-STIX) references.
const MAX_STIX_REFS_PER_CONTAINER = 50;

// capStixExternalRefs truncates a container's STIX-sourced externalReferences[]
// to MAX_STIX_REFS_PER_CONTAINER, keeping every non-STIX reference. On truncation
// it logs a warning (via limitArrayWithWarning) and rebuilds the array regrouped —
// non-STIX references first, capped STIX references after — so only the relative
// order WITHIN each group is preserved, not the original interleaving. A no-op
// when the container is under the cap.
function capStixExternalRefs(container: Doc, label: string): void {
  const refs = container.externalReferences;
  if (!Array.isArray(refs) || refs.length === 0) return;
  const stix: unknown[] = [];
  const other: unknown[] = [];
  for (const r of refs) {
    if (r !== null && typeof r === 'object' && (r as Doc).sourceName === 'stix') stix.push(r);
    else other.push(r);
  }
  if (stix.length <= MAX_STIX_REFS_PER_CONTAINER) return;
  const capped = limitArrayWithWarning(stix, `enrich-stix ${label} references`, MAX_STIX_REFS_PER_CONTAINER);
  container.externalReferences = [...other, ...capped];
}
