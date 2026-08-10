// Evidence-verify engine — the TypeScript peer of hdf-engine/go/evidence.go.
// Pure, filesystem-agnostic core of `hdf evidence verify` (ADR-0007 §11):
// content-checksum classification and plan/results completeness. All filesystem
// IO and path confinement stay in the caller, injected as a FetchFn. Kept at
// behavioural parity with the Go implementation (see test/evidence.test.ts,
// which runs both over the same fixtures).

import { createHash } from 'node:crypto';

/** Classifies a single content entry's checksum verification. */
export type ChecksumStatus = 'match' | 'mismatch' | 'skipped' | 'error';

/** One content entry of an evidence package: a referenced document and its
 * recorded checksum ('' when the entry carries none). */
export interface EvidenceContent {
  uri: string;
  type: string;
  checksum: string;
}

/** The verification outcome for one content entry. */
export interface ChecksumResult {
  uri: string;
  type: string;
  status: ChecksumStatus;
  expected?: string;
  actual?: string;
  error?: string;
}

/** Reports which planned baselines are covered by results. */
export interface CompletenessResult {
  planned: string[];
  covered: string[];
  missing: string[];
  complete: boolean;
}

/** Resolves a content URI to its bytes. The caller owns path confinement
 * (HDF_MCP_ROOT for the MCP, the package directory for the CLI). Throws when the
 * uri cannot be read. */
export type FetchFn = (uri: string) => Uint8Array;

interface RawContent {
  uri?: string;
  type?: string;
  checksum?: { value?: string };
}

/** Extracts the planRef and content entries from an evidence-package document. */
export function parseEvidencePackage(pkg: string): { planRef: string; contents: EvidenceContent[] } {
  const doc = JSON.parse(pkg) as { planRef?: string; contents?: RawContent[] };
  const contents: EvidenceContent[] = (doc.contents ?? []).map((c) => ({
    uri: c.uri ?? '',
    type: c.type ?? '',
    checksum: c.checksum?.value ?? '',
  }));
  return { planRef: doc.planRef ?? '', contents };
}

/** Verifies each content entry's sha256 against fetch(uri), preserving entry
 * order. No checksum → skipped; a fetch throw → error; hash mismatch → mismatch
 * (carrying expected+actual). */
export function verifyChecksums(contents: EvidenceContent[], fetch: FetchFn): ChecksumResult[] {
  return contents.map((c) => {
    const r: ChecksumResult = { uri: c.uri, type: c.type, status: 'skipped' };
    if (c.checksum === '') {
      return r;
    }
    let data: Uint8Array;
    try {
      data = fetch(c.uri);
    } catch (e) {
      return { ...r, status: 'error', error: e instanceof Error ? e.message : String(e) };
    }
    const actual = sha256Hex(data);
    if (actual === c.checksum) {
      return { ...r, status: 'match' };
    }
    return { ...r, status: 'mismatch', expected: c.checksum, actual };
  });
}

/** Extracts assessment baselineRefs from a plan document, deduped in first-seen
 * order. */
export function plannedBaselineRefs(plan: string): string[] {
  const doc = JSON.parse(plan) as { assessments?: Array<{ baselineRef?: string }> };
  const refs = (doc.assessments ?? []).map((a) => a.baselineRef ?? '').filter((s) => s !== '');
  return dedupe(refs);
}

/** Extracts baseline names from a results document, deduped in first-seen order. */
export function coveredBaselineNames(results: string): string[] {
  const doc = JSON.parse(results) as { baselines?: Array<{ name?: string }> };
  const names = (doc.baselines ?? []).map((b) => b.name ?? '').filter((s) => s !== '');
  return dedupe(names);
}

/** Diffs planned baseline refs against covered baseline names. A planned ref is
 * covered when some results baseline shares its name. Missing is sorted so the
 * outcome is deterministic across languages and runs. */
export function completeness(planned: string[], covered: string[]): CompletenessResult {
  const coveredSet = new Set(covered);
  const missing = planned.filter((p) => !coveredSet.has(p)).sort();
  return { planned, covered, missing, complete: missing.length === 0 };
}

function sha256Hex(data: Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

function dedupe(input: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const s of input) {
    if (!seen.has(s)) {
      seen.add(s);
      out.push(s);
    }
  }
  return out;
}
