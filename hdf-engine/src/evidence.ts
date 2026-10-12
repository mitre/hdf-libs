// Evidence-verify engine — the TypeScript peer of hdf-engine/go/evidence.go.
// Pure, filesystem-agnostic core of `hdf evidence info --verify` (ADR-0007 §11):
// content-checksum classification and plan/results completeness. All filesystem
// IO and path confinement stay in the caller, injected as a FetchFn. Kept at
// behavioural parity with the Go implementation (see test/evidence.test.ts,
// which runs both over the same fixtures).

import { createHash } from 'node:crypto';
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { agentOverrideCount } from './compliance.js';
import type { HDFResults } from '@mitre/hdf-schema';

/** Classifies a single content entry's checksum verification. 'unsupported' is a
 * recorded algorithm this build cannot compute — deliberately NOT 'error', since the
 * bytes may be intact and the package valid. Every consumer switching on this type
 * must handle it; leaving it to a default reports an unverified entry as verified. */
export type ChecksumStatus = 'match' | 'mismatch' | 'skipped' | 'error' | 'unsupported';

/** One content entry of an evidence package: a referenced document and its
 * recorded checksum ('' when the entry carries none). */
export interface EvidenceContent {
  uri: string;
  type: string;
  checksum: string;
  /** The algorithm the package recorded, '' when it stated none. Optional so an
   * omitted field behaves exactly like Go's zero-valued string: absent means
   * sha256 at verification time. The sha256 default belongs to verification, not
   * to the parse, so an unstated algorithm is not invented here. */
  checksumAlgorithm?: string;
  /** Distinguishes an entry carrying no checksum object from one carrying a
   * checksum whose value is empty. `checksum` alone conflates them, and the
   * difference matters: a recorded-but-blank value is unverifiable, whereas an
   * absent checksum is simply not a claim. Optional so an omitted field behaves
   * like Go's zero-valued bool. */
  checksumRecorded?: boolean;
  /** Set for an `externalEvidence[]` entry and absent for a `contents[]` one;
   * `type` is the reverse. The schema gives the two arrays different fields — a
   * content entry records a Content_Type, an external entry records a native
   * Native_Format — so they are kept apart rather than collapsed into `type`,
   * which would put 'raw-log' in a field whose vocabulary is the seven document
   * types. Optional so an omitted field behaves like Go's zero-valued string. */
  format?: string;
}

/** The verification outcome for one content entry. */
export interface ChecksumResult {
  uri: string;
  type: string;
  /** Mirrors `EvidenceContent.format`: set for an `externalEvidence[]` entry,
   * absent for a `contents[]` one, so a caller can report what an artifact is
   * without reading `type`'s Content_Type vocabulary onto it. */
  format?: string;
  /** The algorithm this entry's checksum is recorded under, with an unstated one
   * reported as the sha256 it defaults to. Absent for a skipped entry — one with no
   * checksum VALUE to verify, whether it carries no checksum at all or one whose
   * value is blank (Checksum.value has no minLength, so a blank value is
   * schema-valid and may still name an algorithm). Nothing was hashed in either
   * case, and naming an algorithm would imply a computation that never ran. */
  algorithm?: string;
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

type RawObject = Record<string, unknown>;

/** Go decodes into a typed struct, so a JSON `null` document leaves zero values
 * while a wrong-typed one is a decode error. These three helpers give the TS
 * peer the same split instead of asserting a shape onto untrusted input. */
function parseDocument(text: string, what: string): RawObject {
  const doc: unknown = JSON.parse(text);
  if (doc === null) return {};
  if (typeof doc !== 'object' || Array.isArray(doc)) {
    throw new Error(`parse ${what}: cannot unmarshal ${describe(doc)} into an object`);
  }
  return doc as RawObject;
}

function objectArray(value: unknown, what: string, field: string): RawObject[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) {
    throw new Error(`parse ${what}: cannot unmarshal ${describe(value)} into ${field}`);
  }
  return value.map((entry: unknown) => {
    if (entry === null) return {};
    if (typeof entry !== 'object' || Array.isArray(entry)) {
      throw new Error(`parse ${what}: cannot unmarshal ${describe(entry)} into a ${field} entry`);
    }
    return entry as RawObject;
  });
}

function str(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

function describe(value: unknown): string {
  return Array.isArray(value) ? 'array' : value === null ? 'null' : typeof value;
}

/** Extracts the planRef and content entries from an evidence-package document. */
export function parseEvidencePackage(pkg: string): { planRef: string; contents: EvidenceContent[] } {
  const doc = parseDocument(pkg, 'evidence package');
  const contents: EvidenceContent[] = objectArray(doc.contents, 'evidence package', 'contents').map((c) => {
    const checksum = c.checksum;
    const isObject = typeof checksum === 'object' && checksum !== null;
    return {
      uri: str(c.uri),
      type: str(c.type),
      checksum: isObject ? str((checksum as RawObject).value) : '',
      checksumAlgorithm: isObject ? str((checksum as RawObject).algorithm) : '',
      checksumRecorded: isObject,
    };
  });
  return { planRef: str(doc.planRef), contents };
}

/** Returns the `externalEvidence[]` entries as the same shape `contents[]` parses
 * to, so ONE verification pass covers both arrays. It exists because verify
 * examined `contents[]` only, and a wrong checksum in the other array passed at
 * exit 0 while bundle refused the same package — the two commands disagreeing
 * about one document.
 *
 * Additive on purpose: `verifyChecksums` is reused unchanged on what this returns,
 * so the hashing has one implementation rather than one per array. */
export function parseExternalEvidence(pkg: string): EvidenceContent[] {
  const doc = parseDocument(pkg, 'evidence package');
  return objectArray(doc.externalEvidence, 'evidence package', 'externalEvidence').map((e) => {
    const checksum = e.checksum;
    const isObject = typeof checksum === 'object' && checksum !== null;
    return {
      uri: str(e.uri),
      type: '',
      format: str(e.format),
      checksum: isObject ? str((checksum as RawObject).value) : '',
      checksumAlgorithm: isObject ? str((checksum as RawObject).algorithm) : '',
      checksumRecorded: isObject,
    };
  });
}

/** Verifies each content entry against fetch(uri) using the algorithm the entry
 * recorded, preserving entry order. No checksum → skipped; an algorithm this
 * build cannot compute → unsupported, never mismatch (that would say their evidence
 * changed when it did not) and never error, since the bytes may be intact; a fetch throw → error;
 * hash mismatch → mismatch (carrying expected+actual). */
export function verifyChecksums(contents: EvidenceContent[], fetch: FetchFn): ChecksumResult[] {
  return contents.map((c) => {
    const r: ChecksumResult = { uri: c.uri, type: c.type, status: 'skipped' };
    if (c.format !== undefined && c.format !== '') {
      r.format = c.format;
    }
    if (c.checksum === '') {
      return r;
    }
    r.algorithm = effectiveAlgorithm(c.checksumAlgorithm);
    // The algorithm is checked before any IO: whether this build can compute it
    // is a property of the package, not of the filesystem.
    if (!supportedAlgorithm(c.checksumAlgorithm)) {
      return { ...r, status: 'unsupported', error: unsupportedAlgorithmMessage(c.checksumAlgorithm) };
    }
    let data: Uint8Array;
    try {
      data = fetch(c.uri);
    } catch (e) {
      return { ...r, status: 'error', error: e instanceof Error ? e.message : String(e) };
    }
    const actual = checksumHex(c.checksumAlgorithm, data);
    if (actual === c.checksum) {
      return { ...r, status: 'match' };
    }
    return { ...r, status: 'mismatch', expected: c.checksum, actual };
  });
}

/** Extracts assessment baselineRefs from a plan document, deduped in first-seen
 * order. */
export function plannedBaselineRefs(plan: string): string[] {
  const doc = parseDocument(plan, 'plan');
  const refs = objectArray(doc.assessments, 'plan', 'assessments')
    .map((a) => str(a.baselineRef))
    .filter((s) => s !== '');
  return dedupe(refs);
}

/** Extracts baseline names from a results document, deduped in first-seen order. */
export function coveredBaselineNames(results: string): string[] {
  const doc = parseDocument(results, 'results');
  const names = objectArray(doc.baselines, 'results', 'baselines')
    .map((b) => str(b.name))
    .filter((s) => s !== '');
  return dedupe(names);
}

/** Concatenates the covered baseline names of every hdf-results document the
 * package references, in entry order. An entry that cannot be fetched or parsed
 * is skipped: checksum verification is what reports a read failure, and a
 * partial coverage list is what the completeness diff needs. */
export function coveredBaselinesInPackage(contents: EvidenceContent[], fetch: FetchFn): string[] {
  const covered: string[] = [];
  forEachResultsDocument(contents, fetch, (text) => {
    try {
      covered.push(...coveredBaselineNames(text));
    } catch {
      return;
    }
  });
  return covered;
}

/** Sums the agent-attributed override count across every hdf-results document
 * the package references. Unreadable or unparseable entries are skipped. */
export function agentOverridesInPackage(contents: EvidenceContent[], fetch: FetchFn): number {
  let total = 0;
  forEachResultsDocument(contents, fetch, (text) => {
    try {
      total += agentOverrideCount(JSON.parse(text) as HDFResults);
    } catch {
      return;
    }
  });
  return total;
}

/** Fetches each referenced hdf-results document in entry order, skipping
 * entries that carry no uri or cannot be read. */
function forEachResultsDocument(
  contents: EvidenceContent[],
  fetch: FetchFn,
  visit: (text: string) => void
): void {
  for (const c of contents) {
    if (c.type !== 'hdf-results' || c.uri === '') {
      continue;
    }
    let data: Uint8Array;
    try {
      data = fetch(c.uri);
    } catch {
      continue;
    }
    visit(new TextDecoder().decode(data));
  }
}

/** Diffs planned baseline refs against covered baseline names. A planned ref is
 * covered when some results baseline shares its name. Missing is sorted so the
 * outcome is deterministic across languages and runs. */
export function completeness(planned: string[], covered: string[]): CompletenessResult {
  const coveredSet = new Set(covered);
  const missing = planned.filter((p) => !coveredSet.has(p)).sort();
  return { planned, covered, missing, complete: missing.length === 0 };
}

/** The algorithms this build can verify — every value Hash_Algorithm admits. An
 * algorithm outside the enum is refused by name rather than silently treated as
 * something else. Kept identical to Go's ChecksumHex. */
const SUPPORTED_ALGORITHMS = ['sha256', 'sha384', 'sha512', 'blake3'] as const;

/** Names the algorithm an entry's checksum is verified under: an unstated
 * algorithm means sha256, so reporting '' would understate it. */
function effectiveAlgorithm(recorded: string | undefined): string {
  return !recorded ? 'sha256' : recorded;
}

function supportedAlgorithm(algorithm: string | undefined): boolean {
  return !algorithm || (SUPPORTED_ALGORITHMS as readonly string[]).includes(algorithm);
}

/** Formats the algorithm list exactly as Go's ChecksumHex does, so the two languages
 * emit the SAME user-visible refusal rather than two spellings of it. */
function algorithmList(): string {
  const all = SUPPORTED_ALGORITHMS as readonly string[];
  return `${all.slice(0, -1).join(', ')} and ${all[all.length - 1]}`;
}

function unsupportedAlgorithmMessage(algorithm: string | undefined): string {
  return `unsupported checksum algorithm "${algorithm}": this build computes ${algorithmList()}`;
}

/** Hashes data with the named Hash_Algorithm, hex-encoded. An empty algorithm
 * means sha256, so a package that records only a value keeps its meaning. Throws
 * for an algorithm this build cannot compute. */
export function checksumHex(algorithm: string | undefined, data: Uint8Array): string {
  if (!supportedAlgorithm(algorithm)) {
    throw new Error(unsupportedAlgorithmMessage(algorithm));
  }
  if (algorithm === 'blake3') {
    // Node's crypto offers blake2b512 and blake2s256 only, so this is the one
    // algorithm in the enum that needs a package. The 32-byte default-length digest
    // is what the BLAKE3 reference vectors direct implementations to compare.
    return bytesToHex(blake3(data));
  }
  return createHash(!algorithm ? 'sha256' : algorithm)
    .update(data)
    .digest('hex');
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
