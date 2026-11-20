/**
 * Validation for externally-produced scanner-to-NIST candidate corpora on
 * their way into this repo. A candidate is a scored suggestion for a human to
 * adjudicate, never a mapping: nothing here resolves a scanner check into a
 * `tags.nist` value.
 *
 * The Go twin is go/controlmapping/validate.go, and the two are held to the
 * same refusals by the shared table
 * go/controlmapping/testdata/candidate-validation-cases.json.
 */
import { normalizeNistId } from '../nist/normalize.js';
import { nistExists, SUPPORTED_NIST_REVISIONS } from '../nist/index.js';

/** The only schema literal {@link validateCandidates} accepts. */
export const CANDIDATE_SCHEMA = 'control-mapping-candidates/v1';

/** Refusal codes. Identical literals to the Go twin's Fault* constants. */
export const CandidateFaultCode = {
  DocumentUnparseable: 'document_unparseable',
  SchemaUnknown: 'schema_unknown',
  FieldTypeInvalid: 'field_type_invalid',
  CatalogRevisionMissing: 'catalog_revision_missing',
  CatalogRevisionUnsupported: 'catalog_revision_unsupported',
  CatalogRevisionInconsistent: 'catalog_revision_inconsistent',
  CatalogCommitMissing: 'catalog_commit_missing',
  ScannerNameMissing: 'scanner_name_missing',
  ScannerVersionMissing: 'scanner_version_missing',
  ScannerVersionFloating: 'scanner_version_floating',
  ChecksEmpty: 'checks_empty',
  CheckIdEmpty: 'check_id_empty',
  CheckIdInvalid: 'check_id_invalid',
  CandidatesEmpty: 'candidates_empty',
  ControlMissing: 'candidate_control_missing',
  ControlUnspellable: 'candidate_control_unspellable',
  ControlWrongRevision: 'candidate_control_wrong_revision',
  ControlUnknown: 'candidate_control_unknown',
  ScoreMissing: 'candidate_score_missing',
  ScoreRange: 'candidate_score_range',
} as const;

export type CandidateFaultCode = (typeof CandidateFaultCode)[keyof typeof CandidateFaultCode];

/** One reason a corpus was refused. `path` is a JSON Pointer into the document. */
export interface CandidateFault {
  code: CandidateFaultCode;
  path: string;
  detail: string;
}

/** The NIST catalog the scores were computed against. */
export interface CandidateCatalog {
  source: string;
  revision: number;
  pinnedCommit: string;
}

/** The tool whose check catalog the corpus maps. */
export interface CandidateScanner {
  name: string;
  version: string;
  checks: number;
}

/**
 * One scored suggestion. `control` is upstream's spelling;
 * `normalizedControl` is this repo's canonical spelling of the same id.
 */
export interface Candidate {
  control: string;
  normalizedControl: string;
  controlTitle: string;
  score: number;
  matchedOn: string[];
}

/** One scanner check and its ranked candidates. */
export interface CandidateCheck {
  queryName: string;
  platform: string;
  cwe: string;
  category: string;
  candidates: Candidate[];
}

/** An accepted candidate corpus. */
export interface CandidateCorpus {
  catalog: CandidateCatalog;
  scanner: CandidateScanner;
  /** Upstream's description of how the scores were produced, carried uninterpreted. */
  method?: unknown;
  checks: ReadonlyMap<string, CandidateCheck>;
}

/** The outcome of validation. `corpus` is present only when `faults` is empty. */
export interface CandidateValidation {
  corpus?: CandidateCorpus;
  faults: CandidateFault[];
}

/**
 * Thrown by {@link resolveNistFromCandidates}. Candidates order a review
 * queue; only the adjudicated artifact maps.
 */
export class UnadjudicatedError extends Error {
  constructor() {
    super('candidates are unadjudicated and resolve to no NIST controls');
    this.name = 'UnadjudicatedError';
  }
}

/**
 * Always throws {@link UnadjudicatedError}. It exists so a caller reaching for
 * a mapping is refused rather than handed an empty array that reads as "no
 * controls apply".
 */
export function resolveNistFromCandidates(_corpus: CandidateCorpus, _checkId: string): never {
  throw new UnadjudicatedError();
}

// Upstream writes enhancements with a dot ("SA-10.4"); NIST writes them
// parenthesised ("SA-10 (4)"). NIST uses no dots in control numbers, so the
// substitution is unambiguous.
const DOT_ENHANCEMENT = /\.(\d+)/g;

/**
 * Bounds the scanner's catalog size to what both languages carry identically.
 * Go's float-to-int conversion is implementation-defined beyond int range, and
 * JavaScript has no integer type at all, so an unbounded count could mean two
 * different things in one accepted document.
 */
const MAX_CHECK_COUNT = 2 ** 31 - 1;

/**
 * Leading and trailing blanks, where "blank" is the union of JavaScript's
 * `String.prototype.trim` and Go's `unicode.IsSpace`. The two stdlib sets are
 * not the same — JavaScript trims U+FEFF and not U+0085, Go the reverse — so
 * the contract defines its own set rather than inheriting either, and the Go
 * twin implements this exact union.
 */
const BLANK_EDGES = /^[\s\uFEFF\u0085]+|[\s\uFEFF\u0085]+$/g;

function trimBlank(value: string): string {
  return value.replace(BLANK_EDGES, '');
}

/**
 * Reports whether a string carries an unpaired surrogate or U+FFFD. A check id
 * keys the published mapping, and Go's JSON decoder replaces unpaired
 * surrogates with U+FFFD, so such an id would key the corpus differently in
 * each language.
 */
function hasUndecodableText(value: string): boolean {
  return [...value].some((ch) => {
    const code = ch.codePointAt(0) ?? 0;
    return code === 0xfffd || (code >= 0xd800 && code <= 0xdfff);
  });
}

/**
 * Reports whether any number in the document is non-finite. `JSON.parse` turns
 * an out-of-range literal such as 1e400 into Infinity, where Go's decoder
 * fails outright; without this the two languages would refuse such a document
 * with different faults.
 */
function hasNonFiniteNumber(value: unknown): boolean {
  if (typeof value === 'number') {
    return !Number.isFinite(value);
  }
  if (Array.isArray(value)) {
    return value.some(hasNonFiniteNumber);
  }
  if (typeof value === 'object' && value !== null) {
    return Object.values(value).some(hasNonFiniteNumber);
  }
  return false;
}

/** Orders strings by code point, as Go's byte-wise sort of valid UTF-8 does. */
function compareCodePoints(a: string, b: string): number {
  const left = [...a];
  const right = [...b];
  for (let i = 0; i < Math.min(left.length, right.length); i += 1) {
    const diff = (left[i]?.codePointAt(0) ?? 0) - (right[i]?.codePointAt(0) ?? 0);
    if (diff !== 0) {
      return diff;
    }
  }
  return left.length - right.length;
}

// Version values that name no specific release.
const FLOATING_TAGS = new Set(['latest', 'main', 'master', 'head', 'edge', 'nightly', 'dev', 'stable']);

type JsonObject = Record<string, unknown>;

function jsonType(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

/** Escapes a JSON Pointer reference token (RFC 6901 §3). */
function escapePointer(token: string): string {
  return token.replace(/~/g, '~0').replace(/\//g, '~1');
}

/**
 * Walks a decoded document. Every member is read through {@link Validator.field},
 * so a member of the wrong JSON type is reported against that member rather
 * than coerced — which is what keeps this twin's refusals identical to the Go
 * validator's on a mistyped document.
 */
class Validator {
  readonly faults: CandidateFault[] = [];

  add(code: CandidateFaultCode, path: string, detail: string): void {
    this.faults.push({ code, path, detail });
  }

  field(parent: JsonObject, key: string, path: string, want: string): { value: unknown; ok: boolean } {
    const raw = parent[key];
    if (raw === undefined) {
      return { value: undefined, ok: false };
    }
    // An explicit null is a JSON type like any other, and never the wanted
    // one. Reading it as absence would let a null suppress the member's own
    // "missing" fault and admit a corpus with nothing declared.
    if (jsonType(raw) !== want) {
      this.add(
        CandidateFaultCode.FieldTypeInvalid,
        path,
        `want a JSON ${want}, got ${jsonType(raw)}`
      );
      return { value: undefined, ok: false };
    }
    return { value: raw, ok: true };
  }

  object(parent: JsonObject, key: string, path: string): JsonObject {
    const { value, ok } = this.field(parent, key, path, 'object');
    return ok ? (value as JsonObject) : {};
  }

  str(parent: JsonObject, key: string, path: string): { value: string; ok: boolean } {
    const { value, ok } = this.field(parent, key, path, 'string');
    return { value: ok ? (value as string) : '', ok };
  }

  number(parent: JsonObject, key: string, path: string): { value: number; ok: boolean } {
    const { value, ok } = this.field(parent, key, path, 'number');
    return { value: ok ? (value as number) : 0, ok };
  }

  array(parent: JsonObject, key: string, path: string): { value: unknown[]; ok: boolean } {
    const { value, ok } = this.field(parent, key, path, 'array');
    return { value: ok ? (value as unknown[]) : [], ok };
  }
}

/**
 * Checks a candidate corpus against the contract. Acceptance is all-or-nothing:
 * on any fault no corpus is returned, because a partially-imported corpus
 * leaves adjudication running against an unknown subset.
 */
export function validateCandidates(raw: string): CandidateValidation {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch (error) {
    return {
      faults: [
        {
          code: CandidateFaultCode.DocumentUnparseable,
          path: '',
          detail: error instanceof Error ? error.message : String(error),
        },
      ],
    };
  }

  if (hasNonFiniteNumber(parsed)) {
    return {
      faults: [
        {
          code: CandidateFaultCode.DocumentUnparseable,
          path: '',
          detail: 'the document carries a number outside the range a 64-bit float can represent',
        },
      ],
    };
  }

  if (jsonType(parsed) !== 'object') {
    return {
      faults: [
        {
          code: CandidateFaultCode.DocumentUnparseable,
          path: '',
          detail: 'the document is not a JSON object',
        },
      ],
    };
  }
  const root = parsed as JsonObject;

  if (root.schema !== CANDIDATE_SCHEMA) {
    return {
      faults: [
        {
          code: CandidateFaultCode.SchemaUnknown,
          path: '/schema',
          detail: `schema is ${JSON.stringify(root.schema)}, want ${JSON.stringify(CANDIDATE_SCHEMA)}`,
        },
      ],
    };
  }

  const v = new Validator();
  const { catalog, usable } = validateCatalog(v, v.object(root, 'catalog', '/catalog'));
  const scanner = validateScanner(v, v.object(root, 'scanner', '/scanner'));
  const revision = catalog.revision;

  const checksRaw = v.object(root, 'checks', '/checks');
  if (Object.keys(checksRaw).length === 0) {
    v.add(
      CandidateFaultCode.ChecksEmpty,
      '/checks',
      'a corpus with no checks is an upstream build failure, not an empty import'
    );
    return { faults: v.faults };
  }

  const checks = new Map<string, CandidateCheck>();
  for (const id of Object.keys(checksRaw).sort(compareCodePoints)) {
    const base = `/checks/${escapePointer(id)}`;
    if (hasUndecodableText(id)) {
      v.add(
        CandidateFaultCode.CheckIdInvalid,
        base,
        'a check id carrying U+FFFD came from text that did not survive decoding, and would key the mapping differently in each language'
      );
    }
    if (trimBlank(id) === '') {
      v.add(
        CandidateFaultCode.CheckIdEmpty,
        base,
        'a check id keys the published mapping and cannot be blank'
      );
    }
    const checkRaw = v.object(checksRaw, id, base);
    const candidatesRaw = v.array(checkRaw, 'candidates', `${base}/candidates`);
    if (!candidatesRaw.ok || candidatesRaw.value.length === 0) {
      v.add(
        CandidateFaultCode.CandidatesEmpty,
        `${base}/candidates`,
        'a check with no candidates must be absent, so adjudication cannot read it as reviewed-and-rejected'
      );
    }
    checks.set(id, {
      queryName: v.str(checkRaw, 'query_name', `${base}/query_name`).value,
      platform: v.str(checkRaw, 'platform', `${base}/platform`).value,
      cwe: v.str(checkRaw, 'cwe', `${base}/cwe`).value,
      category: v.str(checkRaw, 'category', `${base}/category`).value,
      candidates: validateCandidateList(v, candidatesRaw.value, base, revision, usable),
    });
  }

  validateRevisionConsistency(v, checks);

  if (v.faults.length > 0) {
    return { faults: v.faults };
  }
  return { corpus: { catalog, scanner, method: root.method, checks }, faults: v.faults };
}

/**
 * Reports the declared revision and whether it can be used for catalog
 * lookups. An unusable revision suppresses per-candidate existence checks, so
 * one missing declaration does not also report every candidate as unknown.
 */
function validateCatalog(
  v: Validator,
  catalog: JsonObject
): { catalog: CandidateCatalog; usable: boolean } {
  const source = v.str(catalog, 'source', '/catalog/source');
  const commit = v.str(catalog, 'pinned_commit', '/catalog/pinned_commit');
  if (!commit.ok || commit.value === '') {
    v.add(
      CandidateFaultCode.CatalogCommitMissing,
      '/catalog/pinned_commit',
      'an unpinned catalog cannot be re-derived, so the scores are unreproducible'
    );
  }
  const out: CandidateCatalog = { source: source.value, revision: 0, pinnedCommit: commit.value };

  const declared = v.number(catalog, 'revision', '/catalog/revision');
  if (!declared.ok) {
    if (catalog.revision === undefined) {
      v.add(
        CandidateFaultCode.CatalogRevisionMissing,
        '/catalog/revision',
        `declare the NIST SP 800-53 revision the corpus was indexed against, one of ${JSON.stringify([...SUPPORTED_NIST_REVISIONS])}`
      );
    }
    return { catalog: out, usable: false };
  }
  // JSON has one number type, so a revision written 5.0 is the integer the
  // contract asks for; 5.5 is not.
  if (!Number.isInteger(declared.value)) {
    v.add(
      CandidateFaultCode.FieldTypeInvalid,
      '/catalog/revision',
      `want a JSON integer, got the fractional number ${declared.value}`
    );
    return { catalog: out, usable: false };
  }
  out.revision = declared.value;
  if (!SUPPORTED_NIST_REVISIONS.includes(out.revision)) {
    v.add(
      CandidateFaultCode.CatalogRevisionUnsupported,
      '/catalog/revision',
      `revision ${out.revision} is not one this repo carries a catalog for ${JSON.stringify([...SUPPORTED_NIST_REVISIONS])}`
    );
    return { catalog: out, usable: false };
  }
  return { catalog: out, usable: true };
}

function validateScanner(v: Validator, scanner: JsonObject): CandidateScanner {
  const name = v.str(scanner, 'name', '/scanner/name');
  if (!name.ok || trimBlank(name.value) === '') {
    v.add(
      CandidateFaultCode.ScannerNameMissing,
      '/scanner/name',
      'the scanner name keys the published mapping'
    );
  }
  const raw = v.str(scanner, 'version', '/scanner/version');
  const version = trimBlank(raw.value);
  const out: CandidateScanner = { name: name.value, version: raw.value, checks: checkCount(v, scanner) };
  if (!raw.ok || version === '') {
    v.add(
      CandidateFaultCode.ScannerVersionMissing,
      '/scanner/version',
      'the scanner stamps its version into its own reports, so a corpus must name the one it scored'
    );
    return out;
  }
  // Accept an image reference and judge its tag, since that is how upstream
  // records the scanner it ran.
  const colon = version.lastIndexOf(':');
  const tag = colon >= 0 ? version.slice(colon + 1) : version;
  if (FLOATING_TAGS.has(tag.toLowerCase())) {
    v.add(
      CandidateFaultCode.ScannerVersionFloating,
      '/scanner/version',
      `${JSON.stringify(version)} names no specific release, leaving the set of checks scored unknowable`
    );
  }
  return out;
}

/**
 * Reads the scanner's catalog size, which the contract declares a non-negative
 * integer. Truncating a fractional value instead would let an accepted
 * document mean different things in the two languages.
 */
function checkCount(v: Validator, scanner: JsonObject): number {
  const count = v.number(scanner, 'checks', '/scanner/checks');
  if (!count.ok) {
    return 0;
  }
  if (!Number.isInteger(count.value) || count.value < 0 || count.value > MAX_CHECK_COUNT) {
    v.add(
      CandidateFaultCode.FieldTypeInvalid,
      '/scanner/checks',
      `want a JSON integer in 0..${MAX_CHECK_COUNT}, got ${count.value}`
    );
    return 0;
  }
  return count.value;
}

function validateCandidateList(
  v: Validator,
  list: unknown[],
  base: string,
  revision: number,
  usable: boolean
): Candidate[] {
  return list.map((entry, index) => {
    const path = `${base}/candidates/${index}`;
    const raw = v.object({ candidate: entry }, 'candidate', path);
    const candidate: Candidate = {
      control: '',
      normalizedControl: '',
      controlTitle: v.str(raw, 'control_title', `${path}/control_title`).value,
      score: 0,
      matchedOn: [],
    };

    const matched = v.array(raw, 'matched_on', `${path}/matched_on`);
    matched.value.forEach((entryValue, j) => {
      const text = v.field({ m: entryValue }, 'm', `${path}/matched_on/${j}`, 'string');
      if (text.ok) {
        candidate.matchedOn.push(text.value as string);
      }
    });

    // Declared a number by the contract and carried upstream for provenance.
    // Read so a mistyped one is refused, not for its value.
    v.number(raw, 'raw', `${path}/raw`);

    const control = v.str(raw, 'control', `${path}/control`);
    if (!control.ok || trimBlank(control.value) === '') {
      v.add(
        CandidateFaultCode.ControlMissing,
        `${path}/control`,
        'a candidate without a control id suggests nothing'
      );
    } else {
      candidate.control = control.value;
      candidate.normalizedControl = validateControl(
        v,
        control.value,
        `${path}/control`,
        revision,
        usable
      );
    }

    const score = v.number(raw, 'score', `${path}/score`);
    if (!score.ok) {
      if (raw.score === undefined) {
        v.add(
          CandidateFaultCode.ScoreMissing,
          `${path}/score`,
          'an unscored candidate cannot be ranked, and absent must not read as 0.0'
        );
      }
    } else if (score.value < 0 || score.value > 1) {
      v.add(
        CandidateFaultCode.ScoreRange,
        `${path}/score`,
        `score ${score.value} is outside the normalised 0..1 range the method declares`
      );
    } else {
      candidate.score = score.value;
    }
    return candidate;
  });
}

/**
 * Reports the canonical spelling of `control`, or `''` when the id is not
 * usable. A control absent at the declared revision but present at another is
 * named distinctly, because the remedy is a revision declaration or a
 * crosswalk translation rather than a data correction.
 */
function validateControl(
  v: Validator,
  control: string,
  path: string,
  revision: number,
  usable: boolean
): string {
  const normalized = normalizeNistId(control.replace(DOT_ENHANCEMENT, ' ($1)'));
  if (normalized === undefined) {
    v.add(
      CandidateFaultCode.ControlUnspellable,
      path,
      `${JSON.stringify(control)} is not a NIST SP 800-53 id spelling`
    );
    return '';
  }
  if (!usable || nistExists(normalized, revision)) {
    return normalized;
  }
  for (const other of SUPPORTED_NIST_REVISIONS) {
    if (other !== revision && nistExists(normalized, other)) {
      v.add(
        CandidateFaultCode.ControlWrongRevision,
        path,
        `${JSON.stringify(control)} is defined at revision ${other}, not the declared revision ${revision}; declare the revision the corpus was indexed against or translate it through the Rev 4 to Rev 5 crosswalk`
      );
      return normalized;
    }
  }
  v.add(
    CandidateFaultCode.ControlUnknown,
    path,
    `NIST defines no control ${JSON.stringify(control)} at any supported revision ${JSON.stringify([...SUPPORTED_NIST_REVISIONS])}`
  );
  return normalized;
}

/**
 * Reports when no single supported revision defines every candidate id. It runs
 * whether or not a revision was declared, because a corpus that declares none
 * is exactly the one whose catalog needs checking: a mixed catalog is a defect
 * in how the corpus was indexed, not in the declaration, and it silently skews
 * every score computed over it.
 */
function validateRevisionConsistency(
  v: Validator,
  checks: ReadonlyMap<string, CandidateCheck>
): void {
  // An id no revision defines is reported as unknown and says nothing about
  // which catalog was indexed, so it is left out of the analysis.
  const ids: string[] = [];
  const seen = new Set<string>();
  for (const id of [...checks.keys()].sort()) {
    for (const candidate of checks.get(id)!.candidates) {
      const norm = candidate.normalizedControl;
      if (norm === '' || seen.has(norm) || !existsAtAnyRevision(norm)) {
        continue;
      }
      seen.add(norm);
      ids.push(norm);
    }
  }
  if (ids.length === 0) {
    return;
  }

  const misses = new Map<number, string[]>();
  for (const rev of SUPPORTED_NIST_REVISIONS) {
    const missing = ids.filter((id) => !nistExists(id, rev));
    if (missing.length === 0) {
      return;
    }
    misses.set(rev, missing);
  }

  const parts = [...SUPPORTED_NIST_REVISIONS].map((rev) => {
    const missing = misses.get(rev)!;
    return `revision ${rev} does not define ${missing.length} of them (e.g. ${missing[0]})`;
  });
  v.add(
    CandidateFaultCode.CatalogRevisionInconsistent,
    '/catalog/revision',
    `no supported revision defines all ${ids.length} candidate control ids, so the corpus was indexed against a mixed catalog: ${parts.join('; ')}`
  );
}

function existsAtAnyRevision(normalized: string): boolean {
  return SUPPORTED_NIST_REVISIONS.some((rev) => nistExists(normalized, rev));
}
