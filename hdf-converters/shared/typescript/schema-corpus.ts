/**
 * Adversarial exporter inputs, shared across every converter's schema tests.
 *
 * The TS peer of shared/go/schemacorpus.go. The two corpora are asserted
 * byte-equal (after canonicalization) against a Go-generated golden, so a case
 * added, renamed, reclassified, or altered on one side alone fails the build rather
 * than silently going uncovered on the other.
 */
import * as testhdf from '@mitre/hdf-schema/testhdf';
import { EvidenceType, type HDFResults } from '@mitre/hdf-schema';
import type { ValidateFunction } from 'ajv';
import { schemaErrors } from './schema-validation.js';

/**
 * The obligation an exporter owes for one corpus input.
 *
 * A single "HDF-invalid input must be rejected" rule conflated two different
 * obligations. A document whose TOP-LEVEL shape is wrong is not the document
 * type it claims to be, and refusing it is the only honest outcome. A document
 * that is merely wrong in NESTED content is something no converter validates —
 * the shared structural guard is deliberately top-level only — so demanding
 * rejection there asserted something no converter satisfies, which forced
 * per-converter exemptions. Exemptions that accumulate quietly are how a corpus
 * stops meaning anything, so the distinction belongs to the case.
 *
 * - `MustConvert`: sparse but schema-valid HDF. Must convert, and the output
 *   must satisfy the target schema. Refusing legal input is as much a defect as
 *   emitting an invalid document for it.
 * - `MustReject`: the top-level shape is wrong. The exporter must throw.
 * - `MustNotCorrupt`: only nested content is invalid. Converting or refusing are
 *   both acceptable, but if it converts, the output must still satisfy the
 *   target schema.
 */
export type CorpusContract = 'MustConvert' | 'MustReject' | 'MustNotCorrupt';

/**
 * One adversarial exporter input. Every shipped defect this corpus exists to
 * catch sat in one of the three contracts above, and a suite that only feeds
 * fully-populated fixtures exercises none of them.
 */
export interface CorpusCase {
  name: string;
  input: string;
  /**
   * The obligation the exporter owes for this input. Derived observably rather
   * than asserted: the Go peer checks each case against the real HDF schema AND
   * the shared top-level guard, and the Go-owned golden pins the result here, so
   * a case cannot be quietly reclassified to make a converter pass.
   */
  contract: CorpusContract;
  /** What the case is probing, surfaced in failure output. */
  why: string;
}

const CVE = 'CVE-2021-44228';

/** The builder's fixed result time, reused so corpus inputs never touch the wall clock. */
const DEFAULT_TIME = '2020-01-01T00:00:00Z';

/**
 * Stamps the deterministic builder time onto a document so a case probing some
 * other absent field is not silently also probing a missing timestamp.
 *
 * Returns a JSON payload rather than an HDFResults, deliberately: the field is
 * typed Date, and a Date stringifies with milliseconds ("...T00:00:00.000Z")
 * while Go emits the trimmed form. That is a real value difference, which
 * canonicalization would NOT paper over — so the trimmed string is assigned here
 * to keep the corpora byte-equal once canonicalized.
 */
function withTimestamp(d: HDFResults): Record<string, unknown> {
  return { ...d, timestamp: DEFAULT_TIME };
}

/**
 * Adversarial HDF Results inputs every exporter consuming HDF Results should
 * survive. Every MustConvert case is built with the testhdf builder, including
 * `zero-baselines` — a JS rest parameter yields [], so `doc()` emits
 * `"baselines": []`. (Go's peer cannot do this: a variadic leaves the slice nil
 * and HDFResults.Baselines has no omitempty, so it marshals to null. That one
 * case is a typed struct literal there. The asymmetry is real, not an oversight.)
 *
 * Each MustConvert case isolates exactly one absent field, so a failure names the
 * cause rather than leaving two candidates.
 */
export function resultsCorpus(): CorpusCase[] {
  return [
    // --- MustConvert: sparse but schema-valid HDF.
    {
      name: 'zero-baselines',
      input: JSON.stringify(testhdf.doc()),
      contract: 'MustConvert',
      why: 'baselines has no minItems, so an assessment that evaluated nothing is legal HDF',
    },
    {
      // Everything else populated, so a failure here is unambiguously the timestamp.
      name: 'no-timestamp',
      input: JSON.stringify(
        testhdf.results(testhdf.req('V-1', { title: 't', severity: 'medium', code: 'c' })),
      ),
      contract: 'MustConvert',
      why: 'timestamp is optional in HDF but feeds target fields that are required (XCCDF end-time)',
    },
    {
      name: 'requirement-without-title',
      input: JSON.stringify(
        withTimestamp(testhdf.results(testhdf.req('V-1', { severity: 'medium', code: 'c' }))),
      ),
      contract: 'MustConvert',
      why: 'title is optional in HDF but backs target title fields that are often minLength-constrained',
    },
    {
      name: 'requirement-without-code',
      input: JSON.stringify(
        withTimestamp(testhdf.results(testhdf.req('V-1', { title: 't', severity: 'medium' }))),
      ),
      contract: 'MustConvert',
      why: 'absent code must omit the check element entirely, not emit an empty one',
    },
    {
      name: 'requirement-without-severity',
      input: JSON.stringify(
        withTimestamp(testhdf.results(testhdf.req('V-1', { title: 't', code: 'c' }))),
      ),
      contract: 'MustConvert',
      why: 'severity is optional in HDF but target formats constrain it to a fixed vocabulary',
    },

    // --- MustReject: the top-level shape is wrong, so this is not a results
    // document at all. MustNotCorrupt: the top level is fine and only nested
    // content is invalid, which no converter validates.
    {
      name: 'baselines-missing',
      input: '{"generator":{"name":"t","version":"0.0.0"}}',
      contract: 'MustReject',
      why: 'baselines is the one required top-level field',
    },
    {
      name: 'baselines-null',
      input: '{"baselines":null}',
      contract: 'MustReject',
      why: 'a nil slice marshals to null, so an upstream producer with this bug must be rejected',
    },
    {
      name: 'baselines-wrong-type',
      input: '{"baselines":"not-an-array"}',
      contract: 'MustReject',
      why: 'a typed decode can coerce or zero-fill where a structural guard must reject',
    },
    {
      name: 'baseline-empty-requirements',
      input: '{"baselines":[{"name":"b","requirements":[]}]}',
      contract: 'MustNotCorrupt',
      why: 'requirements has minItems 1; exporters that map it unguarded emit empty container elements',
    },
    {
      name: 'requirement-empty-results',
      input:
        '{"baselines":[{"name":"b","requirements":[{"id":"V-1","impact":0,"tags":{},"descriptions":[{"label":"default","data":"d"}],"results":[]}]}]}',
      contract: 'MustNotCorrupt',
      why: 'results has minItems 1; exporters that index results[0] unguarded crash',
    },
    {
      name: 'requirement-missing-id',
      input:
        '{"baselines":[{"name":"b","requirements":[{"impact":0,"tags":{},"descriptions":[{"label":"default","data":"d"}],"results":[{"status":"passed","codeDesc":"c","startTime":"2020-01-01T00:00:00Z"}]}]}]}',
      contract: 'MustNotCorrupt',
      why: 'id is required; absent it, exporters emit empty-string identifiers into required target fields',
    },
    {
      name: 'top-level-array',
      input: '[]',
      contract: 'MustReject',
      why: 'the one degenerate shape most exporters already reject — pins that they keep doing so',
    },
  ];
}

/**
 * Adversarial HDF Amendments inputs every exporter consuming HDF Amendments
 * should survive. Every MustConvert override carries a status because the amendments
 * schema requires an override to declare either `status` or `impact`.
 */
export function amendmentsCorpus(): CorpusCase[] {
  return [
    // --- MustConvert: sparse but schema-valid HDF Amendments.
    {
      name: 'override-empty-reason',
      input: JSON.stringify(
        testhdf.amendments('a', testhdf.override('waiver', CVE, { status: 'failed', reason: '' })),
      ),
      contract: 'MustConvert',
      why: 'reason carries no minLength, but backs target fields that require non-empty text',
    },
    {
      name: 'override-no-milestones',
      input: JSON.stringify(
        testhdf.amendments(
          'a',
          testhdf.override('waiver', CVE, { status: 'failed', reason: 'accepted' }),
        ),
      ),
      contract: 'MustConvert',
      why: 'milestones are optional; without them remediation text must still be derivable',
    },
    {
      name: 'evidence-without-description',
      input: amendmentsWithBareEvidence(),
      contract: 'MustConvert',
      why: 'evidence description is optional but backs CSAF references[].summary, which is minLength 1',
    },

    // --- MustReject: the top-level shape is wrong.
    {
      name: 'overrides-missing',
      input: '{"name":"a"}',
      contract: 'MustReject',
      why: 'overrides is required alongside name',
    },
    {
      name: 'overrides-empty',
      input: '{"name":"a","overrides":[]}',
      contract: 'MustReject',
      why: 'overrides has minItems 1, so an amendments document that amends nothing is not convertible',
    },
    {
      name: 'top-level-array',
      input: '[]',
      contract: 'MustReject',
      why: 'pins that the structural guard rejects a non-object document',
    },
  ];
}

/**
 * Builds an override carrying url evidence with no description. testhdf.override
 * exposes no evidence option, so the override is finished by hand here rather
 * than hand-writing the whole document — keeping the builder's schema-valid
 * scaffolding (appliedAt, expiresAt, identity), the tedious part to get right.
 */
function amendmentsWithBareEvidence(): string {
  const override = testhdf.override('waiver', CVE, { status: 'failed', reason: 'accepted' });
  override.evidence = [{ type: EvidenceType.URL, data: 'https://example.com/advisory' }];
  return JSON.stringify(testhdf.amendments('a', override));
}

/** An exporter entry point taking raw HDF text and returning its rendered output. */
export type CorpusConvertFn = (input: string) => Promise<unknown> | unknown;

/**
 * Apply the corpus contract to a single case, returning why it failed or null
 * when it passes.
 *
 * The contract is a pure function, not assertions inside a test closure, so the
 * runner's own logic is testable — an untested branch is what let the Go peer
 * ship a bug where a crash silently satisfied the MustReject contract.
 *
 * A crash fails EVERY contract and is checked before the contract switch. JS has no
 * panic/error distinction, so a crash is identified by what was thrown: any
 * built-in runtime fault (an unguarded index or property access, a bad argument,
 * an escaped JSON.parse failure) or a thrown non-Error, which gives a caller
 * nothing to act on. A deliberate rejection is a plain Error or a converter's own
 * subclass. Letting a runtime fault satisfy MustReject would green-light exactly the
 * defect those contracts exist to catch.
 */
export async function checkCase(
  validate: ValidateFunction,
  c: CorpusCase,
  convert: CorpusConvertFn,
): Promise<string | null> {
  let out: unknown;
  let threw: unknown;
  let didThrow = false;
  try {
    out = await convert(c.input);
  } catch (e) {
    threw = e;
    didThrow = true;
  }

  if (didThrow && isRuntimeFault(threw)) {
    return `${c.name}: converter crashed with ${describeThrown(threw)} — a crash is never an acceptable rejection (${c.why})`;
  }

  // Shared by MustConvert and MustNotCorrupt: whenever the exporter produced a
  // document, that document has to satisfy the target schema.
  const outputViolation = (): string | null => {
    let parsed: unknown;
    try {
      parsed = parseIfString(out);
    } catch (e) {
      return `${c.name}: output is not parseable JSON (${c.why}): ${String(e)}`;
    }
    return schemaErrors(validate, parsed);
  };

  switch (c.contract) {
    case 'MustConvert': {
      if (didThrow) {
        return `${c.name}: schema-valid HDF must convert (${c.why}): ${String(threw)}`;
      }
      const errors = outputViolation();
      return errors === null
        ? null
        : `${c.name}: output does not satisfy the target schema (${c.why}):\n${errors}`;
    }

    case 'MustReject':
      return didThrow
        ? null
        : `${c.name}: input whose top-level shape HDF rejects must not be converted (${c.why})`;

    case 'MustNotCorrupt': {
      // Rejecting is fine: no converter validates nested content, so tolerance
      // and strictness are both defensible. What is never acceptable is
      // converting it into a document the target schema rejects.
      if (didThrow) return null;
      const errors = outputViolation();
      return errors === null
        ? null
        : `${c.name}: converted nested-invalid HDF into output the target schema rejects (${c.why}):\n${errors}`;
    }
  }
}

/**
 * Assert every corpus contract against one exporter; see CorpusContract for what
 * each obliges.
 *
 * Converters opt in with a single call, so the corpus has one definition rather
 * than a copy per converter. Every failing case is collected and reported in one
 * throw, so a red run names all of them rather than one per re-run. (Go's peer
 * needs no equivalent: each case is its own subtest and already reports
 * independently.)
 */
export async function runSchemaCorpus(
  validate: ValidateFunction,
  cases: CorpusCase[],
  convert: CorpusConvertFn,
): Promise<void> {
  if (cases.length === 0) throw new Error('corpus is empty — the run would pass vacuously');

  const failures: string[] = [];
  for (const c of cases) {
    const failure = await checkCase(validate, c, convert);
    if (failure !== null) failures.push(failure);
  }
  if (failures.length > 0) throw new Error(failures.join('\n\n'));
}

/**
 * Built-in error types that signal a fault in the converter rather than a
 * decision by it. A converter rejecting bad input throws a plain Error; one that
 * hits any of these has lost control of its own execution.
 */
const RUNTIME_FAULTS = new Set([
  'TypeError',
  'RangeError',
  'ReferenceError',
  'SyntaxError',
  'EvalError',
  'URIError',
]);

/** Whether a thrown value represents a crash rather than a deliberate rejection. */
function isRuntimeFault(thrown: unknown): boolean {
  // A thrown non-Error (string, undefined, object literal) carries no message or
  // stack, so it is not a rejection a caller can diagnose either.
  if (!(thrown instanceof Error)) return true;
  return RUNTIME_FAULTS.has(thrown.name);
}

/** Renders a thrown value for a failure message, whatever its type. */
function describeThrown(thrown: unknown): string {
  if (thrown instanceof Error) return `${thrown.name}: ${thrown.message}`;
  return `a non-Error value (${typeof thrown})`;
}

/** Converters return either a JSON string or an object; validate the object form. */
function parseIfString(out: unknown): unknown {
  return typeof out === 'string' ? (JSON.parse(out) as unknown) : out;
}

// --- Cross-language parity ---------------------------------------------------

/**
 * Re-serialize a document with object keys sorted, so the same values produce
 * the same bytes in TypeScript and Go.
 *
 * Raw serialization cannot be compared across the two: Go marshals struct fields
 * in declaration order while TS uses insertion order. Both are language
 * artifacts, not meaningful differences — canonicalizing removes them so the
 * corpora can be asserted byte-equal rather than merely assumed equivalent.
 * (Go additionally disables its default HTML escaping of <, > and & to match
 * JSON.stringify, and normalizes -0 to 0 where JSON.stringify already does.)
 *
 * Known limit: a lone UTF-16 surrogate still differs between the two. No corpus
 * case can produce one, and one appearing would fail the golden loudly rather
 * than pass silently.
 */
export function canonicalJSON(raw: string): string {
  // Go's encoder escapes U+2028/U+2029; JSON.stringify emits them literally.
  // Escaping here keeps the two byte-equal (and the output valid JavaScript,
  // where a bare U+2028 is a line terminator).
  return JSON.stringify(sortValue(JSON.parse(raw)))
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

function sortValue(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortValue);
  if (v === null || typeof v !== 'object') return v;
  const src = v as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(src).sort()) out[k] = sortValue(src[k]);
  return out;
}

/** One case as recorded in the cross-language golden. */
export interface CorpusGoldenEntry {
  name: string;
  contract: CorpusContract;
  input: string;
}

/** Renders a corpus in golden form for comparison against the checked-in file. */
export function toGoldenEntries(cases: CorpusCase[]): CorpusGoldenEntry[] {
  return cases.map((c) => ({ name: c.name, contract: c.contract, input: canonicalJSON(c.input) }));
}

