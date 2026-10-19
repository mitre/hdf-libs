/**
 * Writes the extensions.passthrough.sarif.propertyBags carriage block.
 *
 * Mirrors Go's passthrough.go exactly: this converter is the producer and
 * hdf-to-sarif the consumer of one carriage contract, so an address shape that
 * differs between the two languages writes a bag only one of them can restore.
 */

/** The objects a carried SARIF property bag can be addressed to. */
export const BAG_ON_LOG = 'log';
export const BAG_ON_RUN = 'run';
export const BAG_ON_RULE = 'rule';
export const BAG_ON_RESULT = 'result';

/**
 * The version of the carriage block this converter WRITES. hdf-to-sarif declares
 * the version it reads; the two are the same contract and must move together.
 */
export const PASSTHROUGH_SCHEMA_VERSION = 1;

/**
 * The per-rule slice of a run the collector needs: the requirement id the rule
 * became, its own bag, and each of its results' bags in the order the requirement
 * carries them, so an ordinal addresses the right one.
 */
export interface BagGroup {
  ruleId: string;
  ruleProps?: Record<string, unknown>;
  resultProps: (Record<string, unknown> | undefined)[];
}

type Entry = Record<string, unknown>;

/**
 * Gathers every SARIF property bag into carriage entries, addressed by the HDF
 * identities that survive the conversion.
 *
 * SARIF 3.8.1 puts a properties bag on every object and Appendix D tells producers
 * to name the keys after their own native fields, so the bags cannot be enumerated
 * by key and nothing can be mapped from them. Dropping them instead loses the
 * producer's own taxonomy. So they are carried verbatim and addressed, never
 * interpreted.
 *
 * Addressing is by identity, never array position: HDF groups results by rule and
 * reorders them, so /runs/0/results/3 would reattach a bag to a different finding.
 */
export function collectPropertyBags(
  doc: SarifLike,
  baselineNames: string[],
  bagGroups: BagGroup[][]
): Entry[] {
  const entries: Entry[] = [];

  if (doc.properties && Object.keys(doc.properties).length > 0) {
    entries.push({on: BAG_ON_LOG, properties: doc.properties});
  }

  (doc.runs ?? []).forEach((run, runIdx) => {
    const baseline = baselineNames[runIdx] ?? '';
    if (run.properties && Object.keys(run.properties).length > 0) {
      entries.push({on: BAG_ON_RUN, baseline, properties: run.properties});
    }
    for (const g of bagGroups[runIdx] ?? []) {
      if (g.ruleProps && Object.keys(g.ruleProps).length > 0) {
        entries.push({on: BAG_ON_RULE, baseline, ruleId: g.ruleId, properties: g.ruleProps});
      }
      g.resultProps.forEach((props, ordinal) => {
        if (!props || Object.keys(props).length === 0) return;
        entries.push({on: BAG_ON_RESULT, baseline, ruleId: g.ruleId, ordinal, properties: props});
      });
    }
  });

  return entries;
}

/** The shape collectPropertyBags needs from a parsed SARIF log. */
export interface SarifLike {
  properties?: Record<string, unknown>;
  runs?: {properties?: Record<string, unknown>}[];
}

/**
 * Builds the carriage block, or undefined when there is nothing to carry —
 * extensions stays absent rather than holding an empty block.
 */
export function buildPassthroughBlock(entries: Entry[]): Record<string, unknown> | undefined {
  if (entries.length === 0) return undefined;
  return {schemaVersion: PASSTHROUGH_SCHEMA_VERSION, propertyBags: entries};
}

// --- Restoring HDF fields SARIF cannot express (owner ruling, option (c)) ---

/** The single reserved key hdf-to-sarif writes its carriage under. */
export const HDF_BAG_KEY = 'hdf';

/**
 * Bag key -> HDF field, for the fields SARIF has no way to express.
 *
 * Deliberately short. A bag is only present when hdf-to-sarif produced the
 * document, it lives in `extensions.passthrough` which the schema leaves
 * unconstrained by design, and it is therefore untrusted data used only when it
 * happens to be there AND SARIF offers no other way to recover the field.
 *
 * Anything SARIF DOES express is derived from the SARIF content instead, even when
 * the bag also carries it: impact (security-severity), status and kind, level,
 * fingerprints, locations and the codeDesc built from them,
 * descriptions[default]/[check]/[rationale], nist and cci tags, and a suppression's
 * justification and kind. A document round-tripping through here therefore does NOT
 * reproduce its original impact where a CVSS score is present, nor a per-result
 * codeDesc's column and snippet. Those are ruled, deliberate losses.
 *
 * Mirrors the key list in Go's restoreUnexpressible; the two lists are one contract.
 */
const UNEXPRESSIBLE_BAG_KEYS: Record<string, string> = {
  cvss: 'cvss',
  epss: 'epss',
  kev: 'kev',
  affected_packages: 'affectedPackages',
  code: 'code',
  refs: 'refs',
  // SARIF carries a single helpUri, not a reference array, so a requirement-level
  // externalReferences of any size has no SARIF expression.
  external_references: 'externalReferences',
  effective_checksum: 'effectiveChecksum',
  control_type: 'controlType',

  applicability: 'applicability',
  evidence: 'evidence',
  poams: 'poams',
};

/** The description labels hdf-to-sarif maps onto real SARIF fields. */
const SARIF_EXPRESSES_DESCRIPTION = new Set(['default', 'check', 'rationale']);

/**
 * Merges a carried bag's unexpressible fields into a requirement already built from
 * the SARIF content. Never overwrites a field the mapping produced: the derived
 * value is the one SARIF actually supports, and a bag that disagreed with it would
 * be asserting something the document's own findings do not.
 */
export function restoreUnexpressible(req: Record<string, unknown>, bag: Record<string, unknown>): void {
  for (const [bagKey, hdfKey] of Object.entries(UNEXPRESSIBLE_BAG_KEYS)) {
    if (!(bagKey in bag)) continue;
    if (req[hdfKey] !== undefined) continue;
    req[hdfKey] = bag[bagKey];
  }
  // These two OVERRIDE what the mapping produced, for two different reasons, and
  // are the one exception to the rule above. Mirrors Go's restoreUnexpressible.
  //
  // verificationMethod: the mapping does not derive it from SARIF — SARIF has no
  // field for it. This converter sets a constant `automated` because it is reading
  // scanner output, but the schema defines the field as "how this requirement is
  // intended to be verified" and puts it on Requirement_Core, which baseline
  // requirements share and which nothing has assessed. Reading a SARIF file says a
  // check ran; it does not say the requirement is INTENDED to be automated. The
  // schema also says to infer no default when it is omitted. So the constant is an
  // inferred default, not a derived value, and a carried witness outranks it.
  if ('verification_method' in bag) req.verificationMethod = bag.verification_method;
  // statusOverrides: ONLY the invented fields. This converter derives the override's
  // type, status and reason from the SARIF suppression, so those stay derived.
  // appliedBy, appliedAt and expiresAt are derived from nothing — it invents them —
  // and the carried values are the document's real ones. Scoped rather than
  // wholesale because disposition and the effective-status rollup are computed from
  // the DERIVED override before this runs.
  restoreInventedOverrideFields(req, bag);
  restoreUnexpressibleDescriptions(req, bag);
}

/**
 * Restores only labels the SARIF mapping cannot produce. "fix" comes from SARIF
 * fixes[], which hdf-to-sarif does not emit, so a fix description reaching SARIF has
 * no way back except the bag.
 */
function restoreUnexpressibleDescriptions(req: Record<string, unknown>, bag: Record<string, unknown>): void {
  const carried = bag.descriptions;
  if (!Array.isArray(carried)) return;
  const existing = Array.isArray(req.descriptions) ? [...req.descriptions] : [];
  const have = new Set(
    existing.map(d => (d as {label?: string})?.label).filter((l): l is string => typeof l === 'string'));
  for (const d of carried) {
    const label = (d as {label?: string})?.label;
    if (typeof label !== 'string' || label === '' || have.has(label)
      || SARIF_EXPRESSES_DESCRIPTION.has(label)) continue;
    existing.push(d);
    have.add(label);
  }
  if (existing.length > 0) req.descriptions = existing;
}

/** The `hdf` bag a run carries, or undefined. Mirrors Go's runBag. */
export function runBag(run: {properties?: Record<string, unknown>}): Record<string, unknown> | undefined {
  const bag = run.properties?.[HDF_BAG_KEY];
  return bag && typeof bag === 'object' && !Array.isArray(bag) ? bag as Record<string, unknown> : undefined;
}

// Baseline fields that are plain strings. title and version are absent here because
// they override rather than fill, and are handled separately below.
const BASELINE_STRING_FIELDS = [
  'summary', 'description', 'maintainer', 'copyright', 'copyrightEmail',
  'license', 'status', 'statusMessage', 'parentBaseline',
] as const;

// Array fields, with the keys the HDF schema REQUIRES on each element. Go gets this
// check for free — a decode that drops or invents members is rejected as not being of
// that type — and TypeScript has no types at runtime, so it is written out. Without it
// the two languages diverge on exactly the input that is hardest to reason about: Go
// skips a malformed element, TypeScript would take it verbatim and emit a document
// that fails the output schema gate.
//
// Element types with no required keys (Dependency, Supported_Platform) are still
// checked for being objects, which is all the schema itself demands of them.
const BASELINE_ARRAY_FIELDS: ReadonlyArray<readonly [string, readonly string[]]> = [
  ['supports', []],
  ['depends', []],
  ['groups', ['id', 'requirements']],
  ['inputs', ['name']],
  ['externalReferences', ['sourceName']],
] as const;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Merges a carried run bag's baseline identity back onto the baseline this run
 * converted to. Mirrors Go's restoreBaselineFields.
 *
 * SARIF's toolComponent describes the SCANNER. A baseline describes the POLICY — what
 * was required — so SARIF has no way to say any of these, and ruling (c) therefore
 * permits reading them. The exporter carries 23 keys; five are excluded, in three
 * groups:
 *
 * - `name` and `resultsChecksum` are DERIVED, not read. SARIF does express the name, on
 *   the driver, and resultsChecksum must be computed over the results actually present
 *   or it attests to content this document does not contain.
 * - `integrity` and `originalChecksum` are REFUSED. Both are tamper-evidence, and a
 *   round trip is a transformation of the thing they cover: Integrity is defined over
 *   "the HDF file" and carries an optional signature and signedBy, so restoring it
 *   would re-attach a signature to a document nobody signed.
 * - `generator` is REFUSED because it names the converter that produced THIS file, and
 *   this converter produced it. Restoring the upstream one would misattribute the
 *   document; the original stays readable in the bag.
 *
 * Every value is shape-checked before it is taken. The bag is untrusted, and Go's
 * decode skips an entry whose type does not fit; assigning here without the same check
 * would put the two languages out of step on exactly the input that is hardest to
 * reason about.
 */
export function restoreBaselineFields(
  baseline: Record<string, unknown>,
  bag: Record<string, unknown> | undefined,
): void {
  if (!bag) return;

  // title and version override what the mapping produced. The mapping has no baseline
  // to describe, so it writes the SARIF format's own name and spec version; where the
  // bag carries the real ones, those invented values are a false claim about the
  // policy rather than a neutral default.
  for (const key of ['title', 'version'] as const) {
    if (typeof bag[key] === 'string') baseline[key] = bag[key];
  }

  for (const key of BASELINE_STRING_FIELDS) {
    if (baseline[key] !== undefined) continue;
    if (typeof bag[key] === 'string') baseline[key] = bag[key];
  }

  for (const [key, required] of BASELINE_ARRAY_FIELDS) {
    if (baseline[key] !== undefined) continue;
    const v = bag[key];
    if (!Array.isArray(v)) continue;
    if (!v.every(e => isPlainObject(e) && required.every(r => e[r] !== undefined))) continue;
    baseline[key] = v;
  }

  if (baseline.labels === undefined) {
    const labels = bag.labels;
    if (isPlainObject(labels) && Object.values(labels).every(v => typeof v === 'string')) {
      baseline.labels = labels;
    }
  }

  // The baseline's own passthrough — producer data outside the HDF model that belongs
  // to this baseline. SARIF cannot express it either, so it restores like the rest. It
  // does not collide with this converter's own carriage, which is written at the
  // DOCUMENT level rather than the baseline's.
  if (baseline.extensions === undefined && isPlainObject(bag.extensions)) {
    baseline.extensions = bag.extensions;
  }
}

/** The `hdf` bag a rule carries, or undefined. */
export function ruleBag(rule: {properties?: Record<string, unknown>} | undefined): Record<string, unknown> | undefined {
  const bag = rule?.properties?.[HDF_BAG_KEY];
  return bag && typeof bag === 'object' ? bag as Record<string, unknown> : undefined;
}

/** The HDF result row hdf-to-sarif carried on one SARIF result's own bag. */
export function resultBagRow(result: {properties?: Record<string, unknown>}): Record<string, unknown> | undefined {
  const bag = result.properties?.[HDF_BAG_KEY];
  if (!bag || typeof bag !== 'object') return undefined;
  const row = (bag as Record<string, unknown>).result;
  return row && typeof row === 'object' ? row as Record<string, unknown> : undefined;
}

/**
 * Fills in the result fields SARIF cannot carry. codeDesc and status are NOT among
 * them: SARIF expresses position as result locations and verdict as kind, so both
 * are derived from the SARIF content under the same rule that governs the
 * requirement-level restore. Mirrors Go's restoreUnexpressibleResult.
 */
export function restoreUnexpressibleResult(out: Record<string, unknown>, row: Record<string, unknown> | undefined): void {
  if (!row) return;
  for (const field of ['resource', 'resourceId']) {
    if (out[field] !== undefined) continue;
    if (row[field] !== undefined) out[field] = row[field];
  }
  // startTime is the scan's time, not the conversion's. SARIF has no per-result
  // timestamp and this exporter writes no invocations block, so nothing in the SARIF
  // expresses it and the converter falls back to the current time — silently
  // restamping every finding with the moment it was converted.
  if (row.startTime !== undefined) out.startTime = row.startTime;
}

/**
 * The SARIF kind each HDF status is written as — mirrors hdf-to-sarif's statusKinds.
 * Declared here rather than imported so the two converters do not form a cycle, the same
 * reason HDF_BAG_KEY is declared twice. The map is injective: five statuses, five
 * distinct kinds, so a carried status can always be checked against its kind.
 */
const STATUS_EXPORT_KINDS: Record<string, string> = {
  passed: 'pass',
  failed: 'fail',
  notApplicable: 'notApplicable',
  notReviewed: 'review',
  error: 'open',
};

/**
 * Takes the status from a carried result row, but only when exporting that status would
 * have produced the kind this SARIF actually states. Mirrors Go's restoreCarriedStatus.
 *
 * SARIF cannot express HDF's `error`: there is no kind meaning "the check threw", so the
 * export writes `open` — §3.27.9's state where the tool had insufficient information to
 * decide — and an importer reading the kind alone cannot tell that from a tool that
 * genuinely reported `open`. That is the one distinction the kind cannot carry, and the
 * owner's ruling is that the bag may settle it, because HDF cannot reflect every source
 * status and deriving it only from what SARIF expresses discards what the source said.
 *
 * The gate is what keeps this honest. The bag is untrusted carriage, so it may REFINE a
 * kind that cannot express the distinction and never overrule one that can: a carried
 * `passed` found under kind `open` disagrees with the document it arrived in, and the
 * SARIF wins. Same rule `tags.kind` already follows.
 */
export function restoreCarriedStatus(
  out: Record<string, unknown>,
  row: Record<string, unknown> | undefined,
  kind: string | undefined,
): void {
  if (!row) return;
  const carried = row.status;
  if (typeof carried !== 'string') return;
  const want = STATUS_EXPORT_KINDS[carried];
  if (want === undefined) return;
  // 3.27.9 defaults an absent kind to "fail".
  if (want !== (kind || 'fail')) return;
  out.status = carried;
}

/**
 * Replaces the identity, application time and expiry this converter invented with
 * the carried ones, position by position, leaving the type, status and reason it
 * derived from the SARIF suppression untouched. Positional because an override has
 * no id. Mirrors Go's restoreInventedOverrideFields.
 */
function restoreInventedOverrideFields(req: Record<string, unknown>, bag: Record<string, unknown>): void {
  const carried = bag.status_overrides;
  const derived = req.statusOverrides;
  if (!Array.isArray(carried) || !Array.isArray(derived) || derived.length === 0) return;
  derived.forEach((d, i) => {
    const c = carried[i] as Record<string, unknown> | undefined;
    if (!c || typeof c !== 'object') return;
    const row = d as Record<string, unknown>;
    const by = c.appliedBy as {identifier?: string} | undefined;
    if (by?.identifier) row.appliedBy = c.appliedBy;
    if (c.appliedAt) row.appliedAt = c.appliedAt;
    row.expiresAt = c.expiresAt;
  });
}
