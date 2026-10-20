/**
 * HDF Results → SARIF 2.1.0 static-analysis log.
 *
 * The reverse direction of sarif-to-hdf. Like the other HDF export converters
 * this works on generically-parsed JSON rather than typed HDF objects so the
 * output stays byte-identical with the Go peer: SARIF property bags are open
 * maps, Go sorts map keys while JSON.stringify preserves insertion order, so
 * both languages canonicalize the whole document instead of maintaining two
 * field orders by hand.
 */
import { formatJsonNumber, impactToSeverity } from '@mitre/hdf-utilities';
import { requireHdfResults } from '../../../shared/typescript/converterutil.js';
import {
  type Obj,
  asArr,
  asMap,
  buildHDFBlock,
  canonicalize,
  defaultDescription,
  firstRefURL,
  getStr,
  governingOverrideOf,
  setIf,
  statusOf,
  stringSlice,
  stringifyDocument,
} from '../../../shared/typescript/exportmap.js';
import {
  type CarriedBags,
  HDF_BAG_KEY,
  REGION_TAG,
  baselineExtensions,
  readCarriedBags,
  remainingExtensions,
  setBag,
  withoutRawSourceRecord,
} from './passthrough.js';
import { absoluteUri, encodeUriReference } from './uri.js';

const CONVERTER_NAME = 'hdf-to-sarif';

/** The only value the 2.1.0 schema's version enum admits. */
export const SARIF_VERSION = '2.1.0';

/** The OASIS canonical location of the schema this output is validated against. */
export const SARIF_SCHEMA_URI =
  'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json';

/**
 * Fills run.tool.driver.name, which SARIF requires, when the HDF document names
 * neither a tool nor a generator. The same documented constant hdf-to-oscal-sar
 * uses for the same gap; inventing a plausible tool name would be fabrication.
 */
const UNNAMED_TOOL = 'HDF Assessment Tool';

const KIND_FAIL = 'fail';

/** Converts HDF Results JSON to a SARIF 2.1.0 log. */
export function convertHdfToSarif(input: string, converterVersion = ''): string {
  const { doc, items: baselines } = requireHdfResults(input, CONVERTER_NAME);
  return `${stringifyDocument(canonicalize(buildLog(doc, baselines, converterVersion)))}\n`;
}

function buildLog(doc: Obj, baselines: unknown[], converterVersion: string): Obj {
  const carried = readCarriedBags(doc);
  const generator = asMap(doc.generator);
  const tool = asMap(doc.tool);

  const runs: Obj[] = [];
  for (const raw of baselines) {
    const baseline = asMap(raw);
    if (!baseline) continue;
    runs.push(buildRun(baseline, generator, tool, converterVersion, carried));
  }

  const log: Obj = { $schema: SARIF_SCHEMA_URI, version: SARIF_VERSION, runs };
  setBag(log, documentBlock(doc), carried.find({ on: 'log' }));
  return log;
}

/**
 * The document-level HDF data SARIF has no field for. The mapped fields (tool,
 * generator) are deliberately absent: tool reaches run.tool.driver and generator
 * reaches run.properties, so repeating them here would be dumping data that
 * already has a home.
 */
function documentBlock(doc: Obj): Obj | undefined {
  const block: Obj = {};
  for (const key of [
    'id',
    'timestamp',
    'statistics',
    'runner',
    'components',
    'planRef',
    'systemRef',
    'integrity',
    'externalReferences',
    'derivation',
    'preAmendmentChecksum',
    'remediation',
  ]) {
    if (key in doc) block[key] = doc[key];
  }
  const ext = remainingExtensions(doc);
  if (ext) block.extensions = ext;
  if (Object.keys(block).length === 0) return undefined;
  return { [HDF_BAG_KEY]: block };
}

/**
 * Maps one HDF baseline onto one SARIF run.
 *
 * One run per baseline, not one per document: SARIF ties a run to a single tool
 * invocation, and the baseline is the HDF unit that carries its own identity
 * (name, version, checksums, status). Flattening several baselines into one run
 * would lose all of it and merge rules that were never evaluated together.
 */
function buildRun(
  baseline: Obj,
  generator: Obj | undefined,
  tool: Obj | undefined,
  converterVersion: string,
  carried: CarriedBags,
): Obj {
  const baselineName = getStr(baseline, 'name');
  const { rules, results } = buildRulesAndResults(
    baseline,
    baselineName,
    generator,
    tool,
    converterVersion,
    carried,
  );

  const driver: Obj = { name: driverName(tool) };
  setIf(driver, 'version', getStr(tool, 'version'));
  setIf(driver, 'informationUri', absoluteUri(getStr(tool, 'url')));
  if (rules.length > 0) driver.rules = rules;
  setBag(driver, undefined, carried.find({ on: 'driver', baseline: baselineName }));

  const run: Obj = { tool: { driver } };
  if (results.length > 0) run.results = results;
  // SARIF's conversion object describes the converter that produced this log,
  // which is this exporter; the HDF generator converted some earlier format into
  // HDF and SARIF models no chain of them, so it stays in the run's bag.
  const conversion: Obj = {
    tool: { driver: { name: CONVERTER_NAME, version: converterVersion } },
  };
  setBag(conversion, undefined, carried.find({ on: 'conversion', baseline: baselineName }));
  run.conversion = conversion;
  const details = automationDetails(baseline, baselineName);
  if (details) run.automationDetails = details;
  setBag(run, baselineBlock(baseline, generator), carried.find({ on: 'run', baseline: baselineName }));
  return run;
}

/** Resolves run.tool.driver.name, which SARIF requires. */
function driverName(tool: Obj | undefined): string {
  return getStr(tool, 'name') || UNNAMED_TOOL;
}

/**
 * Carries the baseline's identity: runAutomationDetails.id is SARIF's
 * "hierarchical string that uniquely identifies this run", which is exactly what
 * an HDF baseline name is within a document.
 */
function automationDetails(baseline: Obj, baselineName: string): Obj | undefined {
  if (baselineName === '') return undefined;
  const details: Obj = { id: baselineName };
  const text = getStr(baseline, 'title');
  if (text !== '') details.description = { text };
  return details;
}

/**
 * The baseline's own HDF data with no SARIF field, plus the document generator
 * (an upstream converter SARIF cannot represent).
 */
function baselineBlock(baseline: Obj, generator: Obj | undefined): Obj | undefined {
  const block: Obj = {};
  for (const key of [
    'name',
    'title',
    'version',
    'summary',
    'description',
    'maintainer',
    'copyright',
    'copyrightEmail',
    'license',
    'status',
    'statusMessage',
    'supports',
    'depends',
    'groups',
    'inputs',
    'labels',
    'parentBaseline',
    'integrity',
    'originalChecksum',
    'resultsChecksum',
    'externalReferences',
  ]) {
    if (key in baseline) block[key] = baseline[key];
  }
  const ext = baselineExtensions(baseline);
  if (ext) block.extensions = ext;
  if (generator) block.generator = generator;
  if (Object.keys(block).length === 0) return undefined;
  return { [HDF_BAG_KEY]: block };
}

/**
 * Maps a baseline's requirements onto the run's rules and results. Rules are
 * deduplicated by id because the schema puts uniqueItems on the rules array and
 * the spec requires rule ids to identify one descriptor; HDF, by contrast,
 * legitimately re-reports a requirement id (overlay chains do it constantly), so
 * the later occurrences reuse the first one's rule index and carry their own
 * requirement data on their results.
 */
function buildRulesAndResults(
  baseline: Obj,
  baselineName: string,
  generator: Obj | undefined,
  tool: Obj | undefined,
  converterVersion: string,
  carried: CarriedBags,
): { rules: Obj[]; results: Obj[] } {
  const requirements = asArr(baseline.requirements) ?? [];
  const rules: Obj[] = [];
  const ruleIndex = new Map<string, number>();
  const results: Obj[] = [];

  for (const raw of requirements) {
    const req = asMap(raw);
    if (!req) continue;
    const ruleId = getStr(req, 'id');
    let owner = false;
    let idx = ruleIndex.get(ruleId);
    if (idx === undefined) {
      idx = rules.length;
      ruleIndex.set(ruleId, idx);
      rules.push(buildRule(req, baseline, baselineName, generator, tool, converterVersion, carried));
      owner = true;
    }
    results.push(
      ...buildResults(req, baseline, baselineName, ruleId, idx, owner, generator, tool, converterVersion, carried),
    );
  }
  return { rules, results };
}

/** Maps one HDF requirement onto a SARIF reportingDescriptor. */
function buildRule(
  req: Obj,
  baseline: Obj,
  baselineName: string,
  generator: Obj | undefined,
  tool: Obj | undefined,
  converterVersion: string,
  carried: CarriedBags,
): Obj {
  const ruleId = getStr(req, 'id');
  const rule: Obj = { id: ruleId };
  const title = getStr(req, 'title');
  setIf(rule, 'name', title);
  if (title !== '') rule.shortDescription = { text: title };
  // fullDescription ← the rationale label and help ← the check label are the
  // exact inverse of what sarif-to-hdf reads back out of those two fields.
  const rationale = labelledDescription(req, 'rationale');
  const fallback = defaultDescription(req);
  if (rationale !== '') rule.fullDescription = { text: rationale };
  else if (fallback !== '') rule.fullDescription = { text: fallback };
  const check = labelledDescription(req, 'check');
  if (check !== '') rule.help = { text: check };
  setIf(rule, 'helpUri', absoluteUri(ruleHelpUri(req)));

  rule.defaultConfiguration = { level: ruleLevel(req) };

  const props: Obj = {};
  const tags = ruleTags(req);
  if (tags.length > 0) props.tags = tags;
  // security-severity is the SARIF convention for a CVSS base score and what
  // sarif-to-hdf reads to recover impact, so it is emitted only where the
  // requirement actually carries CVSS — writing a STIG severity there would
  // label it as something it is not.
  const score = cvssBaseScore(req);
  if (score !== undefined) props['security-severity'] = formatJsonNumber(score);
  props[HDF_BAG_KEY] = requirementBlock(req, baseline, generator, tool, converterVersion);
  setBag(rule, props, carried.find({ on: 'rule', baseline: baselineName, ruleId }));
  return rule;
}

/**
 * The lossless HDF carriage block for one requirement: the shared export block,
 * minus the per-result rows that live on each SARIF result's own bag, plus the
 * sourceLocation the shared block does not carry and whose ref this exporter
 * encodes to satisfy SARIF's uri-reference format.
 */
function requirementBlock(
  req: Obj,
  baseline: Obj,
  generator: Obj | undefined,
  tool: Obj | undefined,
  converterVersion: string,
): Obj {
  const st = statusOf(req);
  const block = buildHDFBlock(req, baseline, st.raw, st.overridden, st.suppressed, generator, tool, converterVersion);
  delete block.results;
  if ('sourceLocation' in req) block.source_location = req.sourceLocation;
  return block;
}

/**
 * Maps a requirement's HDF results onto SARIF results. A requirement with no
 * results emits none: SARIF already represents "this rule ran and reported
 * nothing" as a rule with no results, and inventing one would be inventing a
 * finding.
 */
function buildResults(
  req: Obj,
  baseline: Obj,
  baselineName: string,
  ruleId: string,
  ruleIdx: number,
  ownsRule: boolean,
  generator: Obj | undefined,
  tool: Obj | undefined,
  converterVersion: string,
  carried: CarriedBags,
): Obj[] {
  const rows = asArr(req.results) ?? [];

  const suppressions = buildSuppressions(req);

  const out: Obj[] = [];
  rows.forEach((raw, ordinal) => {
    const row = asMap(raw);
    if (!row) return;
    const kind = resultKind(req, row, ordinal);
    // Per result, not per requirement: a rule's results can sit at different places,
    // and sarif-to-hdf carries each one's own location.
    const locations = buildLocations(req, baselineName, ruleId, carried, ordinal);
    const result: Obj = {
      ruleId,
      ruleIndex: ruleIdx,
      message: { text: resultMessage(req, row, ordinal) },
      kind,
    };
    // level and kind are orthogonal axes (SARIF §3.27.9/§3.27.10), and for any
    // kind other than fail the spec allows only the value "none" — which is also
    // the default when level is absent, so it is simply omitted. The rule's
    // defaultConfiguration.level still carries the severity.
    if (kind === KIND_FAIL) result.level = resultLevel(req, ordinal);
    if (locations.length > 0) result.locations = locations;
    if (suppressions.length > 0) result.suppressions = suppressions;
    const { fingerprints, partialFingerprints } = resultFingerprintsAt(req, ordinal);
    if (fingerprints) result.fingerprints = fingerprints;
    if (partialFingerprints) result.partialFingerprints = partialFingerprints;
    const props: Obj = {
      [HDF_BAG_KEY]: resultBlock(req, baseline, row, ownsRule, generator, tool, converterVersion),
    };
    setBag(result, props, carried.find({ on: 'result', baseline: baselineName, ruleId, ordinal }));
    out.push(result);
  });
  return out;
}

/**
 * The HDF data for one result row. The requirement block is repeated here only
 * for a requirement that does not own its rule — a duplicate id whose data would
 * otherwise be dropped when the first occurrence's rule won.
 */
function resultBlock(
  req: Obj,
  baseline: Obj,
  row: Obj,
  ownsRule: boolean,
  generator: Obj | undefined,
  tool: Obj | undefined,
  converterVersion: string,
): Obj {
  const block: Obj = { result: withoutRawSourceRecord(row) };
  if (!ownsRule) {
    block.requirement = requirementBlock(req, baseline, generator, tool, converterVersion);
  }
  return block;
}

// --- level and kind ---

/**
 * The set a carried severity tag must belong to before it is trusted as a SARIF
 * level rather than an HDF severity word.
 */
const SARIF_LEVELS = new Set(['none', 'note', 'warning', 'error']);

/**
 * Resolves the SARIF severity level for a requirement.
 *
 * A tags.severity written by sarif-to-hdf holds the source level verbatim and is
 * the only thing that can restore "none", which HDF impact cannot express —
 * impact 0.0 means no impact, not ungraded. Absent that, the level is derived
 * from impact on the repo's own severity bands, which is the inverse of the alias
 * table sarif-to-hdf maps levels through.
 */
/**
 * The level for ONE result, preferring the level sarif-to-hdf carried for it.
 * tags["severity"] is a requirement-level summary, so a rule whose results carried
 * different levels had them all re-emitted at the summary's level and the RESOLVED
 * level (SARIF 3.27.10) came back changed for every result but one.
 *
 * A result the source left level-less carries nothing here and falls through to the
 * rule level, which is the rule's defaultConfiguration — so the level still resolves
 * to what it resolved to before. Mirrors Go's resultLevel.
 */
function resultLevel(req: Obj, ordinal: number): string {
  const carried = carriedResultField(req, ordinal, 'level');
  if (SARIF_LEVELS.has(carried)) return carried;
  return ruleLevel(req);
}

function ruleLevel(req: Obj): string {
  const tags = asMap(req.tags);
  const carried = getStr(tags, 'severity');
  if (SARIF_LEVELS.has(carried)) return carried;
  const impact = typeof req.impact === 'number' ? req.impact : 0;
  switch (impactToSeverity(impact)) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'note';
    default:
      return 'none';
  }
}

/**
 * Maps an HDF Result_Status onto the SARIF kind it belongs to. HDF "error" has
 * no importer counterpart: SARIF's "open" is the state where the tool had
 * insufficient information to decide, which is what a check that threw leaves
 * behind.
 */
const STATUS_KINDS: Record<string, string> = {
  passed: 'pass',
  failed: KIND_FAIL,
  notApplicable: 'notApplicable',
  notReviewed: 'review',
  error: 'open',
};

/**
 * sarif-to-hdf's kind→status map. Two SARIF kinds collapse onto one HDF status
 * in each of two cases, so a carried tags.kind is what restores the distinction
 * — but only when it agrees with the status actually recorded, so the tag can
 * never contradict the mapped data.
 */
const IMPORTER_KIND_STATUS: Record<string, string> = {
  pass: 'passed',
  open: 'failed',
  fail: 'failed',
  review: 'notReviewed',
  informational: 'notApplicable',
  notApplicable: 'notApplicable',
};

/** Resolves the SARIF kind for one HDF result row. */
function resultKind(req: Obj, row: Obj, ordinal: number): string {
  const status = getStr(row, 'status');
  // SARIF's own default for an unrecognized verdict.
  const kind = STATUS_KINDS[status] ?? KIND_FAIL;
  // The PER-RESULT carried kind first. tags["kind"] below is only set when every
  // result in the group shared one kind, so a rule mixing "open" with
  // "informational" has no requirement-level value and both would otherwise
  // collapse onto whatever their HDF status maps to — "open" to fail,
  // "informational" to notApplicable, neither recoverable.
  const perResult = carriedResultField(req, ordinal, 'kind');
  if (status !== '' && IMPORTER_KIND_STATUS[perResult] === status) return perResult;
  const tags = asMap(req.tags);
  const carried = getStr(tags, 'kind');
  if (status !== '' && IMPORTER_KIND_STATUS[carried] === status) return carried;
  return kind;
}

/**
 * Resolves result.message.text, which SARIF requires.
 *
 * A carried SARIF message wins, because it is what the tool actually said about
 * THIS result. HDF's codeDesc is location prose this converter would otherwise
 * emit as the finding's message — accurate for a natively-authored HDF document
 * and wrong for one imported from SARIF.
 */
function resultMessage(req: Obj, row: Obj, ordinal: number): string {
  return carriedResultField(req, ordinal, 'message')
    || getStr(row, 'message')
    || getStr(row, 'codeDesc')
    || defaultDescription(req);
}

/**
 * Reads one field of tags["sarif-results"][ordinal]. Addressed by position WITHIN
 * the requirement, which is the order the importer wrote and this exporter
 * re-emits. Mirrors Go's carriedResultField.
 */
function carriedResultField(req: Obj, ordinal: number, field: string): string {
  const tags = asMap(req.tags);
  if (!tags) return '';
  const entries = asArr(tags['sarif-results']);
  if (!entries || ordinal < 0 || ordinal >= entries.length) return '';
  const entry = asMap(entries[ordinal]);
  if (!entry) return '';
  return getStr(entry, field);
}

// --- descriptions, tags, scores ---

/** The first descriptions[] entry with the given label, or ''. */
function labelledDescription(req: Obj, label: string): string {
  for (const raw of asArr(req.descriptions) ?? []) {
    const d = asMap(raw);
    if (d && getStr(d, 'label') === label) return getStr(d, 'data');
  }
  return '';
}

/**
 * Restores the helpUri sarif-to-hdf parked in tags, falling back to the first
 * external reference HDF carries for the requirement.
 */
function ruleHelpUri(req: Obj): string {
  return getStr(asMap(req.tags), 'helpUri') || firstRefURL(req);
}

/**
 * Builds the propertyBag tags array: the CWE taxonomy entries in the form
 * GitHub's SARIF ingestion keys on, plus the control ids HDF carries. Sorted and
 * deduplicated because the schema puts uniqueItems on it.
 */
function ruleTags(req: Obj): string[] {
  const tags = new Set<string>();
  const reqTags = asMap(req.tags);
  // Both homes. CWE is a first-class Requirement field, but sarif-to-hdf writes it to
  // tags["cwe"] instead, so reading only the first-class field meant a SARIF-sourced
  // document's CWEs never reached the SARIF tags — and the importer, which recovers
  // CWE from exactly these tags, rebuilt an empty list. The NIST and CCI tags derive
  // from that list, so they degraded to the static-analysis fallback too.
  for (const src of [stringSlice(req.cwe), stringSlice(reqTags?.cwe)]) {
    for (const cwe of src) {
      if (cwe !== '') tags.add(`external/cwe/${cwe.toLowerCase()}`);
    }
  }
  for (const nist of stringSlice(reqTags?.nist)) if (nist !== '') tags.add(`nist/${nist}`);
  for (const cci of stringSlice(reqTags?.cci)) if (cci !== '') tags.add(`cci/${cci}`);
  return [...tags].sort();
}

/** The first CVSS base score on the requirement. */
function cvssBaseScore(req: Obj): number | undefined {
  for (const raw of asArr(req.cvss) ?? []) {
    const entry = asMap(raw);
    if (entry && typeof entry.baseScore === 'number') return entry.baseScore;
  }
  return undefined;
}

/** Restores the fingerprint maps sarif-to-hdf parked in tags. */
function resultFingerprints(req: Obj): { fingerprints?: Obj; partialFingerprints?: Obj } {
  const block = asMap(asMap(req.tags)?.fingerprints);
  return {
    fingerprints: stringValued(asMap(block?.fingerprints)),
    partialFingerprints: stringValued(asMap(block?.partialFingerprints)),
  };
}

/**
 * Keeps only the string-valued entries, which is all SARIF's fingerprint maps
 * admit.
 */
function stringValued(m: Obj | undefined): Obj | undefined {
  if (!m) return undefined;
  const out: Obj = {};
  for (const [k, v] of Object.entries(m)) if (typeof v === 'string') out[k] = v;
  return Object.keys(out).length > 0 ? out : undefined;
}

// --- locations and suppressions ---

/**
 * The SARIF region members HDF can carry through the sarif-region tag. They are
 * integers in SARIF; a carried value that is not a whole number is dropped
 * rather than coerced.
 */
const REGION_INT_FIELDS = [
  'startLine',
  'startColumn',
  'endLine',
  'endColumn',
  'charOffset',
  'charLength',
  'byteOffset',
  'byteLength',
];

/**
 * Maps a requirement's location onto SARIF locations.
 *
 * HDF Source_Location is {ref, line} and closed, so column and end positions
 * come from the documented sarif-region tag when a document carries one, and the
 * {ref, line} pair alone otherwise. The locations are requirement-level: HDF
 * results[] rows carry no location of their own, so every result of a
 * requirement reports at the requirement's location.
 */
function buildLocations(req: Obj, baselineName: string, ruleId: string, carried: CarriedBags, ordinal: number): Obj[] {
  // A per-result carried location wins. HDF puts sourceLocation on the REQUIREMENT,
  // so without this every result of a rule reports at the first one's location.
  const perLoc = carriedResultLocation(req, ordinal);
  const source = perLoc ?? asMap(req.sourceLocation);
  const region = buildRegion(req, source, perLoc ? asMap(perLoc.region) : undefined);
  const uri = getStr(source, 'ref');
  const bag = carried.find({ on: 'location', baseline: baselineName, ruleId });

  if (uri === '' && Object.keys(region).length === 0 && !bag) return [];

  const physical: Obj = {};
  if (uri !== '') physical.artifactLocation = { uri: encodeUriReference(uri) };
  if (Object.keys(region).length > 0) physical.region = region;

  const location: Obj = {};
  if (Object.keys(physical).length > 0) location.physicalLocation = physical;
  setBag(location, undefined, bag);
  return Object.keys(location).length > 0 ? [location] : [];
}

/**
 * Assembles a SARIF region, in precedence order: the per-result carried region,
 * then the requirement-level sarif-region tag, then sourceLocation.line for
 * startLine. The per-result region is most specific — it is the one the tool
 * reported for THIS finding — so it wins. Mirrors Go's buildRegion.
 */
function buildRegion(req: Obj, source: Obj | undefined, perResult?: Obj): Obj {
  const carried = asMap(asMap(req.tags)?.[REGION_TAG]);
  const region: Obj = {};
  for (const field of REGION_INT_FIELDS) {
    const v = wholeNumber(perResult?.[field]) ?? wholeNumber(carried?.[field]);
    if (v !== undefined) region[field] = v;
  }
  if (!('startLine' in region)) {
    const v = wholeNumber(source?.line);
    if (v !== undefined) region.startLine = v;
  }
  setIf(region, 'sourceLanguage', getStr(carried, 'sourceLanguage'));
  // Per-result snippet first, then the requirement-level sarif-region tag.
  for (const src of [perResult, carried]) {
    const text = getStr(asMap(src?.snippet), 'text');
    if (text !== '') {
      region.snippet = { text };
      break;
    }
  }
  return region;
}

/**
 * A JSON number that is a positive whole value, which is what every SARIF region
 * position is. A fractional or non-positive value is not a line or column, so it
 * is dropped rather than truncated into a wrong one.
 */
function wholeNumber(v: unknown): number | undefined {
  if (typeof v !== 'number' || !Number.isInteger(v) || v <= 0) return undefined;
  return v;
}

/** The SARIF review-status enum. */
const SUPPRESSION_STATUSES = new Set(['accepted', 'underReview', 'rejected']);

/**
 * Maps HDF overrides onto SARIF suppressions.
 *
 * A suppressions array asserts the finding was suppressed, so it is emitted only
 * when an override actually drove a failing verdict non-failing. A riskAdjustment
 * or POA&M that leaves the requirement failing is still actionable and is carried
 * in the HDF property bag instead of being dressed up as a suppression.
 *
 * A tags.suppressions written by sarif-to-hdf holds every source suppression
 * verbatim, including the rejected and under-review ones and their original kind,
 * so it takes priority over anything derived from the overrides.
 */
function buildSuppressions(req: Obj): Obj[] {
  const carried = carriedSuppressions(req);
  if (carried.length > 0) return carried;
  if (!statusOf(req).suppressed) return [];
  const gov = governingOverrideOf(asArr(req.statusOverrides) ?? []);
  if (!gov) return [];
  const suppression: Obj = {
    // An HDF override is a signed, attributed record in the HDF document, never
    // a marker inside the artifact that was scanned, so "external" is the only
    // value SARIF's definition admits — not a convenience default.
    kind: 'external',
    status: 'accepted',
  };
  setIf(suppression, 'justification', getStr(gov, 'reason'));
  // appliedBy/appliedAt/expiresAt/type/signature/previousChecksum and the
  // structured justification have no SARIF suppression field at all.
  suppression.properties = { [HDF_BAG_KEY]: gov };
  return [suppression];
}

/**
 * Rebuilds the suppressions array from the tag sarif-to-hdf writes, keeping only
 * the members SARIF's suppression object admits.
 */
function carriedSuppressions(req: Obj): Obj[] {
  const out: Obj[] = [];
  for (const raw of asArr(asMap(req.tags)?.suppressions) ?? []) {
    const entry = asMap(raw);
    if (!entry) continue;
    const kind = getStr(entry, 'kind');
    if (kind !== 'inSource' && kind !== 'external') continue;
    const suppression: Obj = { kind };
    const status = getStr(entry, 'status');
    if (SUPPRESSION_STATUSES.has(status)) suppression.status = status;
    setIf(suppression, 'justification', getStr(entry, 'justification'));
    out.push(suppression);
  }
  return out;
}

/**
 * Reads the location sarif-to-hdf carried for the result at this ordinal, shaped
 * like a Source_Location so it drops straight into the requirement-level path.
 * Mirrors Go's carriedResultLocation.
 */
function carriedResultLocation(req: Obj, ordinal: number): Obj | undefined {
  const tags = asMap(req.tags);
  if (!tags) return undefined;
  const entries = asArr(tags['sarif-results']);
  if (!entries || ordinal < 0 || ordinal >= entries.length) return undefined;
  const entry = asMap(entries[ordinal]);
  const loc = asMap(entry?.location);
  return loc && Object.keys(loc).length > 0 ? loc : undefined;
}

/**
 * The PER-RESULT fingerprint maps win. tags["fingerprints"] is a requirement-level
 * summary holding the first result's, so a rule whose results have different
 * fingerprints — the normal case, since a fingerprint identifies a finding — gave
 * every result the first one's, defeating the correlation they exist for.
 * Mirrors Go's resultFingerprintsAt.
 */
function resultFingerprintsAt(req: Obj, ordinal: number): { fingerprints?: Obj; partialFingerprints?: Obj } {
  const tags = asMap(req.tags);
  const entries = tags ? asArr(tags['sarif-results']) : undefined;
  if (entries && ordinal >= 0 && ordinal < entries.length) {
    const entry = asMap(entries[ordinal]);
    const fingerprints = asMap(entry?.fingerprints);
    const partialFingerprints = asMap(entry?.partialFingerprints);
    if ((fingerprints && Object.keys(fingerprints).length > 0)
      || (partialFingerprints && Object.keys(partialFingerprints).length > 0)) {
      return {fingerprints, partialFingerprints};
    }
  }
  return resultFingerprints(req);
}
