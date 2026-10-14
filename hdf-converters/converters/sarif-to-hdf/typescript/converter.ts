import { impactToSeverity, parseJSON, parsePurl, roundImpact, severityToImpactWithAliases, worstStatus } from '@mitre/hdf-utilities';
import {
  nistToCci,
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
} from '@mitre/hdf-mappings';
import { buildAffectedPackage, buildNoFindingsRequirement, buildNotAnalyzedRequirement, buildRunFailedRequirement, deriveControlTypeFromTags, ecosystemFromPurlType, extractCWEIDs, inputChecksum, limitArray, mapCWEToNIST, validateInputSize, buildHdfResults, defaultOverrideExpiry} from '../../../shared/typescript/converterutil.js';
import { Ecosystem } from '@mitre/hdf-schema';
import { governingOverride } from '../../../shared/typescript/status.js';
import { canonicalize, parseJSONPreservingNumbers, stringifyLine } from '../../../shared/typescript/exportmap.js';
import { buildPassthroughBlock, collectPropertyBags, restoreUnexpressible, restoreUnexpressibleResult, resultBagRow, ruleBag, type BagGroup, type SarifLike } from './passthrough.js';
import type { EvaluatedBaseline, EvaluatedRequirement, RequirementResult, Checksum, Description, RawSourceRecord, Severity, SourceLocation, StatusOverride } from '@mitre/hdf-schema';
import { ResultStatus, IdentityType, OverrideType, VerificationMethodEnum, ExternalReferenceEncoding, createMinimalBaseline, createRequirement, createDescription, createResult } from '@mitre/hdf-schema';

// --- SARIF 2.1.0 type definitions ---

interface SarifFile {
  $schema?: string;
  version: string;
  runs: SarifRun[];
  // The log-level bag. Captured only so the passthrough can carry it; nothing in
  // the mapping reads it.
  properties?: Record<string, unknown>;
}

// One execution of the tool. executionSuccessful is the only required property of
// the object, and the only one this converter maps to status; the exit fields are
// read solely to describe the failure. Mirrors Go's SarifInvocation.
interface SarifInvocation {
  executionSuccessful?: boolean;
  exitCode?: number;
  exitCodeDescription?: string;
  exitSignalName?: string;
}

interface SarifRun {
  // The run-level bag, captured for the passthrough only.
  properties?: Record<string, unknown>;
  // Rules may be defined on the driver or on any extension: modern CodeQL leaves
  // tool.driver.rules empty and puts every rule on an extension.
  tool?: {
    driver?: SarifDriver;
    extensions?: SarifDriver[];
  };
  // Nullable and optional on purpose: §3.14.23 gives an absent or null results
  // array the opposite meaning to [] — nothing analyzed, versus a scan that ran
  // and found nothing. Declaring it as a plain array also threw on the null.
  results?: SarifResult[] | null;
  // The run's own account of whether it succeeded. A run can report its own
  // failure, and a failure says something the results array cannot.
  invocations?: SarifInvocation[];
  taxonomies?: SarifTaxonomy[];
  // The table artifactLocation.index addresses (§3.4.5). Only each entry's location
  // is read: an index resolves to that location's uri and no further.
  artifacts?: { location?: { uri?: string; index?: number } }[];
}

interface SarifDriver {
  name?: string;
  version?: string;
  informationUri?: string;
  rules?: ReportingDescriptor[];
}

interface ReportingDescriptor {
  id: string;
  name?: string;
  shortDescription?: MultiformatMessage;
  fullDescription?: MultiformatMessage;
  helpUri?: string;
  help?: MultiformatMessage;
  defaultConfiguration?: ReportingConfiguration;
  relationships?: ReportingDescriptorRelation[];
  properties?: Record<string, unknown>;
  messageStrings?: Record<string, MultiformatMessage>;
}

interface MultiformatMessage {
  text: string;
  markdown?: string;
}

interface ReportingConfiguration {
  level?: string;
}

interface ReportingDescriptorRelation {
  target: DescriptorReference;
  kinds?: string[];
}

interface DescriptorReference {
  id: string;
  guid?: string;
  toolComponent?: ToolComponentReference;
}

interface ToolComponentReference {
  name: string;
  guid?: string;
}

interface SarifTaxonomy {
  name: string;
  version?: string;
  organization?: string;
  taxa?: ReportingDescriptor[];
}

interface SarifResult {
  ruleId: string;
  ruleIndex?: number;
  kind?: string;
  level?: string;
  message: {
    text?: string;
    id?: string;
    arguments?: string[];
  };
  locations?: SarifLocation[];
  relatedLocations?: SarifLocation[];
  suppressions?: Suppression[];
  fixes?: Fix[];
  codeFlows?: CodeFlow[];
  fingerprints?: Record<string, string>;
  partialFingerprints?: Record<string, string>;
  /** SCA-SARIF property-bag carrying package identity. Populated by
   *  SCA tools (Grype, Trivy, Dependency-Check); empty for SAST. */
  properties?: {
    purl?: string;
    cpe?: string;
    packageName?: string;
    packageVersion?: string;
    name?: string;
    version?: string;
    ecosystem?: string;
    fixedInVersion?: string;
  } & Record<string, unknown>;
}

interface Suppression {
  kind: string;
  status?: string;
  justification?: string;
}

interface Fix {
  description?: {
    text: string;
  };
}

interface CodeFlow {
  threadFlows: ThreadFlow[];
}

interface ThreadFlow {
  locations: ThreadFlowLocation[];
}

interface ThreadFlowLocation {
  location: SarifLocation;
  importance?: string;
}

interface SarifLocation {
  id?: number;
  physicalLocation?: {
    artifactLocation?: {
      uri?: string;
      // Optional, so an ABSENT index is undefined rather than 0: §3.4.5 gives index a
      // default of -1, and treating a missing one as 0 would resolve every uri-less
      // location to artifacts[0] and invent a path the document never claimed.
      index?: number;
    };
    region?: {
      startLine?: number;
      startColumn?: number;
      endLine?: number;
      endColumn?: number;
      snippet?: {
        text: string;
      };
    };
  };
  message?: {
    text: string;
  };
}

// SARIF's "severity does not apply" level (§3.27.10), distinct from an absent level,
// which defaults to warning.
const LEVEL_NONE = 'none';

// Where a requirement's impact came from, recorded in tags so a consumer can tell a
// vendor convention from a spec field from a fallback.
const SEVERITY_SOURCE_SECURITY_SEVERITY = 'security-severity';
const SEVERITY_SOURCE_RESULT_LEVEL = 'result-level';
const SEVERITY_SOURCE_RULE_DEFAULT = 'rule-default';
const SEVERITY_SOURCE_FALLBACK = 'fallback';

// --- Impact mapping ---
// SARIF "error"/"warning"/"note" levels are aliases; unknown levels fall through the
// shared standard map to 0.0 and are then bumped to a 0.1 floor at the call site. An
// explicit "none" is exempt from that floor, because §3.27.10 means severity genuinely
// does not apply. Mirrors Go's sarifAliases + getImpact. This table is the FALLBACK —
// a rule carrying a usable security-severity outranks it.
//
// SARIF 2.2 (committee draft) renames this to securitySeverity on a 0-100 scale rather
// than 0-10; nothing here reads that key, so a 2.2 producer falls back to level.
const SARIF_ALIASES: Record<string, number> = {
  error: 0.7,
  warning: 0.5,
  note: 0.3,
};

// --- Conversion entry point ---

export async function convertSarifToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  validateInputSize(input, 'sarif');
  const resultsChecksum: Checksum = await inputChecksum(input);

  const sarif = parseJSON<SarifFile>(input);

  // A SECOND parse, kept apart from the typed one above and used only to build the
  // rawSourceRecords. parseJSON gives numbers as doubles, which is what the typed
  // fields (startLine, index, securitySeverity) want; the record must instead carry
  // the tokens the tool actually wrote, so it is built from this parse. Walking it
  // only to snapshot each result means it is discarded immediately afterward.
  const preserved = parseJSONPreservingNumbers(input) as {runs?: unknown[]} | null;

  if (!sarif || typeof sarif !== 'object') {
    throw new Error('Invalid SARIF structure: not a valid JSON object');
  }

  if (!Array.isArray(sarif.runs)) {
    throw new Error('Invalid SARIF structure: missing or invalid runs field');
  }

  const firstDriver = sarif.runs[0]?.tool?.driver;

  const { items: limitedRuns, truncated: truncatedRuns } = limitArray(sarif.runs);
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncatedRuns) {
    // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedRuns.length} run items (original: ${sarif.runs.length})`);
  }

  const timestamp = new Date();

  const converted = limitedRuns.map((run, runIdx) =>
    convertRun(runIdx, run, sarif.version, resultsChecksum, timestamp, preserved?.runs?.[runIdx]));
  const baselines = converted.map(c => c.baseline);

  // Carriage last, so it describes the document that was actually built: the
  // baseline names it addresses runs by are the ones convertRun settled on.
  const block = buildPassthroughBlock(
    collectPropertyBags(sarif as SarifLike, baselines.map(b => b.name), converted.map(c => c.bagGroups)));

  return buildHdfResults({
    generatorName: 'sarif-to-hdf',
    converterVersion,
    toolName: firstDriver?.name,
    toolVersion: firstDriver?.version,
    toolFormat: 'SARIF',
    baselines,
    timestamp,
    ...(block ? {extensions: {passthrough: {sarif: block}}} : {}),
  });
}

// --- Run-level conversion ---

// Whether the run declared its own execution a failure. Only an explicit false
// counts: executionSuccessful is required on an invocation the run chose to emit,
// so its absence means the run said nothing, not that it failed. Mirrors Go's
// executionFailed.
function executionFailed(run: SarifRun): boolean {
  return (run.invocations ?? []).some(inv => inv.executionSuccessful === false);
}

// The exit information of the first failed invocation, as a parenthetical suffix
// or '' when the run supplied none. Mirrors Go's invocationFailureDetail.
function invocationFailureDetail(run: SarifRun): string {
  for (const inv of run.invocations ?? []) {
    if (inv.executionSuccessful !== false) continue;
    const parts: string[] = [];
    // Null as well as undefined: Go's *int reads JSON null as nil and skips it, so
    // checking only undefined would print "exit code null" in one language alone.
    if (inv.exitCode !== undefined && inv.exitCode !== null) parts.push(`exit code ${inv.exitCode}`);
    if (inv.exitSignalName) parts.push(inv.exitSignalName);
    if (inv.exitCodeDescription) parts.push(inv.exitCodeDescription);
    return parts.length === 0 ? '' : ` (${parts.join(': ')})`;
  }
  return '';
}

// Fills in the uri an artifactLocation.index addresses. §3.4.5 permits a location to
// carry only an index into run.artifacts, so the file IS known even where uri is
// absent — without this the line survives and the path does not.
//
// ONE LEVEL ONLY, and deliberately. An artifact's own location may itself be
// index-addressed, so following the chain would need a cycle guard and would hand a
// consumer a path this converter inferred transitively rather than one the document
// stated about the finding. An artifact whose location has no uri resolves to nothing.
//
// Anything unresolvable falls back to no path rather than throwing: an undefined
// index, the schema's -1 default, a negative value, an index past the table, or no
// table at all. uriBaseId is NOT handled — it names a base-URI symbol resolved
// against run.originalUriBaseIds, which is separate addressing and out of scope.
// Mirrors Go's resolveArtifactIndices.
function resolveArtifactIndices(run: SarifRun): void {
  const artifacts = run.artifacts;
  if (!run.results || !artifacts || artifacts.length === 0) return;

  const resolveOne = (location?: SarifLocation): void => {
    const loc = location?.physicalLocation?.artifactLocation;
    if (!loc || loc.uri || loc.index === undefined) return;
    if (loc.index < 0 || loc.index >= artifacts.length) return;
    const uri = artifacts[loc.index]?.location?.uri;
    if (uri) loc.uri = uri;
  };

  for (const result of run.results) {
    for (const location of result.locations ?? []) resolveOne(location);
    // Code-flow steps are locations too, and extractBacktrace reads them for their uri.
    // Missing them left a backtrace entry as ":7" — an empty path with a bare line, the
    // exact loss this resolution prevents — and CodeQL is the family that hits it.
    for (const flow of result.codeFlows ?? []) {
      for (const thread of flow.threadFlows ?? []) {
        for (const step of thread.locations ?? []) resolveOne(step.location);
      }
    }
  }
}

function convertRun(runIdx: number, run: SarifRun, version: string, resultsChecksum: Checksum, timestamp: Date, preservedRun?: unknown): {baseline: EvaluatedBaseline; bagGroups: BagGroup[]} {
  // Snapshot every result BEFORE resolving indices. resolveArtifactIndices rewrites
  // the parsed objects in place, and rawSourceRecord is built from them, so without
  // this a record would carry the uri THIS CONVERTER inferred rather than what the
  // tool wrote. Go captures the unparsed bytes at decode time for the same reason.
  const preservedResults = (preservedRun as {results?: unknown[]} | undefined)?.results;
  const rawSnapshots = (run.results ?? []).map((r, i) =>
    stringifyLine(canonicalize(preservedResults?.[i] ?? r)).replace(/\n$/, ''));
  resolveArtifactIndices(run);

  const ruleMap = buildRuleMap(run);

  // Group SARIF results by ruleId — each group becomes one EvaluatedRequirement.
  // When ruleId is absent, fall back to message text as the grouping key.
  const analyzed = run.results !== null && run.results !== undefined;
  const { items: limitedResults, truncated: truncatedResults } = limitArray(run.results ?? []);
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncatedResults) {
    // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedResults.length} result items (original: ${(run.results ?? []).length})`);
  }
  const groupOrder: string[] = [];
  // indices is parallel to results: indices[i] is results[i]'s position in
  // run.results, which rawSourceRecord.pointer needs to address the source record.
  const groupMap = new Map<string, { rule?: ReportingDescriptor; results: SarifResult[]; indices: number[]; raws: string[] }>();
  for (const [srcIdx, result] of limitedResults.entries()) {
    const groupKey = result.ruleId || resolveMessageText(result.message, undefined);
    let group = groupMap.get(groupKey);
    if (!group) {
      const rule = ruleMap.get(result.ruleId);
      group = { rule, results: [], indices: [], raws: [] };
      groupMap.set(groupKey, group);
      groupOrder.push(groupKey);
    }
    group.results.push(result);
    group.indices.push(srcIdx);
    group.raws.push(rawSnapshots[srcIdx] ?? '');
  }

  // Collected in the same order the requirement's results are built, so a carried
  // bag's ordinal addresses the result it came from.
  const bagGroups: BagGroup[] = [];
  const requirements = groupOrder.map(ruleId => {
    const group = groupMap.get(ruleId)!;
    bagGroups.push({
      ruleId,
      ruleProps: group.rule?.properties,
      resultProps: group.results.map(r => r.properties),
    });
    return convertResultGroup(runIdx, ruleId, group.rule, group.results, group.indices, group.raws, timestamp);
  });

  // Use tool name for baseline name if available
  const baselineName = run.tool?.driver?.name || 'SARIF';
  const failed = executionFailed(run);

  // A run that declared its own failure contributes a requirement of its own, beside
  // whatever it did report. HDF expresses a partly-failed evaluation as a set of N
  // results where x < N carry error — the way InSpec does, where a control that fails
  // to execute yields error without scrubbing the run. The findings themselves are
  // never restyled: what a failed run tells you is that its coverage was incomplete,
  // not that what it found is wrong.
  //
  // It does NOT go on the baseline. A baseline is a policy document — what was
  // required — and it must not change in response to the results attached to it, or
  // the same policy scanned twice would yield two different baselines.
  if (failed) {
    const driverName = run.tool?.driver?.name?.trim() || '';
    const target = driverName || 'SARIF analyzer';
    const idPrefix = driverName || 'sarif';
    requirements.push(buildRunFailedRequirement(
      `${idPrefix}-run-failed`,
      `${target} reported that its run did not complete successfully${invocationFailureDetail(run)}.`,
      timestamp,
    ));
  }

  if (requirements.length === 0) {
    const driverName = run.tool?.driver?.name?.trim() || '';
    const target = driverName || 'SARIF analyzer';
    const idPrefix = driverName || 'sarif';
    requirements.push(analyzed
      ? buildNoFindingsRequirement(
          `${idPrefix}-no-findings`,
          `${target} ran and reported zero findings.`,
          timestamp,
        )
      : buildNotAnalyzedRequirement(
          `${idPrefix}-not-analyzed`,
          `${target} reported no result set; the run did not analyze.`,
          timestamp,
        ));
  }

  return {
    baseline: createMinimalBaseline(baselineName, requirements, {
      version,
      title: 'Static Analysis Results Interchange Format',
      resultsChecksum,
    }),
    bagGroups,
  };
}

// Indexes every rule a run defines, from the driver and from any extensions.
// Extensions are seeded first so the driver overwrites them: SARIF permits the
// same rule id on both, the driver is the primary tool component, and an
// extension must never silently shadow the tool's own definition. Mirrors Go's
// buildRuleMap.
function buildRuleMap(run: SarifRun): Map<string, ReportingDescriptor> {
  const map = new Map<string, ReportingDescriptor>();
  for (const ext of run.tool?.extensions ?? []) {
    for (const rule of ext.rules ?? []) {
      map.set(rule.id, rule);
    }
  }
  for (const rule of run.tool?.driver?.rules ?? []) {
    map.set(rule.id, rule);
  }
  return map;
}

// --- Result-group conversion (one EvaluatedRequirement per ruleId) ---

function convertResultGroup(runIdx: number, ruleId: string, rule: ReportingDescriptor | undefined, sarifResults: SarifResult[], sourceIndices: number[], raws: string[], timestamp: Date): EvaluatedRequirement {
  const firstResult = sarifResults[0]!;

  // Derive requirement-level metadata from the rule and first result
  const { title, description } = deriveMetadata(firstResult, rule);

  // Extract CWE IDs from rule (or first result message as fallback)
  let cweIds = extractCweFromRule(rule);
  if (cweIds.length === 0) {
    cweIds = extractCweIds(resolveMessageText(firstResult.message, rule));
  }

  const nistControls = mapCWEToNIST(cweIds, DEFAULT_STATIC_ANALYSIS_NIST_TAGS);
  const cciControls = nistToCci(nistControls);

  // Determine requirement-level impact from the rule group's resolved level.
  // security-severity is a GitHub Code Scanning convention, NOT a SARIF one: the
  // string appears nowhere in the OASIS 2.1.0 specification or its schema. It
  // currently OUTRANKS level because it is a 0-10 score rather than one of four
  // buckets, so it carries severity spread that level cannot. Whether a vendor
  // convention should outrank a spec field is an open question on this card.
  const {level: ruleLevel, source: levelSource} = resolveRuleLevel(rule, sarifResults);
  const cvssImpact = securitySeverityImpact(rule);
  const severitySource = cvssImpact === undefined ? levelSource : SEVERITY_SOURCE_SECURITY_SEVERITY;
  const rawImpact = cvssImpact ?? severityToImpactWithAliases(ruleLevel, SARIF_ALIASES, 0.0);
  // Impact 0 is floored so an unrecognized level does not read as "not applicable",
  // which is what the effective-status ladder makes of it. An explicit "none" is
  // exempt: §3.27.10 means severity genuinely does not apply there.
  const impact = rawImpact === 0 && ruleLevel !== LEVEL_NONE ? 0.1 : rawImpact;

  // Source location from first result's first location
  const sourceLocation = firstResult.locations && firstResult.locations.length > 0
    ? extractSourceLocation(firstResult.locations[0]!)
    : undefined;

  // Convert each SARIF result into RequirementResult(s), and give every one the
  // native record it came from. §3.27.12 says the locations array is not a list of
  // distinct occurrences, yet one HDF result per location is what a consumer can act
  // on, so the expansion stays and the source cardinality is published instead (see
  // the sarif-source-result-count tag). All results expanded from one SARIF result
  // share its record and pointer, because they share its source.
  const results: RequirementResult[] = [];
  const perResult: Record<string, unknown>[] = [];
  for (const [i, sr] of sarifResults.entries()) {
    const expanded = convertSarifResultToHDFResults(sr);
    const record = rawSourceRecordFor(raws[i] ?? '', runIdx, sourceIndices[i] ?? i);
    for (const [j, r] of expanded.entries()) {
      // The record goes on the FIRST expanded result only. All of them came from one
      // SARIF result and so share one source record, and that record contains the whole
      // locations array — so copying it onto each of N expanded results makes the output
      // grow with the SQUARE of the location count (measured: a 20KB input with 200
      // locations produced 4.3MB). One record per SARIF result is the honest cardinality
      // and keeps ADR-0017's rule intact, since nothing is merged across SARIF results;
      // the record's own pointer still says which result it came from.
      if (j === 0) r.rawSourceRecord = record;
      // Result fields SARIF cannot carry, from the row hdf-to-sarif put on this
      // result's own bag. Every expanded row came from one SARIF result, so they
      // share its carriage the way they share its record.
      restoreUnexpressibleResult(r as unknown as Record<string, unknown>, resultBagRow(sr));
      perResult.push(perResultTagEntry(sr));
    }
    results.push(...expanded);
  }

  // Title, descriptions, sourceLocation, code and fixes are deliberately derived from
  // the FIRST result and are a requirement-level SUMMARY, not a per-result record. HDF
  // scopes these to the requirement while SARIF scopes them to each finding, and
  // synthesizing a merged title would invent a requirement no tool reported. The
  // per-result detail lives on each result's rawSourceRecord.
  // Build descriptions from rule metadata and first result
  const descriptions = buildDescriptions(description, rule, firstResult);

  // Aggregate every suppression across the grouped results so the suppressions
  // tag is a lossless record (the tag is requirement-level; a group can hold
  // suppressed and unsuppressed results).
  const allSuppressions = sarifResults.flatMap(sr => sr.suppressions ?? []);

  // Build tags
  const tags = buildTags(firstResult, rule, ruleLevel, severitySource, cweIds, nistControls, cciControls, allSuppressions);
  tags['sarif-results'] = perResult;
  tags['sarif-source-result-count'] = sarifResults.length;
  // An aggregate kind is published only when the group agrees on one. Taking the
  // first result's kind made a group holding a pass and a fail report just one.
  const uk = uniformKind(sarifResults);
  if (uk !== undefined) {
    tags['kind'] = uk;
  } else {
    delete tags['kind'];
  }

  const options: {
    sourceLocation?: SourceLocation;
    tags: Record<string, unknown>;
  } = { tags };

  if (sourceLocation) {
    options.sourceLocation = sourceLocation;
  }

  const req = createRequirement(ruleId, title, descriptions, impact, results, options);
  // severity is a schema field consumers read directly, so the converter records
  // the band it already knows rather than leaving every consumer to re-derive it.
  // (The threshold engine is not one of them — it falls back to impact when
  // severity is absent — so this changes what is published, not what gates.)
  req.severity = impactToSeverity(impact) as Severity;
  const controlType = deriveControlTypeFromTags(nistControls);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }
  req.verificationMethod = VerificationMethodEnum.Automated;

  // requirement.code = raw source snippet (region.snippet.text) so Heimdall's
  // CODE tab is populated. Only set when a primary location carries a snippet —
  // never fabricated.
  const snippet = (firstResult.locations ?? [])
    .map((loc) => loc.physicalLocation?.region?.snippet?.text)
    .find((text): text is string => Boolean(text));
  if (snippet) {
    (req as EvaluatedRequirement).code = snippet;
  }

  // SCA-shaped SARIF (Grype, Trivy, Dependency-Check) carries package
  // identity in result.properties. Pure SAST results have empty
  // properties → no affectedPackage. We dedupe by purl/cpe/name@version
  // across the grouped results since SCA tools sometimes emit one
  // SARIF result per occurrence.
  const seenKeys = new Set<string>();
  const packages = [];
  for (const sr of sarifResults) {
    const pkg = packageFromSarifProperties(sr.properties);
    if (!pkg) continue;
    const key = pkg.purl ?? pkg.cpe ?? `${pkg.name ?? ''}@${pkg.version ?? ''}`;
    if (seenKeys.has(key)) continue;
    seenKeys.add(key);
    packages.push(pkg);
  }
  if (packages.length > 0) {
    (req as EvaluatedRequirement).affectedPackages = packages;
  }

  // Reconstruct structured status overrides from accepted suppressions. Each
  // accepted suppression across the grouped results becomes an attributed,
  // expiring override; effectiveStatus/disposition are set only when the overrides
  // actually change the requirement's rolled-up status (an unsuppressed sibling
  // failure keeps the requirement effectively failed).
  const overrides: StatusOverride[] = [];
  const rawStatuses: ResultStatus[] = [];
  const effStatuses: ResultStatus[] = [];
  for (const sr of sarifResults) {
    const raw = mapKindToStatus(sr.kind);
    rawStatuses.push(raw);
    if (raw === ResultStatus.Failed || raw === ResultStatus.Passed) {
      const built = buildSuppressionOverride(sr, timestamp);
      if (built) {
        overrides.push(built.override);
        effStatuses.push(built.effective);
        continue;
      }
    }
    effStatuses.push(raw);
  }
  if (overrides.length > 0) {
    const r = req as EvaluatedRequirement;
    r.statusOverrides = overrides;
    const effRoll = rollupStatus(effStatuses);
    const rawRoll = rollupStatus(rawStatuses);
    if (effRoll !== rawRoll) {
      r.effectiveStatus = effRoll;
      r.disposition = governingDisposition(overrides, effRoll);
    }
  }

  // Last: restore only what SARIF cannot express, from the carried bag if one is
  // there. Untrusted and optional by design — see restoreUnexpressible.
  const bag = ruleBag(rule);
  if (bag) restoreUnexpressible(req as unknown as Record<string, unknown>, bag);

  return req;
}

/**
 * Extract an Affected_Package from a SARIF result.properties bag.
 * Recognizes the SCA-tool convention of carrying purl / cpe /
 * packageName+packageVersion / name+version. Returns undefined for
 * SAST results that lack any package identity.
 */
function packageFromSarifProperties(props: SarifResult['properties']): ReturnType<typeof buildAffectedPackage> {
  if (!props) return undefined;
  const name = props.packageName ?? props.name;
  const version = props.packageVersion ?? props.version;
  let ecosystem: Ecosystem | undefined;
  if (props.purl) {
    const parsed = parsePurl(props.purl);
    ecosystem = ecosystemFromPurlType(parsed?.type);
  } else if (props.ecosystem) {
    ecosystem = ecosystemFromPurlType(props.ecosystem);
  } else if (name && version) {
    ecosystem = Ecosystem.Generic;
  }
  return buildAffectedPackage({
    name,
    version,
    ecosystem,
    purl: props.purl,
    cpe: props.cpe,
    fixedInVersion: props.fixedInVersion,
  });
}

// Matches the plain decimal forms a CVSS score is written in. It exists to keep
// TypeScript and Go agreeing on what parses: Number() accepts "0x8" and "0b101"
// while Go's strconv.ParseFloat accepts hex-float literals ("0x1p3"), so each
// language would otherwise take a value the other rejects. Neither form is a CVSS
// score, so both languages reject both. Mirrors Go's decimalScore.
const DECIMAL_SCORE = /^[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$/;

// Reads the rule's security-severity property — a GitHub Code Scanning convention
// for carrying a CVSS base score, absent from the OASIS SARIF 2.1.0 specification
// and its schema — and scales it to an HDF impact. Returns undefined when the property is absent or is not a finite
// score within 0.0-10.0, so the caller falls back to the level mapping rather than
// deriving an impact from an unusable value. Producers emit the score as a string;
// a JSON number is accepted too. Mirrors Go's securitySeverityImpact.
function securitySeverityImpact(rule?: ReportingDescriptor): number | undefined {
  const raw = rule?.properties?.['security-severity'];
  if (raw === undefined || raw === null) return undefined;
  let score: number;
  if (typeof raw === 'string') {
    const trimmed = raw.trim();
    if (!DECIMAL_SCORE.test(trimmed)) return undefined;
    score = Number(trimmed);
  } else if (typeof raw === 'number') {
    score = raw;
  } else {
    return undefined;
  }
  // score <= 0, not < 0: GitHub documents 0.0 and out-of-range values alike as
  // carrying no security severity, so both fall through to the level mapping.
  if (!Number.isFinite(score) || score <= 0 || score > 10) return undefined;
  return roundImpact(score / 10);
}

// Orders the SARIF level enum by severity so a rule group reports its worst member.
// "none" is outside the order: §3.27.10 defines it as severity not applying, so it
// never competes with a real level.
const LEVEL_RANK: Record<string, number> = {note: 1, warning: 2, error: 3};

// An unrecognized level ranks 0, matching Go's zero value for a missing map key, so
// the two languages order the same group identically.
const rankOf = (level: string): number => LEVEL_RANK[level] ?? 0;

// Determines a rule group's level and where it came from. Mirrors Go's resolveRuleLevel.
//
// §3.27.10 resolves a level only for a result whose kind is "fail" (§3.27.9 defaults
// an absent kind to "fail"), in the order: the result's own level, then
// invocation.ruleConfigurationOverrides, then rule.defaultConfiguration.level, then
// "warning". The override branch is deliberately not implemented — it needs
// run.invocations and result.provenance, neither of which is parsed yet.
//
// Only a failing result's level is ranked, and a "none" is never ranked at all.
// §3.27.10 defines "none" as "the concept of severity does not apply to this result
// because the kind property has a value other than fail". So a "none" on a failing
// result contradicts the spec's own definition and is ignored rather than honoured —
// honouring it would put a reported FAILURE at impact 0, which the effective-status
// ladder reads as notApplicable, dropping a real finding out of the denominator.
//
// A group's level is its WORST failing member, not its first. SARIF scopes severity
// to the result; HDF scopes it to the requirement, and a result says only that a
// requirement of that severity is in some state. That difference is deliberate on
// both sides, so the per-result level is summarized onto the requirement rather than
// HDF's model being bent to mirror SARIF's. Worst-wins cannot under-report.
function resolveRuleLevel(
  rule: ReportingDescriptor | undefined,
  results: SarifResult[]
): {level: string; source: string} {
  const ruleDefault = rule?.defaultConfiguration?.level ?? '';
  let worst = '';
  let source = '';
  let sawNone = false;
  for (const r of results) {
    const failing = !r.kind || r.kind === 'fail';
    if (r.level === LEVEL_NONE) {
      // Only meaningful on a non-failing result, which is the conformant case.
      if (!failing) sawNone = true;
      continue;
    }
    if (!failing) continue;
    // Resolve each failing result SEPARATELY before ranking. A failing result with no
    // level of its own inherits the rule default, so ranking the raw levels would let
    // an explicit note outrank the error a level-less sibling inherited.
    let effective = r.level ?? '';
    let from = SEVERITY_SOURCE_RESULT_LEVEL;
    if (!effective) {
      effective = ruleDefault;
      from = SEVERITY_SOURCE_RULE_DEFAULT;
    }
    if (!effective) {
      effective = 'warning';
      from = SEVERITY_SOURCE_FALLBACK;
    }
    if (!worst || rankOf(effective) > rankOf(worst)) {
      worst = effective;
      source = from;
    }
  }
  if (worst) return {level: worst, source};
  if (ruleDefault) return {level: ruleDefault, source: SEVERITY_SOURCE_RULE_DEFAULT};
  if (sawNone) return {level: LEVEL_NONE, source: SEVERITY_SOURCE_RESULT_LEVEL};
  return {level: 'warning', source: SEVERITY_SOURCE_FALLBACK};
}

// Carries one SARIF result, complete, on the HDF result(s) it produced. ADR-0017 scoped
// this to the result deliberately: records merged onto the requirement collide, and
// merging entries that share an id has to discard one, which is how the non-first
// result's metadata used to be lost. Encoding is utf-8 rather than base64 because a
// SARIF result is JSON and therefore valid UTF-8 text. Mirrors Go's rawSourceRecordFor.
function rawSourceRecordFor(content: string, runIdx: number, resultIdx: number): RawSourceRecord {
  return {
    // The parsed result carries every property the document had, including the 17 of
    // SARIF's 30 that SarifResult does not declare; sorting matches Go, whose record
    // is re-marshalled from the untyped result for the same reason. Original key order
    // and whitespace are therefore not preserved — the content is complete, not
    // byte-exact. The shared canonical encoder is used rather than JSON.stringify
    // because Go HTML-escapes <, > and & while JavaScript does not, and because it
    // sorts keys, escapes U+2028/U+2029 and normalizes negative zero — the four
    // places the two languages' serializers disagree.
    content,
    encoding: ExternalReferenceEncoding.UTF8,
    mediaType: 'application/json',
    pointer: `/runs/${runIdx}/results/${resultIdx}`,
  };
}

// The queryable half of per-result carriage. rawSourceRecord holds the whole record
// but as an opaque string, so nothing can filter on what is inside it; fingerprints
// exist for cross-run correlation, which needs them addressable. Only fields a
// requirement-level summary cannot represent go here. Mirrors Go's perResultTagEntry.
function perResultTagEntry(result: SarifResult): Record<string, unknown> {
  const entry: Record<string, unknown> = {
    // The EFFECTIVE kind: §3.27.9 defaults an absent kind to "fail". This is a new
    // key, so applying the default invents no history; tags["kind"] stays verbatim.
    kind: result.kind || 'fail',
  };
  if (result.level) entry.level = result.level;
  if (result.fingerprints && Object.keys(result.fingerprints).length > 0) {
    entry.fingerprints = result.fingerprints;
  }
  if (result.partialFingerprints && Object.keys(result.partialFingerprints).length > 0) {
    entry.partialFingerprints = result.partialFingerprints;
  }
  // The result's OWN message. SARIF scopes a message to the result; HDF's
  // requirement-level descriptions[default] holds the first one as a summary, so
  // without this a rule whose results carry different messages keeps only one, and
  // an exporter re-deriving the message falls back to codeDesc — HDF location prose,
  // not what the tool said.
  if (result.message?.text) entry.message = result.message.text;
  // The result's OWN location. HDF's Source_Location is {ref, line} and closed and
  // sits on the REQUIREMENT, so a rule with ten results at ten places kept only the
  // first and an exporter re-emitting them gave all ten that one location. Mirrors
  // Go's perResultLocation.
  const loc = perResultLocation(result);
  if (loc) entry.location = loc;
  return entry;
}

/**
 * Carries one result's first location: the uri and the region members SARIF defines
 * as integers. Only the FIRST — a multi-location result is expanded into several
 * HDF results on import, so each expanded row carries what it was expanded from.
 */
function perResultLocation(result: SarifResult): Record<string, unknown> | undefined {
  const phys = result.locations?.[0]?.physicalLocation;
  if (!phys) return undefined;
  const out: Record<string, unknown> = {};
  if (phys.artifactLocation?.uri) out.ref = phys.artifactLocation.uri;
  const r = phys.region;
  if (r) {
    const region: Record<string, number> = {};
    for (const [k, v] of Object.entries({
      startLine: r.startLine, startColumn: r.startColumn,
      endLine: r.endLine, endColumn: r.endColumn,
    })) {
      if (typeof v === 'number' && v !== 0) region[k] = v;
    }
    // The snippet rides here too. It is the one region member with no HDF home at
    // all — it reaches codeDesc as prose and nothing structured — so without this an
    // exporter has nothing to rebuild region.snippet from.
    const snippetText = r.snippet?.text;
    if (snippetText) (region as Record<string, unknown>).snippet = {text: snippetText};
    if (Object.keys(region).length > 0) out.region = region;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

// The kind every result in the group STATED, or undefined when they disagree or any
// omitted it. Deliberately not defaulting an absent kind to "fail" even though
// §3.27.9 does: tags["kind"] carries what the tool wrote, the way tags["sarif-level"]
// carries the level verbatim, so publishing a spec-derived value under the same key
// would silently change what the tag means. The effective kind is in the per-result
// entries instead. Mirrors Go's uniformKind.
function uniformKind(results: SarifResult[]): string | undefined {
  let kind: string | undefined;
  for (const r of results) {
    if (!r.kind) return undefined;
    if (kind === undefined) {
      kind = r.kind;
      continue;
    }
    if (r.kind !== kind) return undefined;
  }
  return kind;
}

// Converts a single SARIF result into one or more HDF RequirementResults.
function convertSarifResultToHDFResults(result: SarifResult): RequirementResult[] {
  // Map kind to HDF status. The raw status stays the tool's — an accepted
  // suppression becomes a structured, attributed override on the requirement
  // (see convertResultGroup), not a laundered notReviewed status.
  const status = mapKindToStatus(result.kind);

  // Surface an accepted suppression's justification as an informative per-result
  // message; the requirement's Status_Override carries the authoritative record.
  let suppressionJustification = '';
  if (status === ResultStatus.Failed || status === ResultStatus.Passed) {
    suppressionJustification = acceptedSuppressionReason(result.suppressions);
  }

  // Build backtrace from code flows
  const backtrace = extractBacktrace(result.codeFlows);

  // Create results for each location
  const results = (result.locations || [])
    // Keep a location when there is something representable in it. Filtering on a
    // truthy uri discarded a position that was known, because §3.4.5 permits an
    // artifactLocation carrying only an index and region is a sibling of
    // artifactLocation. Accepting any physicalLocation went too far the other way: the
    // schema's anyOf admits an address instead of an artifactLocation, and an address
    // with no region became "LINE : 0 COLUMN : 0". Mirrors Go's gate.
    .filter(
      loc =>
        loc.physicalLocation !== undefined &&
        (loc.physicalLocation.artifactLocation !== undefined || loc.physicalLocation.region !== undefined)
    )
    .map(loc => createHDFResult(loc, status, backtrace, suppressionJustification));

  // If no locations, create a location-less result so the finding isn't silently dropped
  if (results.length === 0) {
    const locationlessResult: RequirementResult = {
      status,
      codeDesc: 'No source location',
      startTime: new Date(),
    };
    if (backtrace.length > 0) {
      locationlessResult.backtrace = backtrace;
    }
    if (suppressionJustification) {
      locationlessResult.message = `Suppressed: ${suppressionJustification}`;
    }
    results.push(locationlessResult);
  }

  return results;
}

// --- Message resolution ---

function resolveMessageText(msg: SarifResult['message'], rule?: ReportingDescriptor): string {
  if (msg?.text) {
    return msg.text;
  }
  if (msg?.id && rule) {
    const tmpl = rule.messageStrings?.[msg.id];
    if (tmpl) {
      let text = tmpl.text;
      for (const [i, arg] of (msg.arguments ?? []).entries()) {
        text = text.split(`{${i}}`).join(arg);
      }
      return text;
    }
  }
  return '';
}

// --- Metadata derivation ---

function deriveMetadata(result: SarifResult, rule?: ReportingDescriptor): { title: string; description: string } {
  const messageText = resolveMessageText(result.message, rule);
  if (rule?.name) {
    return { title: rule.name, description: messageText };
  }
  if (rule?.shortDescription?.text) {
    return { title: rule.shortDescription.text, description: messageText };
  }
  return parseMessage(messageText);
}

function parseMessage(text: string): { title: string; description: string } {
  const colonIndex = (text ?? '').indexOf(':');
  if (colonIndex === -1) {
    return { title: text, description: '' };
  }
  return {
    title: text.substring(0, colonIndex).trim(),
    description: text.substring(colonIndex + 1).trim(),
  };
}

// --- CWE extraction with priority ---

function extractCweFromRule(rule?: ReportingDescriptor): string[] {
  if (!rule) {
    return [];
  }

  // Priority 1: rule.relationships where toolComponent.name == "CWE"
  if (rule.relationships) {
    const cweIds: string[] = [];
    for (const rel of rule.relationships) {
      if (rel.target.toolComponent?.name?.toLowerCase() === 'cwe') {
        const id = rel.target.id.startsWith('CWE-') ? rel.target.id : `CWE-${rel.target.id}`;
        cweIds.push(id);
      }
    }
    if (cweIds.length > 0) {
      return cweIds;
    }
  }

  // Priority 2: CWE identifiers embedded in rule.properties.tags. CodeQL writes
  // them as taxonomy paths ("external/cwe/cwe-022"), so match anywhere in the
  // tag rather than requiring the whole tag to be a bare CWE id.
  if (rule.properties?.tags && Array.isArray(rule.properties.tags)) {
    const cweIds: string[] = [];
    for (const tag of rule.properties.tags as string[]) {
      if (typeof tag !== 'string') continue;
      cweIds.push(...extractCWEIDs(tag).map(id => `CWE-${id}`));
    }
    if (cweIds.length > 0) {
      return cweIds;
    }
  }

  return [];
}

function extractCweIds(text: string): string[] {
  return extractCWEIDs(text).map(id => `CWE-${id}`);
}

// --- Kind → Status mapping ---

function mapKindToStatus(kind?: string): ResultStatus {
  switch (kind) {
    case 'pass':
      return ResultStatus.Passed;
    case 'open':
      return ResultStatus.Failed;
    case 'review':
      return ResultStatus.NotReviewed;
    case 'informational':
      return ResultStatus.NotApplicable;
    case 'notApplicable':
      return ResultStatus.NotApplicable;
    default: // "fail" or undefined
      return ResultStatus.Failed;
  }
}

// --- Suppression handling ---

// Fallback Reason for an accepted suppression that carries no justification text
// (reason is REQUIRED on a Status_Override).
const DEFAULT_SUPPRESSION_REASON = 'Suppressed in SARIF source';

// Returns the suppressions in force: status "accepted" or absent — SARIF 2.1.0
// treats a suppression without status as effective, and real producers (CodeQL,
// semgrep) commonly emit only {"kind": ...}. underReview and rejected
// suppressions are NOT overrides — an underReview decision is not final and a
// rejected one was declined.
function acceptedSuppressions(suppressions?: Suppression[]): Suppression[] {
  return (suppressions ?? []).filter(s => s.status === 'accepted' || !s.status);
}

// Joins the justifications of a result's accepted suppressions, falling back to a
// constant when none carry text. Empty when the result has no accepted suppression.
function acceptedSuppressionReason(suppressions?: Suppression[]): string {
  const accepted = acceptedSuppressions(suppressions);
  if (accepted.length === 0) {
    return '';
  }
  const justifications = accepted.map(s => s.justification).filter((j): j is string => Boolean(j));
  return justifications.length > 0 ? justifications.join('; ') : DEFAULT_SUPPRESSION_REASON;
}

// Reports whether a suppression justification reads as a false-positive
// determination rather than a risk-accepted waiver.
function justificationIndicatesFalsePositive(justification?: string): boolean {
  const lower = (justification ?? '').toLowerCase();
  return lower.includes('false positive') || lower.includes('false-positive');
}

// Turns a result's accepted suppression(s) into an HDF Status_Override. SARIF
// carries no owner or decision date, so appliedBy is an honest system identity and
// appliedAt is the run/conversion time (expiresAt +1yr). A justification that reads
// as a false positive maps to falsePositive → notApplicable (SARIF is a vuln/SAST
// format); otherwise a risk-accepted waiver → passed. Returns undefined when the
// result has no accepted suppression.
function buildSuppressionOverride(result: SarifResult, timestamp: Date): { override: StatusOverride; effective: ResultStatus } | undefined {
  const accepted = acceptedSuppressions(result.suppressions);
  if (accepted.length === 0) {
    return undefined;
  }
  const isFalsePositive = accepted.some(s => justificationIndicatesFalsePositive(s.justification));
  const type = isFalsePositive ? OverrideType.FalsePositive : OverrideType.Waiver;
  const effective = isFalsePositive ? ResultStatus.NotApplicable : ResultStatus.Passed;
  // expiresAt = appliedAt + 1yr; setTime avoids the eslint new Date(value) ban.
  const expiresAt = defaultOverrideExpiry(timestamp);
  const override: StatusOverride = {
    type,
    status: effective,
    reason: acceptedSuppressionReason(result.suppressions),
    appliedBy: { type: IdentityType.Other, identifier: 'sarif suppression' },
    appliedAt: timestamp,
    expiresAt,
  };
  return { override, effective };
}

// Returns the worst status in the set per the canonical worst-wins ordering
// (STATUS_SEVERITY_ORDER in @mitre/hdf-utilities) — the requirement-level status.
function rollupStatus(statuses: ResultStatus[]): ResultStatus {
  return worstStatus(statuses) as ResultStatus;
}

// The type of the override that explains the requirement's effective status: the
// one asserting that status, else the governing (most recently applied
// non-expired) one.
//
// It previously scanned for an override whose status matched the effective
// rollup and fell back to overrides[0]. That missed entirely when the governing
// override carried only an impact — the canonical riskAdjustment shape, which
// sets no status — and the fallback read array position as recency, which it is
// not: nothing sorts these and this repo's writers append.
function governingDisposition(overrides: StatusOverride[], effective: ResultStatus): OverrideType {
  // Every override this converter creates carries the same appliedAt (the run
  // timestamp), so recency cannot tell them apart — but they may differ in type
  // (waiver vs falsePositive) and in the status they assert. The override whose
  // status produced the rollup is the one that explains it, so that match stays
  // the primary rule here. Recency is only the tie-break beneath it.
  for (const ov of overrides) {
    if (ov.status === effective) {
      return ov.type;
    }
  }
  // No override asserts the effective status — the governing one carries only an
  // impact, say. Fall back to the shared rule rather than to array position.
  const o = governingOverride({ statusOverrides: overrides } as EvaluatedRequirement);
  return (o?.type ?? overrides[0]!.type) as OverrideType;
}

// --- Code flow → backtrace ---

function extractBacktrace(codeFlows?: CodeFlow[]): string[] {
  if (!codeFlows || codeFlows.length === 0) {
    return [];
  }

  const backtrace: string[] = [];
  for (const cf of codeFlows) {
    for (const tf of cf.threadFlows) {
      for (const tfl of tf.locations) {
        const loc = tfl.location;
        const uri = loc.physicalLocation?.artifactLocation?.uri || '';
        const line = loc.physicalLocation?.region?.startLine || 0;
        const msg = loc.message?.text || '';

        let entry = `${uri}:${line}`;
        if (msg) {
          entry = `${uri}:${line} - ${msg}`;
        }
        backtrace.push(entry);
      }
    }
  }

  return backtrace;
}

// --- Description building ---

function buildDescriptions(defaultDesc: string, rule: ReportingDescriptor | undefined, result: SarifResult): Description[] {
  const descriptions: Description[] = [
    createDescription('default', defaultDesc),
  ];

  if (rule) {
    if (rule.fullDescription?.text) {
      descriptions.push(createDescription('rationale', rule.fullDescription.text));
    } else if (rule.shortDescription?.text && !defaultDesc) {
      descriptions[0] = createDescription('default', rule.shortDescription.text);
    }

    if (rule.help?.text) {
      descriptions.push(createDescription('check', rule.help.text));
    }
  }

  if (result.fixes && result.fixes.length > 0 && result.fixes[0]?.description?.text) {
    descriptions.push(createDescription('fix', result.fixes[0].description.text));
  }

  return descriptions;
}

// --- Tag building ---

function buildTags(
  result: SarifResult,
  rule: ReportingDescriptor | undefined,
  resolvedLevel: string,
  severitySource: string,
  cweIds: string[],
  nistControls: string[],
  cciControls: string[],
  allSuppressions: Suppression[]
): Record<string, unknown> {
  const tags: Record<string, unknown> = {
    // The SARIF level verbatim. Not "severity": impact may derive from GitHub's
    // security-severity instead, so one name would carry two different values.
    'sarif-level': resolvedLevel,
    'sarif-severity-source': severitySource,
    cwe: cweIds,
    nist: nistControls,
    cci: cciControls,
  };

  if (result.kind) {
    tags.kind = result.kind;
  }

  if (rule?.helpUri) {
    tags.helpUri = rule.helpUri;
  }

  // Store EVERY suppression across the grouped results — accepted, underReview,
  // AND rejected — losslessly. Only accepted ones drive a statusOverride; the
  // non-accepted records must still survive here so no source data is dropped.
  if (allSuppressions.length > 0) {
    tags.suppressions = allSuppressions.map(s => {
      const entry: Record<string, string> = { kind: s.kind };
      if (s.status) {
        entry.status = s.status;
      }
      if (s.justification) {
        entry.justification = s.justification;
      }
      return entry;
    });
  }

  if ((result.fingerprints && Object.keys(result.fingerprints).length > 0) ||
      (result.partialFingerprints && Object.keys(result.partialFingerprints).length > 0)) {
    const fp: Record<string, unknown> = {};
    if (result.fingerprints && Object.keys(result.fingerprints).length > 0) {
      fp.fingerprints = result.fingerprints;
    }
    if (result.partialFingerprints && Object.keys(result.partialFingerprints).length > 0) {
      fp.partialFingerprints = result.partialFingerprints;
    }
    tags.fingerprints = fp;
  }

  return tags;
}

// --- Location helpers ---

// Either half alone is a location (the schema requires neither): a lockfile
// finding has a file and no line. Mirrors the Go converter.
function extractSourceLocation(location: SarifLocation): SourceLocation | undefined {
  const uri = location.physicalLocation?.artifactLocation?.uri;
  const line = location.physicalLocation?.region?.startLine;

  const sourceLocation: SourceLocation = {};
  if (uri) {
    sourceLocation.ref = uri;
  }
  if (line) {
    sourceLocation.line = line;
  }
  return sourceLocation.ref !== undefined || sourceLocation.line !== undefined ? sourceLocation : undefined;
}

function createHDFResult(
  location: SarifLocation,
  status: ResultStatus,
  backtrace: string[],
  suppressionMessage?: string
): RequirementResult {
  const uri = location.physicalLocation?.artifactLocation?.uri || '';
  const line = location.physicalLocation?.region?.startLine || 0;
  const column = location.physicalLocation?.region?.startColumn || 0;
  const snippet = location.physicalLocation?.region?.snippet?.text;

  // The URL slot is omitted when no uri is known rather than left empty: publishing
  // "URL :  LINE : 5" reads as missing data, while dropping the location would discard
  // a line we have. An index into run.artifacts is resolved before this point (see
  // resolveArtifactIndices), so a uri reaching here as empty means the document
  // addressed no resolvable file. Mirrors Go's createHDFResult.
  let codeDesc = `LINE : ${line} COLUMN : ${column}`;
  if (uri) {
    codeDesc = `URL : ${uri} ${codeDesc}`;
  }
  if (snippet) {
    codeDesc = `${codeDesc}\n${snippet}`;
  }

  const result = createResult(status, undefined, {
    codeDesc,
    startTime: new Date(),
  });
  delete result.message;
  if (suppressionMessage) {
    result.message = `Suppressed: ${suppressionMessage}`;
  }
  if (backtrace.length > 0) {
    result.backtrace = backtrace;
  }
  return result;
}
