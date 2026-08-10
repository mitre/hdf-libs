import { parseJSON, parsePurl } from '@mitre/hdf-utilities';
import {
  nistToCci,
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
} from '@mitre/hdf-mappings';
import { buildAffectedPackage, buildNoFindingsRequirement, deriveControlTypeFromTags, ecosystemFromPurlType, extractCWEIDs, inputChecksum, limitArray, mapCWEToNIST, validateInputSize, buildHdfResults } from '../../../shared/typescript/converterutil.js';
import { Ecosystem } from '@mitre/hdf-schema';
import type { EvaluatedBaseline, EvaluatedRequirement, RequirementResult, Checksum, Description, StatusOverride } from '@mitre/hdf-schema';
import { ResultStatus, IdentityType, OverrideType, VerificationMethodEnum, createMinimalBaseline, createRequirement, createDescription, createResult } from '@mitre/hdf-schema';

// --- SARIF 2.1.0 type definitions ---

interface SarifFile {
  $schema?: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool?: {
    driver?: SarifDriver;
  };
  results: SarifResult[];
  taxonomies?: SarifTaxonomy[];
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

// --- Impact mapping ---

const IMPACT_MAPPING: Record<string, number> = {
  error: 0.7,
  warning: 0.5,
  note: 0.3,
};

// --- Conversion entry point ---

export async function convertSarifToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  validateInputSize(input, 'sarif');
  const resultsChecksum: Checksum = await inputChecksum(input);

  const sarif = parseJSON<SarifFile>(input);

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

  return buildHdfResults({
    generatorName: 'sarif-to-hdf',
    converterVersion,
    toolName: firstDriver?.name,
    toolVersion: firstDriver?.version,
    toolFormat: 'SARIF',
    baselines: limitedRuns.map(run => convertRun(run, sarif.version, resultsChecksum, timestamp)),
    timestamp,
  });
}

// --- Run-level conversion ---

function convertRun(run: SarifRun, version: string, resultsChecksum: Checksum, timestamp: Date): EvaluatedBaseline {
  const ruleMap = buildRuleMap(run);

  // Group SARIF results by ruleId — each group becomes one EvaluatedRequirement.
  // When ruleId is absent, fall back to message text as the grouping key.
  const { items: limitedResults, truncated: truncatedResults } = limitArray(run.results);
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncatedResults) {
    // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedResults.length} result items (original: ${run.results.length})`);
  }
  const groupOrder: string[] = [];
  const groupMap = new Map<string, { rule?: ReportingDescriptor; results: SarifResult[] }>();
  for (const result of limitedResults) {
    const groupKey = result.ruleId || resolveMessageText(result.message, undefined);
    let group = groupMap.get(groupKey);
    if (!group) {
      const rule = ruleMap.get(result.ruleId);
      group = { rule, results: [] };
      groupMap.set(groupKey, group);
      groupOrder.push(groupKey);
    }
    group.results.push(result);
  }

  const requirements = groupOrder.map(ruleId => {
    const group = groupMap.get(ruleId)!;
    return convertResultGroup(ruleId, group.rule, group.results, timestamp);
  });

  // Use tool name for baseline name if available
  const baselineName = run.tool?.driver?.name || 'SARIF';

  if (requirements.length === 0) {
    const driverName = run.tool?.driver?.name?.trim() || '';
    const target = driverName || 'SARIF analyzer';
    const idPrefix = driverName || 'sarif';
    requirements.push(buildNoFindingsRequirement(
      `${idPrefix}-no-findings`,
      `${target} ran and reported zero findings.`,
      timestamp,
    ));
  }

  return createMinimalBaseline(baselineName, requirements, {
    version,
    title: 'Static Analysis Results Interchange Format',
    resultsChecksum,
  });
}

function buildRuleMap(run: SarifRun): Map<string, ReportingDescriptor> {
  const map = new Map<string, ReportingDescriptor>();
  if (run.tool?.driver?.rules) {
    for (const rule of run.tool.driver.rules) {
      map.set(rule.id, rule);
    }
  }
  return map;
}

// --- Result-group conversion (one EvaluatedRequirement per ruleId) ---

function convertResultGroup(ruleId: string, rule: ReportingDescriptor | undefined, sarifResults: SarifResult[], timestamp: Date): EvaluatedRequirement {
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

  // Determine requirement-level impact from the rule's inherent severity
  const ruleLevel = resolveRuleLevel(rule, sarifResults);
  const impact = IMPACT_MAPPING[ruleLevel] || 0.1;

  // Source location from first result's first location
  const sourceLocation = firstResult.locations && firstResult.locations.length > 0
    ? extractSourceLocation(firstResult.locations[0]!)
    : undefined;

  // Convert each SARIF result into RequirementResult(s)
  const results: RequirementResult[] = [];
  for (const sr of sarifResults) {
    results.push(...convertSarifResultToHDFResults(sr));
  }

  // Build descriptions from rule metadata and first result
  const descriptions = buildDescriptions(description, rule, firstResult);

  // Aggregate every suppression across the grouped results so the suppressions
  // tag is a lossless record (the tag is requirement-level; a group can hold
  // suppressed and unsuppressed results).
  const allSuppressions = sarifResults.flatMap(sr => sr.suppressions ?? []);

  // Build tags
  const tags = buildTags(firstResult, rule, ruleLevel, cweIds, nistControls, cciControls, allSuppressions);

  const options: {
    sourceLocation?: { ref: string; line: number };
    tags: Record<string, unknown>;
  } = { tags };

  if (sourceLocation) {
    options.sourceLocation = sourceLocation;
  }

  const req = createRequirement(ruleId, title, descriptions, impact, results, options);
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

// Determines the inherent severity level for a rule, independent of per-result kind overrides.
function resolveRuleLevel(rule: ReportingDescriptor | undefined, results: SarifResult[]): string {
  if (rule?.defaultConfiguration?.level) {
    return rule.defaultConfiguration.level;
  }
  // Find first result that represents a failure with an explicit level
  for (const r of results) {
    if (!r.kind || r.kind === 'fail') {
      if (r.level) {
        return r.level;
      }
    }
  }
  return 'warning';
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
    .filter(loc => loc.physicalLocation?.artifactLocation?.uri)
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

// Returns the suppressions whose status is "accepted". underReview and rejected
// suppressions are NOT overrides — an underReview decision is not final and a
// rejected one was declined.
function acceptedSuppressions(suppressions?: Suppression[]): Suppression[] {
  return (suppressions ?? []).filter(s => s.status === 'accepted');
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
  const expiresAt = new Date();
  expiresAt.setTime(timestamp.getTime());
  expiresAt.setUTCFullYear(expiresAt.getUTCFullYear() + 1);
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

// Orders result statuses for requirement-level rollup (higher = worse). Used to
// decide whether accepted suppressions actually change the effective status.
const STATUS_SEVERITY_RANK: Record<string, number> = {
  [ResultStatus.Failed]: 5,
  [ResultStatus.Error]: 4,
  [ResultStatus.NotReviewed]: 3,
  [ResultStatus.Passed]: 2,
  [ResultStatus.NotApplicable]: 1,
};

// Returns the worst status in the set — the requirement-level status.
function rollupStatus(statuses: ResultStatus[]): ResultStatus {
  let worst = statuses[0]!;
  let worstRank = -1;
  for (const s of statuses) {
    const rank = STATUS_SEVERITY_RANK[s] ?? 0;
    if (rank > worstRank) {
      worstRank = rank;
      worst = s;
    }
  }
  return worst;
}

// Picks the override type that produced the effective rollup status (the governing
// override); falls back to the first override.
function governingDisposition(overrides: StatusOverride[], effective: ResultStatus): OverrideType {
  for (const ov of overrides) {
    if (ov.status === effective) {
      return ov.type;
    }
  }
  return overrides[0]!.type;
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
  cweIds: string[],
  nistControls: string[],
  cciControls: string[],
  allSuppressions: Suppression[]
): Record<string, unknown> {
  const tags: Record<string, unknown> = {
    severity: resolvedLevel,
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

function extractSourceLocation(location: SarifLocation): { ref: string; line: number } | undefined {
  const uri = location.physicalLocation?.artifactLocation?.uri;
  const line = location.physicalLocation?.region?.startLine;

  if (!uri || !line) {
    return undefined;
  }

  return { ref: uri, line };
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

  let codeDesc = `URL : ${uri} LINE : ${line} COLUMN : ${column}`;
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
