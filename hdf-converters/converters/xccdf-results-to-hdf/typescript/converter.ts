import { parseXmlWithArrays, parseTimestamp } from '@mitre/hdf-utilities';
import { buildNoFindingsRequirement, deriveControlTypeFromTags, inputChecksum, inputIntegrity, limitArray, stripHTML, validateInputSize, serializeHdf } from '../../../shared/typescript/converterutil.js';
import type {
  HDFResults,
  HDFBaseline,
  BaselineRequirement,
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Checksum,
  Description,
  RequirementGroup,
  Component,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  TargetType,
  Severity,
  createMinimalBaseline,
  createRequirement,
  severityToImpact,
} from '@mitre/hdf-schema';
import { getCCINistMappings } from '@mitre/hdf-mappings';

// ---------------------------------------------------------------------------
// Parsed XCCDF types (post-fast-xml-parser with removeNSPrefix)
// ---------------------------------------------------------------------------

interface XccdfBenchmark {
  Benchmark?: BenchmarkElement;
}

interface BenchmarkElement {
  id?: string;
  title?: string | TextElement;
  description?: string | TextElement;
  version?: string | VersionElement;
  Group?: GroupElement[];
  Rule?: RuleElement[];
  Profile?: ProfileElement[];
  TestResult?: TestResultElement;
  'plain-text'?: PlainText | PlainText[];
}

interface TextElement {
  '#text'?: string;
}

interface VersionElement {
  '#text'?: string;
  update?: string;
}

interface PlainText {
  '#text'?: string;
  id?: string;
}

interface ProfileElement {
  id?: string;
  title?: string | TextElement;
}

/**
 * An XCCDF Group. A Group may hold any number of Rules and may nest further
 * Groups — SCAP Security Guide content relies on both, so a Group must not be
 * treated as a flat, single-rule container.
 */
interface GroupElement {
  id?: string;
  title?: string | TextElement;
  Rule?: RuleElement[];
  Group?: GroupElement[];
}

/** A rule paired with the Group it was found in, at any depth. */
interface GroupedRule {
  rule: RuleElement;
  group: GroupElement;
}

/**
 * Map XCCDF's severity vocabulary (unknown|info|low|medium|high) onto HDF's
 * (critical|high|medium|low|informational). Casting the raw attribute straight to
 * Severity emitted schema-invalid documents, since XCCDF "unknown" and "info" are
 * not HDF severities.
 *
 * "unknown" states that severity was not determined. HDF cannot express that, so
 * emit no severity at all rather than assert "informational", which would silently
 * downgrade a rule whose severity is merely unstated.
 */
function xccdfSeverityToHdf(severity: string): Severity | undefined {
  switch (severity.toLowerCase()) {
    case 'high':
      return Severity.High;
    case 'medium':
      return Severity.Medium;
    case 'low':
      return Severity.Low;
    case 'info':
      return Severity.Informational;
    default: // 'unknown', empty, or anything unrecognised
      return undefined;
  }
}

/**
 * Walk the Group tree depth-first, collecting every rule at any depth. Rules may
 * sit directly on a Group that also has nested Groups.
 */
function flattenGroups(groups: GroupElement[]): GroupedRule[] {
  const out: GroupedRule[] = [];
  for (const group of groups) {
    for (const rule of group.Rule ?? []) {
      if (!rule.id) continue;
      out.push({ rule, group });
    }
    out.push(...flattenGroups(group.Group ?? []));
  }
  return out;
}

interface RuleElement {
  id?: string;
  severity?: string;
  title?: string | TextElement;
  description?: string | TextElement;
  version?: string | VersionElement;
  fixtext?: string | FixtextElement;
  ident?: IdentElement[];
  check?: CheckElement | CheckElement[];
}

export interface CheckElement {
  system?: string;
  'check-content'?: string | TextElement;
  'check-content-ref'?: CheckContentRefElement | CheckContentRefElement[];
}

export interface CheckContentRefElement {
  name?: string;
  href?: string;
}

interface FixtextElement {
  '#text'?: string;
  fixref?: string;
}

interface IdentElement {
  '#text'?: string;
  system?: string;
}

interface TestResultElement {
  id?: string;
  'start-time'?: string;
  'end-time'?: string;
  title?: string | TextElement;
  target?: string;
  'target-address'?: string[];
  'rule-result'?: RuleResultElement[];
}

interface RuleResultElement {
  idref?: string;
  time?: string;
  severity?: string;
  version?: string;
  result?: string;
  ident?: IdentElement[];
}

// ---------------------------------------------------------------------------
// Parsed ARF types (post-fast-xml-parser with removeNSPrefix)
// ---------------------------------------------------------------------------

interface ArfParsed {
  'asset-report-collection'?: ArfCollectionElement;
}

interface ArfCollectionElement {
  relationships?: {
    relationship?: ArfRelationshipElement[];
  };
  'report-requests'?: {
    'report-request'?: ArfReportRequestElement[];
  };
  assets?: {
    asset?: ArfAssetElement[];
  };
  reports?: {
    report?: ArfReportElement[];
  };
}

interface ArfRelationshipElement {
  type?: string;
  subject?: string;
  ref?: string[];
}

interface ArfReportRequestElement {
  id?: string;
  content?: {
    'data-stream-collection'?: {
      component?: ArfComponentElement[];
      'data-stream'?: unknown[];
    };
  };
}

interface ArfComponentElement {
  id?: string;
  Benchmark?: BenchmarkElement;
}

interface ArfAssetElement {
  id?: string;
  'computing-device'?: {
    connections?: {
      connection?: ArfConnectionElement[];
    };
    fqdn?: string;
    hostname?: string;
  };
}

interface ArfConnectionElement {
  'ip-address'?: {
    'ip-v4'?: string;
    'ip-v6'?: string;
  };
  'mac-address'?: string;
}

interface ArfReportElement {
  id?: string;
  content?: {
    TestResult?: TestResultElement;
  };
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Tags that must always be parsed as arrays even if only one element exists. */
const ARRAY_TAGS = [
  'Group',
  'Rule',
  'Profile',
  'rule-result',
  'ident',
  'select',
  'set-value',
  'target-address',
  'platform',
  'check-content',
  // ARF-specific array tags
  'report',
  'report-request',
  'asset',
  'connection',
  'relationship',
  'ref',
  'component',
  'data-stream',
];

/** Map XCCDF result values to HDF ResultStatus. */
const STATUS_MAP: Record<string, ResultStatus> = {
  pass: ResultStatus.Passed,
  fail: ResultStatus.Failed,
  error: ResultStatus.Error,
  unknown: ResultStatus.Error,
  notapplicable: ResultStatus.NotApplicable,
  notchecked: ResultStatus.NotReviewed,
  notselected: ResultStatus.NotReviewed,
  informational: ResultStatus.NotReviewed,
  fixed: ResultStatus.Passed,
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Converts an XCCDF results document (1.1 or 1.2) or ARF 1.1 XML to HDF Results JSON.
 * The input must contain TestResult elements.
 * For benchmark-only documents (no TestResult), use convertXccdfBenchmarkToHdf.
 *
 * @param input - Raw XML string (XCCDF Benchmark with TestResult, or ARF asset-report-collection)
 * @returns Stringified HDF Results JSON
 */

// Parse an XCCDF start-time attribute, treating a present-but-invalid value the
// same as missing: fall back to conversion time. An Invalid Date would later
// throw in JSON.stringify (Date#toISOString RangeError).
function parseStartTime(raw: string | undefined): Date {
  if (raw) {
    const t = parseTimestamp(raw);
    if (t) return t;
  }
  return new Date();
}

export async function convertXccdfResultsToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  if (!input || !input.trim()) {
    throw new Error('Empty input');
  }
  validateInputSize(input, 'xccdf-results');

  // trimValues would strip each text node before the parser concatenates them, so
  // prose interrupted by an inline element ("The <xhtml:code>x</xhtml:code> package")
  // came back as "Thepackage". Keep the whitespace and let stripHTML collapse it, the
  // way the Go converter does when it strips tags from the raw element text.
  const parsed = parseXmlWithArrays(input, ARRAY_TAGS, { trimValues: false });

  // Detect input format: ARF or raw XCCDF
  const arfParsed = parsed as ArfParsed;
  if (arfParsed['asset-report-collection']) {
    return convertArfCollection(arfParsed['asset-report-collection'], input, converterVersion);
  }

  const xccdfParsed = parsed as XccdfBenchmark;
  const benchmark = xccdfParsed.Benchmark;
  if (!benchmark) {
    throw new Error(
      'Input is not an XCCDF document: expected <Benchmark> root element'
    );
  }

  if (!benchmark.TestResult) {
    throw new Error(
      "Input has no TestResult elements — this is a benchmark. Use 'xccdf-benchmark' or 'xccdf' instead"
    );
  }

  return convertBenchmarkResultsToHdf(benchmark, input, converterVersion);
}

/**
 * Converts an XCCDF benchmark document (no TestResult) to HDF Baseline JSON.
 * Supports both XCCDF 1.1 and 1.2 (namespace-agnostic via fast-xml-parser).
 *
 * @param input - Raw XML string (XCCDF Benchmark without TestResult)
 * @returns Stringified HDF Baseline JSON
 */
export async function convertXccdfBenchmarkToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  if (!input || !input.trim()) {
    throw new Error('Empty input');
  }
  validateInputSize(input, 'xccdf-benchmark');

  // trimValues would strip each text node before the parser concatenates them, so
  // prose interrupted by an inline element ("The <xhtml:code>x</xhtml:code> package")
  // came back as "Thepackage". Keep the whitespace and let stripHTML collapse it, the
  // way the Go converter does when it strips tags from the raw element text.
  const parsed = parseXmlWithArrays(input, ARRAY_TAGS, { trimValues: false });
  const xccdfParsed = parsed as XccdfBenchmark;
  const benchmark = xccdfParsed.Benchmark;

  if (!benchmark) {
    throw new Error(
      'Input is not an XCCDF Benchmark document'
    );
  }

  if (benchmark.TestResult) {
    throw new Error(
      "Input contains TestResult elements — this is a results document, not a benchmark. Use 'xccdf-results' or 'xccdf' instead"
    );
  }

  return convertBenchmarkToBaselineJson(benchmark, input, converterVersion);
}

/**
 * Auto-detects whether the input is an XCCDF benchmark, results, or ARF
 * document and returns the appropriate JSON output.
 *
 * @param input - Raw XML string
 * @returns Object with json output and outputType ('baseline' or 'results')
 */
export async function convertXccdfToHdf(input: string, converterVersion = '1.0.0'): Promise<{ json: string; outputType: 'baseline' | 'results' }> {
  if (!input || !input.trim()) {
    throw new Error('Empty input');
  }
  validateInputSize(input, 'xccdf');

  // trimValues would strip each text node before the parser concatenates them, so
  // prose interrupted by an inline element ("The <xhtml:code>x</xhtml:code> package")
  // came back as "Thepackage". Keep the whitespace and let stripHTML collapse it, the
  // way the Go converter does when it strips tags from the raw element text.
  const parsed = parseXmlWithArrays(input, ARRAY_TAGS, { trimValues: false });

  // Check ARF first
  const arfParsed = parsed as ArfParsed;
  if (arfParsed['asset-report-collection']) {
    const json = await convertArfCollection(arfParsed['asset-report-collection'], input, converterVersion);
    return { json, outputType: 'results' };
  }

  // Check XCCDF Benchmark
  const xccdfParsed = parsed as XccdfBenchmark;
  const benchmark = xccdfParsed.Benchmark;
  if (!benchmark) {
    throw new Error(
      'Input is not an XCCDF or ARF document'
    );
  }

  if (benchmark.TestResult) {
    const json = await convertBenchmarkResultsToHdf(benchmark, input, converterVersion);
    return { json, outputType: 'results' };
  }

  const json = await convertBenchmarkToBaselineJson(benchmark, input, converterVersion);
  return { json, outputType: 'baseline' };
}

// ---------------------------------------------------------------------------
// XCCDF Benchmark results conversion (existing path)
// ---------------------------------------------------------------------------

async function convertBenchmarkResultsToHdf(
  benchmark: BenchmarkElement,
  rawInput: string,
  converterVersion: string
): Promise<string> {
  const testResult = benchmark.TestResult!;

  const ruleIndex = buildRuleIndex(benchmark);

  const ruleResults = testResult['rule-result'] ?? [];
  const { items: limitedRuleResults, truncated: truncatedRR } = limitArray(ruleResults);
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncatedRR) {
    // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedRuleResults.length} rule-result items (original: ${ruleResults.length})`);
  }
  // The test result's start-time applies to every rule-result; fall back to
  // conversion time when absent or invalid (startTime is required on each result).
  const scanTime = parseStartTime(testResult['start-time']);

  const requirements = limitedRuleResults.map((rr) =>
    ruleResultToRequirement(rr, ruleIndex, scanTime)
  );

  if (requirements.length === 0) {
    const target = xccdfTargetName(testResult, benchmark);
    requirements.push(
      buildNoFindingsRequirement(
        'xccdf-results-no-findings',
        `XCCDF scanned ${target} and reported zero findings.`,
        scanTime,
      ),
    );
  }

  const resultsChecksum: Checksum = await inputChecksum(rawInput);

  const baselineName = extractText(benchmark.title) || benchmark.id || '';

  // Assigned after createMinimalBaseline because that helper drops empty-string
  // options, while Go emits them (a benchmark with no description yields "").
  const baseline = createMinimalBaseline(
    baselineName,
    requirements,
    { resultsChecksum }
  ) as EvaluatedBaseline;
  baseline.title = baselineName;
  baseline.version = extractVersion(benchmark.version);
  baseline.status = 'loaded';
  baseline.summary = stripHTML(extractText(benchmark.description));

  const hdf: HDFResults = {
    baselines: [baseline],
    generator: { name: 'xccdf-results-to-hdf', version: converterVersion },
    tool: { name: 'XCCDF', format: 'XCCDF' },
    components: buildTargets(testResult),
    timestamp: scanTime,
    statistics: { duration: calculateDuration(testResult) },
  };

  return serializeHdf(hdf);
}

/** Seconds between the TestResult start-time and end-time; 0 when unavailable. */
function calculateDuration(testResult: TestResultElement): number {
  const start = testResult['start-time'] ? parseTimestamp(testResult['start-time'])?.getTime() : undefined;
  const end = testResult['end-time'] ? parseTimestamp(testResult['end-time'])?.getTime() : undefined;
  if (start === undefined || end === undefined || end < start) {
    return 0;
  }
  return (end - start) / 1000;
}

// ---------------------------------------------------------------------------
// Benchmark-to-Baseline conversion
// ---------------------------------------------------------------------------

async function convertBenchmarkToBaselineJson(
  benchmark: BenchmarkElement,
  rawInput: string,
  converterVersion: string
): Promise<string> {
  const integrity = await inputIntegrity(rawInput);

  const requirements: BaselineRequirement[] = [];
  const groups: RequirementGroup[] = [];

  // One RequirementGroup per XCCDF Group, carrying every rule found in it.
  const groupIndex = new Map<string, number>();
  for (const { rule, group } of flattenGroups(benchmark.Group ?? [])) {
    const req = ruleToBaselineRequirement(rule, group);
    requirements.push(req);

    const groupId = group.id ?? '';
    const existing = groupIndex.get(groupId);
    if (existing !== undefined) {
      groups[existing]!.requirements.push(req.id);
      continue;
    }
    groupIndex.set(groupId, groups.length);
    groups.push({
      id: groupId,
      title: extractText(group.title),
      requirements: [req.id],
    });
  }

  const topRules = benchmark.Rule ?? [];
  for (const rule of topRules) {
    if (!rule.id) {
      continue;
    }
    const req = ruleToBaselineRequirement(rule, undefined);
    requirements.push(req);
  }

  const baselineName = kebabCase(benchmark.id ?? 'xccdf-benchmark');

  const baseline: HDFBaseline = {
    name: baselineName,
    title: extractText(benchmark.title),
    version: extractVersion(benchmark.version),
    status: 'loaded',
    summary: stripHTML(extractText(benchmark.description)),
    integrity,
    requirements,
    groups,
    generator: { name: 'xccdf-results-to-hdf', version: converterVersion },
  };

  return serializeHdf(baseline);
}

/**
 * Convert a single XCCDF Rule to an HDF BaselineRequirement.
 */
function ruleToBaselineRequirement(
  rule: RuleElement,
  group: GroupElement | undefined
): BaselineRequirement {
  const id = extractRuleID(rule.id ?? '') || extractVersion(rule.version);
  // A title-less rule gets no title at all: an empty string is junk, and
  // synthesizing one from the id would invent data. Go omits it too.
  const title = extractText(rule.title) || undefined;
  const severity = (rule.severity ?? '').toLowerCase();
  const impact = severity ? severityToImpact(severity) : 0.5;

  const descriptions: Description[] = [{
    label: 'default',
    data: stripHTML(extractVulnDiscussion(extractText(rule.description))),
  }];

  const check = selectCheck(rule.check);
  const checkContent = extractCheckContent(check);
  if (checkContent) {
    descriptions.push({ label: 'check', data: stripHTML(checkContent) });
  }

  const fixtext = extractFixtext(rule.fixtext);
  if (fixtext) {
    descriptions.push({ label: 'fix', data: stripHTML(fixtext) });
  }

  const tags = buildCciNistTags(extractCCIs(rule.ident ?? []));
  const nistTags = tags['nist'] as string[];

  // STIG-specific tags
  tags['rid'] = rule.id;
  tags['stig_id'] = extractVersion(rule.version);
  if (severity) {
    tags['severity'] = severity.toLowerCase();
  }
  if (check?.system) {
    tags['check_id'] = check.system;
  }
  const fixtextObj = rule.fixtext;
  if (fixtextObj && typeof fixtextObj !== 'string' && fixtextObj.fixref) {
    tags['fix_id'] = fixtextObj.fixref;
  }
  if (group) {
    tags['gid'] = group.id;
    tags['gtitle'] = extractText(group.title);
  }

  const req: BaselineRequirement = {
    id,
    title,
    impact,
    descriptions,
    tags,
  };

  const hdfSeverity = xccdfSeverityToHdf(severity);
  if (hdfSeverity) {
    req.severity = hdfSeverity;
  }

  const controlType = deriveControlTypeFromTags(nistTags);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }

  return req;
}

// ---------------------------------------------------------------------------
// ARF conversion
// ---------------------------------------------------------------------------

async function convertArfCollection(
  arc: ArfCollectionElement,
  rawInput: string,
  converterVersion: string
): Promise<string> {
  const resultsChecksum: Checksum = await inputChecksum(rawInput);

  // Find the Benchmark from data-stream-collection components
  const benchmark = findBenchmarkInArf(arc);

  // Build rule index from Benchmark
  const ruleIndex = benchmark
    ? buildRuleIndex(benchmark)
    : new Map<string, RuleElement>();

  // Build asset metadata map: asset ID -> asset element
  const assetMap = new Map<string, ArfAssetElement>();
  for (const asset of arc.assets?.asset ?? []) {
    if (asset.id) {
      assetMap.set(asset.id, asset);
    }
  }

  // Build relationship map: report ID -> asset IDs (isAbout)
  const reportToAssets = new Map<string, string[]>();
  for (const rel of arc.relationships?.relationship ?? []) {
    if (rel.type?.includes('isAbout') && rel.subject) {
      reportToAssets.set(rel.subject, rel.ref ?? []);
    }
  }

  // Process each report
  const baselines: EvaluatedBaseline[] = [];
  const components: Component[] = [];
  let firstTimestamp: Date | undefined;
  let totalDuration = 0;

  for (const report of arc.reports?.report ?? []) {
    const testResult = report.content?.TestResult;
    // Skip non-XCCDF reports (e.g. OVAL)
    if (!testResult?.id) {
      continue;
    }

    // The test result's start-time applies to its rule-results; fall back to
    // conversion time when absent or invalid (startTime is required on each result).
    const scanTime = parseStartTime(testResult['start-time']);

    if (!firstTimestamp) {
      firstTimestamp = scanTime;
    }
    totalDuration += calculateDuration(testResult);

    // Convert rule-results
    const ruleResults = testResult['rule-result'] ?? [];
    const { items: limitedARFRuleResults, truncated: truncatedARFRR } = limitArray(ruleResults);
    /* v8 ignore next -- truncation only triggers with >100K items */
    if (truncatedARFRR) {
      // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedARFRuleResults.length} rule-result items (original: ${ruleResults.length})`);
    }
    const requirements = limitedARFRuleResults.map((rr) =>
      ruleResultToRequirement(rr, ruleIndex, scanTime)
    );

    if (requirements.length === 0) {
      const target = xccdfTargetName(testResult, benchmark);
      requirements.push(
        buildNoFindingsRequirement(
          'xccdf-results-no-findings',
          `XCCDF scanned ${target} and reported zero findings.`,
          scanTime,
        ),
      );
    }

    // Baseline name from Benchmark title
    let baselineName = '';
    if (benchmark) {
      baselineName = extractText(benchmark.title) || benchmark.id || '';
    }
    if (!baselineName) {
      baselineName = extractText(testResult.title) || testResult.id || '';
    }

    const baseline = createMinimalBaseline(
      baselineName,
      requirements,
      { resultsChecksum }
    ) as EvaluatedBaseline;
    baseline.title = baselineName;
    baseline.status = 'loaded';
    if (benchmark) {
      baseline.version = extractVersion(benchmark.version);
      baseline.summary = stripHTML(extractText(benchmark.description));
    }
    baselines.push(baseline);

    // Build target from TestResult, then enrich with ARF asset metadata
    const reportTargets = buildTargets(testResult);
    const target = reportTargets[0];
    if (target && report.id) {
      const assetIds = reportToAssets.get(report.id) ?? [];
      for (const assetId of assetIds) {
        const asset = assetMap.get(assetId);
        if (asset) {
          enrichTargetWithAsset(target, asset);
        }
      }
    }
    components.push(...reportTargets);
  }

  if (baselines.length === 0) {
    throw new Error('ARF document contains no XCCDF TestResult reports');
  }

  const hdf: HDFResults = {
    baselines,
    generator: { name: 'xccdf-results-to-hdf', version: converterVersion },
    tool: { name: 'ARF', format: 'ARF' },
    components,
    timestamp: firstTimestamp ?? new Date(),
    statistics: { duration: totalDuration },
  };

  return serializeHdf(hdf);
}

/**
 * Find the XCCDF Benchmark embedded in an ARF data-stream-collection.
 */
function findBenchmarkInArf(
  arc: ArfCollectionElement
): BenchmarkElement | undefined {
  for (const req of arc['report-requests']?.['report-request'] ?? []) {
    const components =
      req.content?.['data-stream-collection']?.component ?? [];
    for (const comp of components) {
      if (comp.Benchmark?.id) {
        return comp.Benchmark;
      }
    }
  }
  return undefined;
}

/**
 * Enrich an HDF Component with metadata from an ARF asset element.
 */
function enrichTargetWithAsset(
  target: Component,
  asset: ArfAssetElement
): void {
  const cd = asset['computing-device'];
  if (!cd) {
    return;
  }

  if (cd.fqdn) {
    target.fqdn = cd.fqdn;
  }

  // Extract first non-loopback MAC address
  const connections = cd.connections?.connection ?? [];
  for (const conn of connections) {
    const mac = conn['mac-address'];
    if (mac && mac !== '00:00:00:00:00:00') {
      target.macAddress = mac;
      break;
    }
  }

  // If target has no IP yet, try ARF asset connections
  if (!target.ipAddress) {
    for (const conn of connections) {
      const ip = conn['ip-address'];
      if (ip?.['ip-v4']) {
        target.ipAddress = ip['ip-v4'];
        break;
      }
      if (ip?.['ip-v6']) {
        target.ipAddress = ip['ip-v6'];
        break;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/**
 * Builds an index of Rule elements keyed by their @id attribute.
 * Rules can appear directly under Benchmark or nested inside Group elements.
 */
function buildRuleIndex(benchmark: BenchmarkElement): Map<string, RuleElement> {
  const index = new Map<string, RuleElement>();

  const topRules = benchmark.Rule ?? [];
  for (const rule of topRules) {
    if (rule.id) {
      index.set(rule.id, rule);
    }
  }

  for (const { rule } of flattenGroups(benchmark.Group ?? [])) {
    index.set(rule.id!, rule);
  }

  return index;
}

/**
 * Convert a single <rule-result> into an EvaluatedRequirement.
 */
function ruleResultToRequirement(
  rr: RuleResultElement,
  ruleIndex: Map<string, RuleElement>,
  scanTime: Date
): EvaluatedRequirement {
  const ruleId = rr.idref ?? '';
  const ruleDef = ruleIndex.get(ruleId);

  const id = ruleDef?.id ? extractRuleID(ruleDef.id) : ruleId;
  const title = extractText(ruleDef?.title) || ruleId;

  const severity = (rr.severity || ruleDef?.severity || '').toLowerCase();
  const impact = severity ? severityToImpact(severity) : 0.5;

  const descriptions: Description[] = [{
    label: 'default',
    data: stripHTML(extractVulnDiscussion(extractText(ruleDef?.description))),
  }];
  const check = selectCheck(ruleDef?.check);
  const checkContent = extractCheckContent(check);
  if (checkContent) {
    descriptions.push({ label: 'check', data: stripHTML(checkContent) });
  }
  const fixtext = extractFixtext(ruleDef?.fixtext);
  if (fixtext) {
    descriptions.push({ label: 'fix', data: stripHTML(fixtext) });
  }

  const xccdfResult = (rr.result ?? '').trim().toLowerCase();
  const status = STATUS_MAP[xccdfResult] ?? ResultStatus.Error;

  // Prefer each rule-result's own @time (per-finding evaluation time), matching
  // the Go converter; fall back to the TestResult-level start-time (scanTime).
  const perRuleTime = rr.time ? parseTimestamp(rr.time) : null;

  const result: RequirementResult = {
    status,
    codeDesc: `XCCDF rule ${ruleId}`,
    startTime: perRuleTime ?? scanTime,
  };

  const tags = buildCciNistTags(extractCCIs([...(rr.ident ?? []), ...(ruleDef?.ident ?? [])]));
  const nistTags = tags['nist'] as string[];

  const req = createRequirement(
    id,
    title,
    descriptions,
    impact,
    [result],
    { tags }
  ) as EvaluatedRequirement;

  const code = buildCheckCode(check);
  if (code) {
    req.code = code;
  }

  // Mirror the baseline path: set the explicit severity enum, omitting it when
  // the (already precedence-resolved) severity has no HDF equivalent.
  const hdfSeverity = xccdfSeverityToHdf(severity);
  if (hdfSeverity) {
    req.severity = hdfSeverity;
  }

  const controlType = deriveControlTypeFromTags(nistTags);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }

  return req;
}

/**
 * Pick the most specific identifier available for a no-findings codeDesc.
 * Falls back through TestResult target/title, benchmark title/id, then a generic phrase.
 */
function xccdfTargetName(
  testResult: TestResultElement | undefined,
  benchmark: BenchmarkElement | undefined,
): string {
  const tr = testResult ?? {};
  const target = (tr.target ?? '').trim();
  if (target) {
    return target;
  }
  const trTitle = extractText(tr.title).trim();
  if (trTitle) {
    return trTitle;
  }
  const benchTitle = extractText(benchmark?.title).trim();
  if (benchTitle) {
    return benchTitle;
  }
  const benchId = (benchmark?.id ?? '').trim();
  if (benchId) {
    return benchId;
  }
  return 'the target';
}

/**
 * Build Component array from TestResult metadata.
 */
function buildTargets(testResult: TestResultElement): Component[] {
  const targetName = testResult.target;
  if (!targetName) {
    return [];
  }

  const addresses = testResult['target-address'] ?? [];
  const target: Component = {
    name: targetName,
    type: TargetType.Host,
  };

  if (addresses.length > 0) {
    target.ipAddress = addresses[0];
  }

  return [target];
}

const NAMED_ENTITIES: Record<string, string> = {
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  amp: '&',
};

// The shared XML parser runs with processEntities off as XXE defense-in-depth,
// so character references arrive undecoded; Go's encoding/xml decodes them for
// free. STIG fix texts rely on this (an entity-encoded "<partition>" must
// become a real tag before stripHTML can drop it). Only predefined and numeric
// references are decoded; document-defined entities stay untouched.
function decodeXmlEntities(s: string): string {
  return s.replace(
    /&(?:#(\d+)|#[xX]([0-9a-fA-F]+)|(lt|gt|quot|apos|amp));/g,
    (match, dec: string | undefined, hex: string | undefined, name: string | undefined) => {
      if (dec !== undefined) return String.fromCodePoint(Number.parseInt(dec, 10));
      if (hex !== undefined) return String.fromCodePoint(Number.parseInt(hex, 16));
      return name !== undefined ? NAMED_ENTITIES[name] ?? match : match;
    },
  );
}

/**
 * Extract plain text from a field that may be a string or {#text: string}.
 */
/**
 * A rule can carry several <check> elements (SSG emits SCE, OVAL and OCIL for the
 * same rule). Go decodes <check> into one struct field, so encoding/xml overwrites
 * it and the last element wins; match that or the two languages disagree.
 */
// checkPriority ranks XCCDF check systems. A rule can carry several <check>
// elements (SSG emits SCE + OVAL + OCIL for one rule); ranking resolves it to a
// single deterministic check instead of whichever the author placed last.
// Automated engines win over the manual questionnaire: OVAL > SCE > OCIL > else.
function checkPriority(system: string | undefined): number {
  const s = system ?? '';
  if (s.includes('oval.mitre.org')) return 0;
  if (s.includes('open-scap.org') || s.includes('/SCE')) return 1;
  if (s.includes('ocil')) return 2;
  return 3;
}

// selectCheck picks the preferred <check>: the automated OVAL check when
// present, else SCE, else OCIL, else the first in document order (ties keep
// document order). Mirrors the Go selectCheck for byte-identical parity.
function selectCheck(check: CheckElement | CheckElement[] | undefined): CheckElement | undefined {
  if (check === undefined) return undefined;
  const checks = Array.isArray(check) ? check : [check];
  let best: CheckElement | undefined;
  let bestPri = Infinity;
  for (const c of checks) {
    const p = checkPriority(c.system);
    if (p < bestPri) {
      best = c;
      bestPri = p;
    }
  }
  return best;
}

function extractText(
  field: string | TextElement | VersionElement | undefined
): string {
  if (field === undefined || field === null) {
    return '';
  }
  if (typeof field === 'string') {
    return decodeXmlEntities(field);
  }
  return decodeXmlEntities((field as TextElement)['#text'] ?? '');
}

/**
 * Extract version string from a version field.
 */
function extractVersion(
  field: string | VersionElement | undefined
): string {
  if (field === undefined || field === null) {
    return '';
  }
  if (typeof field === 'string') {
    return field;
  }
  return (field as VersionElement)['#text'] ?? '';
}

/**
 * Extract fixtext content from fixtext field.
 */
function extractFixtext(
  field: string | FixtextElement | undefined
): string {
  if (field === undefined || field === null) {
    return '';
  }
  if (typeof field === 'string') {
    return decodeXmlEntities(field);
  }
  return decodeXmlEntities((field as FixtextElement)['#text'] ?? '');
}

/**
 * Extract check-content text from a check element.
 */
function extractCheckContent(
  check: CheckElement | undefined
): string {
  if (!check) {
    return '';
  }
  const cc = check['check-content'];
  if (!cc) {
    return '';
  }
  if (typeof cc === 'string') {
    return decodeXmlEntities(cc);
  }
  // check-content is forced into an array by ARRAY_TAGS — handle both cases
  if (Array.isArray(cc)) {
    const first = (cc as unknown[])[0];
    if (typeof first === 'string') {
      return decodeXmlEntities(first);
    }
    if (first && typeof first === 'object' && '#text' in first) {
      return decodeXmlEntities((first as TextElement)['#text'] ?? '');
    }
    return '';
  }
  return decodeXmlEntities((cc as TextElement)['#text'] ?? '');
}

/**
 * Extract the OVAL/SCE check-content-ref (name + href) from a check element.
 * check-content-ref is not forced into an array, so handle both single and
 * (rare) multi cases, taking the first.
 */
export function extractCheckContentRef(
  check: CheckElement | undefined
): { name: string; href: string } {
  if (!check) {
    return { name: '', href: '' };
  }
  let ref = check['check-content-ref'];
  if (Array.isArray(ref)) {
    ref = ref[0];
  }
  if (!ref || typeof ref !== 'object') {
    return { name: '', href: '' };
  }
  return { name: ref.name ?? '', href: ref.href ?? '' };
}

/**
 * Render a rule's selected <check> as the indented-JSON blob carried in
 * requirement.code — the automated-check logic (system + OVAL/SCE definition
 * reference + any inline content). Returns '' when the check is empty so the
 * caller leaves code unset rather than fabricating one. Key order and the
 * escape-free JSON.stringify mirror the Go buildCheckCode for byte parity.
 */
export function buildCheckCode(check: CheckElement | undefined): string {
  if (!check) {
    return '';
  }
  const system = check.system ?? '';
  const ref = extractCheckContentRef(check);
  const content = extractCheckContent(check).trim();
  if (!system && !ref.name && !ref.href && !content) {
    return '';
  }

  const code: Record<string, unknown> = {};
  if (system) {
    code.system = system;
  }
  if (ref.name || ref.href) {
    const refObj: Record<string, string> = {};
    if (ref.name) {
      refObj.name = ref.name;
    }
    if (ref.href) {
      refObj.href = ref.href;
    }
    code.checkContentRef = refObj;
  }
  if (content) {
    code.checkContent = content;
  }

  return JSON.stringify(code, null, 2);
}

/**
 * Extract the VulnDiscussion text from an XCCDF description that contains
 * embedded XML like `<VulnDiscussion>...</VulnDiscussion>`. If no
 * VulnDiscussion tag is found, returns the original text.
 */
function extractVulnDiscussion(description: string): string {
  const match = description.match(
    /<VulnDiscussion>([\s\S]*?)<\/VulnDiscussion>/
  );
  return match ? match[1]! : description;
}

/**
 * Extract CCI identifiers from ident elements, deduplicated in first-seen order.
 */
function extractCCIs(idents: IdentElement[]): string[] {
  const ccis = idents
    .filter((i) => (i.system ?? '').toLowerCase().includes('cci'))
    .map((i) => i['#text'] ?? '')
    .filter((v) => v.length > 0);
  return [...new Set(ccis)];
}

/**
 * Build the cci/nist tag pair. `nist` is always present (empty when there are no
 * CCIs) and sorted, matching Go's cci.CCIToNIST.
 */
function buildCciNistTags(cciIds: string[]): Record<string, unknown> {
  if (cciIds.length === 0) {
    return { nist: [] };
  }
  const nist = [...new Set(cciIds.flatMap((c) => getCCINistMappings(c) ?? []))].sort();
  return { cci: cciIds, nist };
}

/**
 * Extract the vulnerability ID from an XCCDF Rule ID:
 * "SV-254238r991589_rule" and "xccdf_mil.disa.stig_rule_SV-204393r603261_rule"
 * both yield "SV-254238"/"SV-204393". Non-SV IDs pass through unchanged.
 */
function extractRuleID(ruleID: string): string {
  const svIdx = ruleID.toUpperCase().indexOf('SV-');
  if (svIdx < 0) {
    return ruleID;
  }
  const digits = ruleID.slice(svIdx + 3);
  const revIdx = digits.indexOf('r');
  if (revIdx > 0) {
    return `SV-${digits.slice(0, revIdx)}`;
  }
  return `SV-${digits}`;
}

/**
 * Convert a string to kebab-case (e.g., "MS_Windows_Server_2022_STIG" -> "ms-windows-server-2022-stig").
 */
function kebabCase(s: string): string {
  return s.toLowerCase().replace(/_/g, '-');
}
