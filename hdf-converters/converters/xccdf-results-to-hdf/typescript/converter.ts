import { parseXmlWithArrays } from '@mitre/hdf-utilities';
import { inputChecksum, limitArray, validateInputSize } from '../../../shared/typescript/converterutil.js';
import type {
  HdfResults,
  HdfBaseline,
  BaselineRequirement,
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Checksum,
  Description,
  RequirementGroup,
  Target,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  Copyright,
  Severity,
  createMinimalBaseline,
  createRequirement,
  createResult,
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

interface GroupElement {
  id?: string;
  title?: string | TextElement;
  Rule?: RuleElement[];
}

interface RuleElement {
  id?: string;
  severity?: string;
  title?: string | TextElement;
  description?: string | TextElement;
  version?: string | VersionElement;
  fixtext?: string | FixtextElement;
  ident?: IdentElement[];
  check?: CheckElement;
}

interface CheckElement {
  system?: string;
  'check-content'?: string | TextElement;
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

const CONVERTER_VERSION = '1.0.0';

const CCI_SYSTEM = 'http://cyber.mil/cci';

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
export async function convertXccdfResultsToHdf(input: string): Promise<string> {
  if (!input || !input.trim()) {
    throw new Error('Empty input');
  }
  validateInputSize(input, 'xccdf-results');

  const parsed = parseXmlWithArrays(input, ARRAY_TAGS);

  // Detect input format: ARF or raw XCCDF
  const arfParsed = parsed as ArfParsed;
  if (arfParsed['asset-report-collection']) {
    return convertArfCollection(arfParsed['asset-report-collection'], input);
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

  return convertBenchmarkResultsToHdf(benchmark, input);
}

/**
 * Converts an XCCDF benchmark document (no TestResult) to HDF Baseline JSON.
 * Supports both XCCDF 1.1 and 1.2 (namespace-agnostic via fast-xml-parser).
 *
 * @param input - Raw XML string (XCCDF Benchmark without TestResult)
 * @returns Stringified HDF Baseline JSON
 */
export async function convertXccdfBenchmarkToHdf(input: string): Promise<string> {
  if (!input || !input.trim()) {
    throw new Error('Empty input');
  }
  validateInputSize(input, 'xccdf-benchmark');

  const parsed = parseXmlWithArrays(input, ARRAY_TAGS);
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

  return convertBenchmarkToBaselineJson(benchmark, input);
}

/**
 * Auto-detects whether the input is an XCCDF benchmark, results, or ARF
 * document and returns the appropriate JSON output.
 *
 * @param input - Raw XML string
 * @returns Object with json output and outputType ('baseline' or 'results')
 */
export async function convertXccdfToHdf(input: string): Promise<{ json: string; outputType: 'baseline' | 'results' }> {
  if (!input || !input.trim()) {
    throw new Error('Empty input');
  }
  validateInputSize(input, 'xccdf');

  const parsed = parseXmlWithArrays(input, ARRAY_TAGS);

  // Check ARF first
  const arfParsed = parsed as ArfParsed;
  if (arfParsed['asset-report-collection']) {
    const json = await convertArfCollection(arfParsed['asset-report-collection'], input);
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
    const json = await convertBenchmarkResultsToHdf(benchmark, input);
    return { json, outputType: 'results' };
  }

  const json = await convertBenchmarkToBaselineJson(benchmark, input);
  return { json, outputType: 'baseline' };
}

// ---------------------------------------------------------------------------
// XCCDF Benchmark results conversion (existing path)
// ---------------------------------------------------------------------------

async function convertBenchmarkResultsToHdf(
  benchmark: BenchmarkElement,
  rawInput: string
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
  const requirements = limitedRuleResults.map((rr) =>
    ruleResultToRequirement(rr, ruleIndex)
  );

  const resultsChecksum: Checksum = await inputChecksum(rawInput);

  const baselineName = extractText(benchmark.title) || 'XCCDF Benchmark';

  const baseline = createMinimalBaseline(
    baselineName,
    requirements,
    { resultsChecksum }
  ) as EvaluatedBaseline;

  const targets = buildTargets(testResult);

  const timestamp = testResult['start-time']
    ? new Date(testResult['start-time'])
    : new Date();

  let durationSeconds: number | undefined;
  if (testResult['start-time'] && testResult['end-time']) {
    const start = new Date(testResult['start-time']).getTime();
    const end = new Date(testResult['end-time']).getTime();
    if (!isNaN(start) && !isNaN(end) && end >= start) {
      durationSeconds = (end - start) / 1000;
    }
  }

  const hdf: HdfResults = {
    baselines: [baseline],
    generator: { name: 'hdf-converters', version: CONVERTER_VERSION },
    dataSource: { name: 'XCCDF Results', format: 'XML' },
    targets,
    timestamp,
  };

  if (durationSeconds !== undefined) {
    hdf.statistics = { duration: durationSeconds };
  }

  return JSON.stringify(hdf, null, 2);
}

// ---------------------------------------------------------------------------
// Benchmark-to-Baseline conversion
// ---------------------------------------------------------------------------

async function convertBenchmarkToBaselineJson(
  benchmark: BenchmarkElement,
  rawInput: string
): Promise<string> {
  const checksum: Checksum = await inputChecksum(rawInput);

  const requirements: BaselineRequirement[] = [];
  const groups: RequirementGroup[] = [];

  const benchmarkGroups = benchmark.Group ?? [];
  for (const group of benchmarkGroups) {
    const groupRules = group.Rule ?? [];
    for (const rule of groupRules) {
      if (!rule.id) {
        continue;
      }
      const req = ruleToBaselineRequirement(rule, group);
      requirements.push(req);
      groups.push({
        id: group.id ?? '',
        title: extractText(group.title),
        requirements: [req.id],
      });
    }
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

  const baseline: HdfBaseline = {
    name: baselineName,
    title: extractText(benchmark.title),
    version: extractVersion(benchmark.version),
    status: 'loaded',
    summary: extractText(benchmark.description),
    checksum,
    requirements,
    groups,
    generator: { name: 'hdf-converters', version: CONVERTER_VERSION },
  };

  return JSON.stringify(baseline, null, 2);
}

/**
 * Convert a single XCCDF Rule to an HDF BaselineRequirement.
 */
function ruleToBaselineRequirement(
  rule: RuleElement,
  group: GroupElement | undefined
): BaselineRequirement {
  const id = extractVersion(rule.version) || rule.id || '';
  const title = extractText(rule.title) || id;
  const severity = rule.severity ?? '';
  const impact = severity ? severityToImpact(severity) : 0.5;

  const descriptions: Description[] = [];
  const rawDesc = extractText(rule.description);
  if (rawDesc) {
    descriptions.push({
      label: 'default',
      data: extractVulnDiscussion(rawDesc),
    });
  } else {
    descriptions.push({ label: 'default', data: '' });
  }

  const checkContent = extractCheckContent(rule.check);
  if (checkContent) {
    descriptions.push({ label: 'check', data: checkContent });
  }

  const fixtext = extractFixtext(rule.fixtext);
  if (fixtext) {
    descriptions.push({ label: 'fix', data: fixtext });
  }

  const tags: Record<string, unknown> = {};
  const cciIds = extractCCIs(rule.ident ?? []);
  if (cciIds.length > 0) {
    tags['cci'] = cciIds;
    const nistTags = cciIds.flatMap(
      (cci) => getCCINistMappings(cci) ?? []
    );
    if (nistTags.length > 0) {
      tags['nist'] = [...new Set(nistTags)];
    }
  }

  // STIG-specific tags
  tags['rid'] = rule.id;
  tags['stig_id'] = extractVersion(rule.version);
  if (severity) {
    tags['severity'] = severity.toLowerCase();
  }
  if (rule.check?.system) {
    tags['check_id'] = rule.check.system;
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

  if (severity) {
    req.severity = severity.toLowerCase() as Severity;
  }

  return req;
}

// ---------------------------------------------------------------------------
// ARF conversion
// ---------------------------------------------------------------------------

async function convertArfCollection(
  arc: ArfCollectionElement,
  rawInput: string
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
  const targets: Target[] = [];
  let firstTimestamp: Date | undefined;
  let totalDuration = 0;

  for (const report of arc.reports?.report ?? []) {
    const testResult = report.content?.TestResult;
    // Skip non-XCCDF reports (e.g. OVAL)
    if (!testResult?.id) {
      continue;
    }

    // Timing
    if (testResult['start-time'] && !firstTimestamp) {
      firstTimestamp = new Date(testResult['start-time']);
    }
    if (testResult['start-time'] && testResult['end-time']) {
      const start = new Date(testResult['start-time']).getTime();
      const end = new Date(testResult['end-time']).getTime();
      if (!isNaN(start) && !isNaN(end) && end >= start) {
        totalDuration += (end - start) / 1000;
      }
    }

    // Convert rule-results
    const ruleResults = testResult['rule-result'] ?? [];
    const { items: limitedARFRuleResults, truncated: truncatedARFRR } = limitArray(ruleResults);
    /* v8 ignore next -- truncation only triggers with >100K items */
    if (truncatedARFRR) {
      // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedARFRuleResults.length} rule-result items (original: ${ruleResults.length})`);
    }
    const requirements = limitedARFRuleResults.map((rr) =>
      ruleResultToRequirement(rr, ruleIndex)
    );

    // Baseline name from Benchmark title
    let baselineName = '';
    if (benchmark) {
      baselineName = extractText(benchmark.title) || '';
    }
    if (!baselineName) {
      baselineName = extractText(testResult.title) || testResult.id || 'ARF Report';
    }

    const baseline = createMinimalBaseline(
      baselineName,
      requirements,
      { resultsChecksum }
    ) as EvaluatedBaseline;
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
    targets.push(...reportTargets);
  }

  if (baselines.length === 0) {
    throw new Error('ARF document contains no XCCDF TestResult reports');
  }

  const hdf: HdfResults = {
    baselines,
    generator: { name: 'hdf-converters', version: CONVERTER_VERSION },
    dataSource: { name: 'ARF', format: 'ARF' },
    targets,
    timestamp: firstTimestamp ?? new Date(),
  };

  if (totalDuration > 0) {
    hdf.statistics = { duration: totalDuration };
  }

  return JSON.stringify(hdf, null, 2);
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
 * Enrich an HDF Target with metadata from an ARF asset element.
 */
function enrichTargetWithAsset(
  target: Target,
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

  const groups = benchmark.Group ?? [];
  for (const group of groups) {
    const rules = group.Rule ?? [];
    for (const rule of rules) {
      if (rule.id) {
        index.set(rule.id, rule);
      }
    }
  }

  return index;
}

/**
 * Convert a single <rule-result> into an EvaluatedRequirement.
 */
function ruleResultToRequirement(
  rr: RuleResultElement,
  ruleIndex: Map<string, RuleElement>
): EvaluatedRequirement {
  const ruleId = rr.idref ?? '';
  const ruleDef = ruleIndex.get(ruleId);

  const id = extractVersion(ruleDef?.version) || ruleId;
  const title = extractText(ruleDef?.title) || id;

  const severity = rr.severity ?? ruleDef?.severity ?? '';
  const impact = severity ? severityToImpact(severity) : 0.5;

  const descriptions: Description[] = [];
  const rawDesc = extractText(ruleDef?.description);
  if (rawDesc) {
    descriptions.push({
      label: 'default',
      data: extractVulnDiscussion(rawDesc),
    });
  }
  const fixtext = extractFixtext(ruleDef?.fixtext);
  if (fixtext) {
    descriptions.push({ label: 'fix', data: fixtext });
  }

  const xccdfResult = (rr.result ?? '').toLowerCase();
  const status = STATUS_MAP[xccdfResult] ?? ResultStatus.NotReviewed;

  const result = createResult(status, '', {
    codeDesc: `XCCDF rule ${id}`,
  }) as RequirementResult;

  const tags: Record<string, unknown> = {};
  const cciIds = extractCCIs(rr.ident ?? ruleDef?.ident ?? []);
  if (cciIds.length > 0) {
    tags['cci'] = cciIds;
    const nistTags = cciIds.flatMap(
      (cci) => getCCINistMappings(cci) ?? []
    );
    if (nistTags.length > 0) {
      tags['nist'] = [...new Set(nistTags)];
    }
  }

  return createRequirement(
    id,
    title,
    descriptions,
    impact,
    [result],
    { tags }
  ) as EvaluatedRequirement;
}

/**
 * Build Target array from TestResult metadata.
 */
function buildTargets(testResult: TestResultElement): Target[] {
  const targetName = testResult.target;
  if (!targetName) {
    return [];
  }

  const addresses = testResult['target-address'] ?? [];
  const target: Target = {
    name: targetName,
    type: Copyright.Host,
  };

  if (addresses.length > 0) {
    target.ipAddress = addresses[0];
  }

  return [target];
}

/**
 * Extract plain text from a field that may be a string or {#text: string}.
 */
function extractText(
  field: string | TextElement | VersionElement | undefined
): string {
  if (field === undefined || field === null) {
    return '';
  }
  if (typeof field === 'string') {
    return field;
  }
  return (field as TextElement)['#text'] ?? '';
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
    return field;
  }
  return (field as FixtextElement)['#text'] ?? '';
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
    return cc;
  }
  // check-content is forced into an array by ARRAY_TAGS — handle both cases
  if (Array.isArray(cc)) {
    const first = (cc as unknown[])[0];
    if (typeof first === 'string') {
      return first;
    }
    if (first && typeof first === 'object' && '#text' in first) {
      return (first as TextElement)['#text'] ?? '';
    }
    return '';
  }
  return (cc as TextElement)['#text'] ?? '';
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
  if (match) {
    return match[1]!.trim();
  }
  // Also handle HTML-entity-encoded tags from the XML parser
  const entityMatch = description.match(
    /&lt;VulnDiscussion&gt;([\s\S]*?)&lt;\/VulnDiscussion&gt;/
  );
  if (entityMatch) {
    return entityMatch[1]!.trim();
  }
  return description;
}

/**
 * Extract CCI identifiers from ident elements (system="http://cyber.mil/cci").
 */
function extractCCIs(idents: IdentElement[]): string[] {
  return idents
    .filter((i) => i.system === CCI_SYSTEM)
    .map((i) => i['#text'] ?? '')
    .filter((v) => v.length > 0);
}

/**
 * Convert a string to kebab-case (e.g., "MS_Windows_Server_2022_STIG" -> "ms-windows-server-2022-stig").
 */
function kebabCase(s: string): string {
  return s.toLowerCase().replace(/_/g, '-');
}
