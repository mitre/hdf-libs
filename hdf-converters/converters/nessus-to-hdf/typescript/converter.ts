import { parseXmlWithArrays, parseTimestamp } from '@mitre/hdf-utilities';
import { getNessusNistControl, getCCINistMappings } from '@mitre/hdf-mappings';
import { buildNoFindingsRequirement, deriveControlTypeFromTags, deriveVerificationMethod, inputChecksum, limitArray, validateInputSize } from '../../../shared/typescript/converterutil.js';
import type {
  HDFResults,
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Component,
  Description,
  Reference,
  Checksum,
  Tool,
  Cvss,
  Epss,
} from '@mitre/hdf-schema';
import { ResultStatus, TargetType, createMinimalBaseline, Version as CvssVersion } from '@mitre/hdf-schema';
import { cvssSeverityFromScore } from '../../../shared/typescript/cvss.js';

const CVE_SOURCE_RE = /^CVE-\d{4}-\d{4,}$/;
const CWE_PATTERN = /CWE[- ]?(\d+)/gi;

interface NessusXml {
  NessusClientData_v2: {
    Policy: {
      policyName: string;
      Preferences?: {
        ServerPreferences?: {
          preference?: Array<{ name: string; value: string }>;
        };
      };
    };
    Report: {
      '@name'?: string;
      ReportHost: ReportHost[];
    };
  };
}

interface ReportHost {
  name: string;
  HostProperties?: {
    tag?: HostPropertyTag[];
  };
  ReportItem?: ReportItem[];
}

interface HostPropertyTag {
  name: string;
  '#text'?: string;
}

interface ReportItem {
  port: string;
  svc_name: string;
  protocol: string;
  severity: string;
  pluginID: string;
  pluginName: string;
  pluginFamily: string;
  description?: string;
  fname?: string;
  plugin_modification_date?: string;
  plugin_name?: string;
  plugin_publication_date?: string;
  plugin_type?: string;
  risk_factor?: string;
  script_version?: string;
  see_also?: string;
  solution?: string;
  synopsis?: string;
  plugin_output?: string;
  cvss_base_score?: string;
  cvss3_base_score?: string;
  cve?: string | string[];
  // Structured CVSS fields (Wave 2: CVE-ecosystem)
  cvss_vector?: string;
  cvss3_vector?: string;
  cvss_temporal_vector?: string;
  cvss3_temporal_vector?: string;
  cvss_temporal_score?: string;
  cvss3_temporal_score?: string;
  cvss_score_source?: string;
  // EPSS (newer Tenable plugins emit these inline)
  epss_score?: string;
  epss_percentile?: string;
  // CWE references — Nessus sometimes emits multiple <cwe> elements
  cwe?: string | string[];
  // Compliance fields
  'compliance-reference'?: string;
  'compliance-check-name'?: string;
  'compliance-info'?: string;
  'compliance-solution'?: string;
  'compliance-result'?: string;
  'compliance-actual-value'?: string;
}

// Severity to impact mapping from heimdall2
const IMPACT_MAPPING: Record<string, number> = {
  '4': 0.9,   // Critical
  '3': 0.7,   // High
  'i': 0.7,
  '2': 0.5,   // Medium
  'ii': 0.5,
  '1': 0.3,   // Low
  'iii': 0.3,
  '0': 0.0,   // Info
};

/**
 * Strip HTML tags from a string
 */
function parseHtml(html: string): string {
  return html.replace(/<[^>]*>/g, '').trim();
}

const NAMED_ENTITIES: Record<string, string> = {
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  amp: '&',
};

/**
 * Resolve XML predefined and numeric character references. The shared parser
 * runs with `processEntities: false` (XXE defense), which also leaves `&apos;`
 * and friends unresolved — so scan text would otherwise carry raw entity
 * markup into every title, description and message.
 */
function decodeXmlEntities(text: string): string {
  return text.replace(/&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z]+);/g, (match, ref: string) => {
    if (ref.startsWith('#x') || ref.startsWith('#X')) {
      return String.fromCodePoint(Number.parseInt(ref.slice(2), 16));
    }
    if (ref.startsWith('#')) {
      return String.fromCodePoint(Number.parseInt(ref.slice(1), 10));
    }
    return NAMED_ENTITIES[ref] ?? match;
  });
}

/** Apply decodeXmlEntities to every string in a parsed XML document. */
function decodeEntitiesDeep(value: unknown): unknown {
  if (typeof value === 'string') return decodeXmlEntities(value);
  if (Array.isArray(value)) return value.map(decodeEntitiesDeep);
  if (value !== null && typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      (value as Record<string, unknown>)[k] = decodeEntitiesDeep(v);
    }
  }
  return value;
}

/**
 * Convert Nessus XML scan results to HDF format
 */
export async function convertNessusToHdf(nessusXml: string, converterVersion = '1.0.0'): Promise<HDFResults> {
  validateInputSize(nessusXml, 'nessus');
  // Calculate checksum of source scan data for integrity verification
  const resultsChecksum: Checksum = await inputChecksum(nessusXml);

  const parsed = decodeEntitiesDeep(
    parseXmlWithArrays(nessusXml, ['preference', 'tag', 'ReportItem', 'ReportHost', 'cwe', 'cve']),
  ) as NessusXml;

  const policyName = parsed.NessusClientData_v2.Policy.policyName;
  const version = extractVersion(parsed);
  // parseXmlWithArrays ensures ReportHost is always an array
  const reportHosts = parsed.NessusClientData_v2.Report.ReportHost as ReportHost[];

  const { items: limitedHosts, truncated: truncatedHosts } = limitArray(reportHosts);
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncatedHosts) {
    // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedHosts.length} ReportHost items (original: ${reportHosts.length})`);
  }

  // Calculate start and end times from first and last host
  const { startTime, duration } = calculateTiming(limitedHosts);

  const baselines: EvaluatedBaseline[] = [];
  const components: Component[] = [];

  // Process each ReportHost
  limitedHosts.forEach(host => {
    const baseline = convertReportHostToBaseline(host, policyName, version, resultsChecksum);
    baselines.push(baseline);

    const target = convertReportHostToTarget(host);
    components.push(target);
  });

  const tool: Tool = { name: 'Nessus' };

  const result: HDFResults = {
    baselines,
    components,
    statistics: {
      duration,
    },
    generator: {
      name: 'nessus-to-hdf',
      version: converterVersion,
    },
    tool,
    timestamp: startTime,
  };

  return result;
}

function extractVersion(parsed: NessusXml): string {
  const prefs = parsed.NessusClientData_v2.Policy.Preferences?.ServerPreferences?.preference;
  if (!prefs) return '';

  // parseXmlWithArrays ensures preference is always an array
  const scVersion = (prefs as Array<{ name: string; value: string }>).find(p => p.name === 'sc_version');
  return scVersion?.value || '';
}

function calculateTiming(hosts: ReportHost[]): { startTime: Date; endTime: Date; duration: number } {
  if (hosts.length === 0) {
    const now = new Date();
    return { startTime: now, endTime: now, duration: 0 };
  }

  const firstHost = hosts[0]!;
  const lastHost = hosts[hosts.length - 1]!;

  const startTimeStr = getHostPropertyValue(firstHost, 'HOST_START');
  const endTimeStr = getHostPropertyValue(lastHost, 'HOST_END') || getHostPropertyValue(lastHost, 'HOST_START');

  const startTime = startTimeStr ? (parseTimestamp(startTimeStr) ?? new Date()) : new Date();
  const endTime = endTimeStr ? (parseTimestamp(endTimeStr) ?? startTime) : startTime;

  const duration = (endTime.getTime() - startTime.getTime()) / 1000; // seconds

  return { startTime, endTime, duration };
}

function getHostPropertyValue(host: ReportHost, name: string): string | undefined {
  const tags = host.HostProperties?.tag;
  if (!tags) return undefined;

  // parseXmlWithArrays ensures tag is always an array
  const tag = (tags as HostPropertyTag[]).find(t => t['name'] === name);
  return tag?.['#text'];
}

function convertReportHostToBaseline(
  host: ReportHost,
  policyName: string,
  version: string,
  resultsChecksum: Checksum
): EvaluatedBaseline {
  const items = host.ReportItem;
  // parseXmlWithArrays ensures ReportItem is always an array
  let requirements: EvaluatedRequirement[];
  if (items) {
    const { items: limitedItems, truncated: truncatedItems } = limitArray(items as ReportItem[]);
    /* v8 ignore next -- truncation only triggers with >100K items */
    if (truncatedItems) {
      // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedItems.length} ReportItem items (original: ${(items as ReportItem[]).length})`);
    }
    requirements = limitedItems.map(item => convertReportItemToRequirement(item, host));
  } else {
    requirements = [];
  }

  if (requirements.length === 0) {
    const target = host.name || getHostPropertyValue(host, 'host-ip') || 'host';
    const startTimeStr = getHostPropertyValue(host, 'HOST_START');
    const startTime = startTimeStr ? (parseTimestamp(startTimeStr) ?? new Date()) : new Date();
    requirements = [
      buildNoFindingsRequirement(
        'nessus-no-findings',
        `Nessus scanned ${target} and reported zero findings.`,
        startTime,
      ),
    ];
  }

  return createMinimalBaseline(`Nessus ${policyName}`, requirements, {
    title: `Nessus ${policyName}`,
    version,
    resultsChecksum,
    status: 'loaded',
    summary: `Nessus ${policyName}`,
  });
}

function convertReportItemToRequirement(item: ReportItem, host: ReportHost): EvaluatedRequirement {
  const isCompliance = !!item['compliance-reference'];
  const id = isCompliance
    ? parseComplianceRef(item['compliance-reference']!, 'Vuln-ID')[0] || item['pluginID']
    : item['pluginID'];

  const title = isCompliance
    ? (item['compliance-check-name'] || item['pluginName'])
    : item['pluginName'];

  const descriptions = buildDescriptions(item, isCompliance);
  const impact = calculateImpact(item, isCompliance);
  const tags = buildTags(item, isCompliance);
  const refs = buildRefs(item);
  const results = [buildResult(item, host, isCompliance)];
  const code = JSON.stringify(item, null, 2);
  const nistTags = (tags as Record<string, unknown>)['nist'] as string[] | undefined;
  const controlType = deriveControlTypeFromTags(nistTags ?? []);
  const verificationMethod = deriveVerificationMethod(code);

  const req: EvaluatedRequirement = {
    id,
    title,
    descriptions,
    impact,
    tags,
    refs,
    results,
    code,
  };
  if (controlType !== undefined) req.controlType = controlType;
  if (verificationMethod !== undefined) req.verificationMethod = verificationMethod;

  // Structured CVE-ecosystem fields. Only populated for non-compliance items
  // whose cvss_score_source is a CVE identifier.
  if (!isCompliance) {
    const cvssEntries = buildCvssEntries(item);
    if (cvssEntries.length > 0) req.cvss = cvssEntries;

    const cweIDs = buildCweIDs(item);
    if (cweIDs.length > 0) req.cwe = cweIDs;

    const epss = buildEpss(item, host);
    if (epss !== undefined) req.epss = epss;
  }

  return req;
}

/**
 * Build a structured Cvss entry for a CVE finding. Returns an array because
 * the schema models cvss as a multi-entry array (Nessus emits one entry per
 * item; multi-vendor convergence may yield more).
 */
function buildCvssEntries(item: ReportItem): Cvss[] {
  const source = (item.cvss_score_source || '').trim();
  if (!source || !CVE_SOURCE_RE.test(source)) return [];

  const hasV3 = !!(item.cvss3_vector || item.cvss3_base_score);
  const hasV2 = !!(item.cvss_vector || item.cvss_base_score);
  if (!hasV3 && !hasV2) return [];

  let version: CvssVersion;
  let baseVector: string | undefined;
  let baseScore: number | undefined;
  let threatVector: string | undefined;
  let threatScore: number | undefined;

  if (hasV3) {
    version = detectV3Version(item.cvss3_vector ?? '');
    baseVector = item.cvss3_vector || undefined;
    baseScore = parseFloatOrUndef(item.cvss3_base_score);
    threatVector = stripVersionPrefix(item.cvss3_temporal_vector);
    threatScore = item.cvss3_temporal_score ? parseFloatSafe(item.cvss3_temporal_score) : undefined;
  } else {
    version = CvssVersion.The20;
    baseVector = stripV2Prefix(item.cvss_vector ?? '') || undefined;
    baseScore = parseFloatOrUndef(item.cvss_base_score);
    threatVector = stripV2Prefix(item.cvss_temporal_vector ?? '') || undefined;
    threatScore = item.cvss_temporal_score ? parseFloatSafe(item.cvss_temporal_score) : undefined;
  }

  // Only emit base fields that are actually present: an empty baseVector would
  // fail the schema pattern, and a missing baseScore must not be coerced to 0.
  const entry: Cvss = {version, source};
  if (baseVector) entry.baseVector = baseVector;
  if (baseScore !== undefined) {
    entry.baseScore = baseScore;
    entry.baseSeverity = cvssSeverityFromScore(baseScore);
  }
  if (threatVector !== undefined && threatVector !== '') entry.threatVector = threatVector;
  if (threatScore !== undefined) {
    entry.threatScore = threatScore;
    // Per the spec, the temporal score IS the post-threat-enrichment
    // computed score for both v2 and v3.
    entry.computedScore = threatScore;
    entry.computedSeverity = cvssSeverityFromScore(threatScore);
  }

  return [entry];
}

function detectV3Version(vector: string): CvssVersion {
  if (vector.startsWith('CVSS:3.1/')) return CvssVersion.The31;
  if (vector.startsWith('CVSS:3.0/')) return CvssVersion.The30;
  // Default to 3.0 (Nessus historically emits CVSS:3.0).
  return CvssVersion.The30;
}

function stripVersionPrefix(vector: string | undefined): string | undefined {
  if (!vector) return undefined;
  for (const prefix of ['CVSS:3.0/', 'CVSS:3.1/', 'CVSS:4.0/']) {
    if (vector.startsWith(prefix)) {
      return vector.slice(prefix.length);
    }
  }
  return vector;
}

function stripV2Prefix(vector: string): string {
  return vector.startsWith('CVSS2#') ? vector.slice('CVSS2#'.length) : vector;
}

function parseFloatSafe(s: string | undefined): number {
  if (!s) return 0;
  const f = Number.parseFloat(s);
  return Number.isFinite(f) ? f : 0;
}

// parseFloatOrUndef returns the parsed number, or undefined when the source
// field is absent or unparseable (so callers can omit it rather than emit 0).
function parseFloatOrUndef(s: string | undefined): number | undefined {
  if (s === undefined || s === '') return undefined;
  const f = Number.parseFloat(s);
  return Number.isFinite(f) ? f : undefined;
}

/**
 * Extract CWE IDs from a ReportItem's <cwe> elements. Nessus emits bare
 * numeric IDs (e.g. <cwe>200</cwe>); occasionally pipe-separated or prefixed
 * forms appear. Output is "CWE-N" form per schema convention.
 */
function buildCweIDs(item: ReportItem): string[] {
  if (!item.cwe) return [];
  const raws = Array.isArray(item.cwe) ? item.cwe : [item.cwe];
  const seen = new Set<string>();
  for (const raw of raws) {
    const text = String(raw);
    // Match "CWE-N" / "CWE N" / "cweN" patterns.
    for (const m of text.matchAll(CWE_PATTERN)) {
      if (m[1]) seen.add(m[1]);
    }
    // Fallback: bare numeric tokens (Nessus' typical form).
    for (const tok of text.split(/[^0-9]+/)) {
      if (tok !== '') seen.add(tok);
    }
  }
  if (seen.size === 0) return [];
  return [...seen].sort().map(id => `CWE-${id}`);
}

/**
 * Build a structured Epss entry when the ReportItem includes EPSS data.
 * The date is derived from the host's HOST_START in YYYY-MM-DD form.
 */
function buildEpss(item: ReportItem, host: ReportHost): Epss | undefined {
  const hasScore = item.epss_score !== undefined && item.epss_score !== '';
  const hasPct = item.epss_percentile !== undefined && item.epss_percentile !== '';
  if (!hasScore && !hasPct) return undefined;
  // The schema requires a publish date on every Epss entry. If the scan has no
  // reliable date, omit the entry entirely rather than stamping a
  // non-deterministic "today".
  const date = epssDate(host);
  if (date === undefined) return undefined;
  const score = hasScore ? parseFloatSafe(item.epss_score) : 0;
  const percentile = hasPct ? parseFloatSafe(item.epss_percentile) : 0;
  return { date: date as unknown as Date, score, percentile };
}

function epssDate(host: ReportHost): string | undefined {
  const hs = getHostPropertyValue(host, 'HOST_START');
  if (hs) {
    const d = parseTimestamp(hs);
    if (d) {
      return d.toISOString().slice(0, 10);
    }
  }
  return undefined;
}

function buildDescriptions(item: ReportItem, isCompliance: boolean): Description[] {
  const descriptions: Description[] = [];

  // Default description
  if (isCompliance && item['compliance-info']) {
    descriptions.push({
      label: 'default',
      data: parseHtml(item['compliance-info']),
    });
  } else {
    // Non-compliance: create description from metadata
    const parts = [
      `Plugin Family: ${item['pluginFamily']}`,
      `Port: ${item['port']}`,
      `Protocol: ${item['protocol']}`,
    ];
    descriptions.push({
      label: 'default',
      data: parts.join('; ') + ';',
    });
  }

  // Short summary of the finding (Nessus synopsis element).
  if (item.synopsis) {
    descriptions.push({
      label: 'synopsis',
      data: parseHtml(item.synopsis),
    });
  }

  // Fix/solution description
  const solution = isCompliance ? item['compliance-solution'] : item.solution;
  if (solution && solution !== 'n/a') {
    descriptions.push({
      label: 'fix',
      data: parseHtml(solution),
    });
  } else if (solution === 'n/a') {
    descriptions.push({
      label: 'fix',
      data: 'n/a',
    });
  }

  return descriptions;
}

function calculateImpact(item: ReportItem, isCompliance: boolean): number {
  if (isCompliance && item['compliance-reference']) {
    const cat = parseComplianceRef(item['compliance-reference'], 'CAT')[0];
    const catKey = cat?.toLowerCase();
    return catKey ? (IMPACT_MAPPING[catKey] ?? 0.5) : 0.5;
  }

  return IMPACT_MAPPING[item['severity']] ?? 0.0;
}

function buildTags(item: ReportItem, isCompliance: boolean): Record<string, unknown> {
  const tags: Record<string, unknown> = {
    rid: isCompliance
      ? parseComplianceRef(item['compliance-reference']!, 'Rule-ID').join(',')
      : item['pluginID'],
  };

  // NIST tags
  if (isCompliance && item['compliance-reference']) {
    const cciTags = parseComplianceRef(item['compliance-reference'], 'CCI');
    tags.cci = cciTags;
    // Map CCI IDs to NIST controls using hdf-mappings
    // Pattern: Extract source IDs → Map each ID → Flatten results → Deduplicate
    const mappedControls = cciTags.flatMap(cci => getCCINistMappings(cci) ?? []);
    tags.nist = [...new Set(mappedControls)].sort();
  } else {
    const nistControls = getNessusNistControl(item['pluginFamily'], item['pluginID']);
    tags.nist = nistControls ? nistControls.split('|') : [];
  }

  // STIG ID for compliance
  if (isCompliance && item['compliance-reference']) {
    const stigId = parseComplianceRef(item['compliance-reference'], 'STIG-ID').join(',');
    if (stigId) {
      tags.stig_id = stigId;
    }
  }

  // Additional Nessus metadata tags
  if (item.risk_factor) tags.risk_factor = item.risk_factor;
  if (item.plugin_type) tags.plugin_type = item.plugin_type;
  if (item.plugin_publication_date) tags.plugin_publication_date = item.plugin_publication_date;
  if (item.fname) tags.fname = item.fname;
  if (item.cvss3_base_score) tags.cvss3_base_score = item.cvss3_base_score;
  if (item.cvss_base_score) tags.cvss_base_score = item.cvss_base_score;

  return tags;
}

function buildRefs(item: ReportItem): Reference[] | undefined {
  const refs: Reference[] = [];

  if (item.see_also) {
    // Nessus see_also is a whitespace-separated list of URLs (typically
    // newline-delimited). Emit one Reference per URL so each .url is a
    // standalone URI (schema requires format: uri).
    for (const url of item.see_also.split(/\s+/).filter(Boolean)) {
      refs.push({ url });
    }
  }

  return refs.length > 0 ? refs : undefined;
}

function buildResult(item: ReportItem, host: ReportHost, isCompliance: boolean): RequirementResult {
  const status = getStatus(item, isCompliance);
  const codeDesc = getCodeDesc(item);
  const message =
    isCompliance && item['compliance-actual-value']
      ? item['compliance-actual-value']
      : item.plugin_output;
  const startTimeStr = getHostPropertyValue(host, 'HOST_START');
  const startTime = startTimeStr ? (parseTimestamp(startTimeStr) ?? new Date()) : new Date();

  return {
    status,
    codeDesc,
    message: message || undefined,
    startTime,
  };
}

function getStatus(item: ReportItem, isCompliance: boolean): ResultStatus {
  if (isCompliance && item['compliance-result']) {
    const result = item['compliance-result'];
    switch (result) {
      case 'PASSED':
        return ResultStatus.Passed;
      case 'WARNING':
        return ResultStatus.NotApplicable; // Heimdall2 maps WARNING to skipped
      case 'ERROR':
        return ResultStatus.Error;
      default:
        return ResultStatus.Failed;
    }
  }

  // Non-compliance items are always failed (informational findings)
  return ResultStatus.Failed;
}

function getCodeDesc(item: ReportItem): string {
  const desc = item.description || item.plugin_output || 'This Nessus Plugin does not provide output message.';
  return parseHtml(desc);
}

function parseComplianceRef(ref: string, key: string): string[] {
  const matches = ref.split(',').filter(element => element.startsWith(key));
  return matches.map(element => element.split('|')[1] || '');
}

function convertReportHostToTarget(host: ReportHost): Component {
  const hostName = host['name'];

  // Extract host properties into a lookup map
  const hostProps: Record<string, string> = {};
  const tags = host.HostProperties?.tag;
  if (tags) {
    // parseXmlWithArrays ensures tag is always an array
    (tags as HostPropertyTag[]).forEach(tag => {
      const name = tag['name'];
      const value = tag['#text'];
      if (name && value) {
        hostProps[name] = value;
      }
    });
  }

  const target: Component = {
    name: hostName,
    type: TargetType.Host,
  };

  // The short, OS-reported hostname is a distinct property from the FQDN;
  // carry it in the dedicated field instead of dropping it.
  if (hostProps['hostname']) {
    target.hostname = hostProps['hostname'];
  }

  // Map host properties to typed Component fields
  if (isFQDN(hostName)) {
    target.fqdn = hostName;
  }

  const hostIp = hostProps['host-ip'];
  if (hostIp) {
    target.ipAddress = hostIp;
  } else if (isIPAddress(hostName)) {
    target.ipAddress = hostName;
  }

  if (hostProps['operating-system']) {
    target.osName = hostProps['operating-system'];
  }

  if (hostProps['os']) {
    target.osVersion = hostProps['os'];
  }

  if (hostProps['mac-address']) {
    target.macAddress = hostProps['mac-address'].split('\n')[0];
  }

  if (hostProps['host-fqdn']) {
    target.fqdn = hostProps['host-fqdn'];
  }

  return target;
}

function isFQDN(s: string): boolean {
  return s.includes('.') && !/^\d+\.\d+\.\d+\.\d+$/.test(s);
}

function isIPAddress(s: string): boolean {
  return /^\d+\.\d+\.\d+\.\d+$/.test(s) || s.includes(':');
}
