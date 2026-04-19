import { parseXmlWithArrays } from '@mitre/hdf-utilities';
import { getNessusNistControl, getCCINistMappings } from '@mitre/hdf-mappings';
import { inputChecksum, limitArray, validateInputSize } from '../../../shared/typescript/converterutil.js';
import type {
  HdfResults,
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Component,
  Description,
  Reference,
  Checksum,
  Tool,
} from '@mitre/hdf-schema';
import { ResultStatus, Copyright as TargetType, createMinimalBaseline } from '@mitre/hdf-schema';
// Per-converter version (matches the pattern used by the other 32 converters).
// Bumped manually when the nessus converter's output format changes in a way
// consumers might notice. Distinct from the package's npm version.
const converterVersion = '1.0.0';

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
  cve?: string;
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

/**
 * Convert Nessus XML scan results to HDF format
 */
export async function convertNessusToHdf(nessusXml: string): Promise<HdfResults> {
  validateInputSize(nessusXml, 'nessus');
  // Calculate checksum of source scan data for integrity verification
  const resultsChecksum: Checksum = await inputChecksum(nessusXml);

  const parsed = parseXmlWithArrays(nessusXml, ['preference', 'tag', 'ReportItem', 'ReportHost']) as unknown as NessusXml;

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

  const result: HdfResults = {
    baselines,
    components,
    statistics: {
      duration,
    },
    generator: {
      name: 'hdf-converters',
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

  const startTime = startTimeStr ? new Date(startTimeStr) : new Date();
  const endTime = endTimeStr ? new Date(endTimeStr) : startTime;

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

  return {
    id,
    title,
    descriptions,
    impact,
    tags,
    refs,
    results,
    code,
  };
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
    tags.nist = [...new Set(mappedControls)];
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
    refs.push({ url: item.see_also });
  }

  return refs.length > 0 ? refs : undefined;
}

function buildResult(item: ReportItem, host: ReportHost, isCompliance: boolean): RequirementResult {
  const status = getStatus(item, isCompliance);
  const codeDesc = getCodeDesc(item);
  const message = item.plugin_output || item['compliance-actual-value'];
  const startTimeStr = getHostPropertyValue(host, 'HOST_START');
  const startTime = startTimeStr ? new Date(startTimeStr) : new Date();

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

  target.labels = {};

  return target;
}

function isFQDN(s: string): boolean {
  return s.includes('.') && !/^\d+\.\d+\.\d+\.\d+$/.test(s);
}

function isIPAddress(s: string): boolean {
  return /^\d+\.\d+\.\d+\.\d+$/.test(s) || s.includes(':');
}
