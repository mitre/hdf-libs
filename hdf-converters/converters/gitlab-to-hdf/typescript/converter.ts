import {
  type Checksum,
  createMinimalBaseline,
  Copyright,
  type Tool,
  type EvaluatedBaseline,
  type EvaluatedRequirement,
  type RequirementResult,
  type HdfResults,
  type Component,
  ResultStatus,
  severityToImpact,
} from '@mitre/hdf-schema';
import {
  getCweNistControl,
  nistToCci,
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
} from '@mitre/hdf-mappings';
import {parseJSON} from '@mitre/hdf-utilities';
import {inputChecksum, buildNistCciTags, limitArray, validateInputSize} from '../../../shared/typescript/converterutil.js';

// --- GitLab Security Report input types ---

interface GitLabReport {
  version?: string;
  scan?: GitLabScan;
  vulnerabilities?: GitLabVulnerability[];
  remediations?: GitLabRemediation[];
}

interface GitLabScan {
  analyzer?: GitLabTool;
  scanner?: GitLabTool;
  start_time?: string;
  end_time?: string;
  status?: string;
  type?: string;
}

interface GitLabTool {
  id?: string;
  name?: string;
  version?: string;
}

interface GitLabVulnerability {
  id: string;
  name?: string;
  description?: string;
  severity?: string;
  solution?: string;
  identifiers?: GitLabIdentifier[];
  location?: GitLabLocation;
  links?: Array<{url?: string}>;
}

interface GitLabIdentifier {
  type?: string;
  name?: string;
  value?: string;
  url?: string;
}

interface GitLabLocation {
  file?: string;
  start_line?: number;
  end_line?: number;
  class?: string;
  method?: string;
  hostname?: string;
  path?: string;
  param?: string;
  image?: string;
  operating_system?: string;
  dependency?: {
    package?: {name?: string};
    version?: string;
  };
}

interface GitLabRemediation {
  fixes?: Array<{id?: string}>;
  summary?: string;
  diff?: string;
}

// --- Severity to impact ---

function gitlabSeverityToImpact(severity: string): number {
  return severityToImpact(severity.toLowerCase());
}

// --- Scan type to target type ---

function scanTypeToTargetType(scanType: string): Copyright {
  switch (scanType) {
    case 'dast':
      return Copyright.Application;
    case 'container_scanning':
      return Copyright.ContainerImage;
    default:
      return Copyright.Repository;
  }
}

// --- Scan type label ---

function scanTypeLabel(scanType: string): string {
  const labels: Record<string, string> = {
    sast: 'SAST',
    dast: 'DAST',
    dependency_scanning: 'Dependency Scanning',
    container_scanning: 'Container Scanning',
    secret_detection: 'Secret Detection',
    api_fuzzing: 'API Fuzzing',
  };
  return labels[scanType] ?? scanType.toUpperCase();
}

// --- NIST tag building ---

function buildNistTags(identifiers: GitLabIdentifier[]): string[] {
  const seen = new Set<string>();
  const controls: string[] = [];
  for (const id of identifiers) {
    if (id.type === 'cwe' && id.value) {
      const cweNum = parseInt(id.value, 10);
      if (!isNaN(cweNum)) {
        const control = getCweNistControl(cweNum);
        if (control && !seen.has(control)) {
          seen.add(control);
          controls.push(control);
        }
      }
    }
  }
  if (controls.length > 0) {
    return controls;
  }
  return [...DEFAULT_STATIC_ANALYSIS_NIST_TAGS];
}

// --- Collect identifier tags ---

function collectIdentifierTags(identifiers: GitLabIdentifier[]): Record<string, string[]> {
  const result: Record<string, string[]> = {};
  for (const id of identifiers) {
    if (id.type && id.value) {
      const key = id.type.toLowerCase();
      if (!result[key]) {
        result[key] = [];
      }
      result[key].push(id.value);
    }
  }
  return result;
}

// --- Build code description by scan type ---

function buildCodeDesc(scanType: string, location?: GitLabLocation): string {
  if (!location) return '';

  switch (scanType) {
    case 'sast':
    case 'secret_detection': {
      const parts: string[] = [];
      if (location.file) {
        parts.push(`File: ${location.file}`);
      }
      if (location.start_line != null) {
        const line = location.end_line != null && location.end_line !== location.start_line
          ? `${location.start_line}-${location.end_line}`
          : `${location.start_line}`;
        parts.push(`Line: ${line}`);
      }
      if (location.class) {
        parts.push(`Class: ${location.class}`);
      }
      if (location.method) {
        parts.push(`Method: ${location.method}`);
      }
      return parts.join(' | ');
    }
    case 'dast': {
      const parts: string[] = [];
      if (location.hostname) {
        const url = location.path ? `${location.hostname}${location.path}` : location.hostname;
        parts.push(`URL: ${url}`);
      }
      if (location.method) {
        parts.push(`Method: ${location.method}`);
      }
      if (location.param) {
        parts.push(`Param: ${location.param}`);
      }
      return parts.join(' | ');
    }
    case 'dependency_scanning': {
      const parts: string[] = [];
      if (location.file) {
        parts.push(`File: ${location.file}`);
      }
      if (location.dependency?.package?.name) {
        const pkg = location.dependency.version
          ? `${location.dependency.package.name}@${location.dependency.version}`
          : location.dependency.package.name;
        parts.push(`Package: ${pkg}`);
      }
      return parts.join(' | ');
    }
    case 'container_scanning': {
      const parts: string[] = [];
      if (location.image) {
        parts.push(`Image: ${location.image}`);
      }
      if (location.dependency?.package?.name) {
        const pkg = location.dependency.version
          ? `${location.dependency.package.name}@${location.dependency.version}`
          : location.dependency.package.name;
        parts.push(`Package: ${pkg}`);
      }
      return parts.join(' | ');
    }
    default:
      return `Location: ${JSON.stringify(location)}`;
  }
}

// --- Main converter ---

export async function convertGitlabToHdf(input: string): Promise<string> {
  validateInputSize(input, 'gitlab');
  const resultsChecksum: Checksum = await inputChecksum(input);

  const report = parseJSON<GitLabReport>(input);

  const scanType = report.scan?.type ?? 'sast';
  const scannerName = report.scan?.scanner?.name ?? 'GitLab Security Scanner';
  const scannerVersion = report.scan?.scanner?.version;
  const startTime = report.scan?.start_time;

  const vulns = report.vulnerabilities ?? [];
  const {items: limitedVulns, truncated} = limitArray(vulns);
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncated) {
    // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedVulns.length} vulnerabilities (original: ${vulns.length})`);
  }

  const requirements: EvaluatedRequirement[] = [];

  for (const vuln of limitedVulns) {
    const identifiers = vuln.identifiers ?? [];

    // Build NIST tags
    const nistTags = buildNistTags(identifiers);
    const cciTags = nistToCci(nistTags);

    // Build extra tags from identifiers
    const idTags = collectIdentifierTags(identifiers);
    const extras: Record<string, unknown> = {};
    for (const [key, values] of Object.entries(idTags)) {
      extras[key] = values;
    }
    const tags = buildNistCciTags(nistTags, cciTags, Object.keys(extras).length > 0 ? extras : undefined);

    // Build descriptions
    const descriptions: Array<{label: string; data: string}> = [];
    if (vuln.description) {
      descriptions.push({label: 'default', data: vuln.description});
    }
    if (vuln.solution) {
      descriptions.push({label: 'check', data: vuln.solution});
    }

    // Build result
    const result: RequirementResult = {
      status: ResultStatus.Failed,
      codeDesc: buildCodeDesc(scanType, vuln.location),
      startTime: startTime ? new Date(startTime) : new Date('0001-01-01T00:00:00Z'),
    };

    const impact = gitlabSeverityToImpact(vuln.severity ?? 'Unknown');

    const req: EvaluatedRequirement = {
      id: vuln.id,
      title: vuln.name ?? vuln.id,
      impact,
      results: [result],
      tags,
      descriptions,
    };

    requirements.push(req);
  }

  const label = scanTypeLabel(scanType);
  const baselineTitle = `GitLab ${label} Security Scan`;

  const baseline: EvaluatedBaseline = createMinimalBaseline('GitLab Security Scan', requirements, {
    resultsChecksum,
    title: baselineTitle,
    summary: `Scanner: ${scannerName}${scannerVersion ? ` v${scannerVersion}` : ''}`,
  }) as EvaluatedBaseline;

  const tool: Tool = {
    name: scannerName,
    format: 'JSON',
  };
  if (scannerVersion) {
    tool.version = scannerVersion;
  }

  // Build components based on scan type
  const components: Component[] = [];
  const targetType = scanTypeToTargetType(scanType);
  components.push({name: scannerName, type: targetType});

  const hdf: HdfResults = {
    baselines: [baseline],
    components,
    generator: {
      name: 'gitlab-to-hdf',
      version: 'unknown',
    },
    tool,
  };

  if (report.scan?.end_time) {
    hdf.timestamp = new Date(report.scan.end_time);
  }

  return JSON.stringify(hdf, null, 2);
}
