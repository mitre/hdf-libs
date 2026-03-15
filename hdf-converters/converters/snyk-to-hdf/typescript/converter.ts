import { parseJSON } from '@mitre/hdf-utilities';
import {
  nistToCci,
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
} from '@mitre/hdf-mappings';
import { detectFormat } from '../../../shared/typescript/formatdetect.js';
import { convertSarifToHdf } from '../../sarif-to-hdf/typescript/converter.js';
import { inputChecksum, limitArray, mapCWEToNIST, validateInputSize } from '../../../shared/typescript/converterutil.js';
import type {
  HdfResults,
  EvaluatedBaseline,
  EvaluatedRequirement,
  Checksum,
  DataSource,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  Copyright,
  createMinimalBaseline,
  createRequirement,
  createResult,
  severityToImpact,
  type Description,
} from '@mitre/hdf-schema';

/**
 * Snyk JSON output structures
 * See https://docs.snyk.io/snyk-cli/commands/test for the full schema.
 */
interface SnykReport {
  ok: boolean;
  vulnerabilities: SnykVuln[];
  dependencyCount?: number;
  org?: string;
  packageManager?: string;
  summary?: string;
  projectName?: string;
  path?: string;
}

interface SnykVuln {
  id: string;
  title: string;
  description: string;
  severity: string;
  cvssScore?: number;
  CVSSv3?: string;
  identifiers: SnykIdentifiers;
  language?: string;
  packageName?: string;
  moduleName?: string;
  version?: string;
  from: string[];
  upgradePath?: unknown[];
  fixedIn?: string[];
  exploit?: string;
}

interface SnykIdentifiers {
  CVE?: string[];
  CWE?: string[];
  GHSA?: string[];
}

/**
 * Formats the "from" array as a human-readable dependency path.
 */
function formatDependencyPath(from: string[]): string {
  if (!from || from.length === 0) {
    return 'Unknown dependency path';
  }
  return `From: [ ${from.join(', ')} ]`;
}

/**
 * Builds a single EvaluatedRequirement from a group of vulnerabilities sharing an ID.
 */
function buildRequirement(vulnID: string, vulns: SnykVuln[]): EvaluatedRequirement {
  const rep = vulns[0]!;
  const cweIDs = rep.identifiers.CWE ?? [];
  const nist = mapCWEToNIST(cweIDs, DEFAULT_STATIC_ANALYSIS_NIST_TAGS);
  const cciTags = nistToCci(nist);

  const tags: Record<string, unknown> = {
    nist,
    cci: cciTags,
  };

  if (cweIDs.length > 0) {
    tags['cweid'] = cweIDs;
  }
  if (rep.identifiers.CVE && rep.identifiers.CVE.length > 0) {
    tags['cveid'] = rep.identifiers.CVE;
  }
  if (rep.identifiers.GHSA && rep.identifiers.GHSA.length > 0) {
    tags['ghsaid'] = rep.identifiers.GHSA;
  }

  const descriptions: Description[] = [
    { label: 'default', data: rep.description },
  ];

  const results = vulns.map(vuln =>
    createResult(ResultStatus.Failed, undefined, {
      codeDesc: formatDependencyPath(vuln.from),
    })
  );

  return createRequirement(
    vulnID,
    rep.title,
    descriptions,
    severityToImpact(rep.severity),
    results,
    { tags }
  );
}

/**
 * Converts a single Snyk project report to an HDF baseline.
 */
function convertSingleProject(
  report: SnykReport,
  resultsChecksum: Checksum
): EvaluatedBaseline {
  // Group vulnerabilities by ID, preserving insertion order
  const { items: limitedVulns, truncated: truncatedVulns } = limitArray(report.vulnerabilities);
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncatedVulns) {
    // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedVulns.length} vulnerability items (original: ${report.vulnerabilities.length})`);
  }
  const groups = new Map<string, SnykVuln[]>();
  for (const vuln of limitedVulns) {
    const existing = groups.get(vuln.id);
    if (existing) {
      existing.push(vuln);
    } else {
      groups.set(vuln.id, [vuln]);
    }
  }

  const requirements: EvaluatedRequirement[] = [];
  for (const [vulnID, vulns] of groups) {
    requirements.push(buildRequirement(vulnID, vulns));
  }

  const title = `Snyk Project: ${report.projectName ?? ''} Snyk Path: ${report.path ?? ''}`;

  return createMinimalBaseline(
    'Snyk Scan',
    requirements,
    {
      resultsChecksum,
      title,
      summary: report.summary,
    }
  ) as EvaluatedBaseline;
}

/**
 * Converts Snyk output to HDF format.
 * Accepts both native Snyk JSON and SARIF format — SARIF input is detected
 * automatically and delegated to the shared SARIF converter.
 * Handles both single-project (object) and multi-project (array) input.
 *
 * @param input - Snyk JSON or SARIF string
 * @returns HDF JSON string
 */
export async function convertSnykToHdf(input: string): Promise<string> {
  if (!input || input.trim().length === 0) {
    throw new Error('snyk: empty input');
  }
  validateInputSize(input, 'snyk');

  // Detect format: if SARIF, delegate to the shared SARIF converter
  if (detectFormat(input) === 'sarif') {
    return convertSarifToHdf(input);
  }

  const resultsChecksum: Checksum = await inputChecksum(input);

  const parsed = parseJSON<SnykReport | SnykReport[]>(input);

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('snyk: invalid JSON');
  }

  let baselines: EvaluatedBaseline[];
  let targetName: string;

  if (Array.isArray(parsed)) {
    // Multi-project output
    const { items: limitedProjects, truncated: truncatedProjects } = limitArray(parsed);
    /* v8 ignore next -- truncation only triggers with >100K items */
    if (truncatedProjects) {
      // eslint-disable-next-line no-console
      console.warn(`WARNING: Input truncated at ${limitedProjects.length} project items (original: ${parsed.length})`);
    }
    baselines = limitedProjects.map(report => convertSingleProject(report, resultsChecksum));
    targetName = limitedProjects[0]?.projectName ?? limitedProjects[0]?.path ?? '';
  } else {
    // Single project
    baselines = [convertSingleProject(parsed, resultsChecksum)];
    targetName = parsed.projectName ?? parsed.path ?? '';
  }

  const dataSource: DataSource = { name: 'Snyk', format: 'JSON' };

  const hdf: HdfResults = {
    baselines,
    generator: {
      name: 'snyk-to-hdf',
      version: '1.0.0',
    },
    dataSource,
    targets: [{ name: targetName, type: Copyright.Application }],
    timestamp: new Date(),
  };

  return JSON.stringify(hdf, null, 2);
}
