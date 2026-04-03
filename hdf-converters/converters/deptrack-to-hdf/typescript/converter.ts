import { parseJSON } from '@mitre/hdf-utilities';
import {
  nistToCci,
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
} from '@mitre/hdf-mappings';
import { inputChecksum, mapCWEToNIST, validateInputSize, buildHdfResults } from '../../../shared/typescript/converterutil.js';
import type {
  EvaluatedBaseline,
  EvaluatedRequirement,
  Checksum,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  Copyright,
  createMinimalBaseline,
  createRequirement,
  createResult,
  type Description,
} from '@mitre/hdf-schema';

/**
 * Dependency-Track Finding Packaging Format (FPF) structures.
 */
interface DeptrackReport {
  version?: string;
  meta: DeptrackMeta;
  project: DeptrackProject;
  findings: DeptrackFinding[];
}

interface DeptrackMeta {
  application?: string;
  version?: string;
  timestamp?: string;
  baseUrl?: string;
}

interface DeptrackProject {
  uuid: string;
  name: string;
  version?: string;
  description?: string;
}

interface DeptrackFinding {
  component: DeptrackComponent;
  vulnerability: DeptrackVulnerability;
  analysis?: DeptrackAnalysis;
  attribution?: DeptrackAttribution;
  matrix: string;
}

interface DeptrackComponent {
  uuid?: string;
  name: string;
  version?: string;
  purl?: string;
  latestVersion?: string;
  group?: string;
  project?: string;
  cpe?: string;
}

interface DeptrackVulnerability {
  uuid?: string;
  source?: string;
  vulnId?: string;
  title?: string;
  subtitle?: string;
  severity: string;
  severityRank?: number;
  cweId?: number;
  cweName?: string;
  cwes?: DeptrackCwe[];
  description?: string;
  recommendation?: string;
  aliases?: unknown[];
  cvssV2BaseScore?: number;
  cvssV3BaseScore?: number;
  epssScore?: number;
  epssPercentile?: number;
}

interface DeptrackCwe {
  cweId: number;
  name: string;
}

interface DeptrackAnalysis {
  state?: string;
  isSuppressed?: boolean;
}

interface DeptrackAttribution {
  analyzerIdentity?: string;
  attributedOn?: string;
  alternateIdentifier?: string;
  referenceUrl?: string;
}

/**
 * Maps Dependency-Track severity strings to HDF impact values.
 * Uses the same mapping as the heimdall2 dependency-track-mapper:
 * critical=0.9, high=0.7, medium=0.5, low=0.3, info=0, unassigned=0.5
 */
function getImpact(severity: string): number {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 0.9;
    case 'high':
      return 0.7;
    case 'medium':
      return 0.5;
    case 'low':
      return 0.3;
    case 'info':
      return 0.0;
    default:
      return 0.5;
  }
}

/**
 * Builds the requirement title from component purl and vulnerability title.
 * Matches the heimdall2 pattern: "{purl} - {title}" or just "{purl}".
 */
function getTitle(finding: DeptrackFinding): string {
  const purl = finding.component.purl ?? finding.component.name;
  const title = finding.vulnerability.title;
  if (title) {
    return `${purl} - ${title}`;
  }
  return purl;
}

/**
 * Extracts CWE IDs as "CWE-NNN" strings from the cwes array.
 */
function getCweIDs(cwes: DeptrackCwe[] | undefined): string[] {
  if (!cwes || cwes.length === 0) {
    return [];
  }
  return cwes.map(cwe => `CWE-${cwe.cweId}`);
}

/**
 * Builds a single EvaluatedRequirement from a Dependency-Track finding.
 */
function buildRequirement(finding: DeptrackFinding, timestamp: string | undefined): EvaluatedRequirement {
  const cweIDs = getCweIDs(finding.vulnerability.cwes);
  const nist = mapCWEToNIST(cweIDs, DEFAULT_STATIC_ANALYSIS_NIST_TAGS);
  const cciTags = nistToCci(nist);

  const tags: Record<string, unknown> = {
    nist,
    cci: cciTags,
  };

  if (cweIDs.length > 0) {
    tags['cweIds'] = cweIDs;
  }

  // Build descriptions: default, check, fix
  const descriptions: Description[] = [
    { label: 'default', data: finding.vulnerability.description ?? '' },
  ];

  if (finding.vulnerability.description) {
    descriptions.push({ label: 'check', data: finding.vulnerability.description });
  }
  if (finding.vulnerability.recommendation) {
    descriptions.push({ label: 'fix', data: finding.vulnerability.recommendation });
  }

  // Build result: all findings are Failed
  const codeDesc = finding.vulnerability.recommendation ?? 'No recommendation available';

  const results = [
    createResult(ResultStatus.Failed, undefined, {
      codeDesc,
      startTime: timestamp ? new Date(timestamp) : undefined,
    }),
  ];

  return createRequirement(
    finding.matrix,
    getTitle(finding),
    descriptions,
    getImpact(finding.vulnerability.severity),
    results,
    { tags },
  );
}

/**
 * Converts Dependency-Track FPF JSON output to HDF format.
 *
 * @param input - Dependency-Track FPF JSON string
 * @returns HDF JSON string
 */
export async function convertDeptrackToHdf(input: string): Promise<string> {
  if (!input || input.trim().length === 0) {
    throw new Error('deptrack: empty input');
  }
  validateInputSize(input, 'deptrack');

  const resultsChecksum: Checksum = await inputChecksum(input);

  const parsed = parseJSON<DeptrackReport>(input);

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('deptrack: invalid JSON');
  }

  // Validate it looks like a Dependency-Track report
  if (!parsed.findings && !parsed.project && !parsed.meta) {
    throw new Error('deptrack: input does not appear to be a Dependency-Track report');
  }

  const findings = parsed.findings ?? [];
  const requirements: EvaluatedRequirement[] = findings.map(
    finding => buildRequirement(finding, parsed.meta?.timestamp),
  );

  const title = `Dependency-Track: ${parsed.project?.name ?? ''} ${parsed.project?.version ?? ''}`;

  const baseline = createMinimalBaseline(
    'Dependency-Track Scan',
    requirements,
    {
      resultsChecksum,
      title,
      summary: parsed.project?.description,
    },
  ) as EvaluatedBaseline;

  const targetName = parsed.project?.name ?? parsed.project?.uuid ?? '';

  return buildHdfResults({
    generatorName: 'deptrack-to-hdf',
    converterVersion: '1.0.0',
    toolName: 'Dependency-Track',
    toolFormat: 'JSON',
    baselines: [baseline],
    components: [{ name: targetName, type: Copyright.Application }],
    timestamp: new Date(),
  });
}
