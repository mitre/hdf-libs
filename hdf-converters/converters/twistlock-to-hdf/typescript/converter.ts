import { parseJSON } from '@mitre/hdf-utilities';
import {
  nistToCci,
  DEFAULT_REMEDIATION_NIST_TAGS,
} from '@mitre/hdf-mappings';
import { deriveControlTypeFromTags, inputChecksum, limitArray, buildNistCciTags, validateInputSize, buildHdfResults } from '../../../shared/typescript/converterutil.js';
import type {
  EvaluatedBaseline,
  EvaluatedRequirement,
  Checksum,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  Copyright,
  VerificationMethodEnum,
  createMinimalBaseline,
  createRequirement,
  createResult,
  type Description,
} from '@mitre/hdf-schema';

/**
 * Twistlock/Prisma Cloud scan output structures.
 *
 * Container image scans produce a top-level "results" array.
 * Code repository scans omit the wrapper and return a single result object.
 */
interface TwistlockReport {
  results?: TwistlockResult[];
  consoleURL?: string;
}

interface TwistlockResult {
  id?: string;
  name?: string;
  repository?: string;
  distro?: string;
  collections?: string[];
  vulnerabilities?: TwistlockVuln[] | null;
  vulnerabilityDistribution?: TwistlockDistribution;
  complianceDistribution?: TwistlockDistribution;
}

interface TwistlockVuln {
  id: string;
  status?: string;
  cvss?: number;
  vector?: string;
  description: string;
  severity: string;
  packageName?: string;
  packageVersion?: string;
  link?: string;
  riskFactors?: string[];
  impactedVersions?: string[];
  publishedDate?: string;
  discoveredDate?: string;
  fixDate?: string;
  layerTime?: string;
}

interface TwistlockDistribution {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

/**
 * Maps Twistlock severity strings to HDF impact values.
 * Includes "important" (alias for critical) and "moderate" (alias for medium)
 * which appear in some Twistlock outputs.
 */
function twistlockSeverityToImpact(severity: string): number {
  switch (severity.toLowerCase()) {
    case 'critical':
    case 'important':
      return 0.9;
    case 'high':
      return 0.7;
    case 'medium':
    case 'moderate':
      return 0.5;
    case 'low':
      return 0.3;
    default:
      return 0.5;
  }
}

/**
 * Builds the baseline title from scan result data.
 */
function buildTitle(result: TwistlockResult): string {
  let projectName: string;
  if (result.repository) {
    projectName = result.repository;
  } else if (result.collections && result.collections.length > 0) {
    projectName = result.collections.join(' / ');
  } else {
    projectName = 'N/A';
  }
  return `Twistlock Project: ${projectName}`;
}

/**
 * Builds the baseline summary from distribution data.
 */
function buildSummary(result: TwistlockResult): string {
  const vulnTotal = result.vulnerabilityDistribution
    ? String(result.vulnerabilityDistribution.total)
    : 'N/A';
  const complianceTotal = result.complianceDistribution
    ? String(result.complianceDistribution.total)
    : 'N/A';
  return `Package Vulnerability Summary: ${vulnTotal} Application Compliance Issue Total: ${complianceTotal}`;
}

/**
 * Builds the code_desc string for a vulnerability result.
 */
function formatCodeDesc(vuln: TwistlockVuln): string {
  const packageName = vuln.packageName ?? 'N/A';
  const impactedVersions = vuln.impactedVersions && vuln.impactedVersions.length > 0
    ? JSON.stringify(vuln.impactedVersions)
    : 'N/A';
  return `Package ${JSON.stringify(packageName)} should be updated to latest version above impacted versions ${impactedVersions}`;
}

/**
 * Converts a single vulnerability into an EvaluatedRequirement.
 */
function buildRequirement(vuln: TwistlockVuln): EvaluatedRequirement {
  const nist = DEFAULT_REMEDIATION_NIST_TAGS;
  const cciTags = nistToCci(nist);

  const tags = buildNistCciTags(nist, cciTags, {
    cveid: [vuln.id],
  });

  const descriptions: Description[] = [
    { label: 'default', data: vuln.description },
  ];

  const startTime = vuln.discoveredDate ? new Date(vuln.discoveredDate) : undefined;

  const results = [
    createResult(ResultStatus.Failed, undefined, {
      codeDesc: formatCodeDesc(vuln),
      startTime,
    }),
  ];

  const req = createRequirement(
    vuln.id,
    vuln.id,
    descriptions,
    twistlockSeverityToImpact(vuln.severity),
    results,
    { tags }
  ) as EvaluatedRequirement;

  const controlType = deriveControlTypeFromTags(nist);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }
  req.verificationMethod = VerificationMethodEnum.Automated;

  return req;
}

/**
 * Converts a single TwistlockResult to an EvaluatedBaseline.
 */
function convertSingleResult(
  result: TwistlockResult,
  resultsChecksum: Checksum
): EvaluatedBaseline {
  const vulns = result.vulnerabilities ?? [];
  const { items: limitedVulns, truncated } = limitArray(vulns);
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncated) {
    // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedVulns.length} vulnerability items (original: ${vulns.length})`);
  }

  const requirements: EvaluatedRequirement[] = limitedVulns.map(vuln =>
    buildRequirement(vuln)
  );

  const title = buildTitle(result);
  const summary = buildSummary(result);

  return createMinimalBaseline(
    'Twistlock Scan',
    requirements,
    {
      resultsChecksum,
      title,
      summary,
    }
  ) as EvaluatedBaseline;
}

/**
 * Converts Twistlock/Prisma Cloud scan output to HDF format.
 *
 * Handles both container image scans (with "results" wrapper) and code
 * repository scans (single result object without wrapper).
 *
 * @param input - Twistlock JSON string
 * @returns HDF JSON string
 */
export async function convertTwistlockToHdf(input: string): Promise<string> {
  if (!input || input.trim().length === 0) {
    throw new Error('twistlock: empty input');
  }
  validateInputSize(input, 'twistlock');

  const resultsChecksum: Checksum = await inputChecksum(input);

  const parsed = parseJSON<TwistlockReport & TwistlockResult>(input);

  if (!parsed || typeof parsed !== 'object') {
    throw new Error('twistlock: invalid JSON');
  }

  let results: TwistlockResult[];

  if (Array.isArray((parsed as TwistlockReport).results)) {
    // Container scan with "results" wrapper
    results = (parsed as TwistlockReport).results!;
  } else {
    // Code repo scan — single result object, wrap it
    results = [parsed as TwistlockResult];
  }

  if (results.length === 0) {
    throw new Error('twistlock: no scan results found');
  }

  const baselines = results.map(result =>
    convertSingleResult(result, resultsChecksum)
  );

  // Use the first result's name or repository as target name
  const targetName = results[0]!.name ?? results[0]!.repository ?? '';

  return buildHdfResults({
    generatorName: 'twistlock-to-hdf',
    converterVersion: '1.0.0',
    toolName: 'Twistlock',
    toolFormat: 'JSON',
    baselines,
    components: [{
      name: targetName,
      type: Copyright.ContainerImage,
      labels: { image: results[0]?.id ?? targetName },
    }],
    timestamp: new Date(),
  });
}
