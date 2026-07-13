import { parseJSON } from '@mitre/hdf-utilities';
import {
  nistToCci,
  DEFAULT_REMEDIATION_NIST_TAGS,
} from '@mitre/hdf-mappings';
import { buildAffectedPackage, buildNoFindingsRequirement, deriveControlTypeFromTags, inputChecksum, limitArray, mapCWEToNIST, extractCWEIDs, validateInputSize, buildHdfResults } from '../../../shared/typescript/converterutil.js';
import { Ecosystem } from '@mitre/hdf-schema';
import type {
  EvaluatedBaseline,
  EvaluatedRequirement,
  Checksum,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  TargetType,
  VerificationMethodEnum,
  createMinimalBaseline,
  createRequirement,
  createResult,
  type Description,
} from '@mitre/hdf-schema';

/**
 * NeuVector scan JSON output structures.
 *
 * Top-level object has "error_message" and "report" fields.
 * The report contains image metadata and a vulnerabilities array.
 */
interface NeuVectorScan {
  error_message: string;
  report: NeuVectorScanReport;
}

interface NeuVectorScanReport {
  image_id: string;
  registry: string;
  repository: string;
  tag: string;
  digest: string;
  size: number;
  author: string;
  base_os: string;
  created_at: string;
  cvedb_version: string;
  cvedb_create_time: string;
  layers: unknown[];
  vulnerabilities: NeuVectorVuln[];
  modules?: NeuVectorScanModule[];
}

interface NeuVectorVuln {
  name: string;
  score: number;
  severity: string;
  vectors: string;
  description: string;
  file_name: string;
  package_name: string;
  package_version: string;
  fixed_version: string;
  link: string;
  score_v3: number;
  vectors_v3: string;
  published_timestamp: number;
  last_modified_timestamp: number;
  cpes?: string[];
  cves?: string[];
  feed_rating: string;
  in_base_image?: boolean;
  tags?: string[];
}

interface NeuVectorScanModule {
  name: string;
  file: string;
  version: string;
  source: string;
}

/**
 * Extracts CWE identifiers from a vulnerability description string.
 * Returns CWE-prefixed IDs (e.g., ["CWE-444"]) for use in tags and mapCWEToNIST.
 */
function extractCWEs(description: string): string[] {
  return extractCWEIDs(description).map(id => `CWE-${id}`);
}

/**
 * Computes the HDF impact from NeuVector CVSS scores.
 * Prefers CVSS v3 score; falls back to CVSS v2 if v3 is 0.
 * Impact is normalized to 0.0-1.0 by dividing by 10.
 */
function getImpact(vuln: NeuVectorVuln): number {
  if (vuln.score_v3 > 0) {
    return vuln.score_v3 / 10;
  }
  if (vuln.score > 0) {
    return vuln.score / 10;
  }
  return 0.5; // default when no score available
}

/**
 * Constructs the unique ID for a NeuVector vulnerability.
 */
function vulnID(vuln: NeuVectorVuln): string {
  return `${vuln.name}/${vuln.package_name}/${vuln.package_version}`;
}

/**
 * Generates a human-readable title for the vulnerability.
 */
function vulnTitle(vuln: NeuVectorVuln): string {
  return `NeuVector found a vulnerability to ${vuln.name} in ${vuln.package_name}/${vuln.package_version}.`;
}

/**
 * Generates the result message describing the fix action.
 */
function vulnMessage(vuln: NeuVectorVuln): string {
  if (!vuln.fixed_version) {
    return `Vulnerable package ${vuln.package_name} is at version ${vuln.package_version}. No fixed version available.`;
  }
  return `Vulnerable package ${vuln.package_name} is at version ${vuln.package_version}. Update to fixed version ${vuln.fixed_version}.`;
}

/**
 * Builds a single EvaluatedRequirement from a NeuVector vulnerability.
 */
function buildRequirement(vuln: NeuVectorVuln, scanTime: Date): EvaluatedRequirement {
  const cweIDs = extractCWEs(vuln.description);
  const nist = mapCWEToNIST(cweIDs, DEFAULT_REMEDIATION_NIST_TAGS);
  const cciTags = nistToCci(nist);

  const tags: Record<string, unknown> = {
    nist,
    cci: cciTags,
  };

  if (cweIDs.length > 0) {
    tags['cwe'] = cweIDs;
  }

  const descriptions: Description[] = [
    { label: 'default', data: vuln.description },
  ];

  const results = [
    createResult(ResultStatus.Failed, vulnMessage(vuln), {
      codeDesc: '',
      startTime: scanTime,
    }),
  ];

  const req = createRequirement(
    vulnID(vuln),
    vulnTitle(vuln),
    descriptions,
    getImpact(vuln),
    results,
    { tags }
  ) as EvaluatedRequirement;
  const controlType = deriveControlTypeFromTags(nist);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }
  req.verificationMethod = VerificationMethodEnum.Automated;

  // NeuVector scans container images; the package ecosystem isn't
  // disambiguated by the source format (could be rpm/deb/python/etc.
  // depending on the base image), so we record `generic`. NeuVector
  // emits CPE 2.2 URIs (`cpe:/...`); the schema requires CPE 2.3, so
  // only the first 2.3-shaped entry is carried through.
  const cpe23 = (vuln.cpes ?? []).find((c) => /^cpe:2\.3:[aho]:/.test(c));
  const pkg = buildAffectedPackage({
    name: vuln.package_name,
    version: vuln.package_version,
    ecosystem: vuln.package_name && vuln.package_version ? Ecosystem.Generic : undefined,
    cpe: cpe23,
    fixedInVersion: vuln.fixed_version,
  });
  if (pkg) {
    req.affectedPackages = [pkg];
  }
  return req;
}

/**
 * Constructs the baseline title from the image metadata.
 */
function imageTitle(report: NeuVectorScanReport): string {
  return `${report.registry}/${report.repository}:${report.tag} - Digest: ${report.digest} - Image ID: ${report.image_id}`;
}

/**
 * Constructs the target name from the image metadata.
 */
function targetNameFromReport(report: NeuVectorScanReport): string {
  return `${report.registry}/${report.repository}:${report.tag}`;
}

/**
 * Converts NeuVector container vulnerability scan JSON output to HDF format.
 *
 * Each vulnerability becomes a separate requirement with a unique
 * ID of name/package_name/package_version. Impact is derived from the
 * CVSS v3 score (preferred) or CVSS v2 score as fallback, normalized to 0-1.
 *
 * CWE identifiers are extracted from vulnerability descriptions via regex
 * and mapped to NIST 800-53 controls. When no CWE is found, default
 * remediation NIST tags (SI-2, RA-5) are used.
 *
 * @param input - NeuVector scan JSON string
 * @returns HDF JSON string
 */
export async function convertNeuvectorToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  if (!input || input.trim().length === 0) {
    throw new Error('neuvector: empty input');
  }
  validateInputSize(input, 'neuvector');

  const scan = parseJSON<NeuVectorScan>(input);

  if (!scan || typeof scan !== 'object' || !('report' in scan)) {
    throw new Error('neuvector: invalid JSON structure');
  }

  const resultsChecksum: Checksum = await inputChecksum(input);

  const { items: limitedVulns, truncated } = limitArray(
    scan.report.vulnerabilities ?? []
  );
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncated) {
    // eslint-disable-next-line no-console
    console.warn(
      `WARNING: Input truncated at ${limitedVulns.length} vulnerability items (original: ${scan.report.vulnerabilities.length})`
    );
  }

  // NeuVector reports carry image build time (created_at) and CVE-DB version
  // time (cvedb_create_time), but neither is the scan time, so use conversion
  // time as the single timestamp shared by every result.
  const scanTime = new Date();

  // Deduplicate by composite ID (name/package_name/package_version)
  const seen = new Set<string>();
  const requirements: EvaluatedRequirement[] = [];
  for (const vuln of limitedVulns) {
    const id = vulnID(vuln);
    if (seen.has(id)) {
      continue;
    }
    seen.add(id);
    requirements.push(buildRequirement(vuln, scanTime));
  }

  const target = targetNameFromReport(scan.report);
  if (requirements.length === 0) {
    requirements.push(buildNoFindingsRequirement(
      'neuvector-no-findings',
      `NeuVector scanned ${target} and reported zero vulnerable components.`,
      scanTime,
    ));
  }

  const title = imageTitle(scan.report);

  const baseline = createMinimalBaseline(
    'NeuVector Scan',
    requirements,
    {
      resultsChecksum,
      title,
    }
  ) as EvaluatedBaseline;

  return buildHdfResults({
    generatorName: 'neuvector-to-hdf',
    converterVersion,
    toolName: 'NeuVector',
    toolFormat: 'JSON',
    baselines: [baseline],
    components: [
      {
        name: targetNameFromReport(scan.report),
        type: TargetType.ContainerImage,
        labels: {
          image: `${scan.report.registry}/${scan.report.repository}:${scan.report.tag}`,
          registry: scan.report.registry,
        },
      },
    ],
    timestamp: scanTime,
  });
}
