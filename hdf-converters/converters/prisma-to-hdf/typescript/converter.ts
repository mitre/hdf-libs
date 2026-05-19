/**
 * Prisma Cloud CSV to HDF converter.
 *
 * Prisma Cloud exports compliance scan results as CSV with one row per finding.
 * Findings are grouped by Hostname, producing one baseline per host.
 * Each finding maps to a single requirement with a single failed result.
 */

import { parseCsv } from '@mitre/hdf-utilities';
import {
  nistToCci,
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
} from '@mitre/hdf-mappings';
import { deriveControlTypeFromTags, inputChecksum, buildNistCciTags, limitArrayWithWarning, DEFAULT_REMEDIATION_NIST_TAGS, validateInputSize, buildHdfResults } from '../../../shared/typescript/converterutil.js';
import type {
  HdfResults,
  EvaluatedBaseline,
  EvaluatedRequirement,
  Checksum,
  Description,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  Copyright,
  VerificationMethodEnum,
  createMinimalBaseline,
  createRequirement,
  createResult,
} from '@mitre/hdf-schema';


/** Required CSV columns that must be present */
const REQUIRED_COLUMNS = ['Hostname', 'Compliance ID', 'Severity', 'Type', 'Description'];

/**
 * A single row from the Prisma Cloud CSV export.
 */
interface PrismaRecord {
  Hostname: string;
  Distro: string;
  'CVE ID': string;
  'Compliance ID': string;
  Type: string;
  Severity: string;
  Packages: string;
  Description: string;
  Cause: string;
  'Fix Status': string;
  Published: string;
  'Vulnerability Link': string;
}

/**
 * Prisma uses non-standard severity names: "important" and "moderate"
 * in addition to the standard critical/high/medium/low.
 */
function getImpact(severity: string): number {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 1.0;
    case 'important':
      return 0.9;
    case 'high':
      return 0.7;
    case 'moderate':
    case 'medium':
      return 0.5;
    case 'low':
      return 0.3;
    default:
      return 0.5;
  }
}

/**
 * Returns NIST tags based on whether the finding has a CVE.
 * CVE findings get remediation tags; non-CVE compliance findings get static analysis tags.
 */
function getNistTags(cveID: string): string[] {
  if (cveID) {
    return DEFAULT_REMEDIATION_NIST_TAGS;
  }
  return DEFAULT_STATIC_ANALYSIS_NIST_TAGS;
}

/**
 * Constructs the requirement ID following the heimdall2 pattern:
 * - CVE findings: "{ComplianceID}-{CVEID}"
 * - Non-CVE compliance: "{ComplianceID}-{Distro}-{Severity}"
 */
function makeRequirementID(rec: PrismaRecord): string {
  if (rec['CVE ID']) {
    return `${rec['Compliance ID']}-${rec['CVE ID']}`;
  }
  return `${rec['Compliance ID']}-${rec.Distro}-${rec.Severity}`;
}

/**
 * Builds the code description following the heimdall2 pattern.
 */
function makeCodeDesc(rec: PrismaRecord): string {
  let result = '';
  if (rec.Type === 'image') {
    if (rec.Packages !== '') {
      result += `Version check of package: ${rec.Packages}`;
    }
  } else if (rec.Type === 'linux') {
    if (rec.Distro !== '') {
      result += `Configuration check for ${rec.Distro}`;
    }
  } else {
    result += `${rec.Type} check for ${rec.Hostname}`;
  }
  if (rec.Description) {
    result += `\n\n${rec.Description}`;
  }
  return result;
}

/**
 * Builds the result message from Fix Status and Cause fields.
 */
function makeMessage(rec: PrismaRecord): string {
  const hasFixStatus = rec['Fix Status'] !== '';
  const hasCause = rec.Cause !== '';

  if (hasFixStatus && hasCause) {
    return `Fix Status: ${rec['Fix Status']}\n\n${rec.Cause}`;
  } else if (hasFixStatus) {
    return `Fix Status: ${rec['Fix Status']}`;
  } else if (hasCause) {
    return `Cause: ${rec.Cause}`;
  }
  return 'Unknown';
}

/**
 * Builds the requirement title following the heimdall2 pattern.
 */
function makeTitle(rec: PrismaRecord): string {
  return `${rec.Hostname}-${rec.Distro}-${rec.Type}`;
}

/**
 * Builds a single EvaluatedRequirement from a Prisma record.
 */
function buildRequirement(rec: PrismaRecord): EvaluatedRequirement {
  const id = makeRequirementID(rec);
  const title = makeTitle(rec);
  const codeDesc = makeCodeDesc(rec);
  const message = makeMessage(rec);

  const nist = getNistTags(rec['CVE ID']);
  const cciTags = nistToCci(nist);

  const extras: Record<string, unknown> = {};
  if (rec['CVE ID']) {
    extras['cve'] = [rec['CVE ID']];
  }

  const tags = buildNistCciTags(nist, cciTags, Object.keys(extras).length > 0 ? extras : undefined);

  const descriptions: Description[] = [
    { label: 'default', data: rec.Description },
  ];

  const results = [
    createResult(ResultStatus.Failed, message, {
      codeDesc,
    }),
  ];

  const req = createRequirement(
    id,
    title,
    descriptions,
    getImpact(rec.Severity),
    results,
    { tags },
  );
  const controlType = deriveControlTypeFromTags(nist);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }
  req.verificationMethod = VerificationMethodEnum.Automated;
  return req;
}

/**
 * Groups records by hostname, preserving insertion order.
 */
function groupByHostname(records: PrismaRecord[]): Map<string, PrismaRecord[]> {
  const groups = new Map<string, PrismaRecord[]>();
  for (const rec of records) {
    const existing = groups.get(rec.Hostname);
    if (existing) {
      existing.push(rec);
    } else {
      groups.set(rec.Hostname, [rec]);
    }
  }
  return groups;
}

/**
 * Builds an HDF baseline from all records for a single host.
 */
function buildBaseline(
  hostname: string,
  records: PrismaRecord[],
  resultsChecksum: Checksum,
): EvaluatedBaseline {
  const limitedRecords = limitArrayWithWarning(records, 'finding');

  const requirements = limitedRecords.map(rec => buildRequirement(rec));

  const title = `Prisma Cloud Scan (${hostname})`;

  return createMinimalBaseline(
    'Prisma Cloud Scan',
    requirements,
    {
      resultsChecksum,
      title,
    },
  ) as EvaluatedBaseline;
}

/**
 * Converts Prisma Cloud CSV compliance scan output to HDF format.
 * Records are grouped by hostname, producing one baseline per host.
 *
 * @param input - Prisma Cloud CSV string
 * @returns HDF JSON string
 */
export async function convertPrismaToHdf(input: string): Promise<string> {
  if (!input || input.trim().length === 0) {
    throw new Error('prisma: empty input');
  }
  validateInputSize(input, 'prisma');

  // Parse CSV
  const records = parseCsv<PrismaRecord>(input);

  // Validate required columns exist by checking the first record
  if (records.length === 0) {
    throw new Error('prisma: no data rows in CSV');
  }
  const firstRecord = records[0]!;
  for (const col of REQUIRED_COLUMNS) {
    if (!(col in firstRecord)) {
      throw new Error(`prisma: missing required CSV column "${col}"`);
    }
  }

  const resultsChecksum = await inputChecksum(input);
  const hostGroups = groupByHostname(records);

  const baselines: EvaluatedBaseline[] = [];
  const components: HdfResults['components'] = [];

  for (const [hostname, hostRecords] of hostGroups) {
    baselines.push(buildBaseline(hostname, hostRecords, resultsChecksum));
    components.push({ name: hostname, type: Copyright.Host });
  }

  return buildHdfResults({
    generatorName: 'prisma-to-hdf',
    converterVersion: '1.0.0',
    toolName: 'Prisma Cloud',
    toolFormat: 'CSV',
    baselines,
    components,
    timestamp: new Date(),
  });
}
