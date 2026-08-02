import { parseJSON } from '@mitre/hdf-utilities';
import {
  nistToCci,
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
} from '@mitre/hdf-mappings';
import { detectConverter } from '../../../shared/typescript/fingerprint.js';
import { registerAllFingerprints } from '../../../shared/typescript/register-all.js';
import { convertSarifToHdf } from '../../sarif-to-hdf/typescript/converter.js';
import { buildAffectedPackage, buildNoFindingsRequirement, deriveControlTypeFromTags, ecosystemFromPurlType, inputChecksum, limitArray, mapCWEToNIST, validateInputSize, buildHdfResults } from '../../../shared/typescript/converterutil.js';
import { buildCvss, cvssVersionFromVector } from '../../../shared/typescript/cvss.js';
import type {
  Cvss,
  EvaluatedBaseline,
  EvaluatedRequirement,
  Checksum,
} from '@mitre/hdf-schema';
import {
  Ecosystem,
  ResultStatus,
  TargetType,
  VerificationMethodEnum,
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
/**
 * Map Snyk's `packageManager` value to an Affected_Package ecosystem.
 * Snyk reports values that don't always match PURL types one-to-one
 * (pip → pypi, rubygems → gem, yarn → npm). Unknown managers fall back
 * to `generic`.
 */
function ecosystemFromSnykPackageManager(pm: string | undefined): Ecosystem {
  if (!pm) return Ecosystem.Generic;
  const lower = pm.toLowerCase();
  if (lower === 'pip' || lower === 'pip3') return Ecosystem.Pypi;
  if (lower === 'rubygems' || lower === 'bundler') return Ecosystem.Gem;
  if (lower === 'yarn' || lower === 'npm') return Ecosystem.Npm;
  return ecosystemFromPurlType(lower);
}

/** Synthesize a `pkg:<type>/<name>@<version>` PURL when the ecosystem
 *  maps cleanly. Returns undefined for `generic` so we don't emit a
 *  fake `pkg:generic/...` PURL that downstream tools can't dereference. */
function synthesizePurl(ecosystem: Ecosystem, name: string, version: string): string | undefined {
  if (ecosystem === Ecosystem.Generic) return undefined;
  return `pkg:${ecosystem}/${name}@${version}`;
}

/**
 * Assembles the structured cvss[] entry for a Snyk vulnerability from its
 * cvssScore (base score) and CVSSv3 (base vector, carrying a CVSS:3.1/ prefix).
 * Returns [] when the source carries neither so the field is omitted.
 */
export function buildSnykCvss(vuln: SnykVuln): Cvss[] {
  if (!vuln.cvssScore && !vuln.CVSSv3) return [];
  return [buildCvss({
    version: cvssVersionFromVector(vuln.CVSSv3),
    baseScore: vuln.cvssScore,
    baseVector: vuln.CVSSv3,
  })];
}

function buildRequirement(vulnID: string, vulns: SnykVuln[], scanTime: Date, packageManager?: string): EvaluatedRequirement {
  const rep = vulns[0]!;
  const cweIDs = rep.identifiers.CWE ?? [];
  const nist = mapCWEToNIST(cweIDs, DEFAULT_STATIC_ANALYSIS_NIST_TAGS);
  const cciTags = nistToCci(nist);

  const tags: Record<string, unknown> = {
    nist,
    cci: cciTags,
  };

  // requirement.id is a SNYK/npm advisory id, not the CVE, so tags.cve is the
  // CVE's home. (Interim pending an identifiers[] schema field.)
  if (rep.identifiers.CVE && rep.identifiers.CVE.length > 0) {
    tags['cve'] = rep.identifiers.CVE;
  }
  if (rep.identifiers.GHSA && rep.identifiers.GHSA.length > 0) {
    tags['ghsaid'] = rep.identifiers.GHSA;
  }

  const descriptions: Description[] = [
    { label: 'default', data: rep.description },
  ];

  const results = vulns.map(vuln => {
    const result = createResult(ResultStatus.Failed, undefined, {
      codeDesc: formatDependencyPath(vuln.from),
      startTime: scanTime,
    });
    delete result.message;
    return result;
  });

  const req = createRequirement(
    vulnID,
    rep.title,
    descriptions,
    severityToImpact(rep.severity),
    results,
    { tags }
  ) as EvaluatedRequirement;

  const controlType = deriveControlTypeFromTags(nist);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }
  req.verificationMethod = VerificationMethodEnum.Automated;

  const cvss = buildSnykCvss(rep);
  if (cvss.length > 0) {
    req.cvss = cvss;
  }
  if (cweIDs.length > 0) {
    req.cwe = cweIDs;
  }

  const name = rep.packageName ?? rep.moduleName;
  const version = rep.version;
  if (name && version) {
    const ecosystem = ecosystemFromSnykPackageManager(packageManager);
    const pkg = buildAffectedPackage({
      name,
      version,
      ecosystem,
      purl: synthesizePurl(ecosystem, name, version),
      fixedInVersion: rep.fixedIn?.[0],
    });
    if (pkg) {
      req.affectedPackages = [pkg];
    }
  }

  return req;
}

/**
 * Converts a single Snyk project report to an HDF baseline.
 */
function convertSingleProject(
  report: SnykReport,
  resultsChecksum: Checksum,
  scanTime: Date
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
    requirements.push(buildRequirement(vulnID, vulns, scanTime, report.packageManager));
  }

  if (requirements.length === 0) {
    const target = report.projectName ?? report.path ?? 'project';
    requirements.push(
      buildNoFindingsRequirement(
        'snyk-no-findings',
        `Snyk scanned ${target} and reported zero vulnerable components.`,
        scanTime,
      ),
    );
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
export async function convertSnykToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  if (!input || input.trim().length === 0) {
    throw new Error('snyk: empty input');
  }
  validateInputSize(input, 'snyk');

  // Detect format: if SARIF, delegate to the shared SARIF converter
  registerAllFingerprints();
  const detected = detectConverter(input);
  if (detected && detected.fingerprint.id === 'sarif-to-hdf') {
    return convertSarifToHdf(input, converterVersion);
  }

  const resultsChecksum: Checksum = await inputChecksum(input);

  // Snyk native JSON carries no scan timestamp, so use one conversion-time
  // value for every result's startTime and the document timestamp.
  const scanTime = new Date();

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
    baselines = limitedProjects.map(report => convertSingleProject(report, resultsChecksum, scanTime));
    targetName = limitedProjects[0]?.projectName ?? limitedProjects[0]?.path ?? '';
  } else {
    // Single project
    baselines = [convertSingleProject(parsed, resultsChecksum, scanTime)];
    targetName = parsed.projectName ?? parsed.path ?? '';
  }

  return buildHdfResults({
    generatorName: 'snyk-to-hdf',
    converterVersion,
    toolName: 'Snyk',
    baselines,
    components: [{ name: targetName, type: TargetType.Application }],
    timestamp: scanTime,
  });
}
