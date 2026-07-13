import { parseJSON, cvssScoreToSeverity, parseTimestamp } from '@mitre/hdf-utilities';
import {
  nistToCci,
  DEFAULT_REMEDIATION_NIST_TAGS,
} from '@mitre/hdf-mappings';
import { buildNoFindingsRequirement, deriveControlTypeFromTags, inputChecksum, limitArray, buildNistCciTags, validateInputSize, buildHdfResults } from '../../../shared/typescript/converterutil.js';
import type {
  EvaluatedBaseline,
  EvaluatedRequirement,
  Checksum,
  Cvss,
  AffectedPackage,
  RequirementResult,
  Component,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  createResult,
  TargetType,
  VerificationMethodEnum,
  CVSSSeverity,
  Ecosystem,
  Version as CvssVersion,
  createMinimalBaseline,
  createRequirement,
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
  distroRelease?: string;
  collections?: string[];
  packages?: TwistlockPackage[];
  vulnerabilities?: TwistlockVuln[] | null;
  vulnerabilityDistribution?: TwistlockDistribution;
  complianceDistribution?: TwistlockDistribution;
}

interface TwistlockPackage {
  type?: string;
  name?: string;
  version?: string;
}

interface TwistlockVuln {
  id: string;
  cve?: string;
  status?: string;
  cvss?: number;
  vector?: string;
  description: string;
  severity: string;
  packageName?: string;
  packageVersion?: string;
  packageType?: string;
  cwe?: string;
  link?: string;
  fixedBy?: string;
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
 * Detects CVSS schema version enum from the vector prefix. Defaults to 3.1
 * since modern Twistlock exclusively emits 3.x output.
 */
export function cvssVersionFromVector(vector: string | undefined): CvssVersion {
  if (!vector) return CvssVersion.The31;
  if (vector.startsWith('CVSS:2.0/')) return CvssVersion.The20;
  if (vector.startsWith('CVSS:3.0/')) return CvssVersion.The30;
  if (vector.startsWith('CVSS:4.0/')) return CvssVersion.The40;
  return CvssVersion.The31;
}

/**
 * Maps cvssScoreToSeverity('low'|'medium'|...) into the CVSSSeverity enum.
 */
export function cvssSeverityFromScore(score: number): CVSSSeverity | undefined {
  const band = cvssScoreToSeverity(score);
  switch (band) {
    case 'none': return CVSSSeverity.None;
    case 'low': return CVSSSeverity.Low;
    case 'medium': return CVSSSeverity.Medium;
    case 'high': return CVSSSeverity.High;
    case 'critical': return CVSSSeverity.Critical;
    default: return undefined;
  }
}

/**
 * Builds a Cvss entry from a Twistlock vulnerability. Returns undefined only
 * when neither a score nor a vector is available. When the vendor emits a
 * score but no vector (common in Twistlock/Prisma Cloud output), the Cvss
 * entry is still emitted — the schema makes baseVector optional precisely
 * so vendor-final-score data isn't dropped.
 */
export function buildCvss(vuln: TwistlockVuln): Cvss | undefined {
  // 0.0 is a valid CVSS score ("none"); only treat a non-numeric/non-finite
  // value as "no score". A missing score is omitted, never coerced to 0.
  const hasScore = typeof vuln.cvss === 'number' && Number.isFinite(vuln.cvss);
  const hasVector = !!vuln.vector;
  if (!hasScore && !hasVector) return undefined;

  const cv: Cvss = {version: cvssVersionFromVector(vuln.vector)};
  if (hasScore) {
    cv.baseScore = vuln.cvss as number;
    const sev = cvssSeverityFromScore(vuln.cvss as number);
    if (sev !== undefined) cv.baseSeverity = sev;
  }
  if (hasVector) {
    cv.baseVector = vuln.vector as string;
  }
  const source = vuln.cve ?? vuln.id;
  if (source) cv.source = source;
  return cv;
}

const CWE_REGEX = /cwe[-_]?(\d+)/gi;

/**
 * Extracts canonical CWE-N identifiers from a free-form string.
 */
export function parseCwes(raw: string | undefined): string[] {
  if (!raw) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const m of raw.matchAll(CWE_REGEX)) {
    const id = `CWE-${m[1]}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(id);
  }
  return out;
}

function rhelDistro(distro: string): boolean {
  const low = distro.toLowerCase();
  return ['red hat', 'rhel', 'centos', 'fedora', 'amazon linux', 'oracle linux', 'rocky', 'alma']
    .some(m => low.includes(m));
}

function debDistro(distro: string): boolean {
  const low = distro.toLowerCase();
  return ['debian', 'ubuntu'].some(m => low.includes(m));
}

/**
 * Maps a Twistlock package type plus the result's distro string to a schema
 * Ecosystem value. Defaults to 'generic' for unknown types.
 */
export function resolveEcosystem(packageType: string | undefined, distro: string | undefined): Ecosystem {
  const t = (packageType ?? '').toLowerCase();
  const d = distro ?? '';
  switch (t) {
    case 'os':
      if (rhelDistro(d)) return Ecosystem.RPM;
      if (debDistro(d)) return Ecosystem.Deb;
      return Ecosystem.Generic;
    case 'rpm': return Ecosystem.RPM;
    case 'deb': return Ecosystem.Deb;
    case 'jar':
    case 'maven': return Ecosystem.Maven;
    case 'python':
    case 'pypi': return Ecosystem.Pypi;
    case 'nodejs':
    case 'npm': return Ecosystem.Npm;
    case 'gem': return Ecosystem.Gem;
    case 'nuget': return Ecosystem.Nuget;
    case 'go': return Ecosystem.Go;
    case 'cargo': return Ecosystem.Cargo;
    default: return Ecosystem.Generic;
  }
}

const FIX_VERSION_REGEX = /\d+(?:\.\d+)+[A-Za-z0-9._+\-]*/;

/**
 * Extracts the first version-looking token from fixedBy or a "fixed in X"
 * status string. Returns empty string when no fix info is present.
 */
export function extractFixedInVersion(vuln: TwistlockVuln): string {
  if (vuln.fixedBy) return vuln.fixedBy;
  const status = (vuln.status ?? '').toLowerCase();
  if (!status.includes('fixed')) return '';
  const m = (vuln.status ?? '').match(FIX_VERSION_REGEX);
  return m ? m[0] : '';
}

/**
 * Builds an AffectedPackage entry from per-vulnerability fields. Returns
 * undefined when packageName or packageVersion are missing (both required).
 */
export function buildAffectedPackage(
  vuln: TwistlockVuln,
  packageTypes: Map<string, string>,
  distro: string | undefined,
): AffectedPackage | undefined {
  if (!vuln.packageName || !vuln.packageVersion) return undefined;
  const pkgType = vuln.packageType ?? packageTypes.get(vuln.packageName);
  const pkg: AffectedPackage = {
    name: vuln.packageName,
    version: vuln.packageVersion,
    ecosystem: resolveEcosystem(pkgType, distro),
  };
  const fixed = extractFixedInVersion(vuln);
  if (fixed) pkg.fixedInVersion = fixed;
  return pkg;
}

/**
 * Indexes packageName → packageType from the result-level packages array.
 */
function buildPackageTypeIndex(pkgs: TwistlockPackage[] | undefined): Map<string, string> {
  const idx = new Map<string, string>();
  if (!pkgs) return idx;
  for (const p of pkgs) {
    if (p.name && p.type) idx.set(p.name, p.type);
  }
  return idx;
}

/**
 * Builds the code_desc string for a vulnerability result.
 */
function formatCodeDesc(vuln: TwistlockVuln): string {
  const packageName = vuln.packageName ?? 'N/A';
  const impactedVersions = vuln.impactedVersions && vuln.impactedVersions.length > 0
    ? `[${vuln.impactedVersions.join(' ')}]`
    : 'N/A';
  return `Package ${JSON.stringify(packageName)} should be updated to latest version above impacted versions ${impactedVersions}`;
}

/**
 * Converts a single vulnerability into an EvaluatedRequirement.
 *
 * @param vuln - The Twistlock vulnerability object
 * @param packageTypes - name→type lookup built from the enclosing result's packages array
 * @param distro - the enclosing result's distro string, used to disambiguate "os" packages
 */
function buildRequirement(
  vuln: TwistlockVuln,
  packageTypes: Map<string, string>,
  distro: string | undefined,
): EvaluatedRequirement {
  const nist = DEFAULT_REMEDIATION_NIST_TAGS;
  const cciTags = nistToCci(nist);

  const extras: Record<string, unknown> = { cveid: [vuln.id] };
  // Legacy: retain the cvss_base_score tag for one release so existing
  // downstream queries keep working. Marked for removal in v3.4.0 (see
  // CHANGELOG note in epic hdf-libs-8zn0).
  if (typeof vuln.cvss === 'number' && vuln.cvss > 0) {
    extras['cvss_base_score'] = vuln.cvss;
  }

  const tags = buildNistCciTags(nist, cciTags, extras);

  const descriptions: Description[] = [
    { label: 'default', data: vuln.description },
  ];

  const startTime = (vuln.discoveredDate ? parseTimestamp(vuln.discoveredDate) : null) ?? new Date('0001-01-01T00:00:00Z');

  const results: RequirementResult[] = [
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

  const cv = buildCvss(vuln);
  if (cv) req.cvss = [cv];
  const cwes = parseCwes(vuln.cwe);
  if (cwes.length > 0) req.cwe = cwes;
  const pkg = buildAffectedPackage(vuln, packageTypes, distro);
  if (pkg) req.affectedPackages = [pkg];

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

  const packageTypes = buildPackageTypeIndex(result.packages);
  const requirements: EvaluatedRequirement[] = limitedVulns.map(vuln =>
    buildRequirement(vuln, packageTypes, result.distro)
  );

  if (requirements.length === 0) {
    const target = result.name ?? result.repository ?? result.id ?? 'scan target';
    requirements.push(buildNoFindingsRequirement(
      'twistlock-no-findings',
      `Twistlock scanned ${target} and reported zero vulnerable components.`,
      new Date(),
    ));
  }

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
export async function convertTwistlockToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
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

  // Code-repo scans carry no image id, so there is no image label to attach.
  const component: Component = { name: targetName, type: TargetType.ContainerImage };
  const imageID = results[0]!.id;
  if (imageID) {
    component.labels = { image: imageID };
  }

  return buildHdfResults({
    generatorName: 'twistlock-to-hdf',
    converterVersion,
    toolName: 'Twistlock',
    toolFormat: 'JSON',
    baselines,
    components: [component],
    timestamp: new Date(),
  });
}
