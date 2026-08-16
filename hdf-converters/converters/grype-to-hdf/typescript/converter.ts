import {
  type AffectedPackage,
  type Checksum,
  type Component,
  TargetType,
  createMinimalBaseline,
  type Cvss,
  Ecosystem,
  type Epss,
  type EvaluatedBaseline,
  type EvaluatedRequirement,
  type Kev,
  type RequirementResult,
  ResultStatus,
  VerificationMethodEnum,
} from '@mitre/hdf-schema';
import {nistToCci, DEFAULT_STATIC_ANALYSIS_NIST_TAGS} from '@mitre/hdf-mappings';
import {parseJSON, parseTimestamp} from '@mitre/hdf-utilities';
import {inputChecksum, buildNistCciTags, buildNoFindingsRequirement, deriveControlTypeFromTags, digestToChecksums, limitArray, markUnratedSeverity, validateInputSize, buildHdfResults} from '../../../shared/typescript/converterutil.js';
import {buildCvss as buildSharedCvss, cvssVersionFromString} from '../../../shared/typescript/cvss.js';

// Input types for Grype JSON

interface GrypeReport {
  descriptor: GrypeDescriptor;
  source: GrypeSource;
  distro?: GrypeDistro;
  matches: GrypeMatch[];
  ignoredMatches?: GrypeMatch[];
}

interface GrypeDescriptor {
  name: string;
  version: string;
  timestamp?: string;
  configuration?: unknown;
}

interface GrypeSource {
  type?: string;
  target: GrypeTarget;
}

// GrypeTarget mirrors source.target for an image scan. Only userInput is
// guaranteed across scan types (a directory scan emits target as a bare string).
interface GrypeTarget {
  userInput?: string;
  imageID?: string;
  manifestDigest?: string;
  repoDigests?: string[];
  tags?: string[];
  architecture?: string;
  os?: string;
  layers?: GrypeLayer[];
}

interface GrypeLayer {
  digest?: string;
  size?: number;
}

interface GrypeDistro {
  name?: string;
  version?: string;
  idLike?: string[];
}

interface GrypeMatch {
  vulnerability: GrypeVulnerability;
  relatedVulnerabilities?: GrypeRelatedVulnerability[];
  matchDetails: GrypeMatchDetail[];
  artifact: GrypeArtifact;
}

interface GrypeVulnerability {
  id: string;
  dataSource?: string;
  namespace?: string;
  severity?: string;
  urls?: string[];
  description?: string;
  cvss?: GrypeCVSS[];
  fix?: GrypeFix;
  advisories?: unknown[];
  cwe?: string[];
  epss?: GrypeEpssEntry[];
  kev?: GrypeKev;
}

interface GrypeEpssEntry {
  cve?: string;
  epss?: number;
  percentile?: number;
  date?: string;
}

interface GrypeKev {
  inKev?: boolean;
  dateAdded?: string;
  dueDate?: string;
  notes?: string;
}

interface GrypeRelatedVulnerability {
  id: string;
  dataSource?: string;
  namespace?: string;
  severity?: string;
  urls?: string[];
  description?: string;
  cvss?: GrypeCVSS[];
}

interface GrypeCVSS {
  source?: string;
  type?: string;
  version?: string;
  vector?: string;
  metrics?: {
    baseScore?: number;
    exploitabilityScore?: number;
    impactScore?: number;
  };
  vendorMetadata?: unknown;
}

interface GrypeFix {
  versions?: string[];
  state?: string; // "fixed", "unknown", "wontfix", "not-fixed"
}

interface GrypeMatchDetail {
  type?: string; // "exact-direct-match", "exact-indirect-match", "cpe-match"
  matcher?: string;
  searchedBy?: Record<string, unknown>;
  found?: Record<string, unknown>;
}

interface GrypeArtifact {
  id?: string;
  name: string;
  version: string;
  type?: string; // "apk", "rpm", "deb", "npm", "python", etc.
  locations?: GrypeLocation[];
  licenses?: string[];
  language?: string;
  cpes?: string[];
  purl?: string;
  upstreams?: unknown[];
  metadata?: unknown;
}

interface GrypeLocation {
  path?: string;
  layerID?: string;
}

// Severity to impact mapping
const IMPACT_MAPPING: Map<string, number> = new Map([
  ['critical', 0.9],
  ['high', 0.7],
  ['medium', 0.5],
  ['low', 0.3],
  ['negligible', 0.0],
  ['unknown', 0.5],
]);


function getImpact(severity?: string): number {
  if (!severity) {
    return 0.5; // default for unknown
  }
  return IMPACT_MAPPING.get(severity.toLowerCase()) ?? 0.5;
}

function isNegligibleOrUnknown(severity?: string): boolean {
  if (!severity) {
    return true;
  }
  const lower = severity.toLowerCase();
  return lower === 'negligible' || lower === 'unknown';
}

function getDescription(vuln: GrypeVulnerability, relatedVulns?: GrypeRelatedVulnerability[]): string {
  // Use primary vulnerability description if available
  if (vuln.description) {
    return vuln.description;
  }

  // Fall back to related vulnerability with matching ID
  if (relatedVulns) {
    for (const related of relatedVulns) {
      if (related.id === vuln.id && related.description) {
        return related.description;
      }
    }
  }

  return `Vulnerability ${vuln.id}`;
}

function getFixInfo(fix?: GrypeFix): string {
  if (!fix || !fix.state) {
    return 'vulnerability is not known to be fixed in any versions';
  }

  if (fix.state === 'fixed' && fix.versions && fix.versions.length > 0) {
    return `vulnerability is ${fix.state} for versions ${fix.versions.join(', ')}`;
  }

  return `vulnerability is ${fix.state}`;
}

function getCVSSInfo(vuln: GrypeVulnerability, relatedVulns?: GrypeRelatedVulnerability[]): string {
  const cvssData: Record<string, unknown> = {};

  // Collect CVSS from primary vulnerability
  if (vuln.cvss && vuln.cvss.length > 0) {
    cvssData.primary = vuln.cvss;
  }

  // Collect CVSS from related vulnerabilities
  const related = (relatedVulns ?? [])
    .filter(r => r.cvss && r.cvss.length > 0)
    .map(r => ({
      id: r.id,
      dataSource: r.dataSource,
      cvss: r.cvss,
    }));
  if (related.length > 0) {
    cvssData.related = related;
  }

  return JSON.stringify(cvssData);
}

function getReferences(vuln: GrypeVulnerability, relatedVulns?: GrypeRelatedVulnerability[]): string[] {
  const refs = new Set<string>();

  // Add URLs from primary vulnerability
  if (vuln.urls) {
    for (const url of vuln.urls) {
      refs.add(url);
    }
  }

  // Add URLs from related vulnerabilities
  if (relatedVulns) {
    for (const related of relatedVulns) {
      if (related.urls) {
        for (const url of related.urls) {
          refs.add(url);
        }
      }
    }
  }

  return Array.from(refs);
}

function buildCodeDesc(match: GrypeMatch): string {
  const parts: string[] = [];

  // Package info
  parts.push(`Package: ${match.artifact.name}@${match.artifact.version}`);

  // Package type if available
  if (match.artifact.type) {
    parts.push(`Type: ${match.artifact.type}`);
  }

  // Location if available
  if (match.artifact.locations && match.artifact.locations.length > 0) {
    const location = match.artifact.locations[0]!;
    if (location.path) {
      parts.push(`Location: ${location.path}`);
    }
  }

  // Match type if available
  if (match.matchDetails && match.matchDetails.length > 0) {
    const matchType = match.matchDetails[0]!.type;
    if (matchType) {
      parts.push(`Match Type: ${matchType}`);
    }
  }

  return parts.join(' | ');
}

// buildCvssEntries emits one schema Cvss entry per element of
// vulnerability.cvss[]. Related-vulnerability CVSS arrays are NOT merged in;
// the schema contract is "one entry per source-CVE metric set".
function buildCvssEntries(vuln: GrypeVulnerability): Cvss[] | undefined {
  if (!vuln.cvss || vuln.cvss.length === 0) {
    return undefined;
  }
  const entries: Cvss[] = [];
  for (const c of vuln.cvss) {
    const entry = buildSharedCvss({
      version: cvssVersionFromString(c.version),
      baseScore: c.metrics?.baseScore,
      baseVector: c.vector,
      source: vuln.id,
    });
    // An entry with neither vector nor score cannot satisfy the schema anyOf.
    if (entry.baseVector === undefined && entry.baseScore === undefined) {
      continue;
    }
    entries.push(entry);
  }
  return entries.length > 0 ? entries : undefined;
}

// mapGrypeTypeToEcosystem translates Grype artifact.type to schema Ecosystem.
// Anything outside the schema's published enum (apk, binary, future types)
// falls back to "generic".
export function mapGrypeTypeToEcosystem(grypeType?: string): Ecosystem {
  switch ((grypeType ?? '').toLowerCase()) {
    case 'rpm': return Ecosystem.RPM;
    case 'deb': return Ecosystem.Deb;
    case 'npm': return Ecosystem.Npm;
    case 'python': return Ecosystem.Pypi;
    case 'gem': return Ecosystem.Gem;
    case 'go-module': return Ecosystem.Go;
    case 'java-archive':
    case 'jenkins-plugin':
      return Ecosystem.Maven;
    case 'dotnet': return Ecosystem.Nuget;
    case 'rust-crate': return Ecosystem.Cargo;
    default: return Ecosystem.Generic;
  }
}

// buildAffectedPackages produces a single AffectedPackage from match.artifact.
// First cpes[] element is taken (Grype lists alias-generator variants; the
// first matches the package's canonical vendor:product identity).
function buildAffectedPackages(match: GrypeMatch): AffectedPackage[] {
  const artifact = match.artifact;
  const pkg: AffectedPackage = {
    name: artifact.name,
    version: artifact.version,
    ecosystem: mapGrypeTypeToEcosystem(artifact.type),
  };
  if (artifact.cpes && artifact.cpes.length > 0 && artifact.cpes[0]) {
    pkg.cpe = artifact.cpes[0];
  }
  if (artifact.purl) {
    pkg.purl = artifact.purl;
  }
  const fix = match.vulnerability.fix;
  if (fix && fix.state === 'fixed' && fix.versions && fix.versions.length > 0 && fix.versions[0]) {
    pkg.fixedInVersion = fix.versions[0];
  }
  return [pkg];
}

// Valid canonical CWE-N identifier (MITRE catalog convention: no leading zeros).
const CWE_ID_PATTERN = /^CWE-[1-9]\d*$/;

// extractCwe filters Grype's vulnerability.cwe[] to valid CWE-N entries.
// Malformed entries are dropped silently — the schema layer would reject them.
function extractCwe(raw?: string[]): string[] | undefined {
  if (!raw || raw.length === 0) return undefined;
  const out = raw.filter(c => CWE_ID_PATTERN.test(c));
  return out.length === 0 ? undefined : out;
}

// buildEpss picks the most-recent entry from vulnerability.epss[]. Grype's
// array is typically ordered newest-first; we trust that and take index 0.
function buildEpss(entries?: GrypeEpssEntry[]): Epss | undefined {
  if (!entries || entries.length === 0) return undefined;
  const e = entries[0]!;
  if (!e.date) return undefined;
  return {
    score: e.epss ?? 0,
    percentile: e.percentile ?? 0,
    // format: date (YYYY-MM-DD) string; quicktype types it as Date.
    date: e.date as unknown as Date,
  };
}

// buildKev maps Grype's vulnerability.kev block to the schema Kev primitive.
function buildKev(k?: GrypeKev): Kev | undefined {
  if (!k) return undefined;
  const out: Kev = {inKev: Boolean(k.inKev)};
  // format: date (YYYY-MM-DD) strings; quicktype types them as Date.
  if (k.dateAdded) out.dateAdded = k.dateAdded as unknown as Date;
  if (k.dueDate) out.dueDate = k.dueDate as unknown as Date;
  if (k.notes) out.notes = k.notes;
  return out;
}

function convertMatchToRequirement(match: GrypeMatch, isIgnored: boolean, targetName: string, startTime: Date): EvaluatedRequirement {
  const vuln = match.vulnerability;
  const cveId = vuln.id;
  const severity = vuln.severity;
  const impact = getImpact(severity);
  const description = getDescription(vuln, match.relatedVulnerabilities);
  const fixInfo = getFixInfo(vuln.fix);
  const cvssInfo = getCVSSInfo(vuln, match.relatedVulnerabilities);
  const refs = getReferences(vuln, match.relatedVulnerabilities);

  // Determine status. Severity never changes it (unknown-severity
  // convention): a detected vulnerability is failed regardless of rating
  // confidence; only the ignore-rules triage axis differs.
  let status: ResultStatus;
  if (isIgnored) {
    status = ResultStatus.NotReviewed; // Ignored by configured rules
  } else {
    status = ResultStatus.Failed;
  }

  // Build result message
  const messageParts: string[] = [];
  if (isIgnored) {
    messageParts.push('This vulnerability was ignored by configured rules.');
  }
  if (isNegligibleOrUnknown(severity) && !isIgnored) {
    messageParts.push(
      'Manual review required because a Grype rating severity is set to `negligible` or `unknown`.'
    );
  }
  messageParts.push(`Severity: ${severity || 'unknown'}`);
  messageParts.push(fixInfo);
  const message = messageParts.join(' ');

  // Build execution result
  const result: RequirementResult = {
    status,
    codeDesc: buildCodeDesc(match),
    message,
    startTime,
  };

  // Get CCI mappings for NIST controls using curated mapping table
  const cciTags = nistToCci(DEFAULT_STATIC_ANALYSIS_NIST_TAGS);

  // Build tags object - only include cci if not empty
  const tags = buildNistCciTags(DEFAULT_STATIC_ANALYSIS_NIST_TAGS, cciTags);
  markUnratedSeverity(tags, severity);

  // Build requirement. Grype carries no literal source snippet, so code holds
  // the whole match serialized as indented JSON (byte-identical to the Go twin's
  // json.Indent output — same source key order, same fields).
  const requirement: EvaluatedRequirement = {
    id: isIgnored ? `Grype-Ignored-Match/${cveId}` : `Grype/${cveId}`,
    title: `Grype found a vulnerability to ${cveId} in ${targetName}`,
    impact,
    code: JSON.stringify(match, null, 2),
    results: [result],
    tags,
    descriptions: [
      {label: 'default', data: description},
      {label: 'fix', data: fixInfo},
      {label: 'check', data: cvssInfo},
    ],
    refs: refs.length > 0 ? refs.map(url => ({url})) : undefined,
    verificationMethod: VerificationMethodEnum.Automated,
  };

  const controlType = deriveControlTypeFromTags(DEFAULT_STATIC_ANALYSIS_NIST_TAGS);
  if (controlType !== undefined) {
    requirement.controlType = controlType;
  }

  // Structured CVE-ecosystem fields (omit when empty/absent so output stays
  // tight; the schema treats all five as optional).
  const cvss = buildCvssEntries(vuln);
  if (cvss) requirement.cvss = cvss;
  requirement.affectedPackages = buildAffectedPackages(match);
  const cwe = extractCwe(vuln.cwe);
  if (cwe) requirement.cwe = cwe;
  const epss = buildEpss(vuln.epss);
  if (epss) requirement.epss = epss;
  const kev = buildKev(vuln.kev);
  if (kev) requirement.kev = kev;

  return requirement;
}

// buildComponent surfaces the scan target's identity into a top-level HDF
// component. An image scan yields a containerImage component carrying the image
// digest, id, and distro OS; anything without image identity (e.g. a directory
// scan) falls back to a bare artifact component named for the scan target.
function buildComponent(report: GrypeReport, targetName: string): Component {
  const t = report.source?.target;
  const firstRepoDigest = t?.repoDigests?.find(d => d);
  const firstTag = t?.tags?.find(tag => tag);
  const isImage = Boolean(t && (t.imageID || t.manifestDigest || firstRepoDigest || firstTag));
  if (!t || !isImage) {
    return {name: targetName, type: TargetType.Artifact};
  }

  const name = firstRepoDigest || firstTag || t.imageID || targetName;
  const component: Component = {name, type: TargetType.ContainerImage};
  if (t.imageID) component.imageId = t.imageID;
  // Image the container was started from: a repoDigest pins it exactly; a tag
  // is the fallback when the scan carries no repoDigest.
  const image = firstRepoDigest || firstTag;
  if (image) component.image = image;
  if (report.distro?.name) component.osName = report.distro.name;
  if (report.distro?.version) component.osVersion = report.distro.version;
  const integrity = digestToChecksums(t.manifestDigest);
  if (integrity) component.integrity = integrity;
  if (t.architecture) component.labels = {architecture: t.architecture};
  return component;
}

export async function convertGrypeToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  validateInputSize(input, 'grype');
  // Calculate checksum of input data
  const resultsChecksum: Checksum = await inputChecksum(input);

  // Parse Grype JSON
  const grypeData = parseJSON<GrypeReport>(input);

  // Build requirements from matches
  const requirements: EvaluatedRequirement[] = [];

  // Build baseline name from source.
  const targetName = grypeData.source?.target?.userInput || 'Grype Scan';

  // The scan timestamp anchors every result's start_time; a Go zero-time Date is
  // the schema-safe fallback when Grype omits descriptor.timestamp.
  const scanTime = grypeData.descriptor?.timestamp ? parseTimestamp(grypeData.descriptor.timestamp) : null;
  const resultStart = scanTime ?? new Date('0001-01-01T00:00:00Z');

  // Process regular matches
  if (grypeData.matches && grypeData.matches.length > 0) {
    const { items: limitedMatches, truncated: truncatedMatches } = limitArray(grypeData.matches);
    /* v8 ignore next -- truncation only triggers with >100K items */
    if (truncatedMatches) {
      // eslint-disable-next-line no-console
      console.warn(`WARNING: Input truncated at ${limitedMatches.length} match items (original: ${grypeData.matches.length})`);
    }
    for (const match of limitedMatches) {
      requirements.push(convertMatchToRequirement(match, false, targetName, resultStart));
    }
  }

  // Process ignored matches
  if (grypeData.ignoredMatches && grypeData.ignoredMatches.length > 0) {
    const { items: limitedIgnored, truncated: truncatedIgnored } = limitArray(grypeData.ignoredMatches);
    /* v8 ignore next -- truncation only triggers with >100K items */
    if (truncatedIgnored) {
      // eslint-disable-next-line no-console
      console.warn(`WARNING: Input truncated at ${limitedIgnored.length} ignoredMatch items (original: ${grypeData.ignoredMatches.length})`);
    }
    for (const match of limitedIgnored) {
      requirements.push(convertMatchToRequirement(match, true, targetName, resultStart));
    }
  }

  if (requirements.length === 0) {
    requirements.push(buildNoFindingsRequirement(
      'grype-no-findings',
      `Grype scanned ${targetName} and reported zero vulnerable components.`,
      new Date(),
    ));
  }

  // Create baseline
  const baseline: EvaluatedBaseline = createMinimalBaseline(targetName, requirements, {
    resultsChecksum,
  }) as EvaluatedBaseline;

  // Build HDF results
  return buildHdfResults({
    generatorName: 'grype-to-hdf',
    converterVersion,
    toolName: 'Grype',
    toolVersion: grypeData.descriptor?.version,
    baselines: [baseline],
    components: [buildComponent(grypeData, targetName)],
    // Match the Go peer: omit the top-level timestamp when Grype provides none,
    // rather than fabricating a non-deterministic wall-clock value.
    timestamp: scanTime ?? undefined,
  });
}
