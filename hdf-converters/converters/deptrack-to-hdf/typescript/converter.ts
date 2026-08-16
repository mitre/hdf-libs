import { parseJSON, parsePurl, parseTimestamp } from '@mitre/hdf-utilities';
import {
  nistToCci,
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
} from '@mitre/hdf-mappings';
import { buildAffectedPackage, buildNoFindingsRequirement, deriveControlTypeFromTags, ecosystemFromPurlType, inputChecksum, mapCWEToNIST, validateInputSize, buildHdfResults } from '../../../shared/typescript/converterutil.js';
import { buildCvss } from '../../../shared/typescript/cvss.js';
import type {
  EvaluatedBaseline,
  EvaluatedRequirement,
  Checksum,
  RequirementResult,
  Cvss,
  Epss,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  createResult,
  TargetType,
  VerificationMethodEnum,
  Version as CvssVersion,
  createMinimalBaseline,
  createRequirement,
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
  aliases?: DeptrackAlias[];
  cvssV2BaseScore?: number;
  cvssV3BaseScore?: number;
  epssScore?: number;
  epssPercentile?: number;
}

interface DeptrackCwe {
  cweId: number;
  name: string;
}

/**
 * A cross-reference to the same vulnerability under another naming scheme.
 * Dependency-Track's finding.matrix (the requirement id) is a UUID composite,
 * not the CVE, so aliases[].cveId is where the CVE identifier lives.
 */
interface DeptrackAlias {
  cveId?: string;
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
 * Collects CVE identifiers from vulnerability.aliases[].cveId, deduped in
 * first-seen order. The finding.matrix (requirement id) is a UUID composite, so
 * the CVE has no other home; it goes to tags.cve (interim, pending an
 * identifiers[] schema field).
 */
function getCVEs(vuln: DeptrackVulnerability): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const alias of vuln.aliases ?? []) {
    if (alias.cveId && !seen.has(alias.cveId)) {
      seen.add(alias.cveId);
      out.push(alias.cveId);
    }
  }
  return out;
}

/**
 * Extracts the human-readable CWE names from the cwes array, mirroring the
 * heimdall2 cweNames tag.
 */
function getCweNames(cwes: DeptrackCwe[] | undefined): string[] {
  if (!cwes || cwes.length === 0) {
    return [];
  }
  return cwes.map(cwe => cwe.name);
}

/**
 * Returns the CVE identifier a finding is attributed to. When the NVD-sourced
 * vulnId is itself a CVE it is authoritative; otherwise the first aliased CVE
 * stands in. Used as the cvss[].source. Returns undefined when no CVE is present.
 */
function resolveCVE(vuln: DeptrackVulnerability): string | undefined {
  if (vuln.vulnId?.startsWith('CVE-')) {
    return vuln.vulnId;
  }
  const cves = getCVEs(vuln);
  return cves.length > 0 ? cves[0] : undefined;
}

/**
 * Assembles structured requirement.cvss[] entries from the score-only CVSS
 * metrics Dependency-Track carries. The FPF exposes no vector, so each entry is
 * a bare base score under its major version (v3 → 3.1, the version modern
 * Dependency-Track computes; v2 → 2.0). The v3 entry leads when both are present.
 */
function buildCvssEntries(vuln: DeptrackVulnerability): Cvss[] {
  const source = resolveCVE(vuln);
  const entries: Cvss[] = [];
  if (typeof vuln.cvssV3BaseScore === 'number') {
    entries.push(buildCvss({ version: CvssVersion.The31, baseScore: vuln.cvssV3BaseScore, source }));
  }
  if (typeof vuln.cvssV2BaseScore === 'number') {
    entries.push(buildCvss({ version: CvssVersion.The20, baseScore: vuln.cvssV2BaseScore, source }));
  }
  return entries;
}

/**
 * Assembles a structured requirement.epss entry from the EPSS probability and
 * percentile Dependency-Track carries. The FPF omits the EPSS publication date
 * the schema requires, so it is sourced from the scan time (meta.timestamp) in
 * YYYY-MM-DD form. Returns undefined when the finding carries neither EPSS field.
 */
function buildEpss(vuln: DeptrackVulnerability, timestamp: string | undefined): Epss | undefined {
  if (typeof vuln.epssScore !== 'number' && typeof vuln.epssPercentile !== 'number') {
    return undefined;
  }
  return {
    // format: date (YYYY-MM-DD) string; quicktype types it as Date.
    date: epssDate(timestamp) as unknown as Date,
    score: typeof vuln.epssScore === 'number' ? vuln.epssScore : 0,
    percentile: typeof vuln.epssPercentile === 'number' ? vuln.epssPercentile : 0,
  };
}

/**
 * Renders the scan time as YYYY-MM-DD, falling back to today's date when
 * meta.timestamp is absent or unparseable.
 */
function epssDate(timestamp: string | undefined): string {
  const parsed = timestamp ? parseTimestamp(timestamp) : null;
  return (parsed ?? new Date()).toISOString().slice(0, 10);
}

/**
 * Builds a single EvaluatedRequirement from a Dependency-Track finding.
 */
function buildRequirement(finding: DeptrackFinding, timestamp: string | undefined): EvaluatedRequirement {
  const cweIDs = getCweIDs(finding.vulnerability.cwes);
  const cveIDs = getCVEs(finding.vulnerability);
  const nist = mapCWEToNIST(cweIDs, DEFAULT_STATIC_ANALYSIS_NIST_TAGS);
  const cciTags = nistToCci(nist);

  const vuln = finding.vulnerability;
  const tags: Record<string, unknown> = {
    nist,
    cci: cciTags,
  };

  if (cveIDs.length > 0) {
    tags['cve'] = cveIDs;
  }
  // Typed source attributes heimdall2 surfaces as tags. These also live in
  // requirement.code (the raw finding), but tagging makes them searchable.
  if (vuln.uuid) {
    tags['vulnerabilityUuid'] = vuln.uuid;
  }
  if (vuln.source) {
    tags['vulnerabilitySource'] = vuln.source;
  }
  if (vuln.vulnId) {
    tags['vulnerabilityVulnId'] = vuln.vulnId;
  }
  if (vuln.subtitle) {
    tags['vulnerabilitySubtitle'] = vuln.subtitle;
  }
  if (typeof vuln.severityRank === 'number') {
    tags['vulnerabilitySeverityRank'] = vuln.severityRank;
  }
  const cweNames = getCweNames(vuln.cwes);
  if (cweNames.length > 0) {
    tags['cweNames'] = cweNames;
  }
  const attribution = finding.attribution;
  if (attribution) {
    if (attribution.analyzerIdentity) {
      tags['attributionAnalyzerIdentity'] = attribution.analyzerIdentity;
    }
    if (attribution.attributedOn) {
      tags['attributionAttributedOn'] = attribution.attributedOn;
    }
    if (attribution.alternateIdentifier) {
      tags['attributionAlternateIdentifier'] = attribution.alternateIdentifier;
    }
    if (attribution.referenceUrl) {
      tags['attributionReferenceUrl'] = attribution.referenceUrl;
    }
  }
  const analysis = finding.analysis;
  if (analysis) {
    if (analysis.state) {
      tags['analysisState'] = analysis.state;
    }
    tags['analysisIsSuppressed'] = analysis.isSuppressed ?? false;
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

  const results: RequirementResult[] = [
    createResult(ResultStatus.Failed, undefined, {
      codeDesc,
      startTime: (timestamp ? parseTimestamp(timestamp) : null) ?? new Date('0001-01-01T00:00:00Z'),
    }),
  ];

  const req = createRequirement(
    finding.matrix,
    getTitle(finding),
    descriptions,
    getImpact(finding.vulnerability.severity),
    results,
    { tags },
  ) as EvaluatedRequirement;
  req.verificationMethod = VerificationMethodEnum.Automated;

  // Dependency-Track carries no literal source snippet, so code holds the whole
  // finding serialized as indented JSON (byte-identical to the Go twin's
  // json.Indent output). This preserves every field the typed interfaces drop
  // (aliases, epssScore, source, vulnId) for the Heimdall CODE tab.
  req.code = JSON.stringify(finding, null, 2);

  const controlType = deriveControlTypeFromTags(nist);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }

  if (cweIDs.length > 0) {
    req.cwe = cweIDs;
  }

  const cvss = buildCvssEntries(vuln);
  if (cvss.length > 0) {
    req.cvss = cvss;
  }
  const epss = buildEpss(vuln, timestamp);
  if (epss) {
    req.epss = epss;
  }

  const pkg = buildAffectedPackageFromComponent(finding.component);
  if (pkg) {
    req.affectedPackages = [pkg];
  }

  return req;
}

/**
 * Builds an Affected_Package from a Dependency-Track component. Prefers
 * the rich identifiers Dependency-Track already exposes (purl, cpe) and
 * augments with name/version/ecosystem when available. Returns undefined
 * when the component carries no schema-acceptable identifier.
 */
function buildAffectedPackageFromComponent(c: DeptrackComponent): ReturnType<typeof buildAffectedPackage> {
  // Derive ecosystem from the purl scheme when possible; falls back to
  // generic so the name+version+ecosystem branch stays valid for
  // components Dependency-Track left without a purl.
  let ecosystem;
  if (c.purl) {
    const parsed = parsePurl(c.purl);
    ecosystem = ecosystemFromPurlType(parsed?.type);
  } else if (c.name && c.version) {
    ecosystem = ecosystemFromPurlType(undefined);
  }
  return buildAffectedPackage({
    name: c.name,
    version: c.version,
    ecosystem,
    purl: c.purl,
    cpe: c.cpe,
    fixedInVersion: c.latestVersion,
  });
}

/**
 * Converts Dependency-Track FPF JSON output to HDF format.
 *
 * @param input - Dependency-Track FPF JSON string
 * @returns HDF JSON string
 */
export async function convertDeptrackToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
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

  if (requirements.length === 0) {
    const projectName = parsed.project?.name ?? parsed.project?.uuid ?? '';
    requirements.push(buildNoFindingsRequirement(
      'deptrack-no-findings',
      `Dependency-Track analyzed ${projectName} and reported zero vulnerable components.`,
      new Date(),
    ));
  }

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

  // Top-level timestamp is the scan time from meta.timestamp (source-derived, so
  // converting the same input twice is deterministic). Fall back to wall-clock
  // only when the source omits it or it is unparseable.
  const docTimestamp = (parsed.meta?.timestamp ? parseTimestamp(parsed.meta.timestamp) : null) ?? new Date();

  return buildHdfResults({
    generatorName: 'deptrack-to-hdf',
    converterVersion,
    toolName: 'Dependency-Track',
    toolFormat: 'FPF',
    baselines: [baseline],
    components: [{ name: targetName, type: TargetType.Application }],
    timestamp: docTimestamp,
  });
}
