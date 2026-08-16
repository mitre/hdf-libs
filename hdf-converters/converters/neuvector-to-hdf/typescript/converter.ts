import { parseJSON, roundImpact } from '@mitre/hdf-utilities';
import {
  nistToCci,
  DEFAULT_REMEDIATION_NIST_TAGS,
} from '@mitre/hdf-mappings';
import { buildAffectedPackage, buildNoFindingsRequirement, deriveControlTypeFromTags, digestToChecksums, inputChecksum, limitArray, mapCWEToNIST, extractCWEIDs, validateInputSize, buildHdfResults } from '../../../shared/typescript/converterutil.js';
import { buildCvss, cvssVersionFromVector, cvssVersionFromString } from '../../../shared/typescript/cvss.js';
import { Ecosystem } from '@mitre/hdf-schema';
import type {
  Component,
  Cvss,
  EvaluatedBaseline,
  EvaluatedRequirement,
  Checksum,
  Reference,
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
  cmds?: string[];
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
  cves?: NeuVectorModuleCVE[];
}

interface NeuVectorModuleCVE {
  name: string;
  status: string;
}

/**
 * Indexes report.modules so a flat vulnerability can recover its package
 * `source` and per-CVE `status` (the flat vulnerabilities[] entries omit both).
 * A vuln matches a module by package_name; its status matches the module CVE by
 * name. First non-empty value per key wins.
 */
class ModuleLookup {
  private readonly sourceByName = new Map<string, string>();
  private readonly statusByKey = new Map<string, string>();

  constructor(modules: NeuVectorScanModule[]) {
    for (const m of modules) {
      if (m.source && !this.sourceByName.has(m.name)) {
        this.sourceByName.set(m.name, m.source);
      }
      for (const c of m.cves ?? []) {
        if (!c.status) {
          continue;
        }
        const key = `${m.name}\u0000${c.name}`;
        if (!this.statusByKey.has(key)) {
          this.statusByKey.set(key, c.status);
        }
      }
    }
  }

  source(vuln: NeuVectorVuln): string | undefined {
    return this.sourceByName.get(vuln.package_name);
  }

  status(vuln: NeuVectorVuln): string | undefined {
    return this.statusByKey.get(`${vuln.package_name}\u0000${vuln.name}`);
  }
}

/**
 * Extracts CWE identifiers from a vulnerability description string.
 * Returns CWE-prefixed IDs (e.g., ["CWE-444"]) for use in tags and mapCWEToNIST.
 */
function extractCWEs(description: string): string[] {
  return extractCWEIDs(description).map(id => `CWE-${id}`);
}

/**
 * Collects the distinct CVE identifiers a vulnerability carries in its cves[]
 * field, preserving first-seen order. The requirement ID is a
 * name/package/version composite (not the CVE), so tags.cve is where the CVE
 * list lives.
 */
function extractCVEs(vuln: NeuVectorVuln): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const cve of vuln.cves ?? []) {
    if (cve && !seen.has(cve)) {
      seen.add(cve);
      out.push(cve);
    }
  }
  return out;
}

/**
 * Assembles the structured requirement.cvss[] from the scoring a vulnerability
 * carries. NeuVector emits a CVSS v3 vector (version-prefixed) and, separately,
 * a legacy v2 vector (prefix-less). The v3 metric is preferred; the v2 metric
 * is the fallback. A vulnerability with neither vector contributes no entry —
 * its score still drives impact.
 */
function buildCvssEntries(vuln: NeuVectorVuln): Cvss[] {
  if (vuln.vectors_v3) {
    return [buildCvss({
      version: cvssVersionFromVector(vuln.vectors_v3),
      baseScore: vuln.score_v3 > 0 ? vuln.score_v3 : undefined,
      baseVector: vuln.vectors_v3,
      source: 'NeuVector',
    })];
  }
  if (vuln.vectors) {
    return [buildCvss({
      version: cvssVersionFromString('2.0'),
      baseScore: vuln.score > 0 ? vuln.score : undefined,
      baseVector: vuln.vectors,
      source: 'NeuVector',
    })];
  }
  return [];
}

/**
 * Computes the HDF impact from NeuVector CVSS scores.
 * Prefers CVSS v3 score; falls back to CVSS v2 if v3 is 0.
 * Impact is normalized to 0.0-1.0 by dividing by 10.
 */
function getImpact(vuln: NeuVectorVuln): number {
  if (vuln.score_v3 > 0) {
    return roundImpact(vuln.score_v3 / 10);
  }
  if (vuln.score > 0) {
    return roundImpact(vuln.score / 10);
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

// Collapses runs of ASCII whitespace to a single space; spelled out (not \s)
// so Go and TS collapse identically.
const WHITESPACE_RUN = /[ \t\n\r]+/g;
const CODE_DESC_SNIPPET_RUNES = 100;

/**
 * Returns the CVSS score used in code_desc: CVSS v3 preferred, else v2.
 */
function cvssScore(vuln: NeuVectorVuln): number {
  return vuln.score_v3 > 0 ? vuln.score_v3 : vuln.score;
}

/**
 * Collapses the description to a single line and truncates it to
 * CODE_DESC_SNIPPET_RUNES code points (Array.from matches Go's []rune).
 */
function descSnippet(description: string): string {
  const collapsed = description.replace(WHITESPACE_RUN, ' ').trim();
  const runes = Array.from(collapsed);
  return runes.length > CODE_DESC_SNIPPET_RUNES
    ? runes.slice(0, CODE_DESC_SNIPPET_RUNES).join('') + '…'
    : collapsed;
}

/**
 * Builds the pipe-joined result code_desc from the fields the vuln carries:
 * package@version | name | CVSS score | description snippet. Only parts the
 * source actually provides are included.
 */
function buildCodeDesc(vuln: NeuVectorVuln): string {
  const parts: string[] = [];
  if (vuln.package_name) {
    parts.push(vuln.package_version ? `${vuln.package_name}@${vuln.package_version}` : vuln.package_name);
  }
  if (vuln.name) {
    parts.push(vuln.name);
  }
  const score = cvssScore(vuln);
  if (score > 0) {
    parts.push(`CVSS ${score}`);
  }
  const snippet = descSnippet(vuln.description);
  if (snippet) {
    parts.push(snippet);
  }
  return parts.join(' | ');
}

/**
 * Emits a single external Reference for the vulnerability's advisory link.
 * Returns undefined when the source carries no link so refs[] is omitted.
 */
function buildRefs(vuln: NeuVectorVuln): Reference[] | undefined {
  if (!vuln.link) {
    return undefined;
  }
  return [{ url: vuln.link }];
}

/**
 * Builds a single EvaluatedRequirement from a NeuVector vulnerability.
 * The scan-wide report.cmds is baseline-scope metadata and lives on
 * baseline.extensions, not per requirement.
 */
function buildRequirement(vuln: NeuVectorVuln, scanTime: Date, ml: ModuleLookup): EvaluatedRequirement {
  const cweIDs = extractCWEs(vuln.description);
  const cveIDs = extractCVEs(vuln);
  const nist = mapCWEToNIST(cweIDs, DEFAULT_REMEDIATION_NIST_TAGS);
  const cciTags = nistToCci(nist);

  const tags: Record<string, unknown> = {
    nist,
    cci: cciTags,
  };

  if (cveIDs.length > 0) {
    tags['cve'] = cveIDs;
  }

  if (vuln.feed_rating) {
    tags['feed_rating'] = vuln.feed_rating;
  }

  if (vuln.severity) {
    tags['severity'] = vuln.severity;
  }

  const status = ml.status(vuln);
  if (status) {
    tags['status'] = status;
  }

  const source = ml.source(vuln);
  if (source) {
    tags['source'] = source;
  }

  if (vuln.published_timestamp) {
    tags['published_timestamp'] = vuln.published_timestamp;
  }

  if (vuln.last_modified_timestamp) {
    tags['last_modified_timestamp'] = vuln.last_modified_timestamp;
  }

  const descriptions: Description[] = [
    { label: 'default', data: vuln.description },
  ];

  const results = [
    createResult(ResultStatus.Failed, vulnMessage(vuln), {
      codeDesc: buildCodeDesc(vuln),
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
  req.code = JSON.stringify(vuln, null, 2);
  const controlType = deriveControlTypeFromTags(nist);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }
  req.verificationMethod = VerificationMethodEnum.Automated;
  if (cweIDs.length > 0) {
    req.cwe = cweIDs;
  }
  const cvss = buildCvssEntries(vuln);
  if (cvss.length > 0) {
    req.cvss = cvss;
  }
  const refs = buildRefs(vuln);
  if (refs) {
    req.refs = refs;
  }

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
 * Splits NeuVector's base_os "name:version" form (e.g. "alpine:3.12.1") into OS
 * name and version. A value with no ":" is the name with no version; an empty
 * value yields two empty strings.
 */
function splitBaseOS(baseOS: string): { name: string; version: string } {
  if (!baseOS) {
    return { name: '', version: '' };
  }
  const i = baseOS.indexOf(':');
  if (i >= 0) {
    return { name: baseOS.slice(0, i), version: baseOS.slice(i + 1) };
  }
  return { name: baseOS, version: '' };
}

/**
 * Assembles the scan-wide containerImage component from the report's image
 * identity. base_os → osName/osVersion, digest → integrity, plus
 * imageId/registry/repository/tag when the report carries them.
 */
function buildComponent(report: NeuVectorScanReport): Component {
  const component: Component = {
    name: targetNameFromReport(report),
    type: TargetType.ContainerImage,
    labels: {
      image: `${report.registry}/${report.repository}:${report.tag}`,
      registry: report.registry,
    },
  };
  const { name: osName, version: osVersion } = splitBaseOS(report.base_os);
  if (osName) {
    component.osName = osName;
    if (osVersion) {
      component.osVersion = osVersion;
    }
  }
  if (report.image_id) {
    component.imageId = report.image_id;
  }
  if (report.registry) {
    component.registry = report.registry;
  }
  if (report.repository) {
    component.repository = report.repository;
  }
  if (report.tag) {
    component.tag = report.tag;
  }
  const integrity = digestToChecksums(report.digest);
  if (integrity) {
    component.integrity = integrity;
  }
  return component;
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

  const moduleLookup = new ModuleLookup(scan.report.modules ?? []);

  // Deduplicate by composite ID (name/package_name/package_version)
  const seen = new Set<string>();
  const requirements: EvaluatedRequirement[] = [];
  for (const vuln of limitedVulns) {
    const id = vulnID(vuln);
    if (seen.has(id)) {
      continue;
    }
    seen.add(id);
    requirements.push(buildRequirement(vuln, scanTime, moduleLookup));
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

  // report.cmds is scan-wide image build history — baseline-scope metadata with
  // no typed HDF home. Emit it once under the tool namespace, only when present.
  const cmds = scan.report.cmds ?? [];
  if (cmds.length > 0) {
    baseline.extensions = { neuvector: { cmds } };
  }

  return buildHdfResults({
    generatorName: 'neuvector-to-hdf',
    converterVersion,
    toolName: 'NeuVector',
    baselines: [baseline],
    components: [buildComponent(scan.report)],
    timestamp: scanTime,
  });
}
