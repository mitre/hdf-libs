import { parseJSON, sha256 } from '@mitre/hdf-utilities';
import {
  nistToCci,
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
} from '@mitre/hdf-mappings';
import { buildAffectedPackage, buildNoFindingsRequirement, ecosystemFromPurlType, inputChecksum, limitArray, mapCWEToNIST, validateInputSize, buildHdfResults, deriveControlTypeFromTags } from '../../../shared/typescript/converterutil.js';
import { buildCvss as buildSharedCvss, cvssVersionFromVector, cvssVersionFromString } from '../../../shared/typescript/cvss.js';
import { Ecosystem } from '@mitre/hdf-schema';
import type {
  EvaluatedBaseline,
  EvaluatedRequirement,
  Checksum,
  Cvss,
  RequirementResult,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  TargetType,
  VerificationMethodEnum,
  createMinimalBaseline,
  createRequirement,
  severityToImpact,
  type Description,
} from '@mitre/hdf-schema';

/**
 * JFrog Xray JSON output structures.
 */
interface XrayReport {
  total_count: number;
  data: XrayEntry[];
}

interface XrayEntry {
  id: string;
  severity: string;
  summary: string;
  issue_type?: string;
  provider?: string;
  component?: string;
  source_id?: string;
  source_comp_id?: string;
  component_versions?: ComponentVersions;
  edited?: string;
}

interface ComponentVersions {
  id?: string;
  vulnerable_versions?: string[];
  fixed_versions?: string[];
  more_details?: MoreDetails;
}

interface MoreDetails {
  cves?: CVEEntry[];
  description?: string;
  provider?: string;
}

interface CVEEntry {
  cve?: string;
  cwe?: string[];
  cvss_v2?: string;
  cvss_v3?: string;
}

/**
 * Generate a truncated SHA-256 hash of a string for use as an ID.
 * Truncated to 32 hex chars for compatibility with original hash length.
 */
async function hashID(summary: string): Promise<string> {
  const full = await sha256(summary);
  return full.substring(0, 32);
}

/**
 * Collect the distinct CWE identifiers across every CVE entry, preserving
 * first-seen order. These feed both requirement.cwe[] and the CWE→NIST mapping.
 */
function extractCWEs(entry: XrayEntry): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const cve of entry.component_versions?.more_details?.cves ?? []) {
    for (const cwe of cve.cwe ?? []) {
      if (cwe && !seen.has(cwe)) {
        seen.add(cwe);
        out.push(cwe);
      }
    }
  }
  return out;
}

/**
 * Collect the distinct CVE identifiers across every CVE entry, preserving
 * first-seen order. The requirement id is a summary hash (never the CVE), so
 * tags.cve is where the CVE list lives.
 */
function extractCVEs(entry: XrayEntry): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const cve of entry.component_versions?.more_details?.cves ?? []) {
    if (cve.cve && !seen.has(cve.cve)) {
      seen.add(cve.cve);
      out.push(cve.cve);
    }
  }
  return out;
}

/**
 * Split a JFrog cvss_v2/cvss_v3 field ("<score>/<vector>", e.g.
 * "9.8/CVSS:3.1/AV:N/...") on the FIRST "/" into the numeric base score and the
 * remaining vector. A field with no "/" is a bare score with no vector; an
 * unparseable score yields undefined (the vector may still stand alone).
 */
function parseCvssField(field: string | undefined): { score?: number; vector: string } {
  if (!field) return { vector: '' };
  const idx = field.indexOf('/');
  let scorePart = field;
  let vector = '';
  if (idx >= 0) {
    scorePart = field.slice(0, idx);
    vector = field.slice(idx + 1);
  }
  const parsed = Number.parseFloat(scorePart.trim());
  return { score: Number.isFinite(parsed) ? parsed : undefined, vector };
}

/**
 * Assemble the structured requirement.cvss[] for a group's representative
 * entry. Each CVE contributes its v3 metric (version from the vector prefix)
 * then its v2 metric (always CVSS 2.0 — the cvss_v2 vector prefix is
 * inconsistent, so the field name is the authority). A field with neither a
 * score nor a vector is skipped.
 */
function buildCvssEntries(cves: CVEEntry[] | undefined): Cvss[] {
  const out: Cvss[] = [];
  for (const cve of cves ?? []) {
    const v3 = parseCvssField(cve.cvss_v3);
    if (v3.score !== undefined || v3.vector !== '') {
      out.push(buildSharedCvss({
        version: cvssVersionFromVector(v3.vector),
        baseScore: v3.score,
        baseVector: v3.vector,
        source: cve.cve,
      }));
    }
    const v2 = parseCvssField(cve.cvss_v2);
    if (v2.score !== undefined || v2.vector !== '') {
      out.push(buildSharedCvss({
        version: cvssVersionFromString('2.0'),
        baseScore: v2.score,
        baseVector: v2.vector,
        source: cve.cve,
      }));
    }
  }
  return out;
}

/**
 * Build description from more_details, including CVE data.
 * Matches heimdall2 formatDesc behavior.
 */
function formatDescription(entry: XrayEntry): string {
  const parts: string[] = [];
  const desc = entry.component_versions?.more_details?.description;
  if (desc) {
    parts.push(desc);
  }
  const cves = entry.component_versions?.more_details?.cves;
  if (cves && cves.length > 0) {
    let cveStr = JSON.stringify(cves);
    cveStr = cveStr.replace(/":/g, '"=>');
    cveStr = cveStr.replace(/,/g, ', ');
    parts.push(`cves: ${cveStr}`);
  }
  if (parts.length === 0) {
    return entry.summary;
  }
  return parts.join('\n');
}

/**
 * Build code_desc from component version metadata.
 * Matches heimdall2 formatCodeDesc behavior.
 */
function formatCodeDesc(entry: XrayEntry): string {
  const parts: string[] = [];

  parts.push(`source_comp_id : ${entry.source_comp_id ?? ''}`);

  const vulnVersions = entry.component_versions?.vulnerable_versions;
  if (vulnVersions && vulnVersions.length > 0) {
    parts.push(`vulnerable_versions : ${JSON.stringify(vulnVersions)}`);
  } else {
    parts.push('vulnerable_versions : ');
  }

  const fixedVersions = entry.component_versions?.fixed_versions;
  if (fixedVersions && fixedVersions.length > 0) {
    parts.push(`fixed_versions : ${JSON.stringify(fixedVersions)}`);
  } else {
    parts.push('fixed_versions : ');
  }

  parts.push(`issue_type : ${entry.issue_type ?? ''}`);
  parts.push(`provider : ${entry.provider ?? ''}`);

  return parts.join('\n').replace(/,/g, ', ');
}

/**
 * Render an Xray entry as the indented JSON blob carried in the requirement's
 * code field (the ionchannel pattern), so Heimdall's CODE tab shows the raw
 * finding. The object is reconstructed with a fixed key order and full field set
 * matching the Go twin's struct marshal, keeping Go and TS byte-identical
 * (verified by the shared snapshot test).
 */
function marshalEntryCode(entry: XrayEntry): string {
  const cv = entry.component_versions;
  const md = cv?.more_details;
  const cves = md?.cves;
  const codeObject = {
    id: entry.id ?? '',
    severity: entry.severity ?? '',
    summary: entry.summary ?? '',
    issue_type: entry.issue_type ?? '',
    provider: entry.provider ?? '',
    component: entry.component ?? '',
    source_id: entry.source_id ?? '',
    source_comp_id: entry.source_comp_id ?? '',
    component_versions: {
      id: cv?.id ?? '',
      vulnerable_versions: cv?.vulnerable_versions ?? null,
      fixed_versions: cv?.fixed_versions ?? null,
      more_details: {
        cves: cves
          ? cves.map((c) => ({
              cve: c.cve ?? '',
              cwe: c.cwe ?? null,
              cvss_v2: c.cvss_v2 ?? '',
              cvss_v3: c.cvss_v3 ?? '',
            }))
          : null,
        description: md?.description ?? '',
        provider: md?.provider ?? '',
      },
    },
    edited: entry.edited ?? '',
  };
  return JSON.stringify(codeObject, null, 2);
}

/**
 * Builds a single EvaluatedRequirement from a group of entries sharing an ID.
 */
function buildRequirement(entryID: string, entries: XrayEntry[], scanTime: Date): EvaluatedRequirement {
  const rep = entries[0]!;
  const cweIDs = extractCWEs(rep);
  const cveIDs = extractCVEs(rep);
  const nist = mapCWEToNIST(cweIDs, DEFAULT_STATIC_ANALYSIS_NIST_TAGS);
  const cciTags = nistToCci(nist);

  const tags: Record<string, unknown> = {
    nist,
    cci: cciTags,
  };

  if (cveIDs.length > 0) {
    tags['cve'] = cveIDs;
  }

  const descriptions: Description[] = [
    { label: 'default', data: formatDescription(rep) },
  ];

  // Xray carries no per-result explanation, so `message` stays absent rather
  // than an empty string (createResult would default it to '').
  const results: RequirementResult[] = entries.map(entry => ({
    status: ResultStatus.Failed,
    codeDesc: formatCodeDesc(entry),
    startTime: scanTime,
  }));

  const req = createRequirement(
    entryID,
    rep.summary,
    descriptions,
    severityToImpact(rep.severity),
    results,
    { tags }
  ) as EvaluatedRequirement;
  req.code = marshalEntryCode(rep);
  const controlType = deriveControlTypeFromTags(nist);
  if (controlType !== undefined) {
    req.controlType = controlType;
  }
  req.verificationMethod = VerificationMethodEnum.Automated;

  if (cweIDs.length > 0) {
    req.cwe = cweIDs;
  }
  const cvss = buildCvssEntries(rep.component_versions?.more_details?.cves);
  if (cvss.length > 0) {
    req.cvss = cvss;
  }

  const pkg = buildAffectedPackageFromEntry(rep);
  if (pkg) {
    req.affectedPackages = [pkg];
  }
  return req;
}

// Xray source-id scheme to AffectedPackage ecosystem.
// `gav://` is Maven (group:artifact); other schemes match purl types
// directly (npm, pypi, etc.).
function ecosystemFromXraySource(scheme: string): Ecosystem {
  if (scheme === 'gav') return Ecosystem.Maven;
  return ecosystemFromPurlType(scheme);
}

// Parse `<scheme>://<name>:<version>` (source_comp_id) or
// `<scheme>://<name>` (source_id). Returns undefined when no scheme is
// present.
function parseSourceCompID(s: string | undefined):
  | { scheme: string; name: string; version?: string }
  | undefined {
  if (!s) return undefined;
  const m = /^([a-zA-Z0-9]+):\/\/(.+)$/.exec(s);
  if (!m) return undefined;
  const scheme = m[1]!.toLowerCase();
  const rest = m[2]!;
  const colonIdx = rest.lastIndexOf(':');
  if (colonIdx > 0) {
    return { scheme, name: rest.slice(0, colonIdx), version: rest.slice(colonIdx + 1) };
  }
  return { scheme, name: rest };
}

function buildAffectedPackageFromEntry(entry: XrayEntry): ReturnType<typeof buildAffectedPackage> {
  const parsed = parseSourceCompID(entry.source_comp_id ?? entry.source_id);
  let name = entry.component ?? '';
  let version: string | undefined;
  let ecosystem: Ecosystem | undefined;
  if (parsed) {
    if (parsed.name) name = parsed.name;
    version = parsed.version;
    ecosystem = ecosystemFromXraySource(parsed.scheme);
  }
  // Fall back to component_versions.fixed_versions[0] for the fixed-in
  // marker; vulnerable_versions are range expressions and don't fit
  // AffectedPackage.fixedInVersion (which mirrors `version` syntax).
  const fixed = entry.component_versions?.fixed_versions?.[0];
  // Without a concrete version we still emit the package — the schema
  // accepts name+version+ecosystem OR purl-only; here we ensure at
  // least name+ecosystem are populated, version optional.
  return buildAffectedPackage({
    name,
    version,
    ecosystem: ecosystem ?? (name ? Ecosystem.Generic : undefined),
    fixedInVersion: fixed,
  });
}

/**
 * Converts JFrog Xray JSON output to HDF format.
 *
 * @param input - JFrog Xray JSON string
 * @returns HDF JSON string
 */
export async function convertJfrogXrayToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
  if (!input || input.trim().length === 0) {
    throw new Error('jfrog-xray: empty input');
  }
  validateInputSize(input, 'jfrog-xray');

  const resultsChecksum: Checksum = await inputChecksum(input);

  const parsed = parseJSON<XrayReport>(input);

  if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.data)) {
    throw new Error('jfrog-xray: invalid JSON structure');
  }

  // JFrog Xray output carries no scan-level timestamp (only per-entry `edited`
  // dates, which mark when each vuln-DB record was last edited, not when the
  // scan ran). Use a single conversion timestamp for all results, the doc
  // timestamp, and the no-findings placeholder.
  const scanTime = new Date();

  const { items: limitedEntries, truncated } = limitArray(parsed.data);
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncated) {
    // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedEntries.length} entries (original: ${parsed.data.length})`);
  }

  // Pre-compute entry IDs (hashID is async due to Web Crypto sha256)
  const entryIDs = await Promise.all(
    limitedEntries.map(async (entry) => {
      if (entry.id && entry.id.length > 0) return entry.id;
      return hashID(entry.summary);
    })
  );

  // Group entries by effective ID, preserving insertion order
  const groups = new Map<string, XrayEntry[]>();
  for (let i = 0; i < limitedEntries.length; i++) {
    const id = entryIDs[i]!;
    const entry = limitedEntries[i]!;
    const existing = groups.get(id);
    if (existing) {
      existing.push(entry);
    } else {
      groups.set(id, [entry]);
    }
  }

  const requirements: EvaluatedRequirement[] = [];
  for (const [entryID, entries] of groups) {
    requirements.push(buildRequirement(entryID, entries, scanTime));
  }

  if (requirements.length === 0) {
    requirements.push(buildNoFindingsRequirement(
      'jfrog-xray-no-findings',
      'JFrog Xray scanned the target artifact and reported zero vulnerable components.',
      scanTime,
    ));
  }

  const baseline = createMinimalBaseline(
    'JFrog Xray Scan',
    requirements,
    { resultsChecksum }
  ) as EvaluatedBaseline;

  return buildHdfResults({
    generatorName: 'jfrog-xray-to-hdf',
    converterVersion,
    toolName: 'JFrog Xray',
    baselines: [baseline],
    components: [{ name: 'JFrog Xray Scan', type: TargetType.Application }],
    timestamp: scanTime,
  });
}
