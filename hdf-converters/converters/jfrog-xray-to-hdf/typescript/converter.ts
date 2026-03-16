import { parseJSON, sha256 } from '@mitre/hdf-utilities';
import {
  nistToCci,
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
} from '@mitre/hdf-mappings';
import { inputChecksum, limitArray, mapCWEToNIST, validateInputSize } from '../../../shared/typescript/converterutil.js';
import type {
  HdfResults,
  EvaluatedBaseline,
  EvaluatedRequirement,
  Checksum,
  DataSource,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  Copyright,
  createMinimalBaseline,
  createRequirement,
  createResult,
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
 * Extract CWE identifiers from the first CVE entry.
 */
function extractCWEs(entry: XrayEntry): string[] {
  const cves = entry.component_versions?.more_details?.cves;
  if (!cves || cves.length === 0) {
    return [];
  }
  return cves[0]?.cwe ?? [];
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
 * Builds a single EvaluatedRequirement from a group of entries sharing an ID.
 */
function buildRequirement(entryID: string, entries: XrayEntry[]): EvaluatedRequirement {
  const rep = entries[0]!;
  const cweIDs = extractCWEs(rep);
  const nist = mapCWEToNIST(cweIDs, DEFAULT_STATIC_ANALYSIS_NIST_TAGS);
  const cciTags = nistToCci(nist);

  const tags: Record<string, unknown> = {
    nist,
    cci: cciTags,
  };

  if (cweIDs.length > 0) {
    tags['cweid'] = cweIDs;
  }

  const descriptions: Description[] = [
    { label: 'default', data: formatDescription(rep) },
  ];

  const results = entries.map(entry =>
    createResult(ResultStatus.Failed, undefined, {
      codeDesc: formatCodeDesc(entry),
    })
  );

  return createRequirement(
    entryID,
    rep.summary,
    descriptions,
    severityToImpact(rep.severity),
    results,
    { tags }
  );
}

/**
 * Converts JFrog Xray JSON output to HDF format.
 *
 * @param input - JFrog Xray JSON string
 * @returns HDF JSON string
 */
export async function convertJfrogXrayToHdf(input: string): Promise<string> {
  if (!input || input.trim().length === 0) {
    throw new Error('jfrog-xray: empty input');
  }
  validateInputSize(input, 'jfrog-xray');

  const resultsChecksum: Checksum = await inputChecksum(input);

  const parsed = parseJSON<XrayReport>(input);

  if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.data)) {
    throw new Error('jfrog-xray: invalid JSON structure');
  }

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
    requirements.push(buildRequirement(entryID, entries));
  }

  const baseline = createMinimalBaseline(
    'JFrog Xray Scan',
    requirements,
    { resultsChecksum }
  ) as EvaluatedBaseline;

  const dataSource: DataSource = { name: 'JFrog Xray', format: 'JSON' };

  const hdf: HdfResults = {
    baselines: [baseline],
    generator: {
      name: 'jfrog-xray-to-hdf',
      version: '1.0.0',
    },
    dataSource,
    targets: [{ name: 'JFrog Xray Scan', type: Copyright.Application }],
    timestamp: new Date(),
  };

  return JSON.stringify(hdf, null, 2);
}
