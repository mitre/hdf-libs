import {
  type Checksum,
  Copyright,
  createMinimalBaseline,
  type EvaluatedBaseline,
  type EvaluatedRequirement,
  type RequirementResult,
  ResultStatus,
} from '@mitre/hdf-schema';
import {nistToCci, DEFAULT_STATIC_ANALYSIS_NIST_TAGS} from '@mitre/hdf-mappings';
import {parseJSON} from '@mitre/hdf-utilities';
import {inputChecksum, buildNistCciTags, limitArray, validateInputSize, buildHdfResults} from '../../../shared/typescript/converterutil.js';

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
  target: {
    userInput: string;
  };
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
  if (relatedVulns && relatedVulns.length > 0) {
    cvssData.related = relatedVulns
      .filter(r => r.cvss && r.cvss.length > 0)
      .map(r => ({
        id: r.id,
        dataSource: r.dataSource,
        cvss: r.cvss,
      }));
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

function convertMatchToRequirement(match: GrypeMatch, isIgnored: boolean): EvaluatedRequirement {
  const vuln = match.vulnerability;
  const cveId = vuln.id;
  const severity = vuln.severity;
  const impact = getImpact(severity);
  const description = getDescription(vuln, match.relatedVulnerabilities);
  const fixInfo = getFixInfo(vuln.fix);
  const cvssInfo = getCVSSInfo(vuln, match.relatedVulnerabilities);
  const refs = getReferences(vuln, match.relatedVulnerabilities);

  // Determine status
  let status: ResultStatus;
  if (isIgnored) {
    status = ResultStatus.NotReviewed; // Ignored by configured rules
  } else if (isNegligibleOrUnknown(severity)) {
    status = ResultStatus.NotApplicable;
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
    startTime: new Date('0001-01-01T00:00:00Z'), // Go zero time format
  };

  // Get CCI mappings for NIST controls using curated mapping table
  const cciTags = nistToCci(DEFAULT_STATIC_ANALYSIS_NIST_TAGS);

  // Build tags object - only include cci if not empty
  const tags = buildNistCciTags(DEFAULT_STATIC_ANALYSIS_NIST_TAGS, cciTags);

  // Build requirement
  const requirement: EvaluatedRequirement = {
    id: isIgnored ? `Grype-Ignored-Match/${cveId}` : `Grype/${cveId}`,
    impact,
    results: [result],
    tags,
    descriptions: [
      {label: 'default', data: description},
      {label: 'fix', data: fixInfo},
      {label: 'check', data: cvssInfo},
    ],
    refs: refs.length > 0 ? refs.map(url => ({url})) : undefined,
  };

  return requirement;
}

export async function convertGrypeToHdf(input: string): Promise<string> {
  validateInputSize(input, 'grype');
  // Calculate checksum of input data
  const resultsChecksum: Checksum = await inputChecksum(input);

  // Parse Grype JSON
  const grypeData = parseJSON<GrypeReport>(input);

  // Build requirements from matches
  const requirements: EvaluatedRequirement[] = [];

  // Process regular matches
  if (grypeData.matches && grypeData.matches.length > 0) {
    const { items: limitedMatches, truncated: truncatedMatches } = limitArray(grypeData.matches);
    /* v8 ignore next -- truncation only triggers with >100K items */
    if (truncatedMatches) {
      // eslint-disable-next-line no-console
      console.warn(`WARNING: Input truncated at ${limitedMatches.length} match items (original: ${grypeData.matches.length})`);
    }
    for (const match of limitedMatches) {
      requirements.push(convertMatchToRequirement(match, false));
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
      requirements.push(convertMatchToRequirement(match, true));
    }
  }

  // Build baseline name from source
  const targetName = grypeData.source?.target?.userInput || 'Grype Scan';

  // Create baseline
  const baseline: EvaluatedBaseline = createMinimalBaseline(targetName, requirements, {
    resultsChecksum,
  }) as EvaluatedBaseline;

  // Build HDF results
  return buildHdfResults({
    generatorName: grypeData.descriptor?.name || 'grype',
    converterVersion: grypeData.descriptor?.version || 'unknown',
    toolName: 'Grype',
    toolVersion: grypeData.descriptor?.version,
    baselines: [baseline],
    components: [{
      type: Copyright.Artifact,
      name: targetName,
    }],
    timestamp: grypeData.descriptor?.timestamp ? new Date(grypeData.descriptor.timestamp) : new Date(),
  });
}
