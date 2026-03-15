import { parseJSON } from '@mitre/hdf-utilities';
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
 * CycloneDX JSON structures (subset relevant to vulnerability mapping)
 */
interface CycloneDXBom {
  bomFormat: string;
  specVersion: string;
  metadata?: CycloneDXMetadata;
  components?: CycloneDXComponent[];
  vulnerabilities?: CycloneDXVulnerability[];
}

interface CycloneDXMetadata {
  timestamp?: string;
  component?: CycloneDXMetadataComponent;
}

interface CycloneDXMetadataComponent {
  type?: string;
  name?: string;
  version?: string;
  'bom-ref'?: string;
}

interface CycloneDXComponent {
  type: string;
  name: string;
  version?: string;
  group?: string;
  'bom-ref'?: string;
  components?: CycloneDXComponent[];
}

interface CycloneDXVulnerability {
  id: string;
  source?: CycloneDXSource;
  ratings?: CycloneDXRating[];
  cwes?: number[];
  description?: string;
  detail?: string;
  recommendation?: string;
  affects?: CycloneDXAffect[];
  analysis?: CycloneDXAnalysis;
}

interface CycloneDXSource {
  name?: string;
  url?: string;
}

interface CycloneDXRating {
  source?: CycloneDXSource;
  score?: number;
  severity?: string;
  method?: string;
  vector?: string;
}

interface CycloneDXAffect {
  ref: string;
}

interface CycloneDXAnalysis {
  state?: string;
  justification?: string;
  response?: string[];
  detail?: string;
}

const CVSS_METHODS = new Set([
  'CVSSv2',
  'CVSSv3',
  'CVSSv31',
  'CVSSv4',
]);

const INFO_UNKNOWN_SEVERITIES = new Set(['info', 'unknown']);

/**
 * Computes the maximum impact across all ratings for a vulnerability.
 * Prefers CVSS score/10 when available, falls back to severityToImpact().
 */
function maxImpact(ratings: CycloneDXRating[]): number {
  if (ratings.length === 0) {
    return 0.5;
  }

  let max = 0;
  for (const rating of ratings) {
    let impact: number;
    if (
      rating.method &&
      CVSS_METHODS.has(rating.method) &&
      rating.score !== undefined &&
      rating.score !== null
    ) {
      impact = rating.score / 10;
    } else {
      impact = severityToImpact(rating.severity ?? 'medium');
    }
    if (impact > max) {
      max = impact;
    }
  }
  return max;
}

/**
 * Returns true if all ratings have only info or unknown severity
 * (and none have a recognized severity like critical/high/medium/low/none).
 *
 * NOTE: This replicates heimdall2 behavior. The semantic correctness of mapping
 * "unknown severity" to "not reviewed" is debatable and should be re-examined.
 */
function isInfoOrUnknownOnly(ratings: CycloneDXRating[]): boolean {
  if (ratings.length === 0) {
    return false;
  }
  return ratings.every(
    (r) => INFO_UNKNOWN_SEVERITIES.has((r.severity ?? '').toLowerCase())
  );
}

/**
 * Formats the ratings as a human-readable tag string.
 */
function formatRatingsTag(ratings: CycloneDXRating[]): string {
  return ratings
    .map((r) => `${r.source?.name ?? 'Unknown'} - ${r.severity ?? 'unrated'}`)
    .join(', ');
}

/**
 * Formats a component reference as a code_desc string.
 */
function formatCodeDesc(
  componentLookup: Map<string, CycloneDXComponent>,
  ref: string
): string {
  const comp = componentLookup.get(ref);
  if (!comp) {
    // VEX case: no matching component, use the ref directly
    return `Component ${ref} is vulnerable`;
  }

  let name = '';
  if (comp.group) {
    name += comp.group + '/';
  }
  name += comp.name;
  if (comp.version) {
    name += '@' + comp.version;
  }
  return `Component ${name} is vulnerable`;
}

/**
 * Flattens nested CycloneDX components into a single array.
 */
function flattenComponents(components: CycloneDXComponent[]): CycloneDXComponent[] {
  const result: CycloneDXComponent[] = [];
  for (const comp of components) {
    result.push(comp);
    if (comp.components) {
      result.push(...flattenComponents(comp.components));
    }
  }
  return result;
}

/**
 * Converts CycloneDX SBOM/VEX JSON to HDF format.
 *
 * @param input - CycloneDX JSON string
 * @returns HDF JSON string
 */
export async function convertCyclonedxToHdf(input: string): Promise<string> {
  if (!input || input.trim().length === 0) {
    throw new Error('cyclonedx: empty input');
  }
  validateInputSize(input, 'cyclonedx');

  const bom = parseJSON<CycloneDXBom>(input);

  if (!bom || typeof bom !== 'object') {
    throw new Error('cyclonedx: invalid JSON');
  }

  if (bom.bomFormat !== 'CycloneDX') {
    throw new Error(
      `cyclonedx: missing or invalid bomFormat (expected "CycloneDX", got "${bom.bomFormat ?? 'undefined'}")`
    );
  }

  if (
    (!bom.components || bom.components.length === 0) &&
    (!bom.vulnerabilities || bom.vulnerabilities.length === 0)
  ) {
    throw new Error(
      'cyclonedx: input has neither components nor vulnerabilities'
    );
  }

  const resultsChecksum: Checksum = await inputChecksum(input);

  // Flatten nested components and build lookup by bom-ref
  const allComponents = flattenComponents(bom.components ?? []);
  const componentLookup = new Map<string, CycloneDXComponent>();
  for (const comp of allComponents) {
    if (comp['bom-ref']) {
      componentLookup.set(comp['bom-ref'], comp);
    }
  }

  const requirements: EvaluatedRequirement[] = [];

  const { items: limitedVulns, truncated: truncatedVulns } = limitArray(bom.vulnerabilities ?? []);
  /* v8 ignore next -- truncation only triggers with >100K items */
  if (truncatedVulns) {
    // eslint-disable-next-line no-console
    console.warn(`WARNING: Input truncated at ${limitedVulns.length} vulnerability items (original: ${(bom.vulnerabilities ?? []).length})`);
  }
  for (const vuln of limitedVulns) {
    const ratings = vuln.ratings ?? [];
    const impact = maxImpact(ratings);
    const cwes = vuln.cwes ?? [];
    const nist = mapCWEToNIST(cwes.map(c => `${c}`), DEFAULT_STATIC_ANALYSIS_NIST_TAGS);
    const cciTags = nistToCci(nist);

    const tags: Record<string, unknown> = {
      nist,
      cci: cciTags,
    };

    if (cwes.length > 0) {
      tags['cweid'] = cwes.map((c) => `CWE-${c}`);
    }

    if (ratings.length > 0) {
      tags['ratings'] = formatRatingsTag(ratings);
    }

    // Build descriptions (must always include a 'default' label per HDF schema)
    const descriptions: Description[] = [];

    // Default description: description + detail
    const defaultParts: string[] = [];
    if (vuln.description) {
      defaultParts.push(`Description: ${vuln.description}`);
    }
    if (vuln.detail) {
      defaultParts.push(`Detail: ${vuln.detail}`);
    }
    if (defaultParts.length > 0) {
      descriptions.push({ label: 'default', data: defaultParts.join('\n\n') });
    } else {
      descriptions.push({ label: 'default', data: vuln.id });
    }

    // Fix description: recommendation + workaround from analysis
    const fixParts: string[] = [];
    if (vuln.recommendation) {
      fixParts.push(vuln.recommendation);
    }
    if (vuln.analysis?.detail) {
      fixParts.push(`Workaround: ${vuln.analysis.detail}`);
    }
    if (fixParts.length > 0) {
      descriptions.push({ label: 'fix', data: fixParts.join('\n\n') });
    }

    // Determine if this is an info/unknown-only vulnerability
    const infoUnknownSkip = isInfoOrUnknownOnly(ratings);

    // Build results: one per affected component
    const affects = vuln.affects ?? [];
    const results =
      affects.length > 0
        ? affects.map((affect) => {
            if (infoUnknownSkip) {
              return createResult(
                ResultStatus.NotReviewed,
                'Manual review required because a CycloneDX rating severity is set to `info` or `unknown`.',
                { codeDesc: formatCodeDesc(componentLookup, affect.ref) }
              );
            }
            return createResult(ResultStatus.Failed, undefined, {
              codeDesc: formatCodeDesc(componentLookup, affect.ref),
            });
          })
        : [
            // Vulnerability with no affects — create a single result
            infoUnknownSkip
              ? createResult(
                  ResultStatus.NotReviewed,
                  'Manual review required because a CycloneDX rating severity is set to `info` or `unknown`.',
                  { codeDesc: `Vulnerability ${vuln.id}` }
                )
              : createResult(ResultStatus.Failed, undefined, {
                  codeDesc: `Vulnerability ${vuln.id}`,
                }),
          ];

    const title = vuln.source?.name
      ? `${vuln.id} (${vuln.source.name})`
      : vuln.id;

    requirements.push(
      createRequirement(vuln.id, title, descriptions, impact, results, { tags })
    );
  }

  const baseline = createMinimalBaseline('CycloneDX Scan', requirements, {
    resultsChecksum,
  }) as EvaluatedBaseline;

  const dataSource: DataSource = { name: 'CycloneDX', format: 'JSON' };

  const targetName = bom.metadata?.component?.name ?? '';

  const hdf: HdfResults = {
    baselines: [baseline],
    generator: {
      name: 'cyclonedx-to-hdf',
      version: '1.0.0',
    },
    dataSource,
    targets: [{ name: targetName, type: Copyright.Application }],
    timestamp: new Date(),
  };

  return JSON.stringify(hdf, null, 2);
}
