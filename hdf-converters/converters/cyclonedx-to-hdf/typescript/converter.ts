import { parseJSON, parseTimestamp } from '@mitre/hdf-utilities';
import {
  nistToCci,
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
} from '@mitre/hdf-mappings';
import { deriveControlTypeFromTags, inputChecksum, limitArray, mapCWEToNIST, validateInputSize, buildHdfResults } from '../../../shared/typescript/converterutil.js';
import { parseBom, buildBom, BOMType, type BuildBomParts } from '../../../shared/typescript/bom/index.js';
import type {
  EvaluatedBaseline,
  EvaluatedRequirement,
  Checksum,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  TargetType,
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

// NOTE: heimdall2 mapped info/unknown severity to NotReviewed status.
// We intentionally do NOT replicate that — a vulnerability is a finding
// regardless of severity confidence. Info/unknown severity vulns are Failed
// with impact from the severity mapping (info→0.1, unknown→0.5).

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
 * Reports whether any (possibly nested) component is a machine-learning-model,
 * i.e. the CycloneDX document is an AI-BOM.
 */
function hasMLModelComponent(components: CycloneDXComponent[]): boolean {
  return flattenComponents(components).some(
    (comp) => comp.type === 'machine-learning-model'
  );
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

  if (!bom.vulnerabilities || bom.vulnerabilities.length === 0) {
    if (hasMLModelComponent(bom.components ?? [])) {
      throw new Error(
        'cyclonedx: this file is a CycloneDX AI-BOM (machine-learning-model inventory) with no vulnerabilities; ' +
        'to import it into a system document, use:\n' +
        '  hdf system create <file> --from cyclonedx-mlbom'
      );
    }
    throw new Error(
      'cyclonedx: this file is an SBOM inventory with no vulnerabilities; ' +
      'to import SBOM data into a system document, use:\n' +
      '  hdf system create <sbom-file> --component-name <name>'
    );
  }

  const resultsChecksum: Checksum = await inputChecksum(input);

  // Prefer the BOM creation time as the scan timestamp; fall back to now.
  const parsedTimestamp = bom.metadata?.timestamp
    ? (parseTimestamp(bom.metadata.timestamp) ?? undefined)
    : undefined;
  const scanTime =
    parsedTimestamp && !isNaN(parsedTimestamp.getTime())
      ? parsedTimestamp
      : new Date();

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

    // Build results: one per affected component.
    // All vulnerabilities are Failed — info/unknown severity affects impact
    // score but not status.
    const affects = vuln.affects ?? [];
    const results =
      affects.length > 0
        ? affects.map((affect) =>
            createResult(ResultStatus.Failed, undefined, {
              codeDesc: formatCodeDesc(componentLookup, affect.ref),
              startTime: scanTime,
            })
          )
        : [
            createResult(ResultStatus.Failed, undefined, {
              codeDesc: `Vulnerability ${vuln.id}`,
              startTime: scanTime,
            }),
          ];

    const title = vuln.source?.name
      ? `${vuln.id} (${vuln.source.name})`
      : vuln.id;

    // verificationMethod is intentionally NOT set. CycloneDX carries both
    // machine-generated SBOM vulnerability data and human-authored VEX
    // statements (analyst assertions about CVE exploitability). The converter
    // cannot reliably distinguish the two, so stamping "automated" would
    // misclassify VEX-derived requirements.
    const req = createRequirement(vuln.id, title, descriptions, impact, results, { tags }) as EvaluatedRequirement;
    const controlType = deriveControlTypeFromTags(nist);
    if (controlType !== undefined) {
      req.controlType = controlType;
    }
    requirements.push(req);
  }

  const baseline = createMinimalBaseline('CycloneDX Scan', requirements, {
    resultsChecksum,
  }) as EvaluatedBaseline;

  const targetName = bom.metadata?.component?.name ?? '';

  // Attach the CycloneDX BOM to the component as a generalized boms[] entry.
  // The shared BOM parser yields the normalized package inventory; the raw
  // manifest is also carried via document passthrough so no data is dropped.
  // Vuln-only inputs (no components) have no packages and carry the document only.
  const parsedBom = parseBom(input);
  const bomParts: BuildBomParts = {
    bomType: BOMType.Sbom,
    format: 'cyclonedx',
    uniqueId: parsedBom.normalized.uniqueId,
    document: JSON.parse(input) as Record<string, unknown>,
  };
  if (parsedBom.normalized.packages && parsedBom.normalized.packages.length > 0) {
    bomParts.packages = parsedBom.normalized.packages;
  }
  const componentBom = buildBom(bomParts);

  return buildHdfResults({
    generatorName: 'cyclonedx-to-hdf',
    converterVersion: '1.0.0',
    toolName: 'CycloneDX',
    toolFormat: 'JSON',
    baselines: [baseline],
    components: [{ name: targetName, type: TargetType.Application, boms: [componentBom] }],
    timestamp: scanTime,
  });
}
