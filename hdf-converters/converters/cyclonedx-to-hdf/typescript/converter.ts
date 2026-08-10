import { parseJSON, parseTimestamp } from '@mitre/hdf-utilities';
import {
  nistToCci,
  DEFAULT_STATIC_ANALYSIS_NIST_TAGS,
} from '@mitre/hdf-mappings';
import { deriveControlTypeFromTags, inputChecksum, limitArray, mapCWEToNIST, validateInputSize, buildHdfResults } from '../../../shared/typescript/converterutil.js';
import { parseBom, buildBom, BOMType, type BuildBomParts } from '../../../shared/typescript/bom/index.js';
import { canonicalize } from '../../../shared/typescript/exportmap.js';
import {
  buildCvss,
  cvssVersionFromVector,
  cvssVersionFromString,
} from '../../../shared/typescript/cvss.js';
import type {
  Component,
  Cvss,
  EvaluatedBaseline,
  EvaluatedRequirement,
  Checksum,
  Reference,
  RequirementResult,
  StatusOverride,
  Version as CvssVersion,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  createResult,
  IdentityType,
  Justification,
  OverrideType,
  TargetType,
  createMinimalBaseline,
  createRequirement,
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
  references?: CycloneDXReference[];
  advisories?: CycloneDXAdvisory[];
  ratings?: CycloneDXRating[];
  cwes?: number[];
  description?: string;
  detail?: string;
  recommendation?: string;
  created?: string;
  published?: string;
  updated?: string;
  affects?: CycloneDXAffect[];
  analysis?: CycloneDXAnalysis;
}

interface CycloneDXSource {
  name?: string;
  url?: string;
}

interface CycloneDXReference {
  id?: string;
  source?: CycloneDXSource;
}

interface CycloneDXAdvisory {
  title?: string;
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
 * Assembles structured requirement.cvss[] entries from the CycloneDX ratings. A
 * rating contributes an entry only when it carries a CVSS method
 * (CVSSv2/v3/v31/v4) and at least a score or a vector — ratings that only state a
 * qualitative severity (method "other") carry no CVSS metrics and are left out,
 * their severity already reflected in the requirement impact.
 */
// Derive the CVSS version, preferring an explicit "CVSS:x.y/" vector prefix
// (the precise 3.0-vs-3.1 signal) and using the CycloneDX rating method to
// rescue the prefix-less v2/v4 vectors that would otherwise default to 3.1.
function cvssVersionFromMethod(
  method: string | undefined,
  vector: string | undefined
): CvssVersion {
  if (vector !== undefined && vector.startsWith('CVSS:')) {
    return cvssVersionFromVector(vector);
  }
  switch (method) {
    case 'CVSSv2':
      return cvssVersionFromString('2.0');
    case 'CVSSv4':
      return cvssVersionFromString('4.0');
    default:
      return cvssVersionFromVector(vector);
  }
}

function buildCvssEntries(ratings: CycloneDXRating[]): Cvss[] {
  const entries: Cvss[] = [];
  for (const r of ratings) {
    const hasCvssMethod = r.method !== undefined && CVSS_METHODS.has(r.method);
    const hasMetric =
      (r.score !== undefined && r.score !== null) ||
      (r.vector !== undefined && r.vector !== '');
    if (!hasCvssMethod || !hasMetric) {
      continue;
    }
    entries.push(
      buildCvss({
        version: cvssVersionFromMethod(r.method, r.vector),
        baseScore: r.score,
        baseVector: r.vector,
        source: r.source?.name,
      })
    );
  }
  return entries;
}

/**
 * Collects the external reference links a vulnerability carries — the advisory
 * source URL, each cross-reference's source URL, and each advisory URL —
 * de-duplicated across all three in first-seen order. Returns undefined when the
 * vulnerability carries no links.
 */
function buildRefs(vuln: CycloneDXVulnerability): Reference[] | undefined {
  const seen = new Set<string>();
  const refs: Reference[] = [];
  const add = (url: string | undefined): void => {
    if (!url || seen.has(url)) {
      return;
    }
    seen.add(url);
    refs.push({ url });
  };
  add(vuln.source?.url);
  for (const r of vuln.references ?? []) {
    add(r.source?.url);
  }
  for (const a of vuln.advisories ?? []) {
    add(a.url);
  }
  return refs.length > 0 ? refs : undefined;
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
 * Maps a CycloneDX analysis.justification value to the HDF Justification
 * controlled vocabulary. Returns undefined for an empty or unmapped value — the
 * free-text justification still rides in the override reason.
 */
function vexJustification(j: string | undefined): Justification | undefined {
  switch (j) {
    case 'code_not_present':
      return Justification.VulnerableCodeNotPresent;
    case 'code_not_reachable':
      return Justification.VulnerableCodeNotInExecutePath;
    case 'requires_configuration':
      return Justification.RequiresConfiguration;
    case 'requires_dependency':
      return Justification.RequiresDependency;
    case 'requires_environment':
      return Justification.RequiresEnvironment;
    case 'protected_by_compiler':
      return Justification.ProtectedByCompiler;
    case 'protected_at_runtime':
      return Justification.ProtectedAtRuntime;
    case 'protected_at_perimeter':
      return Justification.ProtectedAtPerimeter;
    case 'protected_by_mitigating_control':
      return Justification.InlineMitigationsAlreadyExist;
    default:
      return undefined;
  }
}

/**
 * Resolves the override's decision time. CycloneDX VEX carries no owner/date on
 * the analysis block, so the vulnerability's own updated -> published -> created
 * time is the defensible decision time; falls back to the finding's scan time
 * only when the vuln carries no parseable date (keeping the override
 * deterministic rather than reaching for now()).
 */
function analysisAppliedAt(vuln: CycloneDXVulnerability, fallback: Date): Date {
  for (const s of [vuln.updated, vuln.published, vuln.created]) {
    if (!s) {
      continue;
    }
    const t = parseTimestamp(s);
    if (t && !isNaN(t.getTime())) {
      return t;
    }
  }
  return fallback;
}

/**
 * Folds the CycloneDX analysis detail and response[] hints into a single override
 * reason. Falls back to a short state-derived constant so the schema-required
 * reason is never empty.
 */
function analysisReason(a: CycloneDXAnalysis): string {
  let reason = a.detail ?? '';
  if (a.response && a.response.length > 0) {
    const ctx = `Response: ${a.response.join(', ')}`;
    reason = reason ? `${reason} (${ctx})` : ctx;
  }
  if (!reason) {
    reason = `Dismissed via CycloneDX VEX analysis: ${a.state ?? ''}`;
  }
  return reason;
}

interface AnalysisOverride {
  override: StatusOverride;
  effectiveStatus: ResultStatus;
  disposition: OverrideType;
}

/**
 * Reconstructs a structured HDF status override from a CycloneDX VEX analysis
 * block. Raw result status stays Failed; the attributed, expiring override
 * carries the triage decision:
 *   - not_affected / false_positive -> falsePositive, effectiveStatus notApplicable
 *     (a vulnerability/SCA scan: the flagged vuln does not apply to this system).
 *   - resolved / resolved_with_pedigree -> attestation, effectiveStatus passed
 *     (the finding was remediated; resolved_with_pedigree carries the evidence).
 * Returns undefined when the analysis is absent or the state leaves the finding
 * actionable (exploitable / in_triage / unknown) — those keep the raw Failed
 * result with no override.
 */
function analysisOverride(
  vuln: CycloneDXVulnerability,
  fallback: Date
): AnalysisOverride | undefined {
  const a = vuln.analysis;
  if (!a) {
    return undefined;
  }
  let disposition: OverrideType;
  let effectiveStatus: ResultStatus;
  switch (a.state) {
    case 'not_affected':
    case 'false_positive':
      disposition = OverrideType.FalsePositive;
      effectiveStatus = ResultStatus.NotApplicable;
      break;
    case 'resolved':
    case 'resolved_with_pedigree':
      disposition = OverrideType.Attestation;
      effectiveStatus = ResultStatus.Passed;
      break;
    default:
      return undefined;
  }
  const appliedAt = analysisAppliedAt(vuln, fallback);
  const expiresAt = new Date();
  expiresAt.setTime(appliedAt.getTime());
  expiresAt.setUTCFullYear(expiresAt.getUTCFullYear() + 1);
  const override: StatusOverride = {
    type: disposition,
    status: effectiveStatus,
    reason: analysisReason(a),
    appliedBy: {type: IdentityType.Other, identifier: 'cyclonedx analysis'},
    appliedAt,
    expiresAt,
  };
  const justification = vexJustification(a.justification);
  if (justification !== undefined) {
    override.justification = justification;
  }
  return {override, effectiveStatus, disposition};
}

/**
 * Converts CycloneDX SBOM/VEX JSON to HDF format.
 *
 * @param input - CycloneDX JSON string
 * @returns HDF JSON string
 */
export async function convertCyclonedxToHdf(input: string, converterVersion = '1.0.0'): Promise<string> {
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

    // CWE identifiers are first-class on requirement.cwe[]; the CWE→NIST mapping
    // is retained in tags.nist.
    const cweIds = cwes.map((c) => `CWE-${c}`);
    const cvssEntries = buildCvssEntries(ratings);

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
    // CycloneDX carries no per-affect explanation, so results carry no message key.
    const toResult = (codeDesc: string): RequirementResult =>
      createResult(ResultStatus.Failed, undefined, { codeDesc, startTime: scanTime });
    const results =
      affects.length > 0
        ? affects.map((affect) => toResult(formatCodeDesc(componentLookup, affect.ref)))
        : [toResult(`Vulnerability ${vuln.id}`)];

    const title = vuln.source?.name
      ? `${vuln.id} (${vuln.source.name})`
      : vuln.id;

    // verificationMethod is intentionally NOT set. CycloneDX carries both
    // machine-generated SBOM vulnerability data and human-authored VEX
    // statements (analyst assertions about CVE exploitability). The converter
    // cannot reliably distinguish the two, so stamping "automated" would
    // misclassify VEX-derived requirements.
    const req = createRequirement(vuln.id, title, descriptions, impact, results, { tags }) as EvaluatedRequirement;
    if (cvssEntries.length > 0) {
      req.cvss = cvssEntries;
    }
    if (cweIds.length > 0) {
      req.cwe = cweIds;
    }
    const refs = buildRefs(vuln);
    if (refs !== undefined) {
      req.refs = refs;
    }
    const controlType = deriveControlTypeFromTags(nist);
    if (controlType !== undefined) {
      req.controlType = controlType;
    }

    // Reconstruct a structured override from the CycloneDX VEX analysis: the raw
    // Failed result stays, and the triage decision rides as an attributed,
    // expiring statusOverride that flips effectiveStatus.
    const triaged = analysisOverride(vuln, scanTime);
    if (triaged !== undefined) {
      req.statusOverrides = [triaged.override];
      req.effectiveStatus = triaged.effectiveStatus;
      req.disposition = triaged.disposition;
    }

    requirements.push(req);
  }

  const baseline = createMinimalBaseline('CycloneDX Scan', requirements, {
    resultsChecksum,
  }) as EvaluatedBaseline;

  const targetComponent: Component = {
    name: bom.metadata?.component?.name ?? '',
    type: TargetType.Application,
  };
  if (bom.metadata?.component?.version) {
    targetComponent.version = bom.metadata.component.version;
  }

  // Attach the CycloneDX BOM to the component as a generalized boms[] entry.
  // The shared BOM parser yields the normalized package inventory; the raw
  // manifest is also carried via document passthrough so no data is dropped.
  // Vuln-only inputs (no components) have no packages and carry the document only.
  const parsedBom = parseBom(input);
  const bomParts: BuildBomParts = {
    bomType: BOMType.Sbom,
    format: 'cyclonedx',
    uniqueId: parsedBom.normalized.uniqueId,
    // Sort keys in code-point order to match Go's json.Marshal, which sorts map
    // keys — keeps the raw passthrough byte-identical across the two languages.
    document: canonicalize(JSON.parse(input)) as Record<string, unknown>,
  };
  if (parsedBom.normalized.packages && parsedBom.normalized.packages.length > 0) {
    bomParts.packages = parsedBom.normalized.packages;
  }
  const componentBom = buildBom(bomParts);

  return buildHdfResults({
    generatorName: 'cyclonedx-to-hdf',
    converterVersion,
    toolName: 'CycloneDX',
    baselines: [baseline],
    components: [{ ...targetComponent, boms: [componentBom] }],
    timestamp: scanTime,
  });
}
