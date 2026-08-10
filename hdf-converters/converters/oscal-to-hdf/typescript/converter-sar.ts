/**
 * OSCAL Assessment Results (SAR) to HDF Results converter.
 *
 * Mirrors the Go implementation in converters/oscal-to-hdf/go/converter_sar.go.
 */

import { parseJSON, parseTimestamp } from '@mitre/hdf-utilities';
import { nistToCci } from '@mitre/hdf-mappings';
import { buildNistCciTags, deriveControlTypeFromTags, inputChecksum, inputIntegrity, serializeHdf, validateInputSize } from '../../../shared/typescript/converterutil.js';
import type {
  HDFResults,
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
} from '@mitre/hdf-schema';
import {
  ResultStatus,
  createMinimalBaseline,
  createRequirement,
  createResult,
  type Description,
  type Reference,
} from '@mitre/hdf-schema';
import type {
  Oscal,
  SecurityAssessmentResultsSAR,
  AssessmentResult,
  Finding,
  Observation,
  IdentifiedRisk,
  RiskResponse,
} from './types.js';
import {
  controlIdToNistTag,
  extractControlIdFromObjectiveId,
  oscalStatusToHdf,
  extractRiskSeverity,
  extractMetadata,
  toKebabCase,
} from './shared.js';

/**
 * Converts an OSCAL Assessment Results (SAR) document to HDF Results JSON.
 *
 * @param input - Raw JSON string containing OSCAL assessment-results
 * @returns HDF Results JSON string
 */
export async function convertOscalSarToHdf(input: string): Promise<string> {
  validateInputSize(input, 'oscal-assessment-results');

  if (!input || input.trim().length === 0) {
    throw new Error('empty input');
  }

  const doc = parseJSON<Oscal>(input);
  if (!doc['assessment-results']) {
    throw new Error(
      "oscal-assessment-results: input is not an assessment-results document (root key is not 'assessment-results')",
    );
  }

  const sar = doc['assessment-results'];
  const meta = extractMetadata(sar.metadata);

  // One conversion-time value, shared as the startTime fallback for any
  // finding whose OSCAL result lacks a usable start.
  const scanTime = new Date();

  // Skip results with no findings — an empty baseline would violate the
  // schema's requirements.minItems=1. Mirrors the Go SAR converter.
  const baselines: EvaluatedBaseline[] = [];
  for (const result of sar.results) {
    if (!result.findings || result.findings.length === 0) {
      // eslint-disable-next-line no-console
      console.warn(
        `WARNING: Skipping assessment result "${result.title || result.uuid}": no findings (empty result set)`,
      );
      continue;
    }
    const baseline = await resultToEvaluatedBaseline(result, sar, input, scanTime);
    baselines.push(baseline);
  }

  // Extract planRef from import-ap
  const planRef = sar['import-ap']?.href || undefined;

  // Parse timestamp from metadata
  let timestamp: Date | undefined;
  if (meta.lastModified) {
    const t = parseTimestamp(meta.lastModified);
    if (t) {
      timestamp = t;
    }
  }

  const hdf: HDFResults = {
    baselines,
    generator: {
      name: 'oscal-assessment-results-to-hdf',
      version: '1.0.0',
    },
    tool: {
      name: 'OSCAL Assessment Results',
      format: 'OSCAL',
    },
    timestamp: timestamp ?? new Date(),
    planRef,
  };

  return serializeHdf(hdf);
}

async function resultToEvaluatedBaseline(
  result: AssessmentResult,
  sar: SecurityAssessmentResultsSAR,
  rawInput: string,
  scanTime: Date,
): Promise<EvaluatedBaseline> {
  const checksum = await inputChecksum(rawInput);

  // Build lookup maps for observations and risks
  const obsMap = buildObservationMap(result.observations ?? []);
  const riskMap = buildRiskMap(result.risks ?? []);

  // Group findings by control ID, preserving insertion order
  const controlOrder: string[] = [];
  const controlMap = new Map<string, Finding[]>();

  for (const f of result.findings ?? []) {
    const controlId = extractControlIdFromFinding(f);
    const existing = controlMap.get(controlId);
    if (existing) {
      existing.push(f);
    } else {
      controlOrder.push(controlId);
      controlMap.set(controlId, [f]);
    }
  }

  // Build requirements in insertion order
  const requirements: EvaluatedRequirement[] = [];
  for (const controlId of controlOrder) {
    const findings = controlMap.get(controlId)!;
    const req = findingsToEvaluatedRequirement(controlId, findings, obsMap, riskMap, result, scanTime);
    requirements.push(req);
  }

  // Derive baseline name
  const name = sarBaselineName(result, sar);

  const baseline = createMinimalBaseline(name, requirements, {
    resultsChecksum: checksum,
    integrity: await inputIntegrity(rawInput),
    status: 'loaded',
    title: result.title,
  }) as EvaluatedBaseline;

  if (result.description) {
    (baseline as Record<string, unknown>).description = result.description;
  }

  return baseline;
}

function findingsToEvaluatedRequirement(
  controlId: string,
  findings: Finding[],
  obsMap: Map<string, Observation>,
  riskMap: Map<string, IdentifiedRisk>,
  result: AssessmentResult,
  scanTime: Date,
): EvaluatedRequirement {
  const nistTag = controlIdToNistTag(controlId);

  // Use the first finding for title
  const firstFinding = findings[0]!;
  const title = firstFinding.title || nistTag;

  // Determine impact from related risks
  const impact = sarFindingsImpact(findings, riskMap);

  // Build descriptions from findings, observations, and related risks
  const descriptions = sarBuildDescriptions(findings, obsMap, riskMap);

  // Build external references from observation relevant-evidence
  const refs = sarBuildRefs(findings, obsMap);

  // Build results from each finding
  const results: RequirementResult[] = [];
  for (const f of findings) {
    results.push(findingToRequirementResult(f, obsMap, riskMap, result, scanTime));
  }

  // tags.nist carries the finding's NIST control; tags.cci is derived from it
  // via the standard NIST→CCI mapping (omitted when the control maps to none),
  // matching how sibling converters emit both.
  const nistTags = [nistTag];
  const tags: Record<string, unknown> = buildNistCciTags(nistTags, nistToCci(nistTags));

  const req = createRequirement(nistTag, title, descriptions, impact, results, {
    tags,
    ...(refs ? { refs } : {}),
  }) as EvaluatedRequirement;
  const controlType = deriveControlTypeFromTags(nistTags);
  if (controlType !== undefined) req.controlType = controlType;
  return req;
}

function findingToRequirementResult(
  f: Finding,
  obsMap: Map<string, Observation>,
  riskMap: Map<string, IdentifiedRisk>,
  result: AssessmentResult,
  scanTime: Date,
): RequirementResult {
  const status = mapFindingStatus(f);
  const codeDesc = buildCodeDesc(f, obsMap);
  const message = buildRiskMessage(f, riskMap);
  // startTime: prefer the earliest observation `collected` time correlated to
  // this finding via related-observations; fall back to the result's
  // assessment-period start, then to the single conversion-time value.
  const obsTime = findingStartTime(f, obsMap);
  const resultTime = parseResultStartTime(result);
  let startTime: Date;
  if (obsTime) {
    startTime = obsTime;
  } else if (resultTime.getTime() > 0) {
    startTime = resultTime;
  } else {
    startTime = scanTime;
  }

  return createResult(status, message || undefined, {
    codeDesc,
    startTime,
  });
}

function extractControlIdFromFinding(f: Finding): string {
  const targetId = f.target['target-id'];
  if (!targetId) return 'unknown';

  // For objective-id and statement-id, extract the base control ID
  let controlId = extractControlIdFromObjectiveId(targetId);

  // Handle statement-id format: "au-1_smt.a" -> "au-1"
  const idx = controlId.indexOf('_');
  if (idx > 0) {
    controlId = controlId.slice(0, idx);
  }

  return controlId;
}

function mapFindingStatus(f: Finding): ResultStatus {
  const status = oscalStatusToHdf(f.target.status.state);
  if (status === 'passed') return ResultStatus.Passed;
  if (status === 'failed') return ResultStatus.Failed;
  return ResultStatus.NotReviewed;
}

function buildCodeDesc(f: Finding, obsMap: Map<string, Observation>): string {
  const parts: string[] = [];

  for (const ref of f['related-observations'] ?? []) {
    const obsUuid = ref['observation-uuid'];
    if (!obsUuid) continue;
    const obs = obsMap.get(obsUuid);
    if (!obs) continue;

    if (obs.methods && obs.methods.length > 0) {
      parts.push('Methods: ' + obs.methods.join(', '));
    }

    for (const subj of obs.subjects ?? []) {
      let subjDesc = subj.type;
      if (subj.title) {
        subjDesc = subj.title + ' (' + subj.type + ')';
      }
      parts.push('Subject: ' + subjDesc);
    }
  }

  if (parts.length === 0) return f.title;

  return parts.join('; ');
}

function buildRiskMessage(f: Finding, riskMap: Map<string, IdentifiedRisk>): string {
  const messages: string[] = [];

  for (const ref of f['related-risks'] ?? []) {
    const riskUuid = ref['risk-uuid'];
    if (!riskUuid) continue;
    const risk = riskMap.get(riskUuid);
    if (!risk) continue;

    let msg = risk.title;
    if (risk.description) {
      msg += ': ' + risk.description;
    }
    messages.push(msg);
  }

  return messages.join('\n');
}

function sarFindingsImpact(
  findings: Finding[],
  riskMap: Map<string, IdentifiedRisk>,
): number {
  let highestImpact = -1.0;

  for (const f of findings) {
    for (const ref of f['related-risks'] ?? []) {
      const riskUuid = ref['risk-uuid'];
      if (!riskUuid) continue;
      const risk = riskMap.get(riskUuid);
      if (!risk) continue;
      const impact = extractRiskSeverity(risk.characterizations, -1.0);
      if (impact > highestImpact) {
        highestImpact = impact;
      }
    }
  }

  if (highestImpact < 0) return 0.5; // default medium impact
  return highestImpact;
}

function sarBuildDescriptions(
  findings: Finding[],
  obsMap: Map<string, Observation>,
  riskMap: Map<string, IdentifiedRisk>,
): Description[] {
  const descriptions: Description[] = [];

  // Default description from finding descriptions
  const findingDescs: string[] = [];
  for (const f of findings) {
    if (f.description) {
      findingDescs.push(f.description);
    }
  }
  descriptions.push({
    label: 'default',
    data: findingDescs.join('\n') || '',
  });

  // Rationale from observation descriptions
  const obsDescs: string[] = [];
  const seen = new Set<string>();
  for (const f of findings) {
    for (const ref of f['related-observations'] ?? []) {
      const obsUuid = ref['observation-uuid'];
      if (!obsUuid || seen.has(obsUuid)) continue;
      seen.add(obsUuid);
      const obs = obsMap.get(obsUuid);
      if (obs?.description) {
        obsDescs.push(obs.description);
      }
    }
  }
  if (obsDescs.length > 0) {
    descriptions.push({
      label: 'rationale',
      data: obsDescs.join('\n'),
    });
  }

  // Risk statement text from related risks.
  const statement = collectRiskStatements(findings, riskMap);
  if (statement) {
    descriptions.push({ label: 'statement', data: statement });
  }

  // Recommended remediation text from related risks.
  const remediation = collectRemediations(findings, riskMap);
  if (remediation) {
    descriptions.push({ label: 'remediation', data: remediation });
  }

  // Relevant-evidence prose from related observations.
  const evidence = collectEvidenceDescriptions(findings, obsMap);
  if (evidence) {
    descriptions.push({ label: 'evidence', data: evidence });
  }

  return descriptions;
}

function collectRiskStatements(
  findings: Finding[],
  riskMap: Map<string, IdentifiedRisk>,
): string {
  const statements: string[] = [];
  const seen = new Set<string>();
  for (const f of findings) {
    for (const ref of f['related-risks'] ?? []) {
      const riskUuid = ref['risk-uuid'];
      if (!riskUuid || seen.has(riskUuid)) continue;
      seen.add(riskUuid);
      const risk = riskMap.get(riskUuid);
      if (risk?.statement) {
        statements.push(risk.statement);
      }
    }
  }
  return statements.join('\n');
}

function collectRemediations(
  findings: Finding[],
  riskMap: Map<string, IdentifiedRisk>,
): string {
  const remediations: string[] = [];
  const seen = new Set<string>();
  for (const f of findings) {
    for (const ref of f['related-risks'] ?? []) {
      const riskUuid = ref['risk-uuid'];
      if (!riskUuid || seen.has(riskUuid)) continue;
      seen.add(riskUuid);
      const risk = riskMap.get(riskUuid);
      for (const rem of risk?.remediations ?? []) {
        const text = remediationText(rem);
        if (text) remediations.push(text);
      }
    }
  }
  return remediations.join('\n\n');
}

function remediationText(rem: RiskResponse): string {
  if (rem.title && rem.description) return rem.title + ': ' + rem.description;
  if (rem.title) return rem.title;
  return rem.description ?? '';
}

function collectEvidenceDescriptions(
  findings: Finding[],
  obsMap: Map<string, Observation>,
): string {
  const descs: string[] = [];
  const seenObs = new Set<string>();
  const seenText = new Set<string>();
  for (const f of findings) {
    for (const ref of f['related-observations'] ?? []) {
      const obsUuid = ref['observation-uuid'];
      if (!obsUuid || seenObs.has(obsUuid)) continue;
      seenObs.add(obsUuid);
      const obs = obsMap.get(obsUuid);
      for (const ev of obs?.['relevant-evidence'] ?? []) {
        if (!ev.description || seenText.has(ev.description)) continue;
        seenText.add(ev.description);
        descs.push(ev.description);
      }
    }
  }
  return descs.join('\n');
}

// Builds external references from observation relevant-evidence hrefs. Only
// resolvable URLs (with a "scheme://" prefix) become references; intra-document
// fragment hrefs ("#uuid") are skipped. URLs are deduplicated. Returns
// undefined when the source carries none.
function sarBuildRefs(
  findings: Finding[],
  obsMap: Map<string, Observation>,
): Reference[] | undefined {
  const refs: Reference[] = [];
  const seenObs = new Set<string>();
  const seenUrl = new Set<string>();
  for (const f of findings) {
    for (const ref of f['related-observations'] ?? []) {
      const obsUuid = ref['observation-uuid'];
      if (!obsUuid || seenObs.has(obsUuid)) continue;
      seenObs.add(obsUuid);
      const obs = obsMap.get(obsUuid);
      for (const ev of obs?.['relevant-evidence'] ?? []) {
        const href = ev.href;
        if (!href || !isResolvableUrl(href) || seenUrl.has(href)) continue;
        seenUrl.add(href);
        refs.push({ url: href });
      }
    }
  }
  return refs.length > 0 ? refs : undefined;
}

function isResolvableUrl(href: string): boolean {
  return href.includes('://');
}

function buildObservationMap(observations: Observation[]): Map<string, Observation> {
  const m = new Map<string, Observation>();
  for (const obs of observations) {
    m.set(obs.uuid, obs);
  }
  return m;
}

function buildRiskMap(risks: IdentifiedRisk[]): Map<string, IdentifiedRisk> {
  const m = new Map<string, IdentifiedRisk>();
  for (const risk of risks) {
    m.set(risk.uuid, risk);
  }
  return m;
}

// Lifts the earliest observation `collected` time across the finding's related
// observations (correlated by observation UUID). Empty or unparseable
// `collected` values are skipped — mirrors the Go zero-time sentinel skip so
// both languages agree. Returns undefined when no correlated observation
// carries a usable collected time.
function findingStartTime(f: Finding, obsMap: Map<string, Observation>): Date | undefined {
  let earliest: Date | undefined;
  for (const ref of f['related-observations'] ?? []) {
    const obsUuid = ref['observation-uuid'];
    if (!obsUuid) continue;
    const obs = obsMap.get(obsUuid);
    if (!obs || obs.collected == null) continue;
    // Generator types collected as Date, but it is a string at runtime; coerce
    // so parseTimestamp applies canonical UTC handling.
    const t = parseTimestamp(String(obs.collected));
    if (!t) continue;
    if (!earliest || t.getTime() < earliest.getTime()) {
      earliest = t;
    }
  }
  return earliest;
}

function parseResultStartTime(result: AssessmentResult): Date {
  if (result.start) {
    // Generator types this as Date, but it is a string at runtime (parsed
    // without a Date reviver); coerce so parseTimestamp applies UTC handling.
    const t = parseTimestamp(String(result.start));
    if (t) {
      return t;
    }
  }
  return new Date(0);
}

function sarBaselineName(result: AssessmentResult, sar: SecurityAssessmentResultsSAR): string {
  const title = result.title || sar.metadata.title;
  return toKebabCase(title, 'oscal-assessment-results');
}
