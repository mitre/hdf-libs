/**
 * OSCAL Assessment Results (SAR) to HDF Results converter.
 *
 * Mirrors the Go implementation in converters/oscal-to-hdf/go/converter_sar.go.
 */

import { parseJSON, parseTimestamp } from '@mitre/hdf-utilities';
import { deriveControlTypeFromTags, inputChecksum, inputIntegrity, serializeHdf, validateInputSize } from '../../../shared/typescript/converterutil.js';
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
} from '@mitre/hdf-schema';
import type {
  Oscal,
  SecurityAssessmentResultsSAR,
  AssessmentResult,
  Finding,
  Observation,
  IdentifiedRisk,
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

  // Build descriptions from findings and observations
  const descriptions = sarBuildDescriptions(findings, obsMap);

  // Build results from each finding
  const results: RequirementResult[] = [];
  for (const f of findings) {
    results.push(findingToRequirementResult(f, obsMap, riskMap, result, scanTime));
  }

  const tags: Record<string, unknown> = {
    nist: [nistTag],
  };

  const req = createRequirement(nistTag, title, descriptions, impact, results, { tags }) as EvaluatedRequirement;
  const controlType = deriveControlTypeFromTags([nistTag]);
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
  // The OSCAL result's assessment-period start applies to all its findings;
  // fall back to the single conversion-time value when the source omits it.
  const startTime = parseResultStartTime(result);

  return createResult(status, message || undefined, {
    codeDesc,
    startTime: startTime.getTime() > 0 ? startTime : scanTime,
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

  return descriptions;
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
