/**
 * Converts HDF Results to OSCAL Assessment Results (SAR) format.
 *
 * This is the reverse direction of the oscal-to-hdf SAR converter. It takes HDF
 * Results JSON and produces an OSCAL 1.1.2 assessment-results JSON document.
 */

import { parseJSON } from '@mitre/hdf-utilities';
import type { HdfResults, EvaluatedBaseline, EvaluatedRequirement, Description, RequirementResult } from '@mitre/hdf-schema';
import type {
  AssessmentResults,
  Metadata,
  ImportAP,
  Result,
  Finding,
  FindingTarget,
  TargetStatus,
  Observation,
  Risk,
  Property,
} from '../../oscal-to-hdf/typescript/types.js';

/** OSCAL specification version used in output documents. */
const OSCAL_VERSION = '1.1.2';

/** Matches NIST 800-53 tags with enhancements like "AC-2 (3)". */
const nistEnhancementRe = /^([A-Z]{2}-\d+)\s*\((\d+)\)$/;

/** Root wrapper for the output JSON. */
interface OscalSARDocument {
  'assessment-results': AssessmentResults;
}

/**
 * Convert HDF Results JSON to OSCAL Assessment Results (SAR) JSON.
 *
 * @param input - HDF Results JSON string
 * @returns OSCAL SAR JSON string
 */
export async function convertHdfToOscalSar(input: string): Promise<string> {
  if (!input || input.trim().length === 0) {
    throw new Error('hdf-to-oscal-sar: empty input');
  }

  let hdfResults: HdfResults;
  try {
    hdfResults = parseJSON<HdfResults>(input);
  } catch {
    throw new Error('hdf-to-oscal-sar: failed to parse HDF JSON');
  }

  if (!hdfResults || typeof hdfResults !== 'object' || !('baselines' in hdfResults)) {
    throw new Error('hdf-to-oscal-sar: invalid HDF structure: missing baselines field');
  }

  const doc = buildOSCALDocument(hdfResults);
  return JSON.stringify(doc, null, 2);
}

/**
 * Constructs the full OSCAL assessment-results document from HDF results.
 */
function buildOSCALDocument(hdfResults: HdfResults): OscalSARDocument {
  let timestamp = new Date().toISOString();
  if (hdfResults.timestamp) {
    timestamp = typeof hdfResults.timestamp === 'string'
      ? hdfResults.timestamp
      : hdfResults.timestamp.toISOString();
  }

  const metadata: Metadata = {
    title: 'HDF Assessment Results Export',
    'last-modified': timestamp,
    version: '1.0.0',
    'oscal-version': OSCAL_VERSION,
  };

  let importAP: ImportAP;
  if (hdfResults.planRef && hdfResults.planRef !== '') {
    importAP = { href: hdfResults.planRef };
  } else {
    importAP = { href: '#' };
  }

  const results: Result[] = [];
  for (const baseline of hdfResults.baselines) {
    results.push(baselineToResult(baseline, timestamp));
  }

  return {
    'assessment-results': {
      uuid: crypto.randomUUID(),
      metadata,
      'import-ap': importAP,
      results,
    },
  };
}

/**
 * Converts a single EvaluatedBaseline to an OSCAL Result.
 */
function baselineToResult(baseline: EvaluatedBaseline, timestamp: string): Result {
  let title = baseline.name;
  if (baseline.title && baseline.title !== '') {
    title = baseline.title;
  }

  let description: string | undefined = 'Converted from HDF results';
  if (baseline.description && baseline.description !== '') {
    description = baseline.description;
  }

  const findings: Finding[] = [];
  const observations: Observation[] = [];
  const risks: Risk[] = [];

  for (const req of baseline.requirements) {
    const { finding, observation, risk } = requirementToFindingSet(req, timestamp);
    findings.push(finding);
    if (observation) {
      observations.push(observation);
    }
    if (risk) {
      risks.push(risk);
    }
  }

  const result: Result = {
    uuid: crypto.randomUUID(),
    title,
    description,
    start: timestamp,
    findings,
    observations,
    risks,
  };

  return result;
}

/**
 * Converts an EvaluatedRequirement into a Finding, optional Observation, and optional Risk.
 */
function requirementToFindingSet(
  req: EvaluatedRequirement,
  timestamp: string,
): { finding: Finding; observation: Observation | undefined; risk: Risk | undefined } {
  const controlID = nistTagToControlID(req.id);
  const { state, reason } = aggregateStatus(req.results);
  const findingDesc = extractDefaultDescription(req.descriptions);

  // Build props from NIST tags
  const props: Property[] = [];
  if (req.tags) {
    const nistRaw = req.tags['nist'];
    if (Array.isArray(nistRaw)) {
      for (const v of nistRaw) {
        if (typeof v === 'string') {
          props.push({ name: 'nist', value: v });
        }
      }
    }
  }

  let title = req.id;
  if (req.title && req.title !== '') {
    title = req.title;
  }

  const targetStatus: TargetStatus = { state };
  if (reason) {
    targetStatus.reason = reason;
  }

  const target: FindingTarget = {
    type: 'objective-id',
    'target-id': controlID,
    status: targetStatus,
  };

  const finding: Finding = {
    uuid: crypto.randomUUID(),
    title,
    description: findingDesc || undefined,
    props: props.length > 0 ? props : undefined,
    target,
  };

  // Build observation from requirement results
  let observation: Observation | undefined;
  if (req.results.length > 0) {
    const obsUUID = crypto.randomUUID();
    const obsDesc = buildObservationDescription(req.results);
    observation = {
      uuid: obsUUID,
      description: obsDesc,
      methods: ['TEST'],
      collected: timestamp,
    };
    finding['related-observations'] = [{ 'observation-uuid': obsUUID }];
  }

  // Build risk from impact
  let risk: Risk | undefined;
  if (req.impact > 0) {
    const riskUUID = crypto.randomUUID();
    const severity = impactToSeverity(req.impact);
    risk = {
      uuid: riskUUID,
      title: `Risk for ${req.id}`,
      description: `Impact: ${req.impact.toFixed(1)} (${severity})`,
      status: riskStatusFromState(state),
      characterizations: [
        {
          facets: [
            {
              name: 'impact',
              system: 'https://fedramp.gov',
              value: severity,
            },
          ],
        },
      ],
    };
    finding['related-risks'] = [{ 'risk-uuid': riskUUID }];
  }

  return { finding, observation, risk };
}

/**
 * Converts NIST 800-53 notation back to OSCAL control ID.
 * "AC-1" -> "ac-1", "AC-2 (3)" -> "ac-2.3"
 */
export function nistTagToControlID(tag: string): string {
  const m = nistEnhancementRe.exec(tag);
  if (m) {
    return `${m[1]!.toLowerCase()}.${m[2]!}`;
  }
  return tag.toLowerCase();
}

/**
 * Determines the overall finding status from requirement results.
 */
export function aggregateStatus(results: RequirementResult[]): { state: string; reason: string } {
  if (results.length === 0) {
    return { state: 'not-satisfied', reason: 'other' };
  }

  let hasFailed = false;
  let hasError = false;
  let hasNotReviewed = false;
  let hasNotApplicable = false;
  let allPassed = true;

  for (const r of results) {
    switch (r.status) {
      case 'passed':
        break;
      case 'failed':
        hasFailed = true;
        allPassed = false;
        break;
      case 'error':
        hasError = true;
        allPassed = false;
        break;
      case 'notReviewed':
        hasNotReviewed = true;
        allPassed = false;
        break;
      case 'notApplicable':
        hasNotApplicable = true;
        allPassed = false;
        break;
      default:
        allPassed = false;
        break;
    }
  }

  if (allPassed) {
    return { state: 'satisfied', reason: '' };
  }
  if (hasFailed || hasError) {
    return { state: 'not-satisfied', reason: '' };
  }
  if (hasNotReviewed) {
    return { state: 'not-satisfied', reason: 'other' };
  }
  if (hasNotApplicable) {
    return { state: 'not-satisfied', reason: 'not-applicable' };
  }
  return { state: 'not-satisfied', reason: '' };
}

/**
 * Finds the "default" labeled description.
 */
function extractDefaultDescription(descriptions: Description[]): string {
  for (const d of descriptions) {
    if (d.label === 'default') {
      return d.data;
    }
  }
  if (descriptions.length > 0) {
    return descriptions[0]!.data;
  }
  return '';
}

/**
 * Concatenates result code descriptions and messages.
 */
function buildObservationDescription(results: RequirementResult[]): string {
  const parts: string[] = [];
  for (const r of results) {
    let desc = `[${r.status}] ${r.codeDesc}`;
    if (r.message && r.message !== '') {
      desc += ': ' + r.message;
    }
    parts.push(desc);
  }
  if (parts.length === 0) {
    return 'No observations recorded';
  }
  return parts.join('\n');
}

/**
 * Converts a 0.0-1.0 impact value to an OSCAL severity string.
 */
export function impactToSeverity(impact: number): string {
  if (impact >= 0.9) return 'critical';
  if (impact >= 0.7) return 'high';
  if (impact >= 0.4) return 'moderate';
  if (impact >= 0.1) return 'low';
  return 'info';
}

/**
 * Maps OSCAL finding state to risk status.
 */
function riskStatusFromState(state: string): string {
  if (state === 'satisfied') {
    return 'closed';
  }
  return 'open';
}
