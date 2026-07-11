/**
 * Converts HDF Results to OSCAL Assessment Results (SAR) format.
 *
 * This is the reverse direction of the oscal-to-hdf SAR converter. It takes HDF
 * Results JSON and produces an OSCAL 1.1.2 assessment-results JSON document.
 */

import { parseJSON } from '@mitre/hdf-utilities';
import { validateInputSize } from '../../../shared/typescript/converterutil.js';
import type { HDFResults, EvaluatedBaseline, EvaluatedRequirement, Description, RequirementResult } from '@mitre/hdf-schema';
import type {
  SecurityAssessmentResultsSAR,
  DocumentMetadata,
  ImportAssessmentPlan,
  AssessmentResult,
  Finding,
  TargetClass,
  StatusClass,
  Observation,
  IdentifiedRisk,
  Property,
  Link,
} from '../../oscal-to-hdf/typescript/types.js';
import {
  nistTagToControlId,
  impactToSeverity,
  OSCAL_VERSION,
} from '../../oscal-to-hdf/typescript/shared.js';

/** Root wrapper for the output JSON. */
interface OscalSARDocument {
  'assessment-results': SecurityAssessmentResultsSAR;
}

/**
 * Convert HDF Results JSON to OSCAL Assessment Results (SAR) JSON.
 *
 * @param input - HDF Results JSON string
 * @returns OSCAL SAR JSON string
 */
export async function convertHdfToOscalSar(input: string): Promise<string> {
  validateInputSize(input, 'hdf-to-oscal-sar');

  if (!input || input.trim().length === 0) {
    throw new Error('hdf-to-oscal-sar: empty input');
  }

  let hdfResults: HDFResults;
  try {
    hdfResults = parseJSON<HDFResults>(input);
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
function buildOSCALDocument(hdfResults: HDFResults): OscalSARDocument {
  let timestamp = new Date().toISOString();
  if (hdfResults.timestamp) {
    timestamp = typeof hdfResults.timestamp === 'string'
      ? hdfResults.timestamp
      : hdfResults.timestamp.toISOString();
  }

  const metadata = {
    title: 'HDF Assessment Results Export',
    'last-modified': timestamp,
    version: '1.0.0',
    'oscal-version': OSCAL_VERSION,
  } as unknown as DocumentMetadata;

  let importAP: ImportAssessmentPlan;
  if (hdfResults.planRef && hdfResults.planRef !== '') {
    importAP = { href: hdfResults.planRef };
  } else {
    importAP = { href: '#' };
  }

  const results: AssessmentResult[] = [];
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
function baselineToResult(baseline: EvaluatedBaseline, timestamp: string): AssessmentResult {
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
  const risks: IdentifiedRisk[] = [];

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

  const result = {
    uuid: crypto.randomUUID(),
    title,
    description,
    start: timestamp,
    findings,
    observations,
    risks,
  } as unknown as AssessmentResult;

  return result;
}

/**
 * Converts an EvaluatedRequirement into a Finding, optional Observation, and optional Risk.
 */
function requirementToFindingSet(
  req: EvaluatedRequirement,
  timestamp: string,
): { finding: Finding; observation: Observation | undefined; risk: IdentifiedRisk | undefined } {
  const controlID = nistTagToControlId(req.id);
  const { state, reason } = aggregateStatus(req.results);
  const findingDesc = extractDefaultDescription(req.descriptions);

  // Build props from control mappings (nist/cci), source code, non-default
  // descriptions (check/fix/rationale), and v3.2 classification fields.
  const props: Property[] = [];
  const pushTagValues = (key: string): void => {
    const raw = req.tags?.[key];
    if (Array.isArray(raw)) {
      for (const v of raw) if (typeof v === 'string') props.push({ name: key, value: v });
    }
  };
  pushTagValues('nist');
  pushTagValues('cci');
  if (req.code) props.push({ name: 'code', value: req.code });
  for (const label of ['check', 'fix', 'rationale']) {
    const d = req.descriptions.find((x) => x.label === label);
    if (d) props.push({ name: label, value: d.data });
  }
  if (req.controlType) props.push({ name: 'control-type', value: req.controlType });
  if (req.verificationMethod) props.push({ name: 'verification-method', value: req.verificationMethod });
  if (req.applicability) props.push({ name: 'applicability', value: req.applicability });

  // refs: url/uri become OSCAL links; a plain string ref becomes a prop (not a valid href).
  const links: Link[] = [];
  if (Array.isArray(req.refs)) {
    for (const r of req.refs) {
      const o = r as { url?: unknown; uri?: unknown; ref?: unknown };
      if (typeof o.url === 'string') links.push({ href: o.url, rel: 'reference' });
      else if (typeof o.uri === 'string') links.push({ href: o.uri, rel: 'reference' });
      else if (typeof o.ref === 'string') props.push({ name: 'reference', value: o.ref });
    }
  }

  let title = req.id;
  if (req.title && req.title !== '') {
    title = req.title;
  }

  const targetStatus: StatusClass = { state } as unknown as StatusClass;
  if (reason) {
    targetStatus.reason = reason;
  }

  const target = {
    type: 'objective-id',
    'target-id': controlID,
    status: targetStatus,
  } as unknown as TargetClass;

  const finding = {
    uuid: crypto.randomUUID(),
    title,
    description: findingDesc || '',
    props: props.length > 0 ? props : undefined,
    links: links.length > 0 ? links : undefined,
    target,
  } as Finding;

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
    } as unknown as Observation;
    finding['related-observations'] = [{ 'observation-uuid': obsUUID }];
  }

  // Build risk from impact
  let risk: IdentifiedRisk | undefined;
  if (req.impact > 0) {
    const riskUUID = crypto.randomUUID();
    const severity = impactToSeverity(req.impact);
    risk = {
      uuid: riskUUID,
      title: `Risk for ${req.id}`,
      description: `Impact: ${req.impact.toFixed(1)} (${severity})`,
      statement: `Impact: ${req.impact.toFixed(1)} (${severity})`,
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
    } as unknown as IdentifiedRisk;
    finding['related-risks'] = [{ 'risk-uuid': riskUUID }];
  }

  return { finding, observation, risk };
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
 * Maps OSCAL finding state to risk status.
 */
function riskStatusFromState(state: string): string {
  if (state === 'satisfied') {
    return 'closed';
  }
  return 'open';
}
