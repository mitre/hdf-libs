/**
 * Converts HDF Results to OSCAL Assessment Results (SAR) format.
 *
 * This is the reverse direction of the oscal-to-hdf SAR converter. It takes HDF
 * Results JSON and produces an OSCAL 1.1.2 assessment-results JSON document.
 */

import { formatTimestampSeconds } from '@mitre/hdf-utilities';
import { validateInputSize, parseHdf, hdfTime } from '../../../shared/typescript/converterutil.js';
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
  Resource,
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
    hdfResults = parseHdf<HDFResults>(input);
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
 * Human-readable assessment-tool label from the HDF tool/generator identity,
 * falling back when neither is present.
 */
function toolPartyName(hdfResults: HDFResults): string {
  const tool = hdfResults.tool;
  if (tool?.name) {
    return tool.version ? `${tool.name} ${tool.version}` : tool.name;
  }
  const gen = hdfResults.generator;
  if (gen?.name) {
    return gen.version ? `${gen.name} ${gen.version}` : gen.name;
  }
  return 'HDF Assessment Tool';
}

/**
 * Constructs the full OSCAL assessment-results document from HDF results.
 */
function buildOSCALDocument(hdfResults: HDFResults): OscalSARDocument {
  // Whole-second RFC3339 in UTC, matching what the Go converter emits.
  let timestamp = formatTimestampSeconds(new Date());
  const documentTime = hdfTime(hdfResults.timestamp);
  if (documentTime) {
    timestamp = formatTimestampSeconds(documentTime);
  }

  // Define the assessment tool once for the whole document and reference its
  // single UUID from every characterization origin, so each actor-uuid resolves
  // to a party defined in the same document (OSCAL referential integrity, which
  // the JSON schema alone does not enforce). Sourced from the HDF tool identity.
  const toolActorUuid = crypto.randomUUID();
  const metadata = {
    title: 'HDF Assessment Results Export',
    'last-modified': timestamp,
    version: '1.0.0',
    'oscal-version': OSCAL_VERSION,
    parties: [{ uuid: toolActorUuid, type: 'organization', name: toolPartyName(hdfResults) }],
  } as unknown as DocumentMetadata;

  let importAP: ImportAssessmentPlan;
  if (hdfResults.planRef && hdfResults.planRef !== '') {
    importAP = { href: hdfResults.planRef };
  } else {
    importAP = { href: '#' };
  }

  // Assessed-asset identity: top-level components[] become the subjects attached
  // to every observation. Built once so all observations share the same subject
  // identity (and subject-uuid) for a given component.
  const subjects = buildSubjects(hdfResults.components);

  // Build results from baselines, collecting the back-matter resources
  // (embedded check source code) their findings link to.
  const results: AssessmentResult[] = [];
  const resources: Resource[] = [];
  for (const baseline of hdfResults.baselines) {
    const { result, resources: baselineResources } = baselineToResult(baseline, timestamp, toolActorUuid, subjects);
    results.push(result);
    resources.push(...baselineResources);
  }

  return {
    'assessment-results': {
      uuid: crypto.randomUUID(),
      metadata,
      'import-ap': importAP,
      results,
      ...(resources.length > 0 ? { 'back-matter': { resources } } : {}),
    },
  };
}

// Assessment-time helpers. OSCAL result.start (when the assessment ran) and
// observation.collected (when the evidence was gathered) both describe the scan,
// which HDF carries on each requirement result — not the document timestamp,
// which is merely when the file was written.

/** Earliest startTime across the results, or undefined if none carry one. */
function earliestResultTime(results: RequirementResult[] | undefined): Date | undefined {
  let earliest: Date | undefined;

  for (const result of results ?? []) {
    const parsed = hdfTime(result.startTime);
    if (!parsed) continue;

    if (earliest === undefined || parsed < earliest) {
      earliest = parsed;
    }
  }

  return earliest;
}

/**
 * Render an assessment time. OSCAL requires result.start and
 * observation.collected, so a fallback is needed when HDF carries no result time
 * — but it must never win over a real one.
 */
function formatAssessmentTime(time: Date | undefined, fallback: string): string {
  return time === undefined ? fallback : formatTimestampSeconds(time);
}

/** When the assessment ran: the earliest result time anywhere in the baseline. */
function assessmentStart(baseline: EvaluatedBaseline, fallback: string): string {
  let earliest: Date | undefined;

  for (const req of baseline.requirements) {
    const reqEarliest = earliestResultTime(req.results);
    if (reqEarliest === undefined) continue;

    if (earliest === undefined || reqEarliest < earliest) {
      earliest = reqEarliest;
    }
  }

  return formatAssessmentTime(earliest, fallback);
}

/**
 * Converts a single EvaluatedBaseline to an OSCAL Result plus any back-matter
 * resources (embedded check source code) its findings link to.
 */
function baselineToResult(
  baseline: EvaluatedBaseline,
  timestamp: string,
  toolActorUuid: string,
  subjects: SubjectRef[],
): { result: AssessmentResult; resources: Resource[] } {
  let title = baseline.name;
  if (baseline.title && baseline.title !== '') {
    title = baseline.title;
  }

  let description: string | undefined = 'Converted from HDF results';
  if (baseline.description && baseline.description !== '') {
    description = baseline.description;
  }

  // baseline.version has no first-class SAR home; carry it as a result prop.
  const resultProps: Property[] = [];
  if (baseline.version && baseline.version !== '') {
    resultProps.push({ name: 'baseline-version', value: baseline.version });
  }

  const findings: Finding[] = [];
  const observations: Observation[] = [];
  const risks: IdentifiedRisk[] = [];
  const resources: Resource[] = [];

  // OSCAL requires result.reviewed-controls: the set of controls assessed.
  // Populate it from the control each requirement targets (deduped).
  const includeControls: Array<{ 'control-id': string }> = [];
  const seenControl = new Set<string>();

  for (const req of baseline.requirements) {
    const { finding, observation, risk, resource } = requirementToFindingSet(req, timestamp, toolActorUuid, subjects);
    findings.push(finding);
    if (observation) {
      observations.push(observation);
    }
    if (risk) {
      risks.push(risk);
    }
    if (resource) {
      resources.push(resource);
    }
    const cid = nistTagToControlId(req.id);
    if (cid !== '' && !seenControl.has(cid)) {
      seenControl.add(cid);
      includeControls.push({ 'control-id': cid });
    }
  }

  // Match Go's omitempty: an empty include-controls list collapses to {}.
  const controlSelection = includeControls.length > 0 ? { 'include-controls': includeControls } : {};

  const result = {
    uuid: crypto.randomUUID(),
    title,
    description,
    start: assessmentStart(baseline, timestamp),
    // Match Go's omitempty: an empty props list is omitted entirely.
    ...(resultProps.length > 0 ? { props: resultProps } : {}),
    'reviewed-controls': { 'control-selections': [controlSelection] },
    findings,
    observations,
    risks,
  } as unknown as AssessmentResult;

  return { result, resources };
}

/** OSCAL subject reference derived from a top-level HDF component. */
interface SubjectRef {
  'subject-uuid': string;
  type: string;
  title: string;
}

/**
 * Turns the top-level HDF components[] into OSCAL assessment subjects. Each
 * component's UUID (componentId when present, otherwise a fresh one) identifies
 * the subject; the HDF component type is a valid OSCAL subject type token and
 * its name becomes the subject title.
 */
function buildSubjects(components: HDFResults['components']): SubjectRef[] {
  if (!Array.isArray(components) || components.length === 0) return [];
  return components.map((c) => ({
    'subject-uuid': c.componentId && c.componentId !== '' ? c.componentId : crypto.randomUUID(),
    type: String(c.type),
    title: c.name,
  }));
}

/**
 * Converts an EvaluatedRequirement into a Finding, optional Observation, and optional Risk.
 */
function requirementToFindingSet(
  req: EvaluatedRequirement,
  timestamp: string,
  toolActorUuid: string,
  subjects: SubjectRef[],
): { finding: Finding; observation: Observation | undefined; risk: IdentifiedRisk | undefined; resource: Resource | undefined } {
  const controlID = nistTagToControlId(req.id);
  // results/descriptions are optional and absent on real minimal HDF; normalize
  // to arrays so this converter matches the Go implementation, which ranges nil
  // slices safely rather than throwing.
  const results = req.results ?? [];
  const descriptions = req.descriptions ?? [];
  // Finding state reflects the effective (post-override) status when present,
  // falling back to raw worst-wins aggregation. The raw result status stays
  // verbatim in the observation description.
  const { state, reason } = effectiveState(req, results);
  const findingDesc = extractDefaultDescription(descriptions);

  // Build props from control mappings (nist/cci), non-default descriptions
  // (check/fix/rationale), and v3.2 classification fields. OSCAL prop values
  // are StringDatatype (no newlines, no edge whitespace), so prose-capable
  // fields emit a single-line preview as the value and carry the full text in
  // the prop's own remarks (markup-multiline).
  // OSCAL prop values must be non-empty strings, so skip any empty value
  // (e.g. an empty source `code`) rather than emitting a schema-invalid value: ''.
  const props: Property[] = [];
  const addProp = (name: string, value: string): void => {
    if (value !== '') props.push({ name, value });
  };
  const addProseProp = (name: string, text: string): void => {
    const preview = previewLine(text);
    if (preview === '') return;
    const p: Property = { name, value: preview };
    if (preview !== text) p.remarks = text;
    props.push(p);
  };
  const descriptionByLabel = (label: string): string => {
    const d = descriptions.find((x) => x.label === label);
    return d ? d.data : '';
  };
  const pushTagValues = (key: string): void => {
    const raw = req.tags?.[key];
    if (Array.isArray(raw)) {
      for (const v of raw) if (typeof v === 'string') addProp(key, v);
    }
  };
  pushTagValues('nist');
  pushTagValues('cci');
  addProseProp('check', descriptionByLabel('check'));
  addProseProp('rationale', descriptionByLabel('rationale'));
  // fix text's OSCAL home is risk.remediations (built below when impact > 0,
  // the reverse importer's read path). Only an impact-0 requirement, which
  // emits no risk, carries it as a finding prop instead.
  if (req.impact <= 0) {
    addProseProp('fix', descriptionByLabel('fix'));
  }
  if (req.controlType) addProp('control-type', req.controlType);
  if (req.verificationMethod) addProp('verification-method', req.verificationMethod);
  if (req.applicability) addProp('applicability', req.applicability);

  // Vulnerability enrichment (CWE / EPSS / KEV / CVSS) has no first-class SAR
  // home; surface it as finding props so it is not silently dropped.
  for (const cwe of req.cwe ?? []) addProp('cwe', cwe);
  if (req.epss) {
    addProp('epss-score', formatFloat(req.epss.score));
    addProp('epss-percentile', formatFloat(req.epss.percentile));
  }
  if (req.kev?.inKev) {
    addProp('kev', 'true');
    if (req.kev.dueDate) addProp('kev-due-date', String(req.kev.dueDate));
  }
  for (const c of req.cvss ?? []) {
    if (c.baseScore != null) addProp('cvss-base-score', formatFloat(c.baseScore));
    if (c.baseVector != null) addProp('cvss-base-vector', c.baseVector);
  }

  // refs: url/uri become OSCAL links; a plain string ref becomes a prop (not a
  // valid href). url/uri refs are additionally emitted as observation
  // relevant-evidence (below) so they round-trip through the reverse SAR
  // importer, which reads refs only from relevant-evidence hrefs, not links.
  const links: Link[] = [];
  if (Array.isArray(req.refs)) {
    for (const r of req.refs) {
      const o = r as { url?: unknown; uri?: unknown; ref?: unknown };
      if (typeof o.url === 'string') links.push({ href: o.url, rel: 'reference' });
      else if (typeof o.uri === 'string') links.push({ href: o.uri, rel: 'reference' });
      else if (typeof o.ref === 'string') addProseProp('reference', o.ref);
    }
  }

  // externalReferences (advisory / STIX / definition-source URIs) share the
  // finding.links home already used for refs.
  for (const er of req.externalReferences ?? []) {
    if (typeof er.href === 'string' && er.href !== '') links.push({ href: er.href, rel: 'reference' });
  }

  let title = req.id;
  if (req.title && req.title !== '') {
    title = req.title;
  }

  // Source code is an artifact with a media type, not a StringDatatype prop:
  // embed it as a back-matter resource and point at it with a rel="code" link.
  let resource: Resource | undefined;
  if (req.code != null && req.code.trim() !== '') {
    const resourceUuid = crypto.randomUUID();
    resource = {
      uuid: resourceUuid,
      title: `Check source code for ${req.id}`,
      base64: {
        value: Buffer.from(req.code, 'utf-8').toString('base64'),
        'media-type': 'text/plain',
      },
    };
    links.push({ href: `#${resourceUuid}`, rel: 'code' });
  }

  const targetStatus: StatusClass = { state } as unknown as StatusClass;
  if (reason) {
    targetStatus.reason = reason;
  }
  // Governing disposition + most-recent override provenance so the reason the
  // requirement is in this state is not lost.
  const remarks = overrideRemarks(req);
  if (remarks) {
    targetStatus.remarks = remarks;
  }

  const target = {
    type: 'objective-id',
    'target-id': controlID,
    status: targetStatus,
  } as unknown as TargetClass;

  const finding = {
    uuid: crypto.randomUUID(),
    title,
    // OSCAL requires a non-empty finding description; fall back to the title
    // when the requirement carries no description of its own.
    description: findingDesc || title,
    props: props.length > 0 ? props : undefined,
    links: links.length > 0 ? links : undefined,
    target,
  } as Finding;

  // Build observation from requirement results
  let observation: Observation | undefined;
  if (results.length > 0) {
    const obsUUID = crypto.randomUUID();
    const obsDesc = buildObservationDescription(results);
    const relevantEvidence = buildRelevantEvidence(req);
    observation = {
      uuid: obsUUID,
      description: obsDesc,
      methods: ['TEST'],
      // When the evidence was gathered — the scan time for this requirement, not
      // when the file was converted.
      collected: formatAssessmentTime(earliestResultTime(results), timestamp),
      // Assessed-asset identity (top-level components) and the requirement's
      // refs / evidence / source location, in the homes the reverse importer
      // reads back. Match Go's omitempty: empty arrays are omitted.
      ...(subjects.length > 0 ? { subjects } : {}),
      ...(relevantEvidence.length > 0 ? { 'relevant-evidence': relevantEvidence } : {}),
    } as unknown as Observation;
    finding['related-observations'] = [{ 'observation-uuid': obsUUID }];
  }

  // Build risk from impact
  let risk: IdentifiedRisk | undefined;
  if (req.impact > 0) {
    const riskUUID = crypto.randomUUID();
    const severity = impactToSeverity(req.impact);
    // An explicit severity that disagrees with the impact-derived band drives
    // the characterization facet (the channel the reverse importer reads).
    let facetValue = severity;
    if (req.severity) {
      const v = severityToFacetValue(req.severity);
      if (v) facetValue = v;
    }
    const remediations = buildRemediations(req);
    const deadline = riskDeadline(req);
    risk = {
      uuid: riskUUID,
      title: `Risk for ${req.id}`,
      description: `Impact: ${req.impact.toFixed(1)} (${severity})`,
      statement: `Impact: ${req.impact.toFixed(1)} (${severity})`,
      status: riskStatusFromState(state),
      characterizations: [
        {
          // OSCAL requires characterization.origin. Reference the single
          // document-level tool party so the actor-uuid resolves to a defined
          // party (referential integrity), not a dangling per-risk UUID.
          origin: {
            actors: [{ type: 'party', 'actor-uuid': toolActorUuid }],
          },
          facets: [
            {
              name: 'impact',
              system: 'https://fedramp.gov',
              value: facetValue,
            },
          ],
        },
      ],
      // Match Go's omitempty: empty remediations / deadline are omitted.
      ...(remediations.length > 0 ? { remediations } : {}),
      ...(deadline ? { deadline } : {}),
    } as unknown as IdentifiedRisk;
    finding['related-risks'] = [{ 'risk-uuid': riskUUID }];
  }

  return { finding, observation, risk, resource };
}

/**
 * Reduces prose to a single line legal as an OSCAL StringDatatype prop value:
 * the first non-empty line, trimmed, truncated to 120 code points.
 */
function previewLine(text: string): string {
  for (let line of text.split('\n')) {
    line = line.trim();
    if (line === '') continue;
    const maxRunes = 120;
    const runes = Array.from(line);
    if (runes.length > maxRunes) {
      line = `${runes.slice(0, maxRunes - 3).join('').trim()}...`;
    }
    return line;
  }
  return '';
}

/**
 * Derives the OSCAL finding target state/reason from the requirement's
 * effectiveStatus when present, otherwise from aggregated raw results.
 */
function effectiveState(req: EvaluatedRequirement, results: RequirementResult[]): { state: string; reason: string } {
  if (req.effectiveStatus) {
    return oscalStateFromStatus(req.effectiveStatus);
  }
  return aggregateStatus(results);
}

/** Maps a single HDF result status to an OSCAL finding target state/reason. */
function oscalStateFromStatus(status: string): { state: string; reason: string } {
  switch (status) {
    case 'passed':
      return { state: 'satisfied', reason: '' };
    case 'notApplicable':
      return { state: 'not-satisfied', reason: 'not-applicable' };
    case 'notReviewed':
      return { state: 'not-satisfied', reason: 'other' };
    default:
      return { state: 'not-satisfied', reason: '' };
  }
}

/**
 * Renders the governing disposition and the most-recent status override's
 * provenance into finding.target.status.remarks. Returns '' when none apply.
 */
function overrideRemarks(req: EvaluatedRequirement): string {
  const parts: string[] = [];
  if (req.disposition) parts.push('Disposition: ' + String(req.disposition));
  const overrides = req.statusOverrides ?? [];
  if (overrides.length > 0) {
    const o = overrides[0]!; // most-recent first per schema convention
    parts.push('Override: ' + String(o.type));
    if (o.reason) parts.push('Reason: ' + o.reason);
    if (o.appliedBy?.identifier) parts.push('Applied by: ' + o.appliedBy.identifier);
    const appliedAt = hdfTime(o.appliedAt);
    if (appliedAt) parts.push('Applied at: ' + formatTimestampSeconds(appliedAt));
    const expiresAt = hdfTime(o.expiresAt);
    if (expiresAt) parts.push('Expires at: ' + formatTimestampSeconds(expiresAt));
  }
  return parts.join('; ');
}

/**
 * Collects the requirement's refs, evidence, and source location into OSCAL
 * observation relevant-evidence — the home the reverse SAR importer reads back
 * into HDF refs (via href) and evidence (via description).
 */
function buildRelevantEvidence(req: EvaluatedRequirement): Array<{ href?: string; description: string }> {
  const ev: Array<{ href?: string; description: string }> = [];
  for (const r of req.refs ?? []) {
    const o = r as { url?: unknown; uri?: unknown };
    if (typeof o.url === 'string' && o.url !== '') ev.push({ href: o.url, description: '' });
    else if (typeof o.uri === 'string' && o.uri !== '') ev.push({ href: o.uri, description: '' });
  }
  for (const e of req.evidence ?? []) {
    const entry: { href?: string; description: string } = { description: e.description ?? '' };
    if (String(e.type) === 'url' && e.data) entry.href = e.data;
    if (entry.href || entry.description) ev.push(entry);
  }
  if (req.sourceLocation) {
    const loc = sourceLocationText(req.sourceLocation);
    if (loc) ev.push({ description: 'Source location: ' + loc });
  }
  return ev;
}

/** Renders a source location as "ref:line", degrading to whichever is present. */
function sourceLocationText(loc: NonNullable<EvaluatedRequirement['sourceLocation']>): string {
  const ref = loc.ref ?? '';
  if (loc.line != null) {
    return ref !== '' ? `${ref}:${Math.trunc(loc.line)}` : `line ${Math.trunc(loc.line)}`;
  }
  return ref;
}

/** Maps an explicit HDF severity to the OSCAL risk facet value vocabulary. */
function severityToFacetValue(s: string): string {
  switch (s) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
      return 'moderate';
    case 'low':
      return 'low';
    case 'informational':
      return 'info';
    default:
      return '';
  }
}

/**
 * Turns the requirement's fix description and any governing risk-acceptance
 * override into OSCAL risk remediations — the home the reverse importer reads
 * back as the HDF remediation description.
 */
function buildRemediations(req: EvaluatedRequirement): Array<Record<string, string>> {
  const rems: Array<Record<string, string>> = [];
  const fix = (req.descriptions ?? []).find((d) => d.label === 'fix');
  if (fix && fix.data) {
    rems.push({ uuid: crypto.randomUUID(), lifecycle: 'recommendation', title: 'Recommended fix', description: fix.data });
  }
  const overrides = req.statusOverrides ?? [];
  if (req.disposition && overrides.length > 0) {
    const o = overrides[0]!;
    const desc = o.reason || 'Risk accepted via ' + String(req.disposition);
    rems.push({ uuid: crypto.randomUUID(), lifecycle: 'accepted', title: String(req.disposition), description: desc });
  }
  return rems;
}

/**
 * Surfaces a governing risk-acceptance override's expiry as the risk deadline
 * (the field the OSCAL POA&M importer reads back). Returns '' when none applies.
 */
function riskDeadline(req: EvaluatedRequirement): string {
  const overrides = req.statusOverrides ?? [];
  if (overrides.length > 0) {
    const expiresAt = hdfTime(overrides[0]!.expiresAt);
    if (expiresAt) return formatTimestampSeconds(expiresAt);
  }
  return '';
}

/** Formats a finite number without a trailing decimal for integers, matching Go's strconv.FormatFloat(-1). */
function formatFloat(n: number): string {
  return String(n);
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
