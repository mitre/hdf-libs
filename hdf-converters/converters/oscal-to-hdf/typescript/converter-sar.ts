/**
 * OSCAL Assessment Results (SAR) to HDF Results converter.
 *
 * Mirrors the Go implementation in converters/oscal-to-hdf/go/converter_sar.go.
 */

import { parseJSON, parseTimestamp } from '@mitre/hdf-utilities';
import { nistToCci } from '@mitre/hdf-mappings';
import { buildNistCciTags, deriveControlTypeFromTags, emitConverterWarning, inputChecksum, inputIntegrity, limitArrayWithWarning, serializeHdf, validateInputSize } from '../../../shared/typescript/converterutil.js';
import type {
  HDFResults,
  EvaluatedBaseline,
  EvaluatedRequirement,
  RequirementResult,
  Component,
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
  RelevantEvidence,
  RiskResponse,
} from './types.js';
import {
  confirmedControlId,
  controlIdToNistTag,
  controlIdsToNistTags,
  oscalStatusToHdf,
  extractRiskSeverity,
  extractMetadata,
  toKebabCase,
  descriptionLabel,
} from './shared.js';
import { findVocabularyProp, vocabularyString } from './vocabulary.js';
import { OSCAL_PROPS_TAG, carryForeignProps, type CarriedProp } from './carriage.js';
import type { IdentifiesTheSubject } from './types.js';

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
    const title = result.title || result.uuid;
    if (!result.findings || result.findings.length === 0) {
      emitConverterWarning(`Skipping assessment result "${title}": no findings (empty result set)`);
      continue;
    }
    const { groups, skipped } = groupFindingsByRequirement(result.findings);
    for (const f of skipped) {
      emitConverterWarning(`Skipping finding "${f.uuid}" titled "${f.title}": empty target-id`);
    }
    if (groups.size === 0) {
      emitConverterWarning(`Skipping assessment result "${title}": no finding has a target-id`);
      continue;
    }
    const baseline = await resultToEvaluatedBaseline(result, groups, input, scanTime);
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

  const components = sarComponents(sar);

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
    ...(components.length > 0 ? { components } : {}),
  };

  return serializeHdf(hdf);
}

/**
 * The set of OSCAL subject types that are HDF component types. A foreign SAR's
 * subject types (component, inventory-item, party, …) are not among them, so
 * those subjects do not reconstitute as HDF components. Mirrors the Go peer.
 */
const HDF_COMPONENT_TYPES = new Set<string>([
  'host', 'containerImage', 'containerInstance', 'containerPlatform', 'cloudAccount',
  'cloudResource', 'repository', 'application', 'artifact', 'network', 'database', 'aiModel', 'dataset',
]);

/**
 * Reconstitutes the top-level HDF components from the assessment subjects the
 * exporter attaches to every observation. Subjects are deduplicated by uuid in
 * first-seen document order, and a subject whose type is not an HDF component
 * type is left alone so foreign SARs gain no invalid components. Mirrors Go.
 */
function sarComponents(sar: SecurityAssessmentResultsSAR): Component[] {
  const components: Component[] = [];
  const seen = new Set<string>();
  for (const result of sar.results) {
    for (const obs of result.observations ?? []) {
      for (const subj of obs.subjects ?? []) {
        const uuid = subj['subject-uuid'];
        if (!uuid || seen.has(uuid) || !HDF_COMPONENT_TYPES.has(subj.type)) continue;
        seen.add(uuid);
        components.push(subjectToComponent(subj));
      }
    }
  }
  return components;
}

/**
 * Rebuilds one HDF component from an assessment subject: the subject uuid is the
 * componentId (ADR-0014 §4.5 SSP analog), and every type-specific identity field
 * comes from the HDF-namespaced props the exporter stamped on the subject.
 * Mirrors the Go peer.
 */
function subjectToComponent(subj: IdentifiesTheSubject): Component {
  const props = subj.props;
  const c: Component = {
    type: subj.type as Component['type'],
    name: subj.title ?? '',
    componentId: subj['subject-uuid'],
  };
  // Literal prop names are required so the importer prop-read sweep can check
  // each one is a vocabulary row (ADR-0014 §1.5).
  c.description = vocabularyString(props, 'component-description', 'description', '');
  c.hostname = vocabularyString(props, 'component-hostname', 'hostname', '');
  c.fqdn = vocabularyString(props, 'component-fqdn', 'fqdn', '');
  c.domain = vocabularyString(props, 'component-domain', 'domain', '');
  c.ipAddress = vocabularyString(props, 'component-ip-address', 'ipAddress', '');
  c.macAddress = vocabularyString(props, 'component-mac-address', 'macAddress', '');
  c.osName = vocabularyString(props, 'component-os-name', 'osName', '');
  c.osVersion = vocabularyString(props, 'component-os-version', 'osVersion', '');
  c.imageId = vocabularyString(props, 'component-image-id', 'imageId', '');
  c.registry = vocabularyString(props, 'component-registry', 'registry', '');
  c.repository = vocabularyString(props, 'component-repository', 'repository', '');
  c.tag = vocabularyString(props, 'component-tag', 'tag', '');
  c.containerId = vocabularyString(props, 'component-container-id', 'containerId', '');
  c.image = vocabularyString(props, 'component-image', 'image', '');
  c.runtime = vocabularyString(props, 'component-runtime', 'runtime', '');
  c.platformType = vocabularyString(props, 'component-platform-type', 'platformType', '');
  c.clusterName = vocabularyString(props, 'component-cluster-name', 'clusterName', '');
  c.namespace = vocabularyString(props, 'component-namespace', 'namespace', '');
  c.version = vocabularyString(props, 'component-version', 'version', '');
  const provider = vocabularyString(props, 'component-provider', 'provider', '');
  if (provider !== undefined) c.provider = provider as Component['provider'];
  c.accountId = vocabularyString(props, 'component-account-id', 'accountId', '');
  c.region = vocabularyString(props, 'component-region', 'region', '');
  c.resourceType = vocabularyString(props, 'component-resource-type', 'resourceType', '');
  c.resourceId = vocabularyString(props, 'component-resource-id', 'resourceId', '');
  c.arn = vocabularyString(props, 'component-arn', 'arn', '');
  c.url = vocabularyString(props, 'component-url', 'url', '');
  c.branch = vocabularyString(props, 'component-branch', 'branch', '');
  c.commit = vocabularyString(props, 'component-commit', 'commit', '');
  c.environment = vocabularyString(props, 'component-environment', 'environment', '');
  c.packageManager = vocabularyString(props, 'component-package-manager', 'packageManager', '');
  c.packageName = vocabularyString(props, 'component-package-name', 'packageName', '');
  c.cidr = vocabularyString(props, 'component-cidr', 'cidr', '');
  c.gateway = vocabularyString(props, 'component-gateway', 'gateway', '');
  c.engine = vocabularyString(props, 'component-engine', 'engine', '');
  c.host = vocabularyString(props, 'component-host', 'host', '');
  const port = vocabularyString(props, 'component-port', 'port', '');
  if (port !== undefined) {
    const n = Number.parseInt(port, 10);
    if (!Number.isNaN(n)) c.port = n;
  }
  c.modelId = vocabularyString(props, 'component-model-id', 'modelId', '');
  c.datasetId = vocabularyString(props, 'component-dataset-id', 'datasetId', '');
  const labels = readComponentMap(
    (g) => vocabularyString(props, 'component-label-key', 'key', g),
    (g) => vocabularyString(props, 'component-label-value', 'value', g),
    'component-label',
  );
  if (labels) c.labels = labels;
  const externalIds = readComponentMap(
    (g) => vocabularyString(props, 'component-external-id-key', 'key', g),
    (g) => vocabularyString(props, 'component-external-id-value', 'value', g),
    'component-external-id',
  );
  if (externalIds) c.externalIds = externalIds;
  return c;
}

/**
 * Rebuilds a component string map from grouped key/value props. Groups are
 * numbered from 1 in the order the exporter emitted them (sorted key order), so
 * reading stops at the first group with neither a key nor a value. Mirrors Go.
 */
function readComponentMap(
  readKey: (group: string) => string | undefined,
  readValue: (group: string) => string | undefined,
  prefix: string,
): Record<string, string> | undefined {
  const m: Record<string, string> = {};
  for (let n = 1; ; n++) {
    const group = `${prefix}-${n}`;
    const key = readKey(group);
    const value = readValue(group);
    if (key === undefined && value === undefined) break;
    m[key ?? ''] = value ?? '';
  }
  return Object.keys(m).length > 0 ? m : undefined;
}

/**
 * Groups findings by requirement id in first-seen order (a Map keeps insertion
 * order), within the finding cap, and returns the findings skipped for an empty
 * target-id. Mirrors Go's groupFindingsByRequirement.
 */
function groupFindingsByRequirement(findings: Finding[]): { groups: Map<string, Finding[]>; skipped: Finding[] } {
  const groups = new Map<string, Finding[]>();
  const skipped: Finding[] = [];
  for (const f of limitArrayWithWarning(findings, 'finding')) {
    const id = sarRequirementId(f);
    if (id === undefined) {
      skipped.push(f);
      continue;
    }
    const existing = groups.get(id);
    if (existing) {
      existing.push(f);
    } else {
      groups.set(id, [f]);
    }
  }
  return { groups, skipped };
}

/**
 * The HDF requirement id a finding belongs to (ADR-0014 §4.5): the HDF-namespaced
 * hdf-requirement-id when present; else the NIST control a roster-confirmed
 * target names; else the target-id verbatim. Undefined for a finding whose
 * target-id is empty. Mirrors Go's sarRequirementID.
 */
export function sarRequirementId(f: Finding): string | undefined {
  const targetId = f.target['target-id'];
  if (!targetId) return undefined;
  const prop = findVocabularyProp(f.props, 'hdf-requirement-id');
  if (prop && prop.value !== '') return prop.value;
  const controlId = confirmedControlId(targetId);
  return controlId === undefined ? targetId : controlIdToNistTag(controlId);
}

async function resultToEvaluatedBaseline(
  result: AssessmentResult,
  groups: Map<string, Finding[]>,
  rawInput: string,
  scanTime: Date,
): Promise<EvaluatedBaseline> {
  const checksum = await inputChecksum(rawInput);

  // Build lookup maps for observations and risks
  const obsMap = buildObservationMap(result.observations ?? []);
  const riskMap = buildRiskMap(result.risks ?? []);

  const requirements: EvaluatedRequirement[] = [];
  for (const [id, findings] of groups) {
    requirements.push(findingsToEvaluatedRequirement(id, findings, obsMap, riskMap, result, scanTime));
  }

  // Derive baseline name
  const name = sarBaselineName(result);

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
  id: string,
  findings: Finding[],
  obsMap: Map<string, Observation>,
  riskMap: Map<string, IdentifiedRisk>,
  result: AssessmentResult,
  scanTime: Date,
): EvaluatedRequirement {
  // Use the first finding for title
  const firstFinding = findings[0]!;
  const title = firstFinding.title || id;

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

  // tags.nist carries the NIST controls the findings' targets confirm; tags.cci
  // is derived from them via the standard NIST→CCI mapping (omitted when they
  // map to none), matching how sibling converters emit both.
  const nistTags = sarConfirmedNistTags(findings);
  const tags: Record<string, unknown> = buildNistCciTags(nistTags, nistToCci(nistTags));

  // Foreign and otherwise-unconsumed props on this requirement's finding(s),
  // observations and risks ride through HDF in the reserved oscal-props tag
  // (ADR-0014 §3) so re-export can reproduce them.
  const carried = sarCarriedProps(findings, obsMap, riskMap);
  if (carried.length > 0) tags[OSCAL_PROPS_TAG] = carried;

  const req = createRequirement(id, title, descriptions, impact, results, {
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

/** The distinct NIST controls, in NIST notation, the findings' targets confirm, in finding order. */
function sarConfirmedNistTags(findings: Finding[]): string[] {
  const controlIds: string[] = [];
  for (const f of findings) {
    const controlId = confirmedControlId(f.target['target-id']);
    if (controlId !== undefined) controlIds.push(controlId);
  }
  return controlIdsToNistTags(controlIds);
}

/**
 * Collects the carriage entries for a requirement (ADR-0014 §3.1): every
 * unconsumed prop on its finding(s), then on their related observations, then on
 * their related risks. Observations and risks are read once each (deduplicated
 * by UUID). Mirrors Go's sarCarriedProps.
 */
function sarCarriedProps(
  findings: Finding[],
  obsMap: Map<string, Observation>,
  riskMap: Map<string, IdentifiedRisk>,
): CarriedProp[] {
  const entries: CarriedProp[] = [];
  for (const f of findings) carryForeignProps(entries, 'finding', f.props);
  const seenObs = new Set<string>();
  for (const f of findings) {
    for (const ref of f['related-observations'] ?? []) {
      const uuid = ref['observation-uuid'];
      if (!uuid || seenObs.has(uuid)) continue;
      seenObs.add(uuid);
      const obs = obsMap.get(uuid);
      if (obs) carryForeignProps(entries, 'observation', obs.props);
    }
  }
  const seenRisk = new Set<string>();
  for (const f of findings) {
    for (const ref of f['related-risks'] ?? []) {
      const uuid = ref['risk-uuid'];
      if (!uuid || seenRisk.has(uuid)) continue;
      seenRisk.add(uuid);
      const risk = riskMap.get(uuid);
      if (risk) carryForeignProps(entries, 'risk', risk.props);
    }
  }
  return entries;
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

  const rationales = findings.map((f) => f.target.description ?? '').filter((d) => d !== '');
  if (rationales.length > 0) {
    descriptions.push({ label: 'rationale', data: rationales.join('\n') });
  }

  const labelled = collectLabelledProse(findings, obsMap, riskMap);
  for (const label of ['check', 'fix']) {
    const texts = labelled.get(label);
    if (texts) {
      descriptions.push({ label, data: texts.join('\n') });
    }
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

/** The HDF description label a relevant-evidence entry carries ("check" or "fix"), or '' for foreign evidence. */
function evidenceDescriptionLabel(ev: RelevantEvidence): string {
  const label = descriptionLabel(ev.props);
  return label === 'check' || label === 'fix' ? label : '';
}

/** Whether a remediation is HDF's fix prose home. */
function isLabelledFix(rem: RiskResponse): boolean {
  return descriptionLabel(rem.props) === 'fix';
}

/**
 * Gathers the check and fix text HDF wrote into labelled relevant-evidence
 * entries (full text from remarks) and labelled remediations, in finding order,
 * reading each observation and risk once.
 */
function collectLabelledProse(
  findings: Finding[],
  obsMap: Map<string, Observation>,
  riskMap: Map<string, IdentifiedRisk>,
): Map<string, string[]> {
  const texts = new Map<string, string[]>();
  const add = (label: string, text: string): void => {
    texts.set(label, [...(texts.get(label) ?? []), text]);
  };
  const seenObs = new Set<string>();
  const seenRisk = new Set<string>();
  for (const f of findings) {
    for (const ref of f['related-observations'] ?? []) {
      const obs = obsMap.get(ref['observation-uuid']);
      if (!obs || seenObs.has(ref['observation-uuid'])) continue;
      seenObs.add(ref['observation-uuid']);
      for (const ev of obs['relevant-evidence'] ?? []) {
        const label = evidenceDescriptionLabel(ev);
        if (label !== '') add(label, ev.remarks || ev.description);
      }
    }
    for (const ref of f['related-risks'] ?? []) {
      const risk = riskMap.get(ref['risk-uuid']);
      if (!risk || seenRisk.has(ref['risk-uuid'])) continue;
      seenRisk.add(ref['risk-uuid']);
      for (const rem of risk.remediations ?? []) {
        if (isLabelledFix(rem)) add('fix', rem.description);
      }
    }
  }
  return texts;
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
        if (isLabelledFix(rem)) continue;
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
        if (!ev.description || seenText.has(ev.description) || evidenceDescriptionLabel(ev) !== '') continue;
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

// sarBaselineName recovers the HDF baseline name. An HDF-produced result carries
// it exactly in the namespaced baseline-name prop (§4.3). A foreign result has
// none, so the name is <kebab-title>--<result-uuid> — the bare uuid when the
// kebab-cased title is empty — which keeps same-title results distinct because
// OSCAL guarantees uniqueness only for uuid (§4.5).
function sarBaselineName(result: AssessmentResult): string {
  const match = findVocabularyProp(result.props, 'baseline-name');
  if (match) return match.value;
  const kebab = toKebabCase(result.title ?? '', '');
  return kebab === '' ? result.uuid : `${kebab}--${result.uuid}`;
}
