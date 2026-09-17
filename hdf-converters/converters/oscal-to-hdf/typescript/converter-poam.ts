/**
 * OSCAL Plan of Action and Milestones (POA&M) to HDF Amendments converter.
 *
 * A POA&M hdf-to-oscal-poam produced returns every amendments field it carries
 * (ADR-0014 §4.6), apart from the integrity fields and generator that contract
 * excludes. Foreign POA&Ms, and HDF exports from before the ADR (§4.3), keep the
 * mapping they had before it: type "poam", with their own extension props not
 * carried (§3.6).
 *
 * Mirrors the Go implementation in converters/oscal-to-hdf/go/converter_poam.go.
 */

import { parseJSON, parseTimestamp } from '@mitre/hdf-utilities';
import { chainOverrides, emitConverterWarning, inputIntegrity, serializeHdf, validateInputSize } from '../../../shared/typescript/converterutil.js';
import {
  IdentityType,
  MilestoneStatus,
  OverrideType,
  ResultStatus,
  type AffectedPackage,
  type CVSSSeverity,
  type Cvss,
  type Ecosystem,
  type EvidenceType,
  type HashAlgorithm,
  type Version,
  type Evidence,
  type ExternalReference,
  type HDFAmendments,
  type Identity,
  type StandaloneOverride,
  type Milestone as HdfMilestone,
} from '@mitre/hdf-schema';
import type {
  Oscal,
  PlanOfActionAndMilestonesPOAM,
  POAMItem,
  IdentifiedRisk,
  DocumentMetadata,
  Link,
  Observation,
  Property,
  Resource,
  RiskLogEntry,
} from './types.js';
import {
  controlIdToNistTag,
  extractPropValue,
  oscalStatusToHdf,
  extractMetadata,
  toKebabCase,
} from './shared.js';
import {
  consumedVocabularyProp,
  findGroupedVocabularyProp,
  findVocabularyProp,
  findVocabularyProps,
  hasFieldMarker,
  vocabularyString,
} from './vocabulary.js';

/**
 * Converts an OSCAL POA&M document to HDF Amendments JSON.
 *
 * @param input - Raw JSON string containing an OSCAL POA&M
 * @returns HDF Amendments JSON string
 */
export async function convertOscalPoamToHdf(input: string): Promise<string> {
  validateInputSize(input, 'oscal-poam');

  if (!input || input.trim().length === 0) {
    throw new Error('empty input');
  }

  const doc = parseJSON<Oscal>(input);
  if (!doc['plan-of-action-and-milestones']) {
    throw new Error(
      "oscal-poam: input is not a plan-of-action-and-milestones document (root key is not 'plan-of-action-and-milestones')",
    );
  }

  const poam = doc['plan-of-action-and-milestones'];
  const integrity = await inputIntegrity(input);
  const meta = extractMetadata(poam.metadata);

  const riskMap = buildRiskMap(poam.risks ?? []);

  const overrides: StandaloneOverride[] = [];
  let hdfProduced = false;
  for (const item of poam['poam-items']) {
    const override = poamItemToOverride(item, riskMap, poam);
    if (!override) {
      emitConverterWarning(`Skipping poam-item "${item.uuid}" titled "${item.title}": its pre-ADR risk has no impacted-control-id`);
      continue;
    }
    if (hdfProducedRisk(item, riskMap)) hdfProduced = true;
    overrides.push(override);
  }

  // Tamper-evidence must not depend on which route authored the document.
  await chainOverrides(overrides);

  const preparedBy = firstResponsibleParty(poam.metadata, 'prepared-by');
  const amendments: HDFAmendments = {
    name: toKebabCase(poam.metadata.title, 'oscal-poam'),
    overrides,
    integrity,
    systemRef: poam['import-ssp']?.href || undefined,
    version: meta.version,
    appliedBy: preparedBy === '' ? undefined : { type: IdentityType.Simple, identifier: preparedBy },
    generator: {
      name: 'oscal-poam-to-hdf',
      version: '1.0.0',
    },
  };
  if (hdfProduced) readHdfDocumentFields(poam, amendments);

  return serializeHdf(amendments);
}

/**
 * Reads the amendments document fields from their ADR-0014 §4.6 homes, which a
 * POA&M carries only when one of its risks is HDF-produced (§4.3).
 */
function readHdfDocumentFields(poam: PlanOfActionAndMilestonesPOAM, amendments: HDFAmendments): void {
  const props = poam.metadata.props;
  amendments.name = findGroupedVocabularyProp(props, 'amendments-name', '')?.value ?? '';
  if (poam.metadata.remarks) {
    amendments.description = poam.metadata.remarks;
  } else if (hasFieldMarker(props, 'empty-field', 'description', '')) {
    amendments.description = '';
  }
  amendments.appliedBy = documentIdentity(poam, 'prepared-by');
  const approvedBy = partyIdentity(poam, firstResponsibleParty(poam.metadata, 'approved-by'));
  if (approvedBy) amendments.approvedBy = approvedBy;
  const amendmentId = vocabularyString(props, 'amendment-id', 'amendmentId', '');
  if (amendmentId !== undefined) amendments.amendmentId = amendmentId;
  const labels = amendmentLabels(props);
  if (labels) amendments.labels = labels;
  amendments.systemRef = markedField(props, 'systemRef', amendments.systemRef);
  amendments.version = markedField(props, 'version', amendments.version);
}

/**
 * Applies the metadata markers for an OSCAL-required field the exporter wrote a
 * display fallback for: absent-field leaves it absent and empty-field returns it empty.
 */
function markedField(props: Property[] | undefined, field: string, value: string | undefined): string | undefined {
  if (hasFieldMarker(props, 'absent-field', field, '')) return undefined;
  if (hasFieldMarker(props, 'empty-field', field, '')) return '';
  return value;
}

/** Reads the label-key and label-value pairs, one per label-<n> group. */
function amendmentLabels(props: Property[] | undefined): Record<string, string> | undefined {
  const groups = new Set<string>();
  for (const m of [...findVocabularyProps(props, 'label-key'), ...findVocabularyProps(props, 'empty-field')]) {
    const p = props![m.index]!;
    if (p.class === 'amendment-label' && p.group) groups.add(p.group);
  }
  if (groups.size === 0) return undefined;
  const labels: Record<string, string> = {};
  for (const group of groups) {
    const key = vocabularyString(props, 'label-key', 'key', group);
    const value = vocabularyString(props, 'label-value', 'value', group);
    if (key !== undefined && value !== undefined) labels[key] = value;
  }
  return labels;
}

function buildRiskMap(risks: IdentifiedRisk[]): Map<string, IdentifiedRisk> {
  const m = new Map<string, IdentifiedRisk>();
  for (const risk of risks) {
    m.set(risk.uuid, risk);
  }
  return m;
}

/**
 * The item's first related risk that carries override-type in the HDF namespace,
 * which makes it HDF-produced (ADR-0014 §4.3), or undefined.
 */
function hdfProducedRisk(item: POAMItem, riskMap: Map<string, IdentifiedRisk>): IdentifiedRisk | undefined {
  return overrideTypeRisk(item, riskMap, false);
}

/** The item's first related risk whose override-type prop is (legacy) or is not (!legacy) matched through the pre-ADR fallback. */
function overrideTypeRisk(item: POAMItem, riskMap: Map<string, IdentifiedRisk>, legacy: boolean): IdentifiedRisk | undefined {
  for (const rr of item['related-risks'] ?? []) {
    const risk = rr['risk-uuid'] ? riskMap.get(rr['risk-uuid']) : undefined;
    if (risk && findVocabularyProp(risk.props, 'override-type')?.legacy === legacy) return risk;
  }
  return undefined;
}

/** Converts a poam-item to an override, or undefined for a pre-ADR item with no requirement id, which is skipped. */
function poamItemToOverride(
  item: POAMItem,
  riskMap: Map<string, IdentifiedRisk>,
  poam: PlanOfActionAndMilestonesPOAM,
): StandaloneOverride | undefined {
  const risk = hdfProducedRisk(item, riskMap);
  if (risk) return hdfOverride(item, risk, riskMap, poam);

  const requirementId = foreignRequirementId(item, riskMap);
  if (requirementId === undefined) return undefined;
  const milestones = extractMilestones(item, riskMap);
  return {
    type: OverrideType.Poam,
    requirementId,
    reason: poamItemReason(item),
    status: poamItemStatus(item, riskMap),
    appliedBy: poamItemAppliedBy(poam),
    appliedAt: poamItemAppliedAt(poam, requirementId),
    expiresAt: poamItemExpiresAt(item, riskMap, requirementId),
    // Omitted when empty, matching the Go peer's omitempty.
    ...(milestones.length > 0 ? { milestones } : {}),
  };
}

/**
 * Reads every override field from its ADR-0014 §4.6 home on an HDF-produced risk.
 * An absent prop is an absent field: nothing is derived from titles or uuids.
 */
function hdfOverride(
  item: POAMItem,
  risk: IdentifiedRisk,
  riskMap: Map<string, IdentifiedRisk>,
  poam: PlanOfActionAndMilestonesPOAM,
): StandaloneOverride {
  const props = risk.props;
  const requirementId = findVocabularyProp(props, 'hdf-requirement-id')?.value ?? '';
  const entry = overrideAppliedEntry(risk);
  const appliedAt = (entry && parseTimestamp(String(entry.start))) || poamItemAppliedAt(poam, requirementId);
  const override: StandaloneOverride = {
    type: findVocabularyProp(props, 'override-type')!.value as OverrideType,
    requirementId,
    reason: item.description,
    appliedBy: poamItemAppliedBy(poam),
    appliedAt,
    expiresAt: poamItemExpiresAt(item, riskMap, requirementId),
  };
  const status = findVocabularyProp(props, 'override-status');
  if (status) override.status = status.value as ResultStatus;
  const impact = findVocabularyProp(props, 'impact-override');
  if (impact && impact.value.trim() !== '' && !isNaN(Number(impact.value))) {
    override.impact = { value: Number(impact.value) };
  }
  const justification = findVocabularyProp(props, 'justification');
  if (justification) override.justification = justification.value as StandaloneOverride['justification'];
  const baselineRef = vocabularyString(props, 'baseline-ref', 'baselineRef', '');
  if (baselineRef !== undefined) override.baselineRef = baselineRef;
  const componentRef = vocabularyString(props, 'component-ref', 'componentRef', '');
  if (componentRef !== undefined) override.componentRef = componentRef;
  const inheritedFrom = vocabularyString(props, 'inherited-from', 'inheritedFrom', '');
  if (inheritedFrom !== undefined) override.inheritedFrom = inheritedFrom;
  const packages = affectedPackages(props);
  if (packages.length > 0) override.affectedPackages = packages;

  const loggedBy = entry?.['logged-by']?.[0]?.['party-uuid'];
  const applier = loggedBy === undefined ? undefined : partyIdentity(poam, loggedBy);
  if (applier) override.appliedBy = applier;

  const milestones = hdfMilestones(risk, poam);
  if (milestones.length > 0) override.milestones = milestones;
  const cvss = riskCvss(risk);
  if (cvss) override.cvss = cvss;
  const evidence = itemEvidence(item, poam);
  if (evidence.length > 0) override.evidence = evidence;
  const refs = riskReferences(risk, poam);
  if (refs.length > 0) override.externalReferences = refs;
  return override;
}

/** The risk-log entry recording when the override was applied. */
function overrideAppliedEntry(risk: IdentifiedRisk): RiskLogEntry | undefined {
  return risk['risk-log']?.entries.find((e) => e.title === 'Override applied');
}

/** Reads the package-<n> prop groups in position order. */
function affectedPackages(props: Property[] | undefined): AffectedPackage[] {
  const positions = new Set<number>();
  for (const p of props ?? []) {
    const m = /^package-(\d+)$/.exec(p.group ?? '');
    if (m && consumedVocabularyProp(p) && Number(m[1]) > 0) positions.add(Number(m[1]));
  }
  return [...positions]
    .sort((a, b) => a - b)
    .map((position) => {
      const group = `package-${position}`;
      const pkg: AffectedPackage = {};
      const name = vocabularyString(props, 'affected-package-name', 'name', group);
      if (name !== undefined) pkg.name = name;
      const version = vocabularyString(props, 'affected-package-version', 'version', group);
      if (version !== undefined) pkg.version = version;
      const ecosystem = vocabularyString(props, 'affected-package-ecosystem', 'ecosystem', group);
      if (ecosystem !== undefined) pkg.ecosystem = ecosystem as Ecosystem;
      const cpe = vocabularyString(props, 'affected-package-cpe', 'cpe', group);
      if (cpe !== undefined) pkg.cpe = cpe;
      const purl = vocabularyString(props, 'affected-package-purl', 'purl', group);
      if (purl !== undefined) pkg.purl = purl;
      const fixedInVersion = vocabularyString(props, 'affected-package-fixed-in-version', 'fixedInVersion', group);
      if (fixedInVersion !== undefined) pkg.fixedInVersion = fixedInVersion;
      return pkg;
    });
}

/** The first party uuid metadata assigns to roleId, or ''. */
function firstResponsibleParty(meta: DocumentMetadata, roleId: string): string {
  for (const rp of meta['responsible-parties'] ?? []) {
    if (rp['role-id'] === roleId && rp['party-uuids'].length > 0) return rp['party-uuids'][0]!;
  }
  return '';
}

/** Reads the HDF identity a metadata party carries, or undefined for a party that carries none. */
function partyIdentity(poam: PlanOfActionAndMilestonesPOAM, partyUuid: string): Identity | undefined {
  const party = (poam.metadata.parties ?? []).find((p) => p.uuid === partyUuid);
  if (!party) return undefined;
  const identityType = findVocabularyProp(party.props, 'identity-type');
  if (!identityType) return undefined;
  const id: Identity = {
    identifier: findVocabularyProp(party.props, 'identity-identifier')?.value ?? '',
    type: identityType.value as IdentityType,
  };
  if (party.remarks) {
    id.description = party.remarks;
  } else if (hasFieldMarker(party.props, 'empty-field', 'description', '')) {
    id.description = '';
  }
  return id;
}

/** The identity metadata assigns to roleId: the HDF identity its party carries, or else the party uuid as a simple identifier. */
function documentIdentity(poam: PlanOfActionAndMilestonesPOAM, roleId: string): Identity | undefined {
  const partyUuid = firstResponsibleParty(poam.metadata, roleId);
  if (partyUuid === '') return undefined;
  return partyIdentity(poam, partyUuid) ?? { type: IdentityType.Simple, identifier: partyUuid };
}

/** Reads each planned remediation task of an HDF-produced risk as a milestone whose description is the remediation description. */
function hdfMilestones(risk: IdentifiedRisk, poam: PlanOfActionAndMilestonesPOAM): HdfMilestone[] {
  const milestones: HdfMilestone[] = [];
  for (const rem of risk.remediations ?? []) {
    if (rem.lifecycle !== 'planned') continue;
    for (const task of rem.tasks ?? []) {
      const end = task.timing?.['within-date-range']?.end;
      const estimatedCompletion = end && parseTimestamp(String(end));
      if (!estimatedCompletion) continue;
      const status = findVocabularyProp(task.props, 'milestone-status');
      const ms: HdfMilestone = {
        description: rem.description,
        estimatedCompletion,
        status: (status?.value as MilestoneStatus | undefined) ?? MilestoneStatus.Pending,
      };
      if (!hasFieldMarker(task.props, 'absent-field', 'title', '')) ms.title = task.title;
      const completedAt = findVocabularyProp(task.props, 'completed-at');
      const completedAtDate = completedAt && parseTimestamp(completedAt.value);
      if (completedAtDate) ms.completedAt = completedAtDate;
      for (const rr of task['responsible-roles'] ?? []) {
        const partyUuid = rr['party-uuids']?.[0];
        const completer = rr['role-id'] === 'completed-by' && partyUuid !== undefined ? partyIdentity(poam, partyUuid) : undefined;
        if (completer) ms.completedBy = completer;
      }
      milestones.push(ms);
    }
  }
  return milestones;
}

/** Begins the facet system of every CVSS version. */
const CVSS_SYSTEM_PREFIX = 'http://www.first.org/cvss/v';

/** Reads the characterization whose facets all use a CVSS system. */
function riskCvss(risk: IdentifiedRisk): Cvss | undefined {
  for (const ch of risk.characterizations ?? []) {
    if (ch.facets.length === 0 || !ch.facets.every((f) => f.system.startsWith(CVSS_SYSTEM_PREFIX))) continue;
    const values = new Map(ch.facets.map((f) => [f.name, f.remarks || f.value] as const));
    const str = (name: string, field: string): string | undefined =>
      values.get(name) ?? (hasFieldMarker(ch.props, 'empty-field', field, '') ? '' : undefined);
    const score = (name: string): number | undefined => {
      const value = values.get(name);
      return value !== undefined && value.trim() !== '' && !isNaN(Number(value)) ? Number(value) : undefined;
    };
    const severity = (name: string): CVSSSeverity | undefined => values.get(name) as CVSSSeverity | undefined;
    // Absent fields stay undefined, which serialization omits.
    const cvss: Cvss = {
      version: values.get('cvss_version') as Version,
      baseScore: score('base_score'),
      baseSeverity: severity('base_severity'),
      baseVector: str('base_vector', 'baseVector'),
      threatScore: score('threat_score'),
      threatVector: str('threat_vector', 'threatVector'),
      environmentalScore: score('environmental_score'),
      environmentalVector: str('environmental_vector', 'environmentalVector'),
      computedScore: score('computed_score'),
      computedSeverity: severity('computed_severity'),
      supplementalVector: str('supplemental_vector', 'supplementalVector'),
      source: str('source', 'source'),
    };
    return cvss;
  }
  return undefined;
}

/** Reads the evidence observations an HDF-produced item lists. */
function itemEvidence(item: POAMItem, poam: PlanOfActionAndMilestonesPOAM): Evidence[] {
  const evidence: Evidence[] = [];
  for (const ro of item['related-observations'] ?? []) {
    const obs = (poam.observations ?? []).find((o) => o.uuid === ro['observation-uuid']);
    if (obs) evidence.push(observationEvidence(obs, poam));
  }
  return evidence;
}

/** Decodes base64 to the UTF-8 text it encodes, or undefined when it is not base64. */
function decodeBase64Utf8(value: string): string | undefined {
  try {
    const binary = atob(value);
    return new TextDecoder().decode(Uint8Array.from(binary, (c) => c.charCodeAt(0)));
  } catch {
    return undefined;
  }
}

/** Reads one evidence item from its observation (ADR-0014 §4.6 Evidence table). */
function observationEvidence(obs: Observation, poam: PlanOfActionAndMilestonesPOAM): Evidence {
  const props = obs.props;
  const ev: Evidence = { type: (obs.types?.[0] ?? '') as EvidenceType, data: '' };
  if (!hasFieldMarker(props, 'absent-field', 'description', '')) ev.description = obs.description;
  const mimeType = vocabularyString(props, 'mime-type', 'mimeType', '');
  if (mimeType !== undefined) ev.mimeType = mimeType;
  const encoding = vocabularyString(props, 'evidence-encoding', 'encoding', '');
  if (encoding !== undefined) ev.encoding = encoding;
  const size = findVocabularyProp(props, 'evidence-size');
  if (size && size.value.trim() !== '' && !isNaN(Number(size.value))) ev.size = Number(size.value);
  if (!hasFieldMarker(props, 'absent-field', 'capturedAt', '')) {
    const capturedAt = parseTimestamp(String(obs.collected));
    if (capturedAt) ev.capturedAt = capturedAt;
  }
  for (const origin of obs.origins ?? []) {
    for (const actor of origin.actors) {
      const capturer = actor.type === 'party' && ev.capturedBy === undefined ? partyIdentity(poam, actor['actor-uuid']) : undefined;
      if (capturer) ev.capturedBy = capturer;
    }
  }

  const href = obs['relevant-evidence']?.[0]?.href;
  if (href) {
    ev.data = href;
    return ev;
  }
  for (const link of obs.links ?? []) {
    const res = backMatterResource(poam, link);
    if (link.rel !== 'evidence' || !res?.base64) continue;
    ev.data = encoding === 'base64' ? res.base64.value : (decodeBase64Utf8(res.base64.value) ?? res.base64.value);
    break;
  }
  return ev;
}

/** Resolves a link to the back-matter resource its "#<uuid>" href names. */
function backMatterResource(poam: PlanOfActionAndMilestonesPOAM, link: Link): Resource | undefined {
  if (!link.href.startsWith('#')) return undefined;
  return (poam['back-matter']?.resources ?? []).find((r) => r.uuid === link.href.slice(1));
}

/** Reads the external references an HDF-produced risk links to (ADR-0014 §4.6 External reference table). */
function riskReferences(risk: IdentifiedRisk, poam: PlanOfActionAndMilestonesPOAM): ExternalReference[] {
  const refs: ExternalReference[] = [];
  for (const link of risk.links ?? []) {
    const res = backMatterResource(poam, link);
    if (link.rel !== 'reference' || !res) continue;
    const props = res.props;
    const ref: ExternalReference = { sourceName: findVocabularyProp(props, 'source-name')?.value ?? '' };
    const externalId = vocabularyString(props, 'external-id', 'externalId', '');
    if (externalId !== undefined) ref.externalId = externalId;
    if (res.rlinks && res.rlinks.length > 0) ref.href = res.rlinks[0]!.href;
    else if (hasFieldMarker(props, 'empty-field', 'href', '')) ref.href = '';
    if (res.description) ref.description = res.description;
    else if (hasFieldMarker(props, 'empty-field', 'description', '')) ref.description = '';
    const rel = vocabularyString(props, 'reference-rel', 'rel', '');
    if (rel !== undefined) ref.rel = rel;
    const mediaType = vocabularyString(props, 'reference-media-type', 'mediaType', '');
    if (mediaType !== undefined) ref.mediaType = mediaType;
    const algorithm = vocabularyString(props, 'checksum-algorithm', 'checksum.algorithm', '');
    if (algorithm !== undefined) {
      ref.checksum = { algorithm: algorithm as HashAlgorithm, value: vocabularyString(props, 'checksum-value', 'checksum.value', '') ?? '' };
    }
    const addedBy = findVocabularyProp(props, 'added-by');
    const adder = addedBy ? partyIdentity(poam, addedBy.value) : undefined;
    if (adder) ref.addedBy = adder;
    const addedAt = findVocabularyProp(props, 'added-at');
    const addedAtDate = addedAt && parseTimestamp(addedAt.value);
    if (addedAtDate) ref.addedAt = addedAtDate;
    const kind = vocabularyString(props, 'reference-kind', 'kind', '');
    if (kind !== undefined) ref.kind = kind;
    const documentJson = res.base64 ? decodeBase64Utf8(res.base64.value) : undefined;
    if (documentJson !== undefined) {
      try {
        const document: unknown = JSON.parse(documentJson);
        if (document !== null && typeof document === 'object' && !Array.isArray(document)) ref.document = document as Record<string, unknown>;
      } catch {
        // Not a JSON document: the reference carries no embedded document.
      }
    }
    refs.push(ref);
  }
  return refs;
}

/**
 * The requirement id of an item that is not HDF-produced. A pre-ADR HDF export's id
 * comes only from its legacy impacted-control-id, never from a title (ADR-0014 §4.3),
 * so it is undefined for one that has none, which the conversion skips. Mirrors
 * foreignRequirementID in Go.
 */
function foreignRequirementId(item: POAMItem, riskMap: Map<string, IdentifiedRisk>): string | undefined {
  const preADR = overrideTypeRisk(item, riskMap, true);
  if (!preADR) return extractRequirementIdFromPOAMItem(item, riskMap);
  const control = findVocabularyProp(preADR.props, 'impacted-control-id');
  return control ? controlIdToNistTag(control.value) : undefined;
}

function extractRequirementIdFromPOAMItem(
  item: POAMItem,
  riskMap: Map<string, IdentifiedRisk>,
): string {
  // Check related risks for impacted-control-id
  for (const rr of item['related-risks'] ?? []) {
    const riskUuid = rr['risk-uuid'];
    if (riskUuid) {
      const risk = riskMap.get(riskUuid);
      if (risk) {
        const controlId = extractPropValue(risk.props, 'impacted-control-id');
        if (controlId) {
          return controlIdToNistTag(controlId);
        }
      }
    }
  }

  // Check poam-item props for POAM-ID
  const poamId = extractPropValue(item.props, 'POAM-ID');
  if (poamId) return poamId;

  // Fall back to the title
  if (item.title) return item.title;

  return 'unknown';
}

function poamItemReason(item: POAMItem): string {
  if (item.description) return item.description;
  if (item.title) return item.title;
  return 'POA&M item';
}

function poamItemStatus(
  item: POAMItem,
  riskMap: Map<string, IdentifiedRisk>,
): ResultStatus {
  for (const rr of item['related-risks'] ?? []) {
    const riskUuid = rr['risk-uuid'];
    if (riskUuid) {
      const risk = riskMap.get(riskUuid);
      if (risk) {
        const status = oscalStatusToHdf(risk.status);
        if (status === 'passed') return ResultStatus.Passed;
        if (status === 'failed') return ResultStatus.Failed;
      }
    }
  }

  // Default: POA&M items typically represent open/failed findings
  return ResultStatus.Failed;
}

function poamItemAppliedBy(
  poam: PlanOfActionAndMilestonesPOAM,
): StandaloneOverride['appliedBy'] {
  // Look for prepared-by in responsible-parties
  const preparedBy = firstResponsibleParty(poam.metadata, 'prepared-by');
  if (preparedBy !== '') {
    return { type: IdentityType.Simple, identifier: preparedBy };
  }

  // Fall back to any responsible party
  const rps = poam.metadata['responsible-parties'];
  if (rps && rps.length > 0 && rps[0]!['party-uuids'].length > 0) {
    return {
      type: IdentityType.Simple,
      identifier: rps[0]!['party-uuids'][0]!,
    };
  }

  return {
    type: IdentityType.System,
    identifier: 'oscal-poam-converter',
  };
}

// Returns appliedAt from the document's metadata.last-modified. OSCAL requires
// last-modified, so its absence is a malformed document — fail loud rather than
// stamp a wall-clock time. (Types say Date, but it is a string at runtime.)
function poamItemAppliedAt(poam: PlanOfActionAndMilestonesPOAM, requirementId: string): Date {
  const t = poam.metadata['last-modified'] && parseTimestamp(String(poam.metadata['last-modified']));
  if (t) return t;
  throw new Error(`poam-item "${requirementId}": no usable metadata.last-modified for appliedAt`);
}

// Returns the override deadline from the related risk's `deadline` — the
// enforceable time commitment of the POA&M. Fails loud when no related risk
// carries a usable deadline rather than inventing one.
function poamItemExpiresAt(
  item: POAMItem,
  riskMap: Map<string, IdentifiedRisk>,
  requirementId: string,
): Date {
  for (const rr of item['related-risks'] ?? []) {
    const riskUuid = rr['risk-uuid'];
    if (!riskUuid) continue;
    const risk = riskMap.get(riskUuid);
    if (!risk?.deadline) continue;
    const t = parseTimestamp(String(risk.deadline));
    if (t) return t;
  }
  throw new Error(
    `poam-item "${requirementId}": no related risk carries a usable deadline; a POA&M requires a time commitment`,
  );
}

// Builds milestones from the planned remediation tasks of a foreign item's
// related risks. Each task's within-date-range end is its estimated completion;
// tasks without a usable end date are skipped (the array is optional) — never
// fabricated — since estimatedCompletion is required and must reflect real data.
function extractMilestones(
  item: POAMItem,
  riskMap: Map<string, IdentifiedRisk>,
): HdfMilestone[] {
  const milestones: HdfMilestone[] = [];

  for (const rr of item['related-risks'] ?? []) {
    const riskUuid = rr['risk-uuid'];
    if (!riskUuid) continue;
    const risk = riskMap.get(riskUuid);
    if (!risk) continue;

    for (const rem of risk.remediations ?? []) {
      if (rem.lifecycle !== 'planned') continue;

      for (const task of rem.tasks ?? []) {
        const end = task.timing?.['within-date-range']?.end;
        const estimatedCompletion = end && parseTimestamp(String(end));
        if (!estimatedCompletion) continue;

        milestones.push({
          description: task.description ? `${task.title}: ${task.description}` : task.title,
          estimatedCompletion,
          status: MilestoneStatus.Pending,
        });
      }
    }
  }

  return milestones;
}
