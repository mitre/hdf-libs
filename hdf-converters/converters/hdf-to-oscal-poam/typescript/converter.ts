/**
 * Converts HDF Amendments to OSCAL Plan of Action and Milestones (POA&M) format.
 *
 * This is the reverse direction of the oscal-poam to HDF converter.
 *
 * Every amendments field has an OSCAL home the importer reads back exactly
 * (ADR-0014 §4.6), with four exclusions: the document integrity and signature,
 * the generator (the importer stamps its own), and each override's signature and
 * previousChecksum. A signature covers the original HDF bytes and the checksum
 * chain covers document order; neither survives a format change, and the
 * importer re-chains the overrides it reads.
 */

import { encodeBase64Utf8, formatTimestamp, formatTimestampSeconds, parseTimestamp } from '@mitre/hdf-utilities';
import { nistExists } from '@mitre/hdf-mappings';
import { requireHdfAmendments, firstNonEmpty } from '../../../shared/typescript/converterutil.js';
import { byCodePoint, canonicalize, floatNumber, stringifyLine } from '../../../shared/typescript/exportmap.js';
import type {
  HDFAmendments,
  StandaloneOverride,
  Evidence,
  Cvss,
  ExternalReference,
  Milestone,
  Identity,
  AffectedPackage,
} from '@mitre/hdf-schema';
import type {
  Oscal,
  DocumentMetadata,
  PlanOfActionAndMilestonesPOAM,
  POAMItem,
  IdentifiedRisk,
  Party,
  Role,
  ResponsibleParty,
  Property,
  RiskResponse,
  RiskLog,
  RiskLogEntry,
  Observation,
  RelevantEvidence,
  Characterization,
  Facet,
  BackMatter,
  Resource,
  Link,
  Task,
} from '../../oscal-to-hdf/typescript/types.js';
import {
  nistTagToControlId,
  hdfStatusToOscalRiskStatus,
  OSCAL_VERSION,
  oscalString,
} from '../../oscal-to-hdf/typescript/shared.js';
import {
  absentFieldProp,
  emptyFieldProp,
  normalizePropValue,
  pushVocabularyProp,
  vocabularyProp,
} from '../../oscal-to-hdf/typescript/vocabulary.js';

/**
 * Convert HDF Amendments JSON to OSCAL POA&M JSON.
 *
 * @param input - HDF Amendments JSON string
 * @returns OSCAL POA&M JSON string
 */
export async function convertHdfToOscalPoam(input: string): Promise<string> {
  // The guard rejects a document that cannot be faithfully converted rather than
  // letting a missing overrides array surface later as a TypeError. The
  // amendments schema puts minItems 1 on overrides, so a document that amends
  // nothing is invalid input, not a request for an empty POA&M — and it keeps
  // poam-items and risks non-empty, which the OSCAL schema requires of both.
  // Main's guard returns the decoded document and its top-level array rather
  // than a typed value, matching the Go reconciliation: the shared names keep
  // their contracts and the typed shape is taken here at the call site.
  const { doc: amendmentsDoc } = requireHdfAmendments(input, 'hdf-to-oscal-poam');
  const amendments = amendmentsDoc as unknown as HDFAmendments;

  const poam = amendmentsToPOAM(amendments);

  const doc: Oscal = {
    'plan-of-action-and-milestones': poam,
  };

  return JSON.stringify(doc, null, 2);
}

/** Role ids of the metadata roles the exporter defines. */
const ROLE_PREPARED_BY = 'prepared-by';
const ROLE_APPROVED_BY = 'approved-by';
const ROLE_COMPLETED_BY = 'completed-by';

/** Marks the risk-log entry whose start is the override's appliedAt and whose logged-by names its appliedBy. */
const OVERRIDE_APPLIED_TITLE = 'Override applied';

/**
 * Picks the document title, which OSCAL requires on metadata. The HDF name is
 * schema-required, so the fallbacks only matter for a document that slipped
 * through some other producer's validation.
 */
function poamTitle(a: HDFAmendments): string {
  // amendmentId is optional in HDF; main's firstNonEmpty takes strings, so the
  // absent case is coerced here rather than widening the shared helper's contract.
  return firstNonEmpty(a.name, a.amendmentId ?? '', 'HDF Amendments');
}

/**
 * Stands in for an empty requirementId: HDF puts no minLength on it, and OSCAL
 * 1.2.x requires risk and POA&M item titles to be non-empty. It is display text
 * only; the requirement id rides in hdf-requirement-id. Mirrors Go's
 * unidentifiedRequirementTitle.
 */
const UNIDENTIFIED_REQUIREMENT_TITLE = 'Unidentified requirement';

/** The title of the risk and POA&M item an override produces. */
function requirementTitle(override: StandaloneOverride): string {
  return firstNonEmpty(override.requirementId, UNIDENTIFIED_REQUIREMENT_TITLE);
}

/**
 * Supplies the text OSCAL requires for a risk's description and statement. HDF
 * puts no minLength on reason, so an override can legitimately carry none; the
 * fallback states that absence rather than inventing an impact assessment the
 * source never made, and names the requirement only when there is one.
 */
function riskRationale(override: StandaloneOverride): string {
  const absence =
    firstNonEmpty(override.requirementId) === ''
      ? `No rationale was recorded for the ${String(override.type)} override.`
      : `No rationale was recorded for the ${String(override.type)} override applied to ${override.requirementId}.`;
  return firstNonEmpty(override.reason, absence);
}

/** HDF dates arrive as strings from JSON.parse but are typed as Date. */
function toDate(value: string | Date | undefined): Date | undefined {
  if (value === undefined) return undefined;
  const d = typeof value === 'string' ? parseTimestamp(value) : value;
  if (!d || isNaN(d.getTime())) return undefined;
  return d;
}

/**
 * Deduplicates HDF identities into OSCAL metadata parties, one per distinct
 * (identifier, type, description) triple; an absent and an empty description are
 * distinct. Insertion order is preserved for deterministic output.
 */
class PartyRegistry {
  private byKey = new Map<string, Party>();

  getOrAdd(id: Identity): string {
    const key = JSON.stringify([id.identifier, id.type, id.description ?? null]);
    const existing = this.byKey.get(key);
    if (existing) return existing.uuid as string;
    // name is omitted, not emptied, when the source identity carries none:
    // OSCAL requires only uuid and type on a party. Mirrors Go's omitempty.
    const name = oscalString(id.identifier);
    const props: Property[] = [];
    pushVocabularyProp(props, 'identity-identifier', id.identifier ?? '');
    pushVocabularyProp(props, 'identity-type', String(id.type));
    if (id.description === '') {
      props.push(emptyFieldProp('description'));
    }
    const party = {
      uuid: crypto.randomUUID(),
      type: 'person',
      ...(name === '' ? {} : { name }),
      ...(props.length > 0 ? { props } : {}),
      ...(id.description ? { remarks: id.description } : {}),
    } as unknown as Party;
    this.byKey.set(key, party);
    return party.uuid as string;
  }

  list(): Party[] {
    return [...this.byKey.values()];
  }
}

/** Accumulates the document-wide objects overrides contribute to. */
interface PoamBuilder {
  parties: PartyRegistry;
  observations: Observation[];
  resources: Resource[];
  completedBy: boolean;
}

/**
 * Converts parsed HDFAmendments to an OSCAL PlanOfActionAndMilestones.
 */
function amendmentsToPOAM(amendments: HDFAmendments): PlanOfActionAndMilestonesPOAM {
  const b: PoamBuilder = { parties: new PartyRegistry(), observations: [], resources: [], completedBy: false };

  const roles: Role[] = [];
  const responsibleParties: ResponsibleParty[] = [];

  // The document preparer and the authorizing official become responsible
  // parties with distinct roles — a direct mirror of one another.
  if (amendments.appliedBy) {
    const uuid = b.parties.getOrAdd(amendments.appliedBy);
    roles.push({ id: ROLE_PREPARED_BY, title: 'Prepared By' } as unknown as Role);
    responsibleParties.push({ 'role-id': ROLE_PREPARED_BY, 'party-uuids': [uuid] } as unknown as ResponsibleParty);
  }
  if (amendments.approvedBy) {
    const uuid = b.parties.getOrAdd(amendments.approvedBy);
    roles.push({ id: ROLE_APPROVED_BY, title: 'Approved By' } as unknown as Role);
    responsibleParties.push({ 'role-id': ROLE_APPROVED_BY, 'party-uuids': [uuid] } as unknown as ResponsibleParty);
  }

  // Register each override's own applier so per-override attribution survives as
  // a distinct metadata party even when it differs from the document default.
  for (const override of amendments.overrides) {
    b.parties.getOrAdd(override.appliedBy);
  }

  const poamItems: POAMItem[] = [];
  const risks: IdentifiedRisk[] = [];
  for (const override of amendments.overrides) {
    const { item, risk } = overrideToPOAMItem(override, b);
    poamItems.push(item);
    risks.push(risk);
  }

  if (b.completedBy) {
    roles.push({ id: ROLE_COMPLETED_BY, title: 'Completed By' });
  }

  const metadata = {
    title: poamTitle(amendments),
    'last-modified': latestAppliedAt(amendments.overrides),
    version: amendmentsVersion(amendments),
    'oscal-version': OSCAL_VERSION,
  } as unknown as DocumentMetadata;

  if (amendments.description) {
    metadata.remarks = amendments.description;
  }
  const partyList = b.parties.list();
  if (partyList.length > 0) {
    metadata.parties = partyList;
  }
  if (roles.length > 0) {
    metadata.roles = roles;
  }
  if (responsibleParties.length > 0) {
    metadata['responsible-parties'] = responsibleParties;
  }
  const metaProps = metadataProps(amendments);
  if (metaProps.length > 0) {
    metadata.props = metaProps;
  }

  const poam: PlanOfActionAndMilestonesPOAM = {
    uuid: crypto.randomUUID(),
    metadata,
    'import-ssp': { href: amendments.systemRef ? amendments.systemRef : '#' },
    'poam-items': poamItems,
  };
  // Emitted only when non-empty, matching the Go peer's omitempty: the schema
  // puts minItems 1 on risks, so an empty array would be invalid where absence
  // is fine. The guard makes zero risks unreachable today; this keeps the two
  // languages from diverging if that ever changes.
  if (risks.length > 0) {
    poam.risks = risks;
  }
  if (b.observations.length > 0) {
    poam.observations = b.observations;
  }
  if (b.resources.length > 0) {
    poam['back-matter'] = { resources: b.resources } as unknown as BackMatter;
  }

  return poam;
}

/**
 * Carries an optional HDF string field: its prop when the value is non-empty,
 * empty-field when it is present and empty (§1.7.3), and nothing when it is
 * absent. Mirrors appendOptionalString in Go.
 */
function pushOptionalString(props: Property[], name: string, field: string, value: string | undefined | null): void {
  if (value === undefined || value === null) return;
  if (value === '') {
    props.push(emptyFieldProp(field));
    return;
  }
  pushVocabularyProp(props, name, value);
}

/** Renders HDF text as single-line OSCAL display text, falling back when there is none. */
function displayLine(text: string, fallback: string): string {
  return normalizePropValue(text) || fallback;
}

/** The HDF canonical trimmed-UTC form of a date, keeping its millisecond fraction. */
function timestamp(value: string | Date | undefined): string | undefined {
  const d = toDate(value);
  return d ? formatTimestamp(d) : undefined;
}

/**
 * Converts a single StandaloneOverride to a POAMItem and its risk, adding its
 * evidence observations, back-matter resources and parties to the builder.
 */
function overrideToPOAMItem(override: StandaloneOverride, b: PoamBuilder): { item: POAMItem; risk: IdentifiedRisk } {
  const riskUUID = crypto.randomUUID();

  // Overrides without a status field (impact-only) are treated as open risks.
  const riskStatus = override.status ? hdfStatusToOscalRiskStatus(String(override.status)) : 'open';

  const applier = b.parties.getOrAdd(override.appliedBy);
  const remediations = milestoneRemediations(override.milestones ?? [], b);
  const characterizations = cvssCharacterizations(override.cvss, applier);
  const riskLog = riskLogFor(override, applier, riskStatus);
  const deadline = timestamp(override.expiresAt);

  const itemObs: string[] = [];
  for (const ev of override.evidence ?? []) {
    const obs = evidenceObservation(ev, override.appliedAt, b);
    b.observations.push(obs);
    itemObs.push(obs.uuid);
  }
  const links: Link[] = [];
  for (const ref of (override.externalReferences ?? []) as ExternalReference[]) {
    const res = referenceResource(ref, b);
    b.resources.push(res);
    links.push({ href: `#${res.uuid}`, rel: 'reference' });
  }

  // OSCAL lists title, description, statement and status as required on a risk.
  // HDF puts no minLength on reason, so an override can legitimately carry none.
  const rationale = riskRationale(override);

  const risk = {
    uuid: riskUUID,
    title: requirementTitle(override),
    description: rationale,
    statement: rationale,
    props: riskProps(override),
    ...(links.length > 0 ? { links } : {}),
    status: riskStatus,
    ...(deadline ? { deadline } : {}),
    ...(characterizations.length > 0 ? { characterizations } : {}),
    ...(remediations.length > 0 ? { remediations } : {}),
    ...(riskLog ? { 'risk-log': riskLog } : {}),
  } as unknown as IdentifiedRisk;

  const item = {
    uuid: crypto.randomUUID(),
    title: requirementTitle(override),
    description: override.reason,
    ...(itemObs.length > 0 ? { 'related-observations': itemObs.map((uuid) => ({ 'observation-uuid': uuid })) } : {}),
    'related-risks': [{ 'risk-uuid': riskUUID }],
  } as unknown as POAMItem;

  return { item, risk };
}

/**
 * Carries the override's identity, disposition and scope. The FedRAMP
 * impacted-control-id is added only for a requirement id NIST defines.
 */
function riskProps(override: StandaloneOverride): Property[] {
  const props: Property[] = [];
  pushVocabularyProp(props, 'hdf-requirement-id', override.requirementId ?? '');
  if (nistExists(override.requirementId ?? '')) {
    pushVocabularyProp(props, 'impacted-control-id', nistTagToControlId(override.requirementId));
  }
  pushVocabularyProp(props, 'override-type', String(override.type));
  if (override.status !== undefined) {
    pushVocabularyProp(props, 'override-status', String(override.status));
  }
  if (override.impact && typeof override.impact.value === 'number') {
    pushVocabularyProp(props, 'impact-override', floatNumber(override.impact.value).token);
  }
  if (override.justification !== undefined) {
    pushVocabularyProp(props, 'justification', String(override.justification));
  }
  pushOptionalString(props, 'baseline-ref', 'baselineRef', override.baselineRef);
  pushOptionalString(props, 'component-ref', 'componentRef', override.componentRef);
  pushOptionalString(props, 'inherited-from', 'inheritedFrom', override.inheritedFrom);
  (override.affectedPackages ?? []).forEach((pkg, i) => {
    props.push(...affectedPackageProps(pkg, `package-${i + 1}`));
  });
  return props;
}

/** Carries one affected package, every prop in its group. */
function affectedPackageProps(pkg: AffectedPackage, group: string): Property[] {
  const props: Property[] = [];
  pushOptionalString(props, 'affected-package-name', 'name', pkg.name);
  pushOptionalString(props, 'affected-package-version', 'version', pkg.version);
  pushOptionalString(props, 'affected-package-ecosystem', 'ecosystem', pkg.ecosystem === undefined ? undefined : String(pkg.ecosystem));
  pushOptionalString(props, 'affected-package-cpe', 'cpe', pkg.cpe);
  pushOptionalString(props, 'affected-package-purl', 'purl', pkg.purl);
  pushOptionalString(props, 'affected-package-fixed-in-version', 'fixedInVersion', pkg.fixedInVersion);
  return props.map((p) => ({ ...p, group }));
}

/** Records when and by whom the override was applied, and its scheduled review at expiry. */
function riskLogFor(override: StandaloneOverride, applier: string, riskStatus: string): RiskLog | undefined {
  // The generated type says Date, but OSCAL JSON carries start as the canonical timestamp string.
  const entries: Array<Omit<RiskLogEntry, 'start'> & { start: string }> = [];
  const appliedAt = timestamp(override.appliedAt);
  if (appliedAt) {
    entries.push({
      uuid: crypto.randomUUID(),
      title: OVERRIDE_APPLIED_TITLE,
      start: appliedAt,
      'logged-by': [{ 'party-uuid': applier }],
    });
  }
  const expiresAt = timestamp(override.expiresAt);
  if (expiresAt) {
    entries.push({
      uuid: crypto.randomUUID(),
      title: 'Scheduled review',
      description: 'Amendment expiration date',
      start: expiresAt,
      'status-change': riskStatus,
    });
  }
  return entries.length > 0 ? ({ entries } as unknown as RiskLog) : undefined;
}

/**
 * Renders each milestone as a planned remediation whose title and description are
 * the milestone's and whose task carries its title, schedule, status and
 * completion. An untitled milestone is titled "Milestone <n>" and marked
 * absent-field on both objects (§1.7.4). Mirrors milestoneRemediations in Go.
 */
function milestoneRemediations(milestones: Milestone[], b: PoamBuilder): RiskResponse[] {
  return milestones.map((ms, i) => {
    const marker = ms.title === undefined ? [absentFieldProp('title')] : [];
    const title = ms.title ?? `Milestone ${i + 1}`;
    const rem: RiskResponse = {
      uuid: crypto.randomUUID(),
      lifecycle: 'planned',
      title,
      description: ms.description,
      ...(marker.length > 0 ? { props: marker } : {}),
    };
    const eta = timestamp(ms.estimatedCompletion);
    if (eta) {
      const props: Property[] = [...marker];
      pushVocabularyProp(props, 'milestone-status', String(ms.status));
      const completedAt = timestamp(ms.completedAt);
      if (completedAt) {
        pushVocabularyProp(props, 'completed-at', completedAt);
      }
      const task = {
        uuid: crypto.randomUUID(),
        type: 'milestone',
        title,
        ...(props.length > 0 ? { props } : {}),
        timing: { 'within-date-range': { start: eta, end: eta } },
      } as unknown as Task;
      if (ms.completedBy) {
        b.completedBy = true;
        task['responsible-roles'] = [{ 'role-id': ROLE_COMPLETED_BY, 'party-uuids': [b.parties.getOrAdd(ms.completedBy)] }];
      }
      rem.tasks = [task];
    }
    return rem;
  });
}

/**
 * Returns the most recent override appliedAt for metadata.last-modified.
 * Sourcing it from the input keeps output deterministic. Falls back to the wall
 * clock only when no override carries a date (appliedAt is schema-required, so
 * real documents always supply one).
 */
function latestAppliedAt(overrides: StandaloneOverride[]): string {
  let latest: Date | undefined;
  for (const o of overrides) {
    const d = toDate(o.appliedAt);
    if (d && (!latest || d.getTime() > latest.getTime())) {
      latest = d;
    }
  }
  return formatTimestampSeconds(latest ?? new Date());
}

/**
 * Sources metadata.version from the amendments document. OSCAL requires a
 * version, so an absent or empty one is written as 1.0.0 and marked by a metadata prop.
 */
function amendmentsVersion(a: HDFAmendments): string {
  return oscalString(a.version ?? '') || '1.0.0';
}

/**
 * Carries the document fields that have no first-class OSCAL home and marks the
 * display fallbacks OSCAL forced. Labels are key/value prop pairs grouped in
 * sorted key order.
 */
function metadataProps(a: HDFAmendments): Property[] {
  const props: Property[] = [];
  pushVocabularyProp(props, 'amendments-name', a.name ?? '');
  pushOptionalString(props, 'amendment-id', 'amendmentId', a.amendmentId);
  if (a.description === '') {
    props.push(emptyFieldProp('description'));
  }
  pushFallbackMarker(props, 'systemRef', a.systemRef);
  pushFallbackMarker(props, 'version', a.version);
  Object.keys(a.labels ?? {})
    .sort(byCodePoint)
    .forEach((key, i) => {
      const group = `label-${i + 1}`;
      props.push(labelProp('label-key', 'key', key, group), labelProp('label-value', 'value', a.labels![key]!, group));
    });
  return props;
}

/**
 * Marks an OSCAL-required field written as a display fallback: absent-field when
 * the HDF field is absent, empty-field when it is empty.
 */
function pushFallbackMarker(props: Property[], field: string, value: string | undefined): void {
  if (value === undefined) {
    props.push(absentFieldProp(field));
  } else if (value === '') {
    props.push(emptyFieldProp(field));
  }
}

/** Renders one half of an amendments label; an empty key or value is carried by empty-field (§1.7.3). */
function labelProp(name: string, field: string, value: string, group: string): Property {
  const prop = vocabularyProp(name, value) ?? emptyFieldProp(field);
  return { ...prop, class: 'amendment-label', group };
}

/** An RFC 3986 URI with a scheme, whose characters are all ones a URI may contain. */
const ABSOLUTE_URI = /^[A-Za-z][A-Za-z0-9+.-]*:[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=%]*$/;

/** Whether evidence data is carried as the observation's relevant-evidence href rather than in a back-matter resource. */
function evidenceDataIsHref(ev: Evidence): boolean {
  switch (String(ev.type)) {
    case 'url':
      return true;
    case 'screenshot':
    case 'file':
      return ABSOLUTE_URI.test(ev.data);
    default:
      return false;
  }
}

/** Renders a single HDF Evidence item as an OSCAL observation. */
function evidenceObservation(ev: Evidence, appliedAt: string | Date, b: PoamBuilder): Observation {
  const props: Property[] = [];
  let display = 'Supporting evidence';
  let description = display;
  if (ev.description === undefined) {
    props.push(absentFieldProp('description'));
  } else {
    description = ev.description;
    display = displayLine(ev.description, display);
  }
  pushOptionalString(props, 'mime-type', 'mimeType', ev.mimeType);
  pushOptionalString(props, 'evidence-encoding', 'encoding', ev.encoding);
  if (typeof ev.size === 'number') {
    pushVocabularyProp(props, 'evidence-size', floatNumber(ev.size).token);
  }
  let collected = timestamp(ev.capturedAt);
  if (collected === undefined) {
    collected = timestamp(appliedAt) ?? formatTimestamp(new Date());
    props.push(absentFieldProp('capturedAt'));
  }

  const re: RelevantEvidence = { description: display };
  let links: Link[] | undefined;
  if (evidenceDataIsHref(ev)) {
    re.href = ev.data;
  } else {
    const res = {
      uuid: crypto.randomUUID(),
      base64: {
        ...(ev.mimeType ? { 'media-type': normalizePropValue(ev.mimeType) } : {}),
        value: ev.encoding === 'base64' ? ev.data : encodeBase64Utf8(ev.data),
      },
    } as unknown as Resource;
    b.resources.push(res);
    links = [{ href: `#${res.uuid}`, rel: 'evidence' }];
  }

  return {
    uuid: crypto.randomUUID(),
    description,
    ...(props.length > 0 ? { props } : {}),
    ...(links ? { links } : {}),
    methods: ['EXAMINE'],
    types: [String(ev.type)],
    ...(ev.capturedBy ? { origins: [{ actors: [{ type: 'party', 'actor-uuid': b.parties.getOrAdd(ev.capturedBy) }] }] } : {}),
    collected,
    'relevant-evidence': [re],
  } as unknown as Observation;
}

/**
 * Carries an HDF Cvss record as one risk characterization: a facet per present
 * field in the CVSS system for its version, attributed to the override's applier.
 */
function cvssCharacterizations(c: Cvss | undefined, applier: string): Characterization[] {
  if (!c) return [];
  const system = `http://www.first.org/cvss/v${String(c.version)}`;
  const props: Property[] = [];
  const facets: Facet[] = [];
  const add = (name: string, field: string, value: string | undefined | null): void => {
    if (value === undefined || value === null) return;
    if (value === '') {
      props.push(emptyFieldProp(field));
      return;
    }
    const facet: Facet = { name, system, value: normalizePropValue(value) };
    if (facet.value !== value) facet.remarks = value;
    facets.push(facet);
  };
  const score = (name: string, field: string, value: number | undefined | null): void => {
    if (typeof value === 'number') add(name, field, floatNumber(value).token);
  };
  add('cvss_version', 'version', String(c.version));
  score('base_score', 'baseScore', c.baseScore);
  add('base_severity', 'baseSeverity', c.baseSeverity === undefined ? undefined : String(c.baseSeverity));
  add('base_vector', 'baseVector', c.baseVector);
  score('threat_score', 'threatScore', c.threatScore);
  add('threat_vector', 'threatVector', c.threatVector);
  score('environmental_score', 'environmentalScore', c.environmentalScore);
  add('environmental_vector', 'environmentalVector', c.environmentalVector);
  score('computed_score', 'computedScore', c.computedScore);
  add('computed_severity', 'computedSeverity', c.computedSeverity === undefined ? undefined : String(c.computedSeverity));
  add('supplemental_vector', 'supplementalVector', c.supplementalVector);
  add('source', 'source', c.source);
  return [
    {
      ...(props.length > 0 ? { props } : {}),
      origin: { actors: [{ type: 'party', 'actor-uuid': applier }] },
      facets,
    } as unknown as Characterization,
  ];
}

/** Carries one external reference as a back-matter resource. */
function referenceResource(ref: ExternalReference, b: PoamBuilder): Resource {
  const props: Property[] = [];
  pushVocabularyProp(props, 'source-name', ref.sourceName ?? '');
  pushOptionalString(props, 'external-id', 'externalId', ref.externalId);
  if (ref.href === '') props.push(emptyFieldProp('href'));
  if (ref.description === '') props.push(emptyFieldProp('description'));
  pushOptionalString(props, 'reference-rel', 'rel', ref.rel);
  pushOptionalString(props, 'reference-media-type', 'mediaType', ref.mediaType);
  if (ref.checksum) {
    pushOptionalString(props, 'checksum-algorithm', 'checksum.algorithm', String(ref.checksum.algorithm));
    pushOptionalString(props, 'checksum-value', 'checksum.value', ref.checksum.value);
  }
  if (ref.addedBy) {
    pushVocabularyProp(props, 'added-by', b.parties.getOrAdd(ref.addedBy));
  }
  const addedAt = timestamp(ref.addedAt);
  if (addedAt) {
    pushVocabularyProp(props, 'added-at', addedAt);
  }
  pushOptionalString(props, 'reference-kind', 'kind', ref.kind);

  return {
    uuid: crypto.randomUUID(),
    title: ref.sourceName,
    ...(ref.description ? { description: ref.description } : {}),
    ...(props.length > 0 ? { props } : {}),
    ...(ref.href ? { rlinks: [{ href: ref.href }] } : {}),
    // Compact JSON with sorted object keys, byte-identical to the Go peer.
    ...(ref.document ? { base64: { 'media-type': 'application/json', value: encodeBase64Utf8(stringifyLine(canonicalize(ref.document))) } } : {}),
  } as unknown as Resource;
}
