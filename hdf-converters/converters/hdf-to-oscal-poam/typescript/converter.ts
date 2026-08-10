/**
 * Converts HDF Amendments to OSCAL Plan of Action and Milestones (POA&M) format.
 *
 * This is the reverse direction of the oscal-poam to HDF converter.
 */

import { parseTimestamp, formatTimestampSeconds } from '@mitre/hdf-utilities';
import { validateInputSize, parseHdf } from '../../../shared/typescript/converterutil.js';
import type { HDFAmendments, StandaloneOverride, Evidence, Cvss, ExternalReference, Milestone, Identity } from '@mitre/hdf-schema';
import type {
  Oscal,
  DocumentMetadata,
  ImportSystemSecurityPlan,
  PlanOfActionAndMilestonesPOAM,
  POAMItem,
  IdentifiedRisk,
  Party,
  Role,
  ResponsibleParty,
  Property,
  RiskResponse,
  RiskLog,
  Observation,
  RelevantEvidence,
  Characterization,
  Facet,
  BackMatter,
  Resource,
} from '../../oscal-to-hdf/typescript/types.js';
import {
  nistTagToControlId,
  hdfStatusToOscalRiskStatus,
  OSCAL_VERSION,
} from '../../oscal-to-hdf/typescript/shared.js';

/**
 * Convert HDF Amendments JSON to OSCAL POA&M JSON.
 *
 * @param input - HDF Amendments JSON string
 * @returns OSCAL POA&M JSON string
 */
export async function convertHdfToOscalPoam(input: string): Promise<string> {
  validateInputSize(input, 'hdf-to-oscal-poam');

  if (!input || input.trim().length === 0) {
    throw new Error('hdf-to-oscal-poam: empty input');
  }

  let amendments: HDFAmendments;
  try {
    amendments = parseHdf<HDFAmendments>(input);
  } catch {
    throw new Error('hdf-to-oscal-poam: failed to parse JSON');
  }

  const poam = amendmentsToPOAM(amendments);

  const doc: Oscal = {
    'plan-of-action-and-milestones': poam,
  };

  return JSON.stringify(doc, null, 2);
}

/** HDF dates arrive as strings from JSON.parse but are typed as Date. */
function toDate(value: string | Date | undefined): Date | undefined {
  if (value === undefined) return undefined;
  const d = typeof value === 'string' ? parseTimestamp(value) : value;
  if (!d || isNaN(d.getTime())) return undefined;
  return d;
}

/**
 * Deduplicates HDF identities into OSCAL metadata parties. A party keeps its
 * UUID across reuse so origin actors and responsible parties reference the same
 * entry. Insertion order is preserved for deterministic output.
 */
class PartyRegistry {
  private byId = new Map<string, Party>();

  getOrAdd(id: Identity): string {
    const existing = this.byId.get(id.identifier);
    if (existing) return existing.uuid as string;
    const party = {
      uuid: crypto.randomUUID(),
      type: 'person',
      name: id.identifier,
    } as unknown as Party;
    this.byId.set(id.identifier, party);
    return party.uuid as string;
  }

  list(): Party[] {
    return [...this.byId.values()];
  }
}

/**
 * Converts parsed HDFAmendments to an OSCAL PlanOfActionAndMilestones.
 */
function amendmentsToPOAM(amendments: HDFAmendments): PlanOfActionAndMilestonesPOAM {
  const parties = new PartyRegistry();

  const roles: Role[] = [];
  const responsibleParties: ResponsibleParty[] = [];

  // The document preparer and the authorizing official become responsible
  // parties with distinct roles — a direct mirror of one another.
  if (amendments.appliedBy) {
    const uuid = parties.getOrAdd(amendments.appliedBy);
    roles.push({ id: 'prepared-by', title: 'Prepared By' } as unknown as Role);
    responsibleParties.push({ 'role-id': 'prepared-by', 'party-uuids': [uuid] } as unknown as ResponsibleParty);
  }
  if (amendments.approvedBy) {
    const uuid = parties.getOrAdd(amendments.approvedBy);
    roles.push({ id: 'approved-by', title: 'Approved By' } as unknown as Role);
    responsibleParties.push({ 'role-id': 'approved-by', 'party-uuids': [uuid] } as unknown as ResponsibleParty);
  }

  // Register each override's own applier so per-override attribution survives as
  // a distinct metadata party even when it differs from the document default.
  for (const override of amendments.overrides) {
    parties.getOrAdd(override.appliedBy);
  }

  // Build import-ssp
  let importSSP: ImportSystemSecurityPlan;
  if (amendments.systemRef && amendments.systemRef !== '') {
    importSSP = { href: amendments.systemRef } as ImportSystemSecurityPlan;
  } else {
    importSSP = { href: '#' } as ImportSystemSecurityPlan;
  }

  // Convert overrides to poam-items, risks and evidence observations.
  const poamItems: POAMItem[] = [];
  const risks: IdentifiedRisk[] = [];
  const observations: Observation[] = [];

  for (const override of amendments.overrides) {
    const { item, itemRisks, itemObs } = overrideToPOAMItem(override, parties);
    poamItems.push(item);
    risks.push(...itemRisks);
    observations.push(...itemObs);
  }

  const metadata = {
    title: amendments.name,
    'last-modified': latestAppliedAt(amendments.overrides),
    version: amendmentsVersion(amendments),
    'oscal-version': OSCAL_VERSION,
  } as unknown as DocumentMetadata;

  if (amendments.description) {
    metadata.remarks = amendments.description;
  }
  const partyList = parties.list();
  if (partyList.length > 0) {
    metadata.parties = partyList;
  }
  if (roles.length > 0) {
    metadata.roles = roles;
    metadata['responsible-parties'] = responsibleParties;
  }
  const metaProps = metadataProps(amendments);
  if (metaProps.length > 0) {
    metadata.props = metaProps;
  }

  const poam: PlanOfActionAndMilestonesPOAM = {
    uuid: crypto.randomUUID(),
    metadata,
    'import-ssp': importSSP,
    risks,
    'poam-items': poamItems,
  };
  if (observations.length > 0) {
    poam.observations = observations;
  }
  const resources = externalRefResources(amendments.overrides);
  if (resources.length > 0) {
    poam['back-matter'] = { resources } as unknown as BackMatter;
  }

  return poam;
}

/**
 * Converts a single StandaloneOverride to a POAMItem, its associated Risk, and
 * any evidence observations.
 */
function overrideToPOAMItem(
  override: StandaloneOverride,
  parties: PartyRegistry,
): { item: POAMItem; itemRisks: IdentifiedRisk[]; itemObs: Observation[] } {
  const riskUUID = crypto.randomUUID();

  // Map HDF status to OSCAL risk status
  const riskStatus = override.status
    ? hdfStatusToOscalRiskStatus(String(override.status))
    : 'open';

  // Convert requirement ID from NIST notation to OSCAL control ID
  const controlID = nistTagToControlId(override.requirementId);

  // Build risk props: impacted control, override type (disposition), impact
  // override, controlled-vocabulary justification, and disambiguating scope.
  const riskProps: Property[] = [
    {
      name: 'impacted-control-id',
      value: controlID,
    },
  ];
  if (override.type) {
    riskProps.push({ name: 'override-type', value: String(override.type) });
  }
  if (override.impact && typeof override.impact.value === 'number') {
    riskProps.push({ name: 'impact-override', value: String(override.impact.value) });
  }
  if (override.justification) {
    riskProps.push({ name: 'justification', value: String(override.justification) });
  }
  if (override.baselineRef) {
    riskProps.push({ name: 'baseline-ref', value: override.baselineRef });
  }
  if (override.componentRef) {
    riskProps.push({ name: 'component-ref', value: override.componentRef });
  }

  // Build remediations from milestones. Each milestone becomes a planned
  // remediation task whose within-date-range end carries the estimated
  // completion — the structure the forward converter reads back.
  const remediations: RiskResponse[] = [];
  if (override.milestones) {
    for (const ms of override.milestones) {
      const msProps: Property[] = [];
      if (ms.status) {
        msProps.push({ name: 'milestone-status', value: String(ms.status) });
      }
      let tasks: RiskResponse['tasks'];
      const d = ms.estimatedCompletion ? toDate(ms.estimatedCompletion) : undefined;
      if (d) {
        const eta = formatTimestampSeconds(d);
        const taskProps = milestoneCompletionProps(ms);
        tasks = [{
          uuid: crypto.randomUUID(),
          type: 'milestone',
          title: ms.description,
          timing: { 'within-date-range': { start: eta, end: eta } },
          ...(taskProps.length > 0 ? { props: taskProps } : {}),
        } as unknown as NonNullable<RiskResponse['tasks']>[number]];
      }
      remediations.push({
        uuid: crypto.randomUUID(),
        lifecycle: 'planned',
        title: ms.description,
        description: ms.description,
        props: msProps.length > 0 ? msProps : undefined,
        tasks,
      });
    }
  }

  // Structured CVSS scoring rides on a risk characterization: its facets carry
  // the scores/vectors, and its origin actor attributes the scoring to the
  // override's applier.
  const characterizations: Characterization[] = [];
  if (override.cvss) {
    const actorUUID = parties.getOrAdd(override.appliedBy);
    characterizations.push({
      origin: { actors: [{ 'actor-uuid': actorUUID, type: 'party' }] },
      facets: cvssFacets(override.cvss),
    } as unknown as Characterization);
  }

  // Build risk log entry for expiration tracking
  let riskLog: RiskLog | undefined;
  const expiresDate = override.expiresAt ? toDate(override.expiresAt) : undefined;
  if (expiresDate && expiresDate.getTime() > 0) {
    riskLog = {
      entries: [
        {
          uuid: crypto.randomUUID(),
          title: 'Scheduled review',
          description: 'Amendment expiration date',
          start: formatTimestampSeconds(expiresDate),
          'status-change': riskStatus,
        },
      ],
    } as unknown as RiskLog;
  }

  // The override's enforceable expiry maps to the risk deadline — the field the
  // forward converter reads to reconstruct expiresAt.
  const deadline = expiresDate && expiresDate.getTime() > 0 ? formatTimestampSeconds(expiresDate) : undefined;

  // Supporting evidence becomes observations, linked back from the poam-item.
  const itemObs: Observation[] = [];
  const relatedObs: Array<{ 'observation-uuid': string }> = [];
  const collected = observationCollected(override);
  if (override.evidence) {
    for (const ev of override.evidence) {
      const obsUUID = crypto.randomUUID();
      itemObs.push(evidenceObservation(ev, obsUUID, collected));
      relatedObs.push({ 'observation-uuid': obsUUID });
    }
  }

  const risk = {
    uuid: riskUUID,
    title: override.requirementId,
    description: override.reason,
    statement: override.reason,
    status: riskStatus,
    deadline,
    props: riskProps,
    characterizations: characterizations.length > 0 ? characterizations : undefined,
    remediations: remediations.length > 0 ? remediations : undefined,
    'risk-log': riskLog,
  } as unknown as IdentifiedRisk;

  const item = {
    uuid: crypto.randomUUID(),
    title: override.requirementId,
    description: override.reason,
    'related-risks': [{ 'risk-uuid': riskUUID }],
    ...(relatedObs.length > 0 ? { 'related-observations': relatedObs } : {}),
  } as unknown as POAMItem;

  return { item, itemRisks: [risk], itemObs };
}

/**
 * Returns the most recent override appliedAt for metadata.last-modified.
 * Sourcing it from the input keeps output deterministic and lets the reverse
 * importer recover appliedAt. Falls back to the wall clock only when no override
 * carries a date (appliedAt is schema-required, so real documents always supply
 * one).
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

/** Sources metadata.version from the amendments document, defaulting when omitted. */
function amendmentsVersion(a: HDFAmendments): string {
  return a.version && a.version !== '' ? a.version : '1.0.0';
}

/**
 * Carries document identifiers and labels that have no first-class OSCAL home.
 * Labels are emitted in sorted key order for deterministic output.
 */
function metadataProps(a: HDFAmendments): Property[] {
  const props: Property[] = [];
  if (a.amendmentId) {
    props.push({ name: 'amendment-id', value: a.amendmentId });
  }
  if (a.labels) {
    for (const k of Object.keys(a.labels).sort()) {
      props.push({ name: k, value: a.labels[k], class: 'amendment-label' } as unknown as Property);
    }
  }
  return props;
}

/** Picks the collection timestamp for evidence observations. */
function observationCollected(override: StandaloneOverride): string {
  const d = toDate(override.appliedAt);
  return formatTimestampSeconds(d ?? new Date());
}

/** Renders a single HDF Evidence item as an OSCAL observation. */
function evidenceObservation(ev: Evidence, uuid: string, defaultCollected: string): Observation {
  const captured = ev.capturedAt ? toDate(ev.capturedAt) : undefined;
  const collected = captured ? formatTimestampSeconds(captured) : defaultCollected;

  const desc = ev.description && ev.description !== '' ? ev.description : 'supporting evidence';

  const re = { description: desc } as unknown as RelevantEvidence;
  if (ev.type === 'url') {
    re.href = ev.data;
  } else if (ev.data) {
    re.remarks = ev.data;
  }

  const props: Property[] = [];
  if (ev.mimeType) {
    props.push({ name: 'mime-type', value: ev.mimeType });
  }
  if (ev.capturedBy && ev.capturedBy.identifier) {
    props.push({ name: 'captured-by', value: ev.capturedBy.identifier });
  }

  return {
    uuid,
    description: desc,
    methods: ['EXAMINE'],
    types: [String(ev.type)],
    collected,
    ...(props.length > 0 ? { props } : {}),
    'relevant-evidence': [re],
  } as unknown as Observation;
}

/**
 * Decomposes an HDF Cvss record into OSCAL risk facets. A version facet is
 * always present so the characterization carries at least one facet.
 */
function cvssFacets(c: Cvss): Facet[] {
  const system = `http://www.first.org/cvss/v${String(c.version)}`;
  const facets: Facet[] = [{ name: 'cvss_version', system, value: String(c.version) }];
  const add = (name: string, value: string | undefined | null): void => {
    if (value !== undefined && value !== null && value !== '') {
      facets.push({ name, system, value });
    }
  };
  add('base_score', num(c.baseScore));
  add('base_severity', c.baseSeverity ? String(c.baseSeverity) : undefined);
  add('base_vector', c.baseVector ?? undefined);
  add('threat_score', num(c.threatScore));
  add('threat_vector', c.threatVector ?? undefined);
  add('environmental_score', num(c.environmentalScore));
  add('environmental_vector', c.environmentalVector ?? undefined);
  add('computed_score', num(c.computedScore));
  add('computed_severity', c.computedSeverity ? String(c.computedSeverity) : undefined);
  add('supplemental_vector', c.supplementalVector ?? undefined);
  add('source', c.source ?? undefined);
  return facets;
}

function num(n: number | undefined | null): string | undefined {
  return typeof n === 'number' ? String(n) : undefined;
}

/**
 * Collects every override's external references into back-matter resources —
 * the OSCAL home for advisories, STIX, and CTI feeds.
 */
function externalRefResources(overrides: StandaloneOverride[]): Resource[] {
  const resources: Resource[] = [];
  for (const o of overrides) {
    if (!o.externalReferences) continue;
    for (const ref of o.externalReferences as ExternalReference[]) {
      const res = {
        uuid: crypto.randomUUID(),
        title: ref.sourceName,
      } as unknown as Resource;
      if (ref.description && ref.description !== '') {
        res.description = ref.description;
      }
      if (ref.href && ref.href !== '') {
        res.rlinks = [{ href: ref.href }] as unknown as Resource['rlinks'];
      }
      const props: Property[] = [];
      if (ref.sourceName) {
        props.push({ name: 'source-name', value: ref.sourceName });
      }
      if (ref.externalId) {
        props.push({ name: 'external-id', value: ref.externalId });
      }
      if (props.length > 0) {
        res.props = props;
      }
      resources.push(res);
    }
  }
  return resources;
}

/**
 * Carries the actual completion attribution that the estimated-completion
 * timing cannot express.
 */
function milestoneCompletionProps(ms: Milestone): Property[] {
  const props: Property[] = [];
  const completedAt = ms.completedAt ? toDate(ms.completedAt) : undefined;
  if (completedAt) {
    props.push({ name: 'completed-at', value: formatTimestampSeconds(completedAt) });
  }
  if (ms.completedBy && ms.completedBy.identifier) {
    props.push({ name: 'completed-by', value: ms.completedBy.identifier });
  }
  return props;
}
