/**
 * Converts HDF Amendments to OSCAL Plan of Action and Milestones (POA&M) format.
 *
 * This is the reverse direction of the oscal-poam to HDF converter.
 */

import { parseTimestamp, formatTimestampSeconds } from '@mitre/hdf-utilities';
import { validateInputSize, parseHdf } from '../../../shared/typescript/converterutil.js';
import type { HDFAmendments, StandaloneOverride } from '@mitre/hdf-schema';
import type {
  Oscal,
  DocumentMetadata,
  ImportSystemSecurityPlan,
  PlanOfActionAndMilestonesPOAM,
  POAMItem,
  IdentifiedRisk,
  Property,
  RiskResponse,
  RiskLog,
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
function toDate(value: string | Date): Date | undefined {
  const d = typeof value === 'string' ? parseTimestamp(value) : value;
  if (!d || isNaN(d.getTime())) return undefined;
  return d;
}

/**
 * Converts parsed HDFAmendments to an OSCAL PlanOfActionAndMilestones.
 */
function amendmentsToPOAM(amendments: HDFAmendments): PlanOfActionAndMilestonesPOAM {
  const now = formatTimestampSeconds(new Date());

  const metadata = {
    title: amendments.name,
    'last-modified': now,
    version: '1.0.0',
    'oscal-version': OSCAL_VERSION,
  } as unknown as DocumentMetadata;

  // Add responsible parties from appliedBy
  if (amendments.appliedBy) {
    const partyUUID = crypto.randomUUID();
    metadata.parties = [
      {
        uuid: partyUUID,
        type: 'person' as unknown,
        name: amendments.appliedBy.identifier,
      },
    ] as unknown as DocumentMetadata['parties'];
    metadata['responsible-parties'] = [
      {
        'role-id': 'prepared-by',
        'party-uuids': [partyUUID],
      },
    ];
    metadata.roles = [
      {
        id: 'prepared-by',
        title: 'Prepared By',
      },
    ];
  }

  // Build import-ssp
  let importSSP: ImportSystemSecurityPlan;
  if (amendments.systemRef && amendments.systemRef !== '') {
    importSSP = { href: amendments.systemRef } as ImportSystemSecurityPlan;
  } else {
    importSSP = { href: '#' } as ImportSystemSecurityPlan;
  }

  // Convert overrides to poam-items and collect risks
  const poamItems: POAMItem[] = [];
  const risks: IdentifiedRisk[] = [];

  for (const override of amendments.overrides) {
    const { item, itemRisks } = overrideToPOAMItem(override);
    poamItems.push(item);
    risks.push(...itemRisks);
  }

  return {
    uuid: crypto.randomUUID(),
    metadata,
    'import-ssp': importSSP,
    risks,
    'poam-items': poamItems,
  };
}

/**
 * Converts a single StandaloneOverride to a POAMItem and its associated Risk(s).
 */
function overrideToPOAMItem(override: StandaloneOverride): { item: POAMItem; itemRisks: IdentifiedRisk[] } {
  const riskUUID = crypto.randomUUID();

  // Map HDF status to OSCAL risk status
  const riskStatus = hdfStatusToOscalRiskStatus(String(override.status));

  // Convert requirement ID from NIST notation to OSCAL control ID
  const controlID = nistTagToControlId(override.requirementId);

  // Build risk props: impacted control, plus the override type (disposition)
  // and any impact override.
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
        tasks = [{
          uuid: crypto.randomUUID(),
          type: 'milestone',
          title: ms.description,
          timing: { 'within-date-range': { start: eta, end: eta } },
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

  const risk = {
    uuid: riskUUID,
    title: override.requirementId,
    description: override.reason,
    statement: override.reason,
    status: riskStatus,
    deadline,
    props: riskProps,
    remediations: remediations.length > 0 ? remediations : undefined,
    'risk-log': riskLog,
  } as unknown as IdentifiedRisk;

  const item: POAMItem = {
    uuid: crypto.randomUUID(),
    title: override.requirementId,
    description: override.reason,
    'related-risks': [{ 'risk-uuid': riskUUID }],
  };

  return { item, itemRisks: [risk] };
}

