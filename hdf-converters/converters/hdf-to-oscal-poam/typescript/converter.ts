/**
 * Converts HDF Amendments to OSCAL Plan of Action and Milestones (POA&M) format.
 *
 * This is the reverse direction of the oscal-poam to HDF converter.
 */

import { parseJSON } from '@mitre/hdf-utilities';
import { validateInputSize } from '../../../shared/typescript/converterutil.js';
import type { HdfAmendments, StandaloneOverride } from '@mitre/hdf-schema';
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

  let amendments: HdfAmendments;
  try {
    amendments = parseJSON<HdfAmendments>(input);
  } catch {
    throw new Error('hdf-to-oscal-poam: failed to parse JSON');
  }

  const poam = amendmentsToPOAM(amendments);

  const doc: Oscal = {
    'plan-of-action-and-milestones': poam,
  };

  return JSON.stringify(doc, null, 2);
}

/**
 * Converts parsed HdfAmendments to an OSCAL PlanOfActionAndMilestones.
 */
function amendmentsToPOAM(amendments: HdfAmendments): PlanOfActionAndMilestonesPOAM {
  const now = new Date().toISOString();

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

  // Build risk props with impacted-control-id
  const riskProps: Property[] = [
    {
      name: 'impacted-control-id',
      value: controlID,
    },
  ];

  // Build remediations from milestones
  const remediations: RiskResponse[] = [];
  if (override.milestones) {
    for (const ms of override.milestones) {
      remediations.push({
        uuid: crypto.randomUUID(),
        lifecycle: 'planned',
        title: ms.description,
        description: ms.description,
      });
    }
  }

  // Build risk log entry for expiration tracking
  let riskLog: RiskLog | undefined;
  const expiresAt = override.expiresAt;
  if (expiresAt) {
    const expiresDate = typeof expiresAt === 'string' ? new Date(expiresAt) : expiresAt;
    if (!isNaN(expiresDate.getTime()) && expiresDate.getTime() > 0) {
      riskLog = {
        entries: [
          {
            uuid: crypto.randomUUID(),
            title: 'Scheduled review',
            description: 'Amendment expiration date',
            start: expiresDate.toISOString(),
            'status-change': riskStatus,
          },
        ],
      } as unknown as RiskLog;
    }
  }

  const risk = {
    uuid: riskUUID,
    title: override.requirementId,
    description: override.reason,
    statement: override.reason,
    status: riskStatus,
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

