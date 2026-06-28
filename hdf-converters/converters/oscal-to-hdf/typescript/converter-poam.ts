/**
 * OSCAL Plan of Action and Milestones (POA&M) to HDF Amendments converter.
 *
 * Mirrors the Go implementation in converters/oscal-to-hdf/go/converter_poam.go.
 */

import { parseJSON, parseTimestamp } from '@mitre/hdf-utilities';
import { inputIntegrity, serializeHdf, validateInputSize } from '../../../shared/typescript/converterutil.js';
import type {
  HDFAmendments,
  StandaloneOverride,
  Milestone as HdfMilestone,
} from '@mitre/hdf-schema';
import {
  OverrideType,
} from '@mitre/hdf-schema';

// The hdf-amendments schema defines its own ResultStatus, AppliedByType, and
// milestone Status enums that conflict with hdf-results enums of the same name.
// They aren't re-exported from the @mitre/hdf-schema barrel to avoid collisions.
// We use string literals with type casts for these fields.
/* eslint-disable @typescript-eslint/no-explicit-any */
import type {
  Oscal,
  PlanOfActionAndMilestonesPOAM,
  POAMItem,
  IdentifiedRisk,
  DocumentMetadata,
} from './types.js';
import {
  controlIdToNistTag,
  extractPropValue,
  oscalStatusToHdf,
  extractMetadata,
  toKebabCase,
} from './shared.js';

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

  // Build risk lookup map
  const riskMap = buildRiskMap(poam.risks ?? []);

  // Convert poam-items to StandaloneOverrides
  const overrides: StandaloneOverride[] = [];
  for (const item of poam['poam-items']) {
    overrides.push(poamItemToOverride(item, riskMap, poam));
  }

  // Extract systemRef from import-ssp
  const systemRef = poam['import-ssp']?.href || undefined;

  // Build appliedBy from metadata responsible-parties
  const appliedBy = extractAppliedBy(poam.metadata);

  const amendments: HDFAmendments = {
    name: toKebabCase(poam.metadata.title, 'oscal-poam'),
    overrides,
    integrity,
    systemRef,
    version: meta.version,
    appliedBy,
    generator: {
      name: 'oscal-poam-to-hdf',
      version: '1.0.0',
    },
  };

  return serializeHdf(amendments);
}

function buildRiskMap(risks: IdentifiedRisk[]): Map<string, IdentifiedRisk> {
  const m = new Map<string, IdentifiedRisk>();
  for (const risk of risks) {
    m.set(risk.uuid, risk);
  }
  return m;
}

function poamItemToOverride(
  item: POAMItem,
  riskMap: Map<string, IdentifiedRisk>,
  poam: PlanOfActionAndMilestonesPOAM,
): StandaloneOverride {
  return {
    type: OverrideType.Poam,
    requirementId: extractRequirementIdFromPOAMItem(item, riskMap),
    reason: poamItemReason(item),
    status: poamItemStatus(item, riskMap),
    appliedBy: poamItemAppliedBy(poam),
    appliedAt: poamItemAppliedAt(poam),
    expiresAt: poamItemExpiresAt(),
    milestones: extractMilestones(item, riskMap) as any,
  };
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
): any {
  for (const rr of item['related-risks'] ?? []) {
    const riskUuid = rr['risk-uuid'];
    if (riskUuid) {
      const risk = riskMap.get(riskUuid);
      if (risk) {
        const status = oscalStatusToHdf(risk.status);
        if (status === 'passed') return 'passed' as any;
        if (status === 'failed') return 'failed' as any;
      }
    }
  }

  // Default: POA&M items typically represent open/failed findings
  return 'failed' as any;
}

function poamItemAppliedBy(
  poam: PlanOfActionAndMilestonesPOAM,
): StandaloneOverride['appliedBy'] {
  // Look for prepared-by in responsible-parties
  const rps = poam.metadata['responsible-parties'];
  if (rps) {
    for (const rp of rps) {
      if (rp['role-id'] === 'prepared-by' && rp['party-uuids'].length > 0) {
        return {
          type: 'simple' as any,
          identifier: rp['party-uuids'][0]!,
        };
      }
    }

    // Fall back to any responsible party
    if (rps.length > 0 && rps[0]!['party-uuids'].length > 0) {
      return {
        type: 'simple' as any,
        identifier: rps[0]!['party-uuids'][0]!,
      };
    }
  }

  return {
    type: 'system' as any,
    identifier: 'oscal-poam-converter',
  };
}

function poamItemAppliedAt(poam: PlanOfActionAndMilestonesPOAM): Date {
  if (poam.metadata['last-modified']) {
    // Generator types this as Date, but it is a string at runtime (parsed
    // without a Date reviver); coerce so parseTimestamp applies UTC handling.
    const t = parseTimestamp(String(poam.metadata['last-modified']));
    if (t) {
      return t;
    }
  }
  return new Date();
}

function poamItemExpiresAt(): Date {
  // Default: 1 year from now
  const d = new Date();
  d.setFullYear(d.getFullYear() + 1);
  return d;
}

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

      const estimatedCompletion = new Date();
      estimatedCompletion.setMonth(estimatedCompletion.getMonth() + 3);

      milestones.push({
        description: rem.title + ': ' + rem.description,
        estimatedCompletion,
        status: 'pending' as any,
      });
    }
  }

  return milestones;
}

function extractAppliedBy(
  meta: DocumentMetadata,
): HDFAmendments['appliedBy'] {
  const rps = meta['responsible-parties'];
  if (rps) {
    for (const rp of rps) {
      if (rp['role-id'] === 'prepared-by' && rp['party-uuids'].length > 0) {
        return {
          type: 'simple' as any,
          identifier: rp['party-uuids'][0]!,
        };
      }
    }
  }
  return undefined;
}
