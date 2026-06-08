/**
 * OpenVEX to HDF Amendments converter.
 *
 * VEX statements are consumer-attached context for CVE findings. The act of
 * attaching IS the amendment, so this converter emits HDF Amendments rather
 * than HDF Results.
 *
 * VEX 'fixed' is an abstract supplier claim; the assessed system has not
 * been verified to carry the fix. Imports therefore become open POA&M
 * overrides (status pinned to failed pending re-scan), not status flips.
 *
 * Spec: https://github.com/openvex/spec
 */

import {
  IdentityType,
  MilestoneStatus,
  OverrideType,
  type Evidence,
  type HDFAmendments,
  type Identity,
  type Milestone,
  type StandaloneOverride,
} from '@mitre/hdf-schema';
import { parseJSON, parseTimestamp } from '@mitre/hdf-utilities';
import {
  inputIntegrity,
  validateInputSize,
} from '../../../shared/typescript/converterutil.js';
import {
  affectedPackagesFromIdentifiers,
  importTargetFor,
  normalizeJustification,
  normalizeStatus,
  supplierEvidence,
} from '../../../shared/typescript/vex/mapping.js';

/** One year in milliseconds. VEX statements are re-evaluated as new info
 *  arrives; one year is a defensive default consistent with the
 *  no-permanent-amendment rule on Standalone_Override. */
const DEFAULT_EXPIRY_HORIZON_MS = 365 * 24 * 60 * 60 * 1000;

interface OpenVexVulnerability {
  '@id'?: string;
  name?: string;
  description?: string;
  aliases?: string[];
}

interface OpenVexProduct {
  '@id'?: string;
  identifiers?: Record<string, string>;
  hashes?: Record<string, string>;
}

interface OpenVexStatement {
  vulnerability?: OpenVexVulnerability;
  products?: OpenVexProduct[];
  status?: string;
  justification?: string;
  impact_statement?: string;
  action_statement?: string;
  timestamp?: string;
  author?: string;
}

interface OpenVexDocument {
  '@context'?: string;
  '@id'?: string;
  author?: string;
  role?: string;
  timestamp?: string;
  version?: number;
  statements?: OpenVexStatement[];
}

export async function convertOpenVexToHdf(
  input: string,
  converterVersion: string,
): Promise<HDFAmendments> {
  validateInputSize(input, 'openvex-to-hdf');
  const doc = parseJSON<OpenVexDocument>(input);
  const docTime = (doc.timestamp ? parseTimestamp(doc.timestamp) : null) ?? new Date();

  const overrides: StandaloneOverride[] = [];
  for (const stmt of doc.statements ?? []) {
    const override = statementToOverride(stmt, doc, docTime);
    if (override) {
      overrides.push(override);
    }
  }

  // HDF Amendments requires overrides.minItems=1. A VEX document with only
  // 'affected' or 'under_investigation' statements has no consumer-action
  // payload, so we refuse to write an empty amendments document.
  if (overrides.length === 0) {
    throw new Error(
      "openvex-to-hdf: VEX document contains no actionable statements (all 'affected' or 'under_investigation'); no amendment to write",
    );
  }

  const name = doc.author
    ? `OpenVEX statements from ${doc.author}`
    : 'OpenVEX statements';

  return {
    name,
    description: `Imported VEX statements from ${truncateId(doc['@id'] ?? '')}`,
    overrides,
    appliedBy: identityFor(doc.author, doc.role),
    generator: {
      name: 'openvex-to-hdf',
      version: converterVersion,
    },
    integrity: await inputIntegrity(input),
  } as HDFAmendments;
}

function statementToOverride(
  stmt: OpenVexStatement,
  doc: OpenVexDocument,
  docTime: Date,
): StandaloneOverride | undefined {
  const canonical = normalizeStatus(stmt.status ?? '');
  if (!canonical) return undefined;
  const target = importTargetFor(canonical);
  if (!target) return undefined;

  const requirementId = stmt.vulnerability?.name ?? stmt.vulnerability?.['@id'] ?? '';
  if (!requirementId) return undefined;

  const stmtTime = (stmt.timestamp ? parseTimestamp(stmt.timestamp) : null) ?? docTime;
  const author = stmt.author ?? doc.author ?? '';

  const expiresAt = new Date(stmtTime.getTime() + DEFAULT_EXPIRY_HORIZON_MS);

  const override: StandaloneOverride = {
    type: target.overrideType,
    requirementId,
    appliedAt: stmtTime,
    expiresAt,
    appliedBy: identityFor(author, doc.role),
    reason: buildReason(stmt, target.poamActionTemplate),
  } as StandaloneOverride;

  const productIds = (stmt.products ?? [])
    .map((p) => p['@id'])
    .filter((id): id is string => Boolean(id));
  const affectedPackages = affectedPackagesFromIdentifiers(productIds);
  if (affectedPackages.length > 0) {
    override.affectedPackages = affectedPackages;
  }

  if (target.status !== undefined) {
    override.status = target.status;
  }

  if (target.setJustification && stmt.justification) {
    const j = normalizeJustification(stmt.justification);
    if (j) {
      override.justification = j;
    }
  }

  const ev = supplierEvidence(doc['@id'] ?? '', 'OpenVEX document');
  if (ev) {
    override.evidence = [ev as Evidence];
  }

  if (target.overrideType === OverrideType.Poam) {
    const milestone: Milestone = {
      description: target.poamActionTemplate,
      status: MilestoneStatus.Pending,
      estimatedCompletion: expiresAt,
    } as Milestone;
    override.milestones = [milestone];
  }

  return override;
}

function buildReason(stmt: OpenVexStatement, poamTemplate: string): string {
  const parts: string[] = [];
  if (stmt.impact_statement) parts.push(stmt.impact_statement);
  if (stmt.action_statement) parts.push(stmt.action_statement);
  // Justification and product list are fully structured fields now
  // (Justification enum + Standalone_Override.affectedPackages); neither
  // is mirrored into reason.
  if (parts.length === 0) {
    return poamTemplate || `Imported from OpenVEX status "${stmt.status ?? ''}"`;
  }
  return parts.join('\n');
}

function identityFor(author: string | undefined, role: string | undefined): Identity {
  if (!author) {
    return {
      type: IdentityType.System,
      identifier: 'openvex-import',
    } as Identity;
  }
  const id: Identity = {
    type: author.includes('@') ? IdentityType.Email : IdentityType.Simple,
    identifier: author,
  } as Identity;
  if (role) {
    id.description = role;
  }
  return id;
}

function truncateId(id: string): string {
  const MAX = 80;
  return id.length <= MAX ? id : `${id.slice(0, MAX)}...`;
}

