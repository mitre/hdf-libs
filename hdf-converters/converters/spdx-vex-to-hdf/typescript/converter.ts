/**
 * SPDX 3.0.1 JSON-LD security-profile to HDF Amendments converter.
 *
 * SPDX-3 is JSON-LD: a top-level { "@context", "@graph" } where "@graph" is a
 * flat array of typed, cross-referenced elements. The security profile adds VEX
 * assessment relationships (security_Vex*VulnAssessmentRelationship) linking a
 * security_Vulnerability (the CVE) to one or more software_Package elements.
 * Each such relationship is one consumer-attached VEX statement, so like the
 * sibling cyclonedx-vex / openvex converters this emits HDF Amendments.
 *
 * VEX 'fixed' is an abstract supplier claim; the assessed system has not been
 * verified to carry the fix. Imports therefore become open POA&M overrides
 * (status pinned to failed pending re-scan), not status flips. 'affected' and
 * 'under_investigation' are informational and produce no override.
 *
 * Spec: https://spdx.github.io/spdx-spec/v3.0.1/ (security profile)
 */

import { parseJSON, parseTimestamp } from '@mitre/hdf-utilities';
import {
  CVSSSeverity,
  IdentityType,
  MilestoneStatus,
  OverrideType,
  Version,
  type AffectedPackage,
  type Cvss,
  type Evidence,
  type HDFAmendments,
  type Identity,
  type Milestone,
  type StandaloneOverride,
} from '@mitre/hdf-schema';
import {
  inputIntegrity,
  validateInputSize,
} from '../../../shared/typescript/converterutil.js';
import {
  affectedPackagesFromIdentifiers,
  importTargetFor,
  normalizeJustification,
  supplierEvidence,
  VexStatus,
} from '../../../shared/typescript/vex/mapping.js';

/** One year in milliseconds — the override expiresAt horizon. */
const DEFAULT_EXPIRY_HORIZON_MS = 365 * 24 * 60 * 60 * 1000;

/** Fallback system identity when no supplier agent resolves. */
const DEFAULT_APPLIED_BY = 'spdx-vex-import';

/** The four SPDX-3 VEX assessment relationship subtypes -> canonical status. */
const VEX_STATUS_BY_TYPE: Record<string, VexStatus> = {
  security_VexNotAffectedVulnAssessmentRelationship: VexStatus.NotAffected,
  security_VexFixedVulnAssessmentRelationship: VexStatus.Fixed,
  security_VexAffectedVulnAssessmentRelationship: VexStatus.Affected,
  security_VexUnderInvestigationVulnAssessmentRelationship: VexStatus.UnderInvestigation,
};

interface ExternalIdentifier {
  externalIdentifierType?: string;
  identifier?: string;
  identifierLocator?: string[];
}

interface ExternalRef {
  locator?: string[];
}

interface GraphElement {
  type?: string;
  spdxId?: string;
  '@id'?: string;
  name?: string;
  description?: string;
  creationInfo?: string;
  created?: string;
  createdBy?: string[];
  externalIdentifier?: ExternalIdentifier[];
  externalRef?: ExternalRef[];
  relationshipType?: string;
  from?: string;
  to?: string[];
  security_score?: string;
  security_severity?: string;
  security_vectorString?: string;
  security_justificationType?: string;
  security_impactStatement?: string;
  security_statusNotes?: string;
  security_actionStatement?: string;
}

interface SpdxDocument {
  '@context'?: string;
  '@graph'?: GraphElement[];
}

/** Cross-reference tables built from a single @graph. */
interface GraphIndex {
  vulnById: Map<string, GraphElement>;
  pkgById: Map<string, GraphElement>;
  agentById: Map<string, string>;
  creationById: Map<string, GraphElement>;
  cvssByVuln: Map<string, GraphElement>;
}

export async function convertSpdxVexToHdf(
  input: string,
  converterVersion = '1.0.0',
): Promise<HDFAmendments> {
  validateInputSize(input, 'spdx-vex-to-hdf');
  const doc = parseJSON<SpdxDocument>(input);
  const graph = doc['@graph'] ?? [];
  if (graph.length === 0) {
    throw new Error('spdx-vex-to-hdf: document has no @graph elements');
  }

  const idx = buildIndex(graph);

  const overrides: StandaloneOverride[] = [];
  for (const el of graph) {
    // A non-VEX element (or one with no type) maps to undefined and is skipped.
    if (VEX_STATUS_BY_TYPE[el.type ?? ''] === undefined) continue;
    const o = relationshipToOverride(el, idx);
    if (o) overrides.push(o);
  }

  if (overrides.length === 0) {
    throw new Error(
      'spdx-vex-to-hdf: SPDX document contains no actionable VEX statements (only affected/under_investigation); no amendment to write',
    );
  }

  const appliedBy = documentIdentity(graph, idx);
  const name =
    appliedBy.identifier && appliedBy.identifier !== DEFAULT_APPLIED_BY
      ? `SPDX VEX statements from ${appliedBy.identifier}`
      : 'SPDX VEX statements';

  return {
    name,
    description: 'Imported SPDX 3.0.1 security-profile VEX statements',
    overrides,
    appliedBy,
    generator: { name: 'spdx-vex-to-hdf', version: converterVersion },
    integrity: await inputIntegrity(input),
  } as HDFAmendments;
}

function buildIndex(graph: GraphElement[]): GraphIndex {
  const idx: GraphIndex = {
    vulnById: new Map(),
    pkgById: new Map(),
    agentById: new Map(),
    creationById: new Map(),
    cvssByVuln: new Map(),
  };
  for (const el of graph) {
    switch (el.type) {
      case 'security_Vulnerability':
        if (el.spdxId) idx.vulnById.set(el.spdxId, el);
        break;
      case 'software_Package':
        if (el.spdxId) idx.pkgById.set(el.spdxId, el);
        break;
      case 'SoftwareAgent':
        if (el.spdxId && el.name) idx.agentById.set(el.spdxId, el.name);
        break;
      case 'CreationInfo':
        if (el['@id']) idx.creationById.set(el['@id'], el);
        break;
      default:
        if (isCvssType(el.type) && el.from && !idx.cvssByVuln.has(el.from)) {
          idx.cvssByVuln.set(el.from, el);
        }
    }
  }
  return idx;
}

function relationshipToOverride(
  rel: GraphElement,
  idx: GraphIndex,
): StandaloneOverride | undefined {
  /* c8 ignore next 2 -- the caller only passes VEX-typed elements, so canonical
     is always defined here; the guard is defensive. */
  const canonical = VEX_STATUS_BY_TYPE[rel.type ?? ''];
  if (canonical === undefined) return undefined;
  const target = importTargetFor(canonical);
  if (!target) return undefined;

  const vuln = rel.from ? idx.vulnById.get(rel.from) : undefined;
  const requirementId = cveIdentifier(vuln);
  if (!requirementId) return undefined;

  const appliedAt =
    createdAt(rel.creationInfo, idx) ?? createdAt(vuln?.creationInfo, idx) ?? new Date();
  const expiresAt = new Date(appliedAt.getTime() + DEFAULT_EXPIRY_HORIZON_MS);

  const override: StandaloneOverride = {
    type: target.overrideType,
    requirementId,
    appliedAt,
    expiresAt,
    appliedBy: identityFor(rel.creationInfo, idx),
    reason: buildReason(vuln, rel, target.poamActionTemplate),
  } as StandaloneOverride;

  const affectedPackages = resolveAffectedPackages(rel.to ?? [], idx);
  if (affectedPackages.length > 0) override.affectedPackages = affectedPackages;

  if (target.status !== undefined) override.status = target.status;

  if (target.setJustification && rel.security_justificationType) {
    const j = normalizeJustification(rel.security_justificationType);
    if (j) override.justification = j;
  }

  const cvssRel = rel.from ? idx.cvssByVuln.get(rel.from) : undefined;
  if (cvssRel) override.cvss = buildCvss(cvssRel, requirementId);

  const evidence = supplierEvidenceFor(vuln);
  if (evidence.length > 0) override.evidence = evidence;

  if (target.overrideType === OverrideType.Poam) {
    const milestone: Milestone = {
      description: rel.security_actionStatement || target.poamActionTemplate,
      status: MilestoneStatus.Pending,
      estimatedCompletion: expiresAt,
    } as Milestone;
    override.milestones = [milestone];
  }

  return override;
}

function resolveAffectedPackages(productIds: string[], idx: GraphIndex): AffectedPackage[] {
  const identifiers: string[] = [];
  for (const id of productIds) {
    const pkg = idx.pkgById.get(id);
    if (!pkg) continue;
    const ident = packageIdentifier(pkg);
    if (ident) identifiers.push(ident);
  }
  return affectedPackagesFromIdentifiers(identifiers);
}

function createdAt(creationInfoRef: string | undefined, idx: GraphIndex): Date | undefined {
  if (!creationInfoRef) return undefined;
  const ci = idx.creationById.get(creationInfoRef);
  if (ci?.created) {
    const t = parseTimestamp(ci.created);
    if (t) return t;
  }
  return undefined;
}

function identityFor(creationInfoRef: string | undefined, idx: GraphIndex): Identity {
  const ci = creationInfoRef ? idx.creationById.get(creationInfoRef) : undefined;
  for (const agentId of ci?.createdBy ?? []) {
    const name = idx.agentById.get(agentId);
    if (name) return { type: IdentityType.System, identifier: name } as Identity;
  }
  return { type: IdentityType.System, identifier: DEFAULT_APPLIED_BY } as Identity;
}

function documentIdentity(graph: GraphElement[], idx: GraphIndex): Identity {
  for (const el of graph) {
    if (el.type === 'SpdxDocument') {
      const id = identityFor(el.creationInfo, idx);
      if (id.identifier !== DEFAULT_APPLIED_BY) return id;
    }
  }
  for (const el of graph) {
    const name = el.spdxId ? idx.agentById.get(el.spdxId) : undefined;
    if (name) return { type: IdentityType.System, identifier: name } as Identity;
  }
  return { type: IdentityType.System, identifier: DEFAULT_APPLIED_BY } as Identity;
}

function buildReason(
  vuln: GraphElement | undefined,
  rel: GraphElement,
  poamTemplate: string,
): string {
  const parts: string[] = [];
  if (vuln?.description) parts.push(vuln.description);
  if (rel.security_impactStatement) parts.push(rel.security_impactStatement);
  if (rel.security_statusNotes) parts.push(rel.security_statusNotes);
  if (parts.length === 0) {
    return poamTemplate || `Imported from SPDX VEX relationship "${rel.relationshipType ?? ''}"`;
  }
  return parts.join('\n');
}

export function buildCvss(rel: GraphElement, cve: string): Cvss {
  const cvss: Cvss = { version: cvssVersion(rel.type, rel.security_vectorString) } as Cvss;
  if (rel.security_score) {
    const score = Number.parseFloat(rel.security_score);
    if (!Number.isNaN(score)) cvss.baseScore = score;
  }
  if (rel.security_vectorString) cvss.baseVector = rel.security_vectorString;
  const severity = cvssSeverity(rel.security_severity);
  if (severity) cvss.baseSeverity = severity;
  if (cve) cvss.source = cve;
  return cvss;
}

export function cvssVersion(relType: string | undefined, vector: string | undefined): Version {
  if (vector?.startsWith('CVSS:')) {
    const rest = vector.slice('CVSS:'.length);
    const slash = rest.indexOf('/');
    if (slash > 0) {
      switch (rest.slice(0, slash)) {
        case '2.0':
          return Version.The20;
        case '3.0':
          return Version.The30;
        case '3.1':
          return Version.The31;
        case '4.0':
          return Version.The40;
      }
    }
  }
  if ((relType ?? '').includes('CvssV2')) return Version.The20;
  if ((relType ?? '').includes('CvssV4')) return Version.The40;
  return Version.The31;
}

export function cvssSeverity(raw: string | undefined): CVSSSeverity | undefined {
  switch ((raw ?? '').trim().toLowerCase()) {
    case 'critical':
      return CVSSSeverity.Critical;
    case 'high':
      return CVSSSeverity.High;
    case 'medium':
      return CVSSSeverity.Medium;
    case 'low':
      return CVSSSeverity.Low;
    case 'none':
      return CVSSSeverity.None;
    default:
      return undefined;
  }
}

function supplierEvidenceFor(vuln: GraphElement | undefined): Evidence[] {
  /* c8 ignore next -- vuln is guaranteed defined by the requirementId check in
     the sole caller; the guard is defensive. */
  if (!vuln) return [];
  const out: Evidence[] = [];
  const seen = new Set<string>();
  const add = (url: string | undefined): void => {
    if (!url || seen.has(url)) return;
    seen.add(url);
    const ev = supplierEvidence(url, 'SPDX vulnerability reference');
    if (ev) out.push(ev as Evidence);
  };
  for (const ref of vuln.externalRef ?? []) {
    for (const loc of ref.locator ?? []) add(loc);
  }
  for (const ext of vuln.externalIdentifier ?? []) {
    for (const loc of ext.identifierLocator ?? []) add(loc);
  }
  return out;
}

export function cveIdentifier(vuln: GraphElement | undefined): string {
  for (const ext of vuln?.externalIdentifier ?? []) {
    if ((ext.externalIdentifierType ?? '').toLowerCase() === 'cve' && ext.identifier) {
      return ext.identifier;
    }
  }
  return '';
}

export function packageIdentifier(pkg: GraphElement): string {
  let cpe = '';
  for (const ext of pkg.externalIdentifier ?? []) {
    const type = (ext.externalIdentifierType ?? '').toLowerCase();
    if (type === 'purl' && ext.identifier) return ext.identifier;
    if ((type === 'cpe23' || type === 'cpe22') && !cpe && ext.identifier) cpe = ext.identifier;
  }
  return cpe;
}

function isCvssType(type: string | undefined): boolean {
  return (
    typeof type === 'string' &&
    type.startsWith('security_Cvss') &&
    type.endsWith('VulnAssessmentRelationship')
  );
}
