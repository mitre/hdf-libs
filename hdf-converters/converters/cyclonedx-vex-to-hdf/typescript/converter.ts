/**
 * CycloneDX VEX to HDF Amendments converter.
 *
 * CycloneDX VEX is not a separate format — it's a CycloneDX BOM whose
 * vulnerabilities[] carry an `analysis` object. CycloneDX-specific
 * justifications without an HDF equivalent (requires_configuration,
 * protected_by_compiler, etc.) are preserved verbatim in the reason
 * field via the shared helper's unknown-value passthrough.
 *
 * Spec: https://cyclonedx.org/use-cases/#vulnerability-exploitability
 */

import { parseJSON, parseTimestamp } from '@mitre/hdf-utilities';
import {
  Ecosystem,
  IdentityType,
  MilestoneStatus,
  OverrideType,
  type AffectedPackage,
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
  affectedPackageFromIdentifier,
  importTargetFor,
  normalizeJustification,
  normalizeStatus,
  supplierEvidence,
} from '../../../shared/typescript/vex/mapping.js';

const DEFAULT_EXPIRY_HORIZON_MS = 365 * 24 * 60 * 60 * 1000;

interface Source {
  name?: string;
  url?: string;
}

interface Author {
  name?: string;
  email?: string;
}

interface Tool {
  vendor?: string;
  name?: string;
  version?: string;
}

interface Component {
  name?: string;
  version?: string;
  type?: string;
  'bom-ref'?: string;
  purl?: string;
}

interface Reference {
  id?: string;
  source?: Source;
}

interface Analysis {
  state?: string;
  justification?: string;
  response?: string[];
  detail?: string;
}

interface AffectedRef {
  ref?: string;
}

interface Vulnerability {
  id?: string;
  source?: Source;
  references?: Reference[];
  description?: string;
  detail?: string;
  analysis?: Analysis;
  affects?: AffectedRef[];
}

interface Metadata {
  timestamp?: string;
  component?: Component;
  authors?: Author[];
  tools?: Tool[];
}

interface BOM {
  bomFormat?: string;
  specVersion?: string;
  serialNumber?: string;
  metadata?: Metadata;
  vulnerabilities?: Vulnerability[];
  components?: Component[];
}

export async function convertCyclonedxVexToHdf(
  input: string,
  converterVersion: string,
): Promise<HDFAmendments> {
  validateInputSize(input, 'cyclonedx-vex-to-hdf');
  const bom = parseJSON<BOM>(input);
  if (bom.bomFormat !== 'CycloneDX') {
    throw new Error(
      `cyclonedx-vex-to-hdf: bomFormat is ${JSON.stringify(bom.bomFormat)}; only 'CycloneDX' is supported`,
    );
  }

  const docTime =
    (bom.metadata?.timestamp ? parseTimestamp(bom.metadata.timestamp) : null) ?? new Date();
  const productLookup = buildProductLookup(bom);
  const publisher = publisherIdentityOrDefault(bom);

  const overrides: StandaloneOverride[] = [];
  for (const v of bom.vulnerabilities ?? []) {
    const o = vulnerabilityToOverride(v, productLookup, docTime, publisher);
    if (o) overrides.push(o);
  }

  if (overrides.length === 0) {
    throw new Error(
      'cyclonedx-vex-to-hdf: BOM contains no actionable VEX statements (only exploitable/in_triage or no analysis); no amendment to write',
    );
  }

  const publisherName = publisher.identifier;
  const name =
    publisherName && publisherName !== 'cyclonedx-vex-import'
      ? `CycloneDX VEX statements from ${publisherName}`
      : 'CycloneDX VEX statements';
  const description = bom.serialNumber
    ? `Imported CycloneDX VEX ${bom.serialNumber}`
    : 'Imported CycloneDX VEX';

  return {
    name,
    description,
    overrides,
    appliedBy: publisher,
    generator: { name: 'cyclonedx-vex-to-hdf', version: converterVersion },
    integrity: await inputIntegrity(input),
  } as HDFAmendments;
}

function vulnerabilityToOverride(
  v: Vulnerability,
  productLookup: Map<string, Component>,
  docTime: Date,
  publisher: Identity,
): StandaloneOverride | undefined {
  if (!v.id || !v.analysis?.state) return undefined;
  const canonical = normalizeStatus(v.analysis.state);
  if (!canonical) return undefined;
  const target = importTargetFor(canonical);
  if (!target) return undefined;

  const affectedPackages = affectedPackagesForVuln(v, productLookup);
  const expiresAt = new Date(docTime.getTime() + DEFAULT_EXPIRY_HORIZON_MS);

  // componentRef is UUID-constrained on the HDF schema (it identifies an
  // HDF component by id, not a foreign-format identifier). Multi-product
  // VEX scoping lands in affectedPackages[] (structured) rather than in
  // the reason free-text field.
  const override: StandaloneOverride = {
    type: target.overrideType,
    requirementId: v.id,
    appliedAt: docTime,
    expiresAt,
    appliedBy: publisher,
    reason: buildReason(v),
  } as StandaloneOverride;

  if (affectedPackages.length > 0) {
    override.affectedPackages = affectedPackages;
  }

  if (target.status !== undefined) override.status = target.status;

  if (target.setJustification && v.analysis.justification) {
    const j = normalizeJustification(v.analysis.justification);
    if (j) override.justification = j;
  }

  const evidence: Evidence[] = [];
  if (v.source?.url) {
    const ev = supplierEvidence(v.source.url, v.source.name ?? '');
    if (ev) evidence.push(ev as Evidence);
  }
  for (const r of v.references ?? []) {
    if (!r.source?.url) continue;
    const ev = supplierEvidence(r.source.url, r.source.name ?? '');
    if (ev) evidence.push(ev as Evidence);
  }
  if (evidence.length > 0) override.evidence = evidence;

  if (target.overrideType === OverrideType.Poam) {
    const action = firstActionFromResponse(v.analysis.response ?? []) || target.poamActionTemplate;
    const milestone: Milestone = {
      description: action,
      status: MilestoneStatus.Pending,
      estimatedCompletion: expiresAt,
    } as Milestone;
    override.milestones = [milestone];
  }

  return override;
}

function buildReason(v: Vulnerability): string {
  const parts: string[] = [];
  if (v.description) parts.push(v.description);
  if (v.analysis?.detail) parts.push(v.analysis.detail);
  // Justification and product list are fully structured fields now
  // (Justification enum + Standalone_Override.affectedPackages); neither
  // is mirrored into reason. Response[] hints are not echoed either —
  // POA&M overrides carry remediation context via milestones.
  return parts.join('\n');
}

/**
 * Resolve CycloneDX affects[].ref entries to structured AffectedPackage
 * entries. Looks up the bom-ref in the component table to recover purl,
 * name/version. Opaque bom-refs with no component-table match are dropped
 * (the schema forbids fabricating name+version, and bom-refs aren't
 * portable identifiers outside their source BOM).
 */
export function affectedPackagesForVuln(
  v: Vulnerability,
  lookup: Map<string, Component>,
): AffectedPackage[] {
  const out: AffectedPackage[] = [];
  const seenKeys = new Set<string>();
  for (const a of v.affects ?? []) {
    if (!a.ref) continue;
    const comp = lookup.get(a.ref);
    const pkg = comp ? affectedPackageFromComponent(comp) : affectedPackageFromIdentifier(a.ref);
    if (!pkg) continue;
    const key = pkg.purl ?? pkg.cpe ?? `${pkg.name ?? ''}@${pkg.version ?? ''}`;
    if (seenKeys.has(key)) continue;
    seenKeys.add(key);
    out.push(pkg);
  }
  return out;
}

/**
 * Build an AffectedPackage from a CycloneDX Component. Prefers structured
 * purl decomposition via the shared helper (so name/version/ecosystem are
 * also populated when the purl is parseable); falls back to the component's
 * name+version when no purl is set. Returns undefined when the component
 * carries neither a purl nor a name+version pair (schema requires at least
 * name+version+ecosystem, purl, or cpe).
 */
export function affectedPackageFromComponent(c: Component): AffectedPackage | undefined {
  if (c.purl) return affectedPackageFromIdentifier(c.purl);
  if (c.name && c.version) {
    return {
      name: c.name,
      version: c.version,
      ecosystem: Ecosystem.Generic,
    };
  }
  return undefined;
}

function buildProductLookup(bom: BOM): Map<string, Component> {
  const lookup = new Map<string, Component>();
  const root = bom.metadata?.component;
  if (root?.['bom-ref']) lookup.set(root['bom-ref'], root);
  for (const c of bom.components ?? []) {
    if (c['bom-ref']) lookup.set(c['bom-ref'], c);
  }
  return lookup;
}

export function firstActionFromResponse(resp: string[]): string {
  for (const r of resp) {
    switch (r.trim().toLowerCase()) {
      case 'update':
        return 'Apply vendor update and re-scan to verify.';
      case 'rollback':
        return 'Roll back to the unaffected version and re-scan to verify.';
      case 'workaround_available':
        return 'Apply the documented workaround.';
    }
  }
  return '';
}

function publisherIdentityOrDefault(bom: BOM): Identity {
  for (const a of bom.metadata?.authors ?? []) {
    if (a.email) return { type: IdentityType.Email, identifier: a.email } as Identity;
    if (a.name) return { type: IdentityType.Simple, identifier: a.name } as Identity;
  }
  for (const t of bom.metadata?.tools ?? []) {
    const ident = [t.vendor, t.name].filter(Boolean).join(' ').trim();
    if (ident) return { type: IdentityType.System, identifier: ident } as Identity;
  }
  return { type: IdentityType.System, identifier: 'cyclonedx-vex-import' } as Identity;
}
