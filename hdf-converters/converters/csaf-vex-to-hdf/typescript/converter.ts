/**
 * CSAF VEX to HDF Amendments converter.
 *
 * CSAF (OASIS Common Security Advisory Framework) VEX profile is the
 * vendor-advisory format. Per the amendment-output pattern (Step 4f),
 * 'fixed' becomes an open POA&M, not a status flip — supplier claim is
 * not assessed-system evidence.
 *
 * Spec: https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html
 */

import { parseTimestamp } from '@mitre/hdf-utilities';
import {
  IdentityType,
  Justification,
  MilestoneStatus,
  OverrideType,
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
  importTargetFor,
  normalizeJustification,
  supplierEvidence,
  VexStatus,
} from '../../../shared/typescript/vex/mapping.js';

const DEFAULT_EXPIRY_HORIZON_MS = 365 * 24 * 60 * 60 * 1000;

interface CsafPublisher {
  category?: string;
  name?: string;
  namespace?: string;
}

interface CsafTracking {
  id?: string;
  status?: string;
  version?: string;
  current_release_date?: string;
  initial_release_date?: string;
}

interface CsafReference {
  category?: string;
  summary?: string;
  url?: string;
}

interface CsafNote {
  category?: string;
  text?: string;
  title?: string;
}

interface CsafDocumentMeta {
  category?: string;
  csaf_version?: string;
  title?: string;
  publisher?: CsafPublisher;
  tracking?: CsafTracking;
  notes?: CsafNote[];
  references?: CsafReference[];
}

interface CsafProductStatus {
  first_affected?: string[];
  first_fixed?: string[];
  fixed?: string[];
  known_affected?: string[];
  known_not_affected?: string[];
  last_affected?: string[];
  recommended?: string[];
  under_investigation?: string[];
}

interface CsafThreat {
  category?: string;
  details?: string;
  product_ids?: string[];
}

interface CsafRemediation {
  category?: string;
  details?: string;
  product_ids?: string[];
  url?: string;
}

interface CsafFlag {
  date?: string;
  label?: string;
  product_ids?: string[];
}

interface CsafVulnerability {
  cve?: string;
  notes?: CsafNote[];
  product_status?: CsafProductStatus;
  threats?: CsafThreat[];
  remediations?: CsafRemediation[];
  flags?: CsafFlag[];
  references?: CsafReference[];
}

interface CsafDocument {
  document?: CsafDocumentMeta;
  vulnerabilities?: CsafVulnerability[];
}

export async function convertCsafVexToHdf(
  input: string,
  converterVersion: string,
): Promise<HDFAmendments> {
  validateInputSize(input, 'csaf-vex-to-hdf');
  const doc = JSON.parse(input) as CsafDocument;
  // CSAF schema requires document + document.category + document.tracking +
  // document.publisher. After this check passes we treat them as present
  // — defensive optional-chaining everywhere bloats the branch surface
  // without buying real safety against a malformed input we've already
  // rejected.
  if (doc.document?.category !== 'csaf_vex') {
    throw new Error(
      `csaf-vex-to-hdf: document.category is ${JSON.stringify(doc.document?.category)}; only 'csaf_vex' is supported`,
    );
  }
  const dm = doc.document;
  const tracking = dm.tracking ?? {};
  const publisher = dm.publisher ?? {};

  const docTime =
    (tracking.current_release_date ? parseTimestamp(tracking.current_release_date) : null) ??
    new Date();

  const overrides: StandaloneOverride[] = [];
  for (const v of doc.vulnerabilities ?? []) {
    overrides.push(...vulnerabilityToOverrides(v, publisher, tracking, docTime));
  }

  if (overrides.length === 0) {
    throw new Error(
      'csaf-vex-to-hdf: CSAF VEX document contains no actionable statements (only affected/under_investigation/recommended); no amendment to write',
    );
  }

  const publisherName = publisher.name ?? '';
  return {
    name: publisherName ? `CSAF VEX statements from ${publisherName}` : 'CSAF VEX statements',
    description: `Imported VEX advisory ${tracking.id ?? ''}`,
    overrides,
    appliedBy: identityFor(publisher),
    generator: { name: 'csaf-vex-to-hdf', version: converterVersion },
    integrity: await inputIntegrity(input),
    version: tracking.version,
  } as HDFAmendments;
}

function vulnerabilityToOverrides(
  vuln: CsafVulnerability,
  publisher: CsafPublisher,
  tracking: CsafTracking,
  docTime: Date,
): StandaloneOverride[] {
  if (!vuln.cve) return [];
  const ps = vuln.product_status;
  if (!ps) return [];

  const out: StandaloneOverride[] = [];
  if (ps.known_not_affected?.length) {
    const o = buildOverride(vuln, publisher, tracking, docTime, VexStatus.NotAffected, ps.known_not_affected);
    if (o) out.push(o);
  }
  const fixedProducts = [...(ps.fixed ?? []), ...(ps.first_fixed ?? [])];
  if (fixedProducts.length > 0) {
    const o = buildOverride(vuln, publisher, tracking, docTime, VexStatus.Fixed, fixedProducts);
    if (o) out.push(o);
  }
  // known_affected / first_affected / last_affected / under_investigation /
  // recommended produce no override (informational only).
  return out;
}

function buildOverride(
  vuln: CsafVulnerability,
  publisher: CsafPublisher,
  tracking: CsafTracking,
  docTime: Date,
  canonical: VexStatus,
  products: string[],
): StandaloneOverride | undefined {
  const target = importTargetFor(canonical);
  if (!target) return undefined;

  const expiresAt = new Date(docTime.getTime() + DEFAULT_EXPIRY_HORIZON_MS);
  const override: StandaloneOverride = {
    type: target.overrideType,
    requirementId: vuln.cve!,
    appliedAt: docTime,
    expiresAt,
    appliedBy: identityFor(publisher),
    reason: buildReason(vuln, products),
  } as StandaloneOverride;

  if (target.status !== undefined) override.status = target.status;

  if (target.setJustification) {
    const j = pickJustification(vuln, products);
    if (j) override.justification = j;
  }

  const evidence: Evidence[] = [];
  const advisoryEv = supplierEvidence(advisoryURI(publisher, tracking), 'CSAF VEX advisory');
  if (advisoryEv) evidence.push(advisoryEv as Evidence);
  for (const r of vuln.references ?? []) {
    if (!r.url) continue;
    const ev = supplierEvidence(r.url, r.summary ?? r.category ?? '');
    if (ev) evidence.push(ev as Evidence);
  }
  if (evidence.length > 0) override.evidence = evidence;

  if (target.overrideType === OverrideType.Poam) {
    const action = firstActionRemediation(vuln, products) || target.poamActionTemplate;
    const milestone: Milestone = {
      description: action,
      status: MilestoneStatus.Pending,
      estimatedCompletion: expiresAt,
    } as Milestone;
    override.milestones = [milestone];
  }

  return override;
}

function pickJustification(
  vuln: CsafVulnerability,
  products: string[],
): Justification | undefined {
  const scope = new Set(products);
  for (const f of vuln.flags ?? []) {
    const ids = f.product_ids ?? [];
    if (!overlap(ids, scope)) continue;
    if (!f.label) continue;
    const j = normalizeJustification(f.label);
    if (j) return j;
  }
  return undefined;
}

function firstActionRemediation(vuln: CsafVulnerability, products: string[]): string {
  const scope = new Set(products);
  for (const r of vuln.remediations ?? []) {
    const ids = r.product_ids;
    if (ids && ids.length > 0 && !overlap(ids, scope)) continue;
    if (
      (r.category === 'vendor_fix' || r.category === 'mitigation' || r.category === 'workaround') &&
      r.details
    ) {
      return r.details;
    }
  }
  return '';
}

// buildReason composes the override reason. products is non-empty by
// construction (we only reach here from a status bucket that contained
// product IDs), so the Products: line always guarantees a non-empty result.
function buildReason(vuln: CsafVulnerability, products: string[]): string {
  const parts: string[] = [];
  const scope = new Set(products);
  for (const n of vuln.notes ?? []) {
    if (n.category === 'description' && n.text) parts.push(n.text);
  }
  for (const t of vuln.threats ?? []) {
    if (!t.details) continue;
    const ids = t.product_ids;
    if (ids && ids.length > 0 && !overlap(ids, scope)) continue;
    parts.push(t.details);
  }
  for (const f of vuln.flags ?? []) {
    const ids = f.product_ids ?? [];
    if (overlap(ids, scope) && f.label) {
      parts.push(`VEX justification: ${f.label}`);
      break;
    }
  }
  parts.push(`Products: ${products.join(', ')}`);
  return parts.join('\n');
}

function identityFor(p: CsafPublisher): Identity {
  if (!p.name) {
    return { type: IdentityType.System, identifier: 'csaf-vex-import' } as Identity;
  }
  const id: Identity = { type: IdentityType.Simple, identifier: p.name } as Identity;
  if (p.category) id.description = p.category;
  return id;
}

function advisoryURI(publisher: CsafPublisher, tracking: CsafTracking): string {
  // tracking.id is required by the CSAF schema; we've already validated
  // document.category so the read is safe. `?? ''` is a paranoid guard
  // against a malformed file that already failed the category check above.
  /* c8 ignore next */
  const id = tracking.id ?? '';
  const ns = publisher.namespace;
  if (ns && id) return `${ns.replace(/\/+$/, '')}/${id}`;
  return id;
}

// overlap is only called with non-empty product scopes (we construct the
// scope from a status bucket that we already checked is non-empty), so
// the empty-set guard is not needed.
function overlap(ids: string[], scope: Set<string>): boolean {
  return ids.some((id) => scope.has(id));
}
