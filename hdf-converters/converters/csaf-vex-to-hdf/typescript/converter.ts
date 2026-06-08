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

import { parseJSON, parseTimestamp } from '@mitre/hdf-utilities';
import {
  Ecosystem,
  IdentityType,
  Justification,
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

interface CsafProductIdentificationHelper {
  purl?: string;
  cpe?: string;
}

interface CsafFullProductName {
  name?: string;
  product_id?: string;
  product_identification_helper?: CsafProductIdentificationHelper;
}

interface CsafBranch {
  category?: string;
  name?: string;
  product?: CsafFullProductName;
  branches?: CsafBranch[];
}

interface CsafProductTree {
  branches?: CsafBranch[];
  full_product_names?: CsafFullProductName[];
}

interface CsafDocument {
  document?: CsafDocumentMeta;
  product_tree?: CsafProductTree;
  vulnerabilities?: CsafVulnerability[];
}

export async function convertCsafVexToHdf(
  input: string,
  converterVersion: string,
): Promise<HDFAmendments> {
  validateInputSize(input, 'csaf-vex-to-hdf');
  const doc = parseJSON<CsafDocument>(input);
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

  const productLookup = buildProductLookup(doc.product_tree);

  const overrides: StandaloneOverride[] = [];
  for (const v of doc.vulnerabilities ?? []) {
    overrides.push(...vulnerabilityToOverrides(v, publisher, tracking, docTime, productLookup));
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
  productLookup: Map<string, AffectedPackage>,
): StandaloneOverride[] {
  if (!vuln.cve) return [];
  const ps = vuln.product_status;
  if (!ps) return [];

  const out: StandaloneOverride[] = [];
  if (ps.known_not_affected?.length) {
    const o = buildOverride(vuln, publisher, tracking, docTime, VexStatus.NotAffected, ps.known_not_affected, productLookup);
    if (o) out.push(o);
  }
  const fixedProducts = [...(ps.fixed ?? []), ...(ps.first_fixed ?? [])];
  if (fixedProducts.length > 0) {
    const o = buildOverride(vuln, publisher, tracking, docTime, VexStatus.Fixed, fixedProducts, productLookup);
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
  productLookup: Map<string, AffectedPackage>,
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

  const affectedPackages = resolveAffectedPackages(products, productLookup);
  if (affectedPackages.length > 0) {
    override.affectedPackages = affectedPackages;
  }

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

// buildReason composes the override reason from CSAF prose (description
// note + product-scoped threat details). Justification and product list
// are fully structured fields now (Justification enum +
// Standalone_Override.affectedPackages); neither is mirrored into reason.
// Falls back to a status synopsis when CSAF carries no prose, so the
// schema's required `reason` string is never empty.
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
  if (parts.length === 0) {
    return `Imported from CSAF VEX (${vuln.cve ?? 'unknown CVE'})`;
  }
  return parts.join('\n');
}

/**
 * Walk a CSAF product_tree and build a lookup from product_id to a
 * structured AffectedPackage. Prefers product_identification_helper.purl,
 * then .cpe, then the full_product_name's `name` (used for matching only
 * — name+version is hard to derive from CSAF reliably, so we drop entries
 * with no purl and no cpe).
 */
export function buildProductLookup(
  tree: CsafProductTree | undefined,
): Map<string, AffectedPackage> {
  const lookup = new Map<string, AffectedPackage>();
  if (!tree) return lookup;
  if (tree.full_product_names) {
    for (const fp of tree.full_product_names) {
      registerProduct(fp, lookup);
    }
  }
  if (tree.branches) {
    walkBranches(tree.branches, lookup);
  }
  return lookup;
}

interface BranchContext {
  productName?: string;
  version?: string;
}

function walkBranches(
  branches: CsafBranch[],
  lookup: Map<string, AffectedPackage>,
  ctx: BranchContext = {},
): void {
  for (const b of branches) {
    // Track product_name and product_version branches so leaf products can
    // recover name+version even when no product_identification_helper is set.
    const next: BranchContext = { ...ctx };
    /* c8 ignore next 2 — falsy branches require a malformed CSAF branch
       node (category set but name empty) which we don't fixture. */
    if (b.category === 'product_name' && b.name) next.productName = b.name;
    if (b.category === 'product_version' && b.name) next.version = b.name;
    if (b.product) registerProduct(b.product, lookup, next);
    if (b.branches) walkBranches(b.branches, lookup, next);
  }
}

function registerProduct(
  fp: CsafFullProductName,
  lookup: Map<string, AffectedPackage>,
  ctx: BranchContext = {},
): void {
  /* c8 ignore next — defensive against a malformed CSAF full_product_name
     missing its required product_id field; not fixtured. */
  if (!fp.product_id) return;
  const helper = fp.product_identification_helper;
  if (helper?.purl) {
    const pkg = affectedPackageFromIdentifier(helper.purl);
    /* c8 ignore next 4 — affectedPackageFromIdentifier always returns a
       non-null value for an input that starts with 'pkg:' (preserves
       malformed input as purl-only). The null branch is unreachable from
       this callsite. */
    if (pkg) {
      lookup.set(fp.product_id, pkg);
      return;
    }
  }
  if (helper?.cpe) {
    const pkg = affectedPackageFromIdentifier(helper.cpe);
    /* c8 ignore next 4 — same as above; identifiers starting with
       'cpe:2.3:' always produce a cpe-only AffectedPackage. */
    if (pkg) {
      lookup.set(fp.product_id, pkg);
      return;
    }
  }
  // No portable identifier — fall back to ancestor product_name +
  // product_version branches if both are present. Ecosystem stays generic
  // since CSAF doesn't disambiguate package managers; the structured triple
  // is still useful for downstream matching.
  if (ctx.productName && ctx.version) {
    lookup.set(fp.product_id, {
      name: ctx.productName,
      version: ctx.version,
      ecosystem: Ecosystem.Generic,
    });
  }
  // Otherwise drop the entry — schema requires name+version+ecosystem OR
  // purl OR cpe; fabricating identity is the anti-pattern Step 1b forbids.
}

function resolveAffectedPackages(
  productIds: string[],
  lookup: Map<string, AffectedPackage>,
): AffectedPackage[] {
  const out: AffectedPackage[] = [];
  const seenKeys = new Set<string>();
  for (const id of productIds) {
    const pkg = lookup.get(id);
    if (!pkg) continue;
    const key = pkg.purl ?? pkg.cpe ?? `${pkg.name ?? ''}@${pkg.version ?? ''}`;
    if (seenKeys.has(key)) continue;
    seenKeys.add(key);
    out.push(pkg);
  }
  return out;
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
