/**
 * HDF Amendments to CSAF VEX (csaf_vex profile) converter.
 *
 * Reverse direction of csaf-vex-to-hdf. Intentionally partial-fidelity:
 * fields the shared VEX mapping considers consumer-action-bearing survive
 * round-trip; the rest collapse into the available CSAF fields.
 */

import {
  Justification,
  MilestoneStatus,
  OverrideType,
  type CVSSSeverity,
  type HDFAmendments,
  type StandaloneOverride,
} from '@mitre/hdf-schema';
import { formatTimestampSeconds } from '@mitre/hdf-utilities';
import {
  validateInputSize,
  parseHdf,
  hdfTime,
  firstNonEmpty,
  emitConverterWarning,
} from '../../../shared/typescript/converterutil.js';
import {
  affectedPackageToIdentifier,
  fixedPackageIdentifier,
  exportStatusFor,
  VexStatus,
} from '../../../shared/typescript/vex/mapping.js';

// Go's zero time.Time, which the Go converter emits when appliedAt is absent.
// TypeScript would otherwise build an Invalid Date here and throw on format.
const GO_ZERO_TIME = new Date('0001-01-01T00:00:00Z');

const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,}$/;
const PRODUCTS_LINE = /^Products:\s*(.+)$/m;
// Kept where the sibling hdf-to-cyclonedx-vex exporter dropped its own: this
// document declares category csaf_vex, whose profile makes product_tree
// mandatory, product_status buckets cannot be empty, and scores[] requires
// products. product_id is a document-local token by spec. Omitting would still
// pass the vendored schema, which does not encode the profile. See the Go peer
// and hdf-libs-5gri.39.
const DEFAULT_PRODUCT_ID = 'HDFPID-0001';

// What a human reads where the token above is what the profile requires. CSAF
// requires a name on every full_product_name, and repeating the token there made
// an invented identifier look like one a vendor had assigned. Mirrors the Go peer.
const DEFAULT_PRODUCT_NAME = 'No product identity was recorded in the source amendment';

interface CSAFVexDocument {
  document: {
    category: 'csaf_vex';
    csaf_version: '2.0';
    title?: string;
    notes?: { category: string; text: string; title?: string }[];
    publisher: { category: string; name: string; namespace?: string };
    tracking: {
      id: string;
      status: 'final';
      version: string;
      current_release_date: string;
      initial_release_date: string;
      revision_history: { date: string; number: string; summary: string }[];
      generator?: { engine: { name: string; version: string }; date: string };
    };
  };
  product_tree: { full_product_names: CsafFullProductName[] };
  vulnerabilities: Vulnerability[];
}

interface CsafFullProductName {
  name: string;
  product_id: string;
  product_identification_helper?: { purl?: string; cpe?: string };
}

interface Vulnerability {
  cve: string;
  notes?: { category: string; text: string }[];
  product_status?: {
    fixed?: string[];
    first_fixed?: string[];
    known_affected?: string[];
    known_not_affected?: string[];
  };
  flags?: { label: string; date?: string; product_ids: string[] }[];
  threats?: { category: string; details: string; product_ids?: string[] }[];
  remediations?: { category: string; details: string; date?: string; product_ids?: string[] }[];
  references?: { category?: string; summary?: string; url: string }[];
  scores?: CsafScore[];
}

// A CSAF score's CVSS block, holding exactly the fields the FIRST.org schema
// for its version requires; buildCsafScore emits nothing else.
interface CsafCvss {
  version: string;
  vectorString: string;
  baseScore: number;
  baseSeverity?: string;
}

interface CsafScore {
  products: string[];
  cvss_v2?: CsafCvss;
  cvss_v3?: CsafCvss;
  cvss_v4?: CsafCvss;
}

/**
 * Map an HDF Cvss_Severity band to the FIRST.org severityType enum: the same
 * five bands, which FIRST spells uppercase. Pinned in both languages to
 * fixtures/cvss-score-cases.json and to the vendored schema's enum.
 */
export function csafSeverity(s: CVSSSeverity): string {
  return s.toUpperCase();
}

/**
 * Map an HDF Cvss block to a CSAF score entry, or undefined when the block
 * cannot be exported.
 *
 * A score is emitted only when every field the FIRST.org schema for its
 * version requires is present: version, vectorString and baseScore, plus
 * baseSeverity for 3.x and 4.0 (2.0 defines no severity, so none is emitted
 * for it). HDF requires only version, so legal HDF can fall short, and the
 * choice is to drop such a block rather than emit it partially: a partial
 * score fails the CSAF schema, and conforming consumers reject a document that
 * fails it, so it would cost every statement in the export, not just itself.
 * Nothing is synthesized to close the gap — a vector cannot be recovered from
 * a score, and a band the source never stated would be asserted in its name —
 * and the drop is logged so the loss is visible. A block with no base metrics
 * at all is consumer enrichment by design (threat or environmental deltas on a
 * riskAdjustment); CSAF scores carry base metrics, so nothing exportable was
 * lost and it is skipped silently.
 */
function buildCsafScore(
  cvss: NonNullable<StandaloneOverride['cvss']>,
  cve: string,
  products: string[],
): CsafScore | undefined {
  const { version, baseVector, baseScore, baseSeverity } = cvss;
  const hasVector = Boolean(baseVector);
  const hasScore = typeof baseScore === 'number';
  const hasSeverity = typeof baseSeverity === 'string';
  if (!hasVector && !hasScore && !hasSeverity) return undefined;

  const v2 = version.startsWith('2');
  if (!baseVector || typeof baseScore !== 'number' || (!v2 && !hasSeverity)) {
    const missing = [
      ...(hasVector ? [] : ['vectorString']),
      ...(hasScore ? [] : ['baseScore']),
      ...(v2 || hasSeverity ? [] : ['baseSeverity']),
    ];
    emitConverterWarning(
      `hdf-to-csaf-vex: ${cve}: CVSS ${version} score not exported, CSAF requires ${missing.join(', ')}`,
    );
    return undefined;
  }

  const inner: CsafCvss = { version, vectorString: baseVector, baseScore };
  if (!v2 && hasSeverity) inner.baseSeverity = csafSeverity(baseSeverity);
  const key = version.startsWith('4') ? 'cvss_v4' : v2 ? 'cvss_v2' : 'cvss_v3';
  // Key order mirrors the Go Score struct so both languages emit identical bytes.
  return { products, [key]: inner };
}

export function convertHdfToCsafVex(input: string, converterVersion: string): string {
  validateInputSize(input, 'hdf-to-csaf-vex');
  const amendments = parseHdf<HDFAmendments>(input);
  const groups = groupByCVE(amendments.overrides ?? []);
  const registry = new Map<string, CsafFullProductName>();
  const vulnerabilities: Vulnerability[] = [];

  for (const group of groups) {
    const v = buildVulnerability(group);
    if (!v) continue;
    vulnerabilities.push(v);
    for (const o of group.overrides) {
      for (const fpn of productEntriesFor(o)) registerProductEntry(registry, fpn);
      for (const fpn of fixedProductEntriesFor(o)) registerProductEntry(registry, fpn);
    }
  }

  if (vulnerabilities.length === 0) {
    throw new Error(
      'hdf-to-csaf-vex: no overrides with CVE-shaped requirementIds; nothing to emit',
    );
  }

  // Global product-id sort (byte order, matching Go's `<`) so multi-product
  // docs are deterministic and byte-identical across languages.
  const names = [...registry.values()].sort((a, b) =>
    a.product_id < b.product_id ? -1 : a.product_id > b.product_id ? 1 : 0,
  );
  const doc = buildDocument(amendments, converterVersion);
  doc.vulnerabilities = vulnerabilities;
  doc.product_tree.full_product_names =
    names.length > 0 ? names : [{ name: DEFAULT_PRODUCT_NAME, product_id: DEFAULT_PRODUCT_ID }];

  return JSON.stringify(doc, null, 2);
}

function registerProductEntry(
  registry: Map<string, CsafFullProductName>,
  fpn: CsafFullProductName,
): void {
  if (!fpn.product_id || registry.has(fpn.product_id)) return;
  registry.set(fpn.product_id, fpn);
}

interface CveGroup {
  cve: string;
  overrides: StandaloneOverride[];
}

function groupByCVE(overrides: StandaloneOverride[]): CveGroup[] {
  const groups = new Map<string, CveGroup>();
  for (const o of overrides) {
    if (!CVE_ID_PATTERN.test(o.requirementId)) continue;
    let g = groups.get(o.requirementId);
    if (!g) {
      g = { cve: o.requirementId, overrides: [] };
      groups.set(o.requirementId, g);
    }
    g.overrides.push(o);
  }
  return [...groups.values()].sort((a, b) => a.cve.localeCompare(b.cve));
}

/**
 * product_tree entries for an override, mirroring productIDsFor but carrying a
 * product_identification_helper (purl/cpe) when affectedPackages supply a
 * portable identifier. The reverse importer reads that helper to recover the
 * structured AffectedPackage; the product_id itself is unchanged.
 */
function productEntriesFor(o: StandaloneOverride): CsafFullProductName[] {
  if (o.affectedPackages && o.affectedPackages.length > 0) {
    const out: CsafFullProductName[] = [];
    for (const p of o.affectedPackages) {
      const id = affectedPackageToIdentifier(p);
      if (!id) continue;
      out.push(fullProductNameFor(id, p));
    }
    if (out.length > 0) return out;
  }
  if (o.componentRef) return [{ name: o.componentRef, product_id: o.componentRef }];
  const m = PRODUCTS_LINE.exec(o.reason ?? '');
  if (m && m[1]) {
    const parts = m[1]
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    if (parts.length > 0) return parts.map((p) => ({ name: p, product_id: p }));
  }
  return [{ name: DEFAULT_PRODUCT_NAME, product_id: DEFAULT_PRODUCT_ID }];
}

/** product_tree entries for the synthesized fixed-version products. */
function fixedProductEntriesFor(o: StandaloneOverride): CsafFullProductName[] {
  const out: CsafFullProductName[] = [];
  for (const p of o.affectedPackages ?? []) {
    const id = fixedPackageIdentifier(p);
    if (!id) continue;
    const fpn: CsafFullProductName = { name: id, product_id: id };
    if (p.purl) fpn.product_identification_helper = { purl: id };
    out.push(fpn);
  }
  return out;
}

/** Build a product_tree leaf, attaching purl (preferred) or cpe as a helper. */
function fullProductNameFor(
  id: string,
  pkg: NonNullable<StandaloneOverride['affectedPackages']>[number],
): CsafFullProductName {
  const fpn: CsafFullProductName = { name: id, product_id: id };
  if (pkg.purl) fpn.product_identification_helper = { purl: pkg.purl };
  else if (pkg.cpe) fpn.product_identification_helper = { cpe: pkg.cpe };
  return fpn;
}

export function productIDsFor(o: StandaloneOverride): string[] {
  // Structured affectedPackages is the source of truth (v3.2.x and later).
  if (o.affectedPackages && o.affectedPackages.length > 0) {
    const ids = o.affectedPackages
      .map((p) => affectedPackageToIdentifier(p))
      .filter((id): id is string => Boolean(id));
    if (ids.length > 0) return ids;
  }
  // Backward-compat fallbacks for pre-affectedPackages HDF inputs.
  if (o.componentRef) return [o.componentRef];
  const m = PRODUCTS_LINE.exec(o.reason ?? '');
  if (m && m[1]) {
    const parts = m[1]
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    if (parts.length > 0) return parts;
  }
  return [DEFAULT_PRODUCT_ID];
}

export function stripProductsLine(reason: string): string {
  return reason.replace(PRODUCTS_LINE, '').replace(/\n+$/, '');
}

/**
 * Fill CSAF references[].summary, which is required with minLength 1 while the
 * HDF description backing it is optional. The URL is the documented fallback:
 * the only text a reference always carries, where a placeholder would assert a
 * description the source never gave.
 */
export function referenceSummary(description: string | undefined, url: string): string {
  return firstNonEmpty(description, url);
}

/**
 * The override reason with the machine-written 'Products:' line removed, or ''
 * when no prose remains. Both sinks it feeds — threats[].details and
 * notes[].text — are minLength 1 in CSAF, so an empty result means the element
 * is omitted, never emitted blank.
 */
export function reasonProse(reason: string | undefined): string {
  return firstNonEmpty(stripProductsLine(reason ?? ''));
}

/**
 * Surface the override reason prose as a CSAF description note. Used on the
 * not_affected/fixed paths, which otherwise drop reason (the affected path
 * keeps it as threats[impact]).
 */
function appendReasonNote(v: Vulnerability, reason: string | undefined): void {
  const text = reasonProse(reason);
  if (!text) return;
  v.notes = v.notes ?? [];
  v.notes.push({ category: 'description', text });
}

/**
 * Render a CSAF remediation date from a milestone: the actual completion when
 * present, else the estimate. Undefined when neither is set.
 */
function milestoneDate(m: NonNullable<StandaloneOverride['milestones']>[number]): string | undefined {
  const t = hdfTime(m.completedAt) ?? hdfTime(m.estimatedCompletion);
  return t ? formatTimestampSeconds(t) : undefined;
}

function allMilestonesCompleted(o: StandaloneOverride): boolean {
  if (!o.milestones || o.milestones.length === 0) return false;
  return o.milestones.every((m) => m.status === MilestoneStatus.Completed);
}

function buildVulnerability(group: CveGroup): Vulnerability | undefined {
  const v: Vulnerability = { cve: group.cve };
  const status: NonNullable<Vulnerability['product_status']> = {};
  let emitted = false;

  for (const o of group.overrides) {
    const pids = productIDsFor(o);

    // Emit consumer-supplied CVSS enrichment as a CSAF score entry.
    if (o.cvss) {
      const score = buildCsafScore(o.cvss, group.cve, pids);
      if (score) {
        v.scores = (v.scores ?? []).concat(score);
        emitted = true;
      }
    }

    // Map each affectedPackages[].fixedInVersion to a distinct fixed-version
    // product referenced in product_status.first_fixed + a vendor_fix remediation.
    for (const p of o.affectedPackages ?? []) {
      const fixedId = fixedPackageIdentifier(p);
      if (!fixedId) continue;
      status.first_fixed = (status.first_fixed ?? []).concat(fixedId);
      status.fixed = (status.fixed ?? []).concat(fixedId);
      v.remediations = (v.remediations ?? []).concat({
        category: 'vendor_fix',
        details: `Fixed in ${p.fixedInVersion}`,
        product_ids: [fixedId],
      });
      emitted = true;
    }

    let canonical = exportStatusFor(o, allMilestonesCompleted(o), false);
    if (!canonical) continue;

    // exportStatusFor returns Fixed only when closureChained is true,
    // which a one-shot export doesn't know. Promote poam-with-all-complete
    // to Fixed here so the obvious case round-trips.
    if (
      o.type === OverrideType.Poam &&
      canonical === VexStatus.Affected &&
      allMilestonesCompleted(o)
    ) {
      canonical = VexStatus.Fixed;
    }

    if (canonical === VexStatus.NotAffected) {
      status.known_not_affected = (status.known_not_affected ?? []).concat(pids);
      if (o.justification) {
        v.flags = v.flags ?? [];
        v.flags.push({
          label: String(o.justification as Justification),
          date: formatTimestampSeconds(hdfTime(o.appliedAt) ?? GO_ZERO_TIME),
          product_ids: pids,
        });
      }
      // The not_affected path historically dropped the override reason (only
      // the affected path surfaced it as threats[impact]). Emit it as a
      // description note — the reverse importer reads that back into
      // override.reason, restoring the prose on round-trip.
      appendReasonNote(v, o.reason);
      emitted = true;
    } else if (canonical === VexStatus.Fixed) {
      status.fixed = (status.fixed ?? []).concat(pids);
      appendReasonNote(v, o.reason);
      for (const m of o.milestones ?? []) {
        if (!m.description) continue;
        v.remediations = v.remediations ?? [];
        const date = milestoneDate(m);
        v.remediations.push({
          category: 'vendor_fix',
          details: m.description,
          ...(date && { date }),
          product_ids: pids,
        });
      }
      emitted = true;
    } else if (canonical === VexStatus.Affected) {
      status.known_affected = (status.known_affected ?? []).concat(pids);
      const details = reasonProse(o.reason);
      if (details) {
        v.threats = v.threats ?? [];
        v.threats.push({ category: 'impact', details, product_ids: pids });
      }
      if (o.type === OverrideType.Poam) {
        for (const m of o.milestones ?? []) {
          if (!m.description) continue;
          v.remediations = v.remediations ?? [];
          const date = milestoneDate(m);
          v.remediations.push({
            category: 'workaround',
            details: m.description,
            ...(date && { date }),
            product_ids: pids,
          });
        }
      }
      emitted = true;
    }

    for (const e of o.evidence ?? []) {
      if (e.type !== 'url' || !e.data) continue;
      v.references = v.references ?? [];
      v.references.push({
        category: 'external',
        summary: referenceSummary(e.description, e.data),
        url: e.data,
      });
    }

    // externalReferences carry advisory/CTI context (STIX, vendor advisories)
    // distinct from url evidence; both share the CSAF references[] home.
    for (const r of o.externalReferences ?? []) {
      if (!r.href) continue;
      v.references = v.references ?? [];
      v.references.push({
        category: 'external',
        summary: referenceSummary(r.description, r.href),
        url: r.href,
      });
    }
  }

  // emitted is false only if every override in the group returned an
  // unmappable canonical status — defensive guard, not reachable from the
  // current shared mapping (which handles every override type).
  /* c8 ignore next */
  if (!emitted) return undefined;

  if (status.fixed) status.fixed = [...new Set(status.fixed)];
  if (status.first_fixed) status.first_fixed = [...new Set(status.first_fixed)];
  if (status.known_affected) status.known_affected = [...new Set(status.known_affected)];
  if (status.known_not_affected) status.known_not_affected = [...new Set(status.known_not_affected)];

  if (v.references) {
    const seen = new Set<string>();
    v.references = v.references.filter((r) => {
      if (seen.has(r.url)) return false;
      seen.add(r.url);
      return true;
    });
  }

  // Key order mirrors the Go Vulnerability struct so both languages emit
  // identical bytes.
  // CSAF constrains product_status with minProperties 1, so an override that
  // contributed no product bucket leaves the field out rather than emit {}.
  return {
    cve: v.cve,
    ...(v.notes && { notes: v.notes }),
    ...(Object.keys(status).length > 0 && { product_status: status }),
    ...(v.flags && { flags: v.flags }),
    ...(v.threats && { threats: v.threats }),
    ...(v.remediations && { remediations: v.remediations }),
    ...(v.references && { references: v.references }),
    ...(v.scores && { scores: v.scores }),
  };
}

/** Stable document time: the earliest override appliedAt, falling back to now. */
function earliestAppliedAt(amendments: HDFAmendments): Date {
  let earliest: Date | undefined;
  for (const o of amendments.overrides ?? []) {
    if (!o.appliedAt) continue;
    const t = hdfTime(o.appliedAt);
    if (!t) continue;
    if (!earliest || t < earliest) earliest = t;
  }
  return earliest ?? new Date();
}

function buildDocument(
  amendments: HDFAmendments,
  converterVersion: string,
): CSAFVexDocument {
  const now = formatTimestampSeconds(earliestAppliedAt(amendments));
  const publisherName = amendments.appliedBy?.identifier || 'HDF Amendments Export';
  const trackingId = amendments.amendmentId || 'HDF-VEX-EXPORT';
  const docVersion = amendments.version || '1';
  const title = amendments.name || 'HDF Amendments exported as CSAF VEX';
  const notes: { category: string; text: string; title?: string }[] = [];
  if (amendments.description) {
    notes.push({ category: 'summary', text: amendments.description, title: 'Description' });
  }
  return {
    document: {
      category: 'csaf_vex',
      csaf_version: '2.0',
      title,
      ...(notes.length > 0 && { notes }),
      // CSAF requires publisher.namespace: a URL under the issuing party's
      // control serving as its globally unique identifier. SAF/HDF tool export.
      publisher: { category: 'other', name: publisherName, namespace: 'https://saf.mitre.org' },
      tracking: {
        id: trackingId,
        status: 'final',
        version: docVersion,
        current_release_date: now,
        initial_release_date: now,
        revision_history: [
          { date: now, number: docVersion, summary: 'Generated by hdf-to-csaf-vex from HDF Amendments.' },
        ],
        generator: { engine: { name: 'hdf-to-csaf-vex', version: converterVersion }, date: now },
      },
    },
    product_tree: { full_product_names: [] },
    vulnerabilities: [],
  };
}
